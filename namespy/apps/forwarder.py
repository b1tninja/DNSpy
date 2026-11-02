"""The forwarder, named (roadmap W4).

namespy already *can* be a forwarding server: ``serve()`` in ``__main__`` wires a
:class:`~namespy.server.DnsServer` whose forwarder rung answers every query from a
:class:`~namespy.stub.StubResolver` before recursion is ever reached -- the stub
owns the walk-upstream behavior (REFUSED advances the list, any other answer comes
back as it arrived, RFC 7858 section 3.4 reuse), and the server owns the relay
(it echoes the client's ID and question, clears ``AA`` because authority is
upstream's to claim, and answers silence with RFC 8914's EDE 22 "No Reachable
Authority"). That wiring works, but it only existed as the CLI's ``serve()`` body --
not something a library embedder could reach.

This module is the composability proof ``docs/strategy.md`` stakes the tier on:
**zero new core code.** :class:`Forwarder` imports the same pieces and assembles
them into one handle -- ``serve()`` brings it up, ``stop()`` lets every socket go,
``stats()`` reports what it has answered. Nothing here computes an answer or touches
a wire format; the relay and the stub are the library's, reused.

One reuse trick is worth naming because it is the whole point: ``DnsServer``'s
forwarder is configured through ``dot_upstreams``, but the constructor passes a
non-string :class:`~namespy.stub.Upstream` through **unchanged** -- the ``dot`` name
only forces a transport on *text* it parses. :class:`Forwarder` hands it built
:class:`Upstream` objects, so the same relay speaks the stub's whole
udp/tcp/dot/doh range. ``DnsServer`` also requires a recursive resolver as its
last-resort rung; in forwarding mode the forwarder answers first and that resolver
never walks, but it is constructed because the type check asks for it -- a fact the
docstring records rather than hides.

Conditional per-name routing (the W3 :class:`~namespy.apps.routing.RouteTable`)
is deliberately *not* wired here: that is a later row. This is plain forwarding to a
configured upstream set, which is the increment the roadmap calls "the forwarder,
named."
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections import Counter
from typing import Any, Literal

from ..engine import Engine
from ..querylog import QueryLog
from ..resolver import RecursiveResolver
from ..server import DnsServer, DnsStreamServer
from ..stub import Upstream
from .lookup import coerce_upstreams

#: The loopback address-port a forwarding fixture binds by default. The server is a
#: loopback instrument by design (RFC 5358 / RFC 9085: an open recursive resolver is
#: an amplification weapon); a Forwarder that listens elsewhere is an operator choice,
#: passed explicitly, not the default.
DEFAULT_LISTEN = ("127.0.0.1", 53)

__all__ = ["DEFAULT_LISTEN", "Forwarder"]


class _MemorySink:
    """A tiny in-memory ``QueryLog`` sink -- the stdlib file-like the log wants.

    The Forwarder always attaches one so :meth:`Forwarder.stats` has something to
    count without the server keeping counters of its own (it does not, and adding
    any would be new core code). The log already records one JSON line per answer
    with the ``origin`` rung it came off; this just keeps those lines in memory.
    """

    def __init__(self) -> None:
        self._buffer: list[str] = []

    def write(self, text: str) -> int:
        self._buffer.append(text)
        return len(text)

    def flush(self) -> None:  # the log flushes per record; nothing buffered here
        pass

    def records(self) -> list[dict]:
        parsed = []
        for line in "".join(self._buffer).splitlines():
            if line.strip():
                parsed.append(json.loads(line))
        return parsed

    def clear(self) -> None:
        self._buffer.clear()


class Forwarder:
    """A named forwarding server: a ``DnsServer`` front, a ``StubResolver`` upstream.

    Built over one or more recursive servers -- the same addresses, configuration
    text, or :class:`~namespy.stub.Upstream` objects ``StubResolver`` takes, so the
    full udp/tcp/dot/doh range is available. ``serve()`` binds the listeners and
    returns the handle; ``stop()`` closes everything it opened (and its own engine,
    if it built one); ``stats()`` summarizes the answers it has relayed.
    """

    def __init__(
        self,
        upstreams: Any,
        *,
        listen: tuple[str, int] = DEFAULT_LISTEN,
        serve_tcp: bool = True,
        nsid: Any = None,
        filter_policy: Any = None,
        engine: Engine | None = None,
        name: str = "namespy-forwarder",
        **server_kwargs: Any,
    ) -> None:
        self._upstreams: tuple[Upstream, ...] = coerce_upstreams(upstreams)
        self._listen = listen
        self._serve_tcp = bool(serve_tcp)
        self._server_args: dict[str, Any] = {
            "nsid": nsid,
            "filter_policy": filter_policy,
            **server_kwargs,
        }
        self._name = name
        self._engine = engine if engine is not None else Engine(name)
        self._owns_engine = engine is None
        self._sink = _MemorySink()
        self._query_log = QueryLog(self._sink)
        # Everything below is bound lazily by serve() on the engine loop and freed by
        # stop(); building a Forwarder never touches a socket or starts a thread.
        self._backstop: RecursiveResolver | None = None
        self._backstop_transport: asyncio.BaseTransport | None = None
        self._server: DnsServer | None = None
        self._server_transport: asyncio.BaseTransport | None = None
        self._stream_server: asyncio.AbstractServer | None = None
        self._built = False
        self._closed = False
        self._lock = threading.Lock()

    # -- lifecycle -----------------------------------------------------------

    def _make_server(self) -> DnsServer:
        """Build the front DnsServer, forwarding to our upstreams via its forwarder rung.

        ``dot_upstreams`` is given built :class:`Upstream` objects on purpose: the
        constructor forces the ``dot`` transport only on text it parses, so objects
        keep their own transport and the relay speaks udp/tcp/dot/doh (module
        docstring). The recursive resolver is the required last-resort rung; the
        forwarder answers first, so it never walks here.
        """
        if self._backstop is None:  # pragma: no cover - _build sets it first
            raise RuntimeError("forwarder built out of order: no backstop resolver")
        return DnsServer(
            self._backstop,
            dot_upstreams=self._upstreams,
            query_log=self._query_log,
            **self._server_args,
        )

    async def _build(self) -> Forwarder:
        """Bind the backstop resolver, the UDP front, and the TCP listener (idempotent)."""
        if self._closed:
            raise RuntimeError(f"forwarder {self._name!r} is closed; build a new one")
        if self._built:
            return self
        loop = asyncio.get_running_loop()
        self._backstop_transport, self._backstop = await loop.create_datagram_endpoint(
            RecursiveResolver, local_addr=("0.0.0.0", 0)
        )
        self._server_transport, self._server = await loop.create_datagram_endpoint(
            self._make_server, local_addr=self._listen
        )
        if self._serve_tcp:
            # BCP 235 (RFC 9210 §3): anything that calls itself a DNS server MUST
            # serve both UDP and TCP -- the same DnsServer instance, framed per
            # connection by DnsStreamServer.
            front = self._server
            if front is None:  # pragma: no cover - create_datagram_endpoint just bound it
                raise RuntimeError("forwarder built out of order: no front server")
            self._stream_server = await loop.create_server(
                lambda: DnsStreamServer(front),
                host=self._listen[0],
                port=self._listen[1],
            )
        self._built = True
        return self

    async def _teardown(self) -> None:
        """Release every listener and socket serve() opened (runs on the engine loop)."""
        server, backstop = self._server, self._backstop
        for transport in (self._server_transport, self._backstop_transport):
            if transport is not None:
                transport.close()
        if self._stream_server is not None:
            self._stream_server.close()
        # The server's aclose releases its forwarder's held upstream sessions; the
        # backstop's releases its own sockets. Both are awaited before the fields go.
        if server is not None:
            await server.aclose()
        if backstop is not None:
            await backstop.aclose()
        self._server = self._backstop = None
        self._server_transport = self._backstop_transport = self._stream_server = None
        self._built = False

    def serve(self) -> Forwarder:
        """Bring the forwarder up on its engine and return the handle (blocking)."""
        return self._engine.run(self._build())

    async def aserve(self) -> Forwarder:
        """Bring the forwarder up, awaitable from any asyncio loop."""
        return await asyncio.wrap_future(self._engine.submit(self._build()))

    def stop(self) -> None:
        """Close listeners, the forwarder's held sessions, the backstop, and -- if this
        Forwarder built it -- its engine. Idempotent; a no-op before ``serve()``."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._engine.run(self._teardown())
        except RuntimeError:
            pass  # the loop is already gone; there is nothing bound left to release
        if self._owns_engine:
            self._engine.close()

    @property
    def running(self) -> bool:
        """Whether the forwarder is currently bound (and not stopped)."""
        return self._built and not self._closed

    # -- observation ---------------------------------------------------------

    def stats(self) -> dict:
        """Summarize the answers relayed so far, read from the in-memory query log.

        ``served`` is the count of answers; ``by_origin`` breaks them down by the
        ladder rung each came off (``forward`` for a relayed upstream answer, plus
        whatever a bound responder or filter would report); ``servfail`` counts the
        answers that came back SERVFAIL -- which for a forwarding server is the
        honest tally of queries its own upstream configuration failed (EDE 22).
        """
        records = self._sink.records()
        by_origin = Counter(record.get("origin", "?") for record in records)
        servfail = sum(1 for record in records if int(record.get("rcode", 0)) == 2)
        return {"served": len(records), "by_origin": dict(by_origin), "servfail": servfail}

    def reset_stats(self) -> None:
        """Zero the counters by emptying the in-memory sink (the server keeps none)."""
        self._sink.clear()

    # -- context managers ----------------------------------------------------

    def __enter__(self) -> Forwarder:
        return self.serve()

    def __exit__(self, *exc_info: object) -> Literal[False]:
        self.stop()
        return False

    async def __aenter__(self) -> Forwarder:
        return await self.aserve()

    async def __aexit__(self, *exc_info: object) -> None:
        await self.astop()

    async def astop(self) -> None:
        """Async form of :meth:`stop` for embedders already running a loop."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            future = self._engine.submit(self._teardown())
        except RuntimeError:
            return
        await asyncio.wrap_future(future)
        if self._owns_engine:
            await asyncio.to_thread(self._engine.close)
