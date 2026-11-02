"""A resident forwarding client with all three drives (roadmap W2).

``StubResolver`` is, like the recursive resolver, an :class:`asyncio.Protocol`:
one object, bound to one event loop, for its whole life. That lifetime is the
feature. RFC 7858 section 3.4 tells a DNS-over-TLS client to "reuse a single TCP
connection to the recursive resolver" and *not* "immediately close a connection
after each response", because the point of TLS to a resolver is partly that the
handshake is paid once. A fresh endpoint per question throws that away -- every
lookup in a thousand-question loop re-does the TCP and TLS setup the standard
asks you to amortize. :class:`StubResolver` already keeps the held sessions
itself (its ``_sessions`` map, RFC 7858 section 3.4 paragraphs 1-2); what was
missing was a public object whose *life* spans the loop so those sessions survive
from one question to the next. This is that object.

It owns exactly two things: one :class:`~namespy.engine.Engine` (the thread and
loop that ``StubResolver`` lives on) and one bound ``StubResolver`` created on
first use. It speaks in all three drives ``namespy.engine`` defines, over a
single :meth:`_ask_one` coroutine -- await, blocking, and callback are the same
forward dressed three ways, never three implementations. Both context-manager
forms close what the object made: ``with`` for a caller with no loop, ``async
with`` for one inside a loop. The held sessions are released, the endpoint socket
is closed, and -- only if this Stub built its own engine -- the engine thread is
stopped.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Literal

from ..engine import Engine
from ..packet import DnsQuestion
from ..stub import StubResolver, Upstream
from .lookup import DEFAULT_TIMEOUT_S, coerce_upstreams, make_question

__all__ = ["Stub"]


class Stub:
    """One forwarding client, one engine, three drives, held streams for its life.

    Constructed from upstreams -- the same addresses, configuration text, or
    :class:`~namespy.stub.Upstream` objects :class:`~namespy.stub.StubResolver`
    takes, and for the same reason (the list arrives from outside; the stub does
    not resolve its own bootstrap servers, RFC 1034 section 5.3.1). Nothing binds
    until the first question is asked, so building a :class:`Stub` never touches
    the network or starts a thread.
    """

    def __init__(
        self,
        upstreams: Any,
        *,
        dnssec_ok: bool = False,
        edns_payload_size: int | None = None,
        query_timeout: float | None = None,
        engine: Engine | None = None,
        name: str = "namespy-stub",
    ) -> None:
        self._upstreams: tuple[Upstream, ...] = coerce_upstreams(upstreams)
        self._resolver_kwargs: dict[str, Any] = {"dnssec_ok": bool(dnssec_ok)}
        if edns_payload_size is not None:
            self._resolver_kwargs["edns_payload_size"] = int(edns_payload_size)
        if query_timeout is not None:
            self._resolver_kwargs["query_timeout"] = float(query_timeout)
        self._name = name
        # A borrowed engine is shared, so closing it would betray its owner; an
        # owned one is ours to stop. The flag is the whole difference between the
        # two teardown paths below.
        self._engine = engine if engine is not None else Engine(name)
        self._owns_engine = engine is None
        # Bound lazily on the engine's loop, the first time a question is asked;
        # the engine serialises coroutines onto one loop, so these two fields are
        # only ever written by that one thread and never race each other.
        self._resolver: StubResolver | None = None
        self._transport: asyncio.BaseTransport | None = None
        self._closed = False
        self._close_lock = threading.Lock()

    # -- the single real surface (every drive awaits this) -------------------

    def _make_resolver(self) -> StubResolver:
        """Build the protocol the endpoint binder hands to the loop."""
        return StubResolver(self._upstreams, **self._resolver_kwargs)

    async def _bound(self) -> StubResolver:
        """The live ``StubResolver``, binding it on first use (on the engine loop).

        Held sessions are the reason this binds *once*: the same object answers
        every question, so its ``_sessions`` map of encrypted streams survives
        between them, which is RFC 7858 section 3.4's reuse made observable. A
        closed Stub raises rather than quietly rebinding -- state does not migrate
        between loops, and a Stub whose sockets are gone is not the same client.
        """
        if self._closed:
            raise RuntimeError(f"stub {self._name!r} is closed; build a new one")
        if self._resolver is not None:
            return self._resolver
        loop = asyncio.get_running_loop()
        transport, resolver = await loop.create_datagram_endpoint(
            self._make_resolver, local_addr=("0.0.0.0", 0)
        )
        self._transport = transport
        self._resolver = resolver
        return resolver

    async def _ask_one(self, question: DnsQuestion) -> Any:
        """Forward *question* to the held resolver -- the one coroutine underneath."""
        resolver = await self._bound()
        return await resolver.forward([question])

    def _submit(self, question: DnsQuestion, *, timeout: float | None, on_done=None):
        """Hand :meth:`_ask_one` to the engine and return its concurrent future.

        If the engine refuses the coroutine at the door -- closed, or its loop
        gone -- the coroutine object this call built is closed here rather than
        abandoned, so a refused question leaves no deallocator warning. Nothing
        below :meth:`_ask_one` belongs to the engine until it takes it.
        """
        coro = self._ask_one(question)
        try:
            return self._engine.submit(coro, timeout=timeout, on_done=on_done)
        except BaseException:
            coro.close()
            raise

    # -- the three drives ----------------------------------------------------

    async def ask(
        self,
        name: Any,
        qtype: Any = "A",
        *,
        qclass: Any = "IN",
        timeout: float | None = DEFAULT_TIMEOUT_S,
    ) -> Any:
        """The **await** drive, usable from any asyncio loop.

        The forward runs on this Stub's engine loop, not the caller's, so the
        result is bridged back with :func:`asyncio.wrap_future` rather than
        awaited across the boundary directly -- awaiting an object bound to
        another loop is the mistake the engine exists to prevent. Returns the
        upstream's :class:`~namespy.packet.Response` exactly as it arrived, or
        ``None`` when no upstream answered.
        """
        future = self._submit(make_question(name, qtype, qclass), timeout=timeout)
        return await asyncio.wrap_future(future)

    def ask_blocking(
        self,
        name: Any,
        qtype: Any = "A",
        *,
        qclass: Any = "IN",
        timeout: float | None = DEFAULT_TIMEOUT_S,
    ) -> Any:
        """The **blocking** drive: :meth:`Engine.run` on the engine loop.

        Works from a thread that already runs its own event loop -- the nested-loop
        trap the engine fixed by construction -- because the call crosses into the
        engine's loop rather than calling :func:`asyncio.run` here.
        """
        coro = self._ask_one(make_question(name, qtype, qclass))
        try:
            return self._engine.run(coro, timeout=timeout)
        except BaseException:
            coro.close()  # a door-refusal leaves the caller's coroutine untouched
            raise

    def ask_callback(
        self,
        name: Any,
        qtype: Any = "A",
        *,
        qclass: Any = "IN",
        timeout: float | None = DEFAULT_TIMEOUT_S,
        on_done: Any = None,
    ):
        """The **callback** drive: return a :class:`concurrent.futures.Future` now.

        *on_done* is called with that future on the engine's loop thread; a
        callback that raises is logged by the engine and never reaches this Stub
        (the responder rule W1 carries to the client side). Returns the future
        whether or not *on_done* was given, so the caller can poll it themselves.
        """
        return self._submit(make_question(name, qtype, qclass), timeout=timeout, on_done=on_done)

    # -- teardown ------------------------------------------------------------

    async def _teardown(self) -> None:
        """Release the bound resolver and its sockets, running on the engine loop.

        Both doors close: the resolver's own ``aclose`` (held TCP/DoT/DoH sessions
        and the private IPv6 socket) and the endpoint transport asyncio handed us,
        which is the two-socket teardown the raw API always required. Fields are
        dropped first so a re-entrant or racing teardown binds nothing a second
        time.
        """
        resolver, transport = self._resolver, self._transport
        self._resolver = self._transport = None
        if resolver is not None:
            await resolver.aclose()
        if transport is not None:
            transport.close()

    def close(self) -> None:
        """Close the Stub from a non-engine thread (the ``with`` exit path).

        Runs :meth:`_teardown` on the engine loop, then stops the engine only if
        this Stub built it. A teardown that finds the engine loop already gone is
        swallowed: there is nothing left to release, and a daemon thread's
        teardown is not the moment to raise.
        """
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._engine.run(self._teardown())
        except RuntimeError:
            pass  # loop already went away; nothing bound remains to close
        if self._owns_engine:
            self._engine.close()

    async def aclose(self) -> None:
        """Close the Stub from inside a running loop (the ``async with`` exit path).

        The teardown is bridged onto the engine loop with
        :func:`asyncio.wrap_future`; the engine itself (if owned) is stopped in a
        worker thread, because :meth:`Engine.close` joins the engine thread and so
        cannot run on it -- and must not block the caller's loop either.
        """
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            future = self._engine.submit(self._teardown())
        except RuntimeError:
            return  # engine already down; nothing bound remains to close
        await asyncio.wrap_future(future)
        if self._owns_engine:
            await asyncio.to_thread(self._engine.close)

    def __enter__(self) -> Stub:
        return self

    def __exit__(self, *exc_info: object) -> Literal[False]:
        self.close()
        return False

    async def __aenter__(self) -> Stub:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
