"""The stub resolver: forwarding the query to servers that will recurse (RFC 1034 §5.3.1).

The document that invented the stub also defined this module in one sentence
(§5.3.1¶2): "All that the remaining stub needs is a list of name server
addresses that will perform the recursive requests." Everything here is that
list wired to a transport: compose the query with ``RD`` set -- §4.1.1's
"If RD is set, it directs the name server to pursue the query recursively" --
hand it to a listed server, and return the answer as it came. The stub
resolves nothing itself, and that restraint is the design: it is why the same
list can stand behind any transport on which a recursive server is reachable,
and why RFC 7858's TLS and RFC 8484's HTTPS will arrive as transports of this
class rather than as new resolvers.

Three fidelities separate forwarding from mere sending.

*RD is a request, not a promise.* §4.1.1 says outright that "Recursive query
support is optional", and §5.3.1¶2 tells the operator to verify the listed
servers will perform the service, because "a name server is free to refuse to
perform recursive services for any or all clients". A REFUSED answer is read
as precisely that -- *this* upstream declining the arrangement -- and the rest
of the list is asked; only when every upstream refused does the caller receive
the refusal. A SERVFAIL, by contrast, is an answer: that server did the work
and reported how it ended, and re-running the whole list behind a name that
failed only multiplies the delay to the same news.

*The answer comes back as it arrived.* The stub keeps no cache and forms no
verdict: it is a forwarding transport, and what the upstream asserted is
returned so the caller -- a client, or the validating layer of whoever owns
this resolver -- decides what it means.

*The client's request rides along.* ``client_cd`` copies the Checking Disabled
bit onto the forwarded query (RFC 4035 §3.2.2's arrangement between a
validating client and the server it asks), and DO goes out whenever this
resolver asked for DNSSEC data -- the one meaning
:attr:`~namespy.resolver.Resolver.dnssec_ok` has carried throughout the
package.

Upstreams are addresses, not names -- resolving a resolver is the bootstrap
problem §5.3.1 hands to the configuration file, and this module inherits that
division: the list arrives from outside, validated as literals at the door.
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import logging
import ssl

from .doh import _DohSession, doh_alpn, open_doh_session
from .edns import keepalive_of, keepalive_option
from .enums import DnsRClass, DnsResponseCode, DnsRType
from .names import DomainName
from .packet import EDNS_DO_BIT, DnsRecord, Query
from .rdata import RData_A, RData_AAAA
from .resolver import (  # noqa: F401 -- re-exported, and the tests import these names from here
    _KEEPALIVE_DEFAULT_S,
    _KEEPALIVE_FLOOR_S,
    Resolver,
    _idle_seconds,
    _Session,
)

LOGGER = logging.getLogger("namespy.stub")

#: The transports this build can speak to a recursive server.
TRANSPORTS: tuple[str, ...] = ("udp", "tcp", "dot", "doh")

#: The port each transport defaults to, when the configuration text names no
#: port: 53 for the two cleartext forms, 853 for DNS over TLS -- RFC 7858
#: §3.1's "By default, a DNS client desiring privacy from DNS over TLS ...
#: MUST establish a TCP connection to port 853", and its warning that a
#: negotiated alternative "MUST NOT be port 53" is why the dot default could
#: not simply inherit 53 -- and 443 for DNS over HTTPS, the https scheme's
#: own default (RFC 8484 §5¶1 binds DoH to https, and §8.1¶2 counts the
#: 443-mixing camouflage among the transport's virtues).
DEFAULT_PORTS = {"udp": 53, "tcp": 53, "dot": 853, "doh": 443}

# The keepalive idle arithmetic (_KEEPALIVE_DEFAULT_S, _KEEPALIVE_FLOOR_S,
# _idle_seconds) and the held-stream session class (_Session) live in
# :mod:`namespy.resolver` beside the base transport that now shares them:
# the walk's own TCP fallbacks pool the same sessions the ``dot`` transport
# holds, so the shape and its RFC 7828 §3.2.2 arithmetic belong to the
# plumbing, not to whichever resolver reached for it first. Imported above.

#: RFC 7858 §3.1¶4's "reasonable period (such as one hour per server)" for
#: remembering a server that refused DNS over TLS -- timeout, refusal, or a
#: handshake that ended in failure, all three saying the same thing about
#: this host. One hour is the document's own example and this build's
#: constant: long enough that a lookup storm does not re-pound a dead 853,
#: short enough that a fixed server is reachable again the same working day.
_DOT_REMEMBER_S = 3600.0


@dataclasses.dataclass(frozen=True)
class Upstream:
    """One recursive server the stub was configured to ask.

    *host* is an IP literal -- the stub does not resolve its own bootstrap
    servers, which is the same reason the root hints are addresses rather
    than names. *port* defaults by transport (:data:`DEFAULT_PORTS`): 53
    clear, 853 for ``dot``. *transport* is validated against
    :data:`TRANSPORTS` at construction so a typo is a startup sentence, not a
    silent fallback.

    *server_name* is the identity a ``dot`` connection authenticates: RFC
    7858 §3.2¶1 sends the client through [BCP195]'s best practices, whose
    first practice is validating the certificate against the name the client
    meant to reach -- and an IP literal cannot be that name. The host stays
    an address (the thing to connect to) while this carries the name (the
    thing to believe); configuration text supplies both, ``#``-joined:
    ``1.2.3.4:853#dns.example.net``. An unauthenticated ``dot`` upstream is
    refused at the door: privacy without authentication is the profile
    §4.1 sketches, but this build declines to be the way into it -- the
    on-path attacker that profile tolerates can feed a stub any answer, and
    an operator who wants that has the cleartext transports to say it with.
    """

    host: str
    port: int | None = None
    transport: str = "udp"
    server_name: str | None = None
    path: str = "/dns-query"

    def __post_init__(self) -> None:
        ip = ipaddress.ip_address(self.host)  # ValueError is the right refusal
        object.__setattr__(self, "host", str(ip))  # one canonical text form
        if self.transport not in TRANSPORTS:
            raise ValueError(
                f"unknown upstream transport {self.transport!r}; "
                f"this build forwards over {', '.join(TRANSPORTS)}"
            )
        port = DEFAULT_PORTS[self.transport] if self.port is None else int(self.port)
        if not 0 < port <= 65535:
            raise ValueError(f"upstream port {self.port!r} is not a usable port number")
        object.__setattr__(self, "port", port)
        if self.transport in ("dot", "doh") and not self.server_name:
            raise ValueError(
                f"{self.transport} upstream {self.host}:{port} names no server to "
                "authenticate; append #<name> to the configuration text"
            )
        path = str(self.path)
        if self.transport == "doh":
            if not path.startswith("/"):
                raise ValueError(
                    f"doh upstream path {path!r} is not a URI-template path "
                    "(it must start with '/')"
                )
            object.__setattr__(self, "path", path)

    @classmethod
    def parse(cls, text: str, transport: str | None = None) -> Upstream:
        """Read one upstream from configuration text.

        ``1.0.0.1``, ``1.0.0.1:5353``, ``2606:4700:4700::1001``,
        ``[2606:4700:4700::1001]:853`` -- brackets around the IPv6 wherever a
        port follows, because a colon is otherwise doing two jobs -- and
        ``<address>#<name>`` to add the identity the encrypted transports
        authenticate, with a trailing ``/<path>`` for a ``doh`` URI template
        (§3¶1's configured template, ``#dns.example.net/dns-query``).

        *transport*, when given, is the caller's declared intent (the CLI's
        ``--stub-transport``): the default port must derive from it, not from
        the ``udp`` the text alone implies, which is why replacing the field
        after construction could never do -- construction has already pinned
        53 into what should become 853 or 443.
        """
        text = text.strip()
        address, _, anchor = text.partition("#")
        name, slash, path_part = anchor.partition("/")
        server_name = name.strip() or None
        path = ("/" + path_part.strip()) if slash and path_part.strip() else "/dns-query"
        port: int | None = None
        if address.startswith("["):
            host, sep, rest = address[1:].partition("]")
            if not sep:
                raise ValueError(f"unbalanced brackets in upstream {text!r}")
            if rest:
                if not rest.startswith(":"):
                    raise ValueError(f"expected ':' before the port in upstream {text!r}")
                port = _parse_port(rest[1:], text)
        elif address.count(":") == 1:
            host, _, digits = address.partition(":")
            port = _parse_port(digits, text)
        else:
            host = address
        return cls(
            host=host,
            port=port,  # None rides through: the transport's default is decided here
            transport=transport or "udp",
            server_name=server_name,
            path=path,
        )


def _parse_port(digits: str, text: str) -> int:
    try:
        return int(digits)
    except ValueError as exc:
        raise ValueError(f"upstream {text!r} carries a non-numeric port") from exc


def _host_address_record(host: str) -> DnsRecord:
    """Wrap the literal IP as the A/AAAA record :meth:`~namespy.resolver.Resolver.query` wants.

    The send path takes an address record because the walk's addresses arrive
    as glue; a configured upstream is the same fact without the glue story, so
    it gets the same wrapper -- root owner name, TTL 0, nothing a caller could
    mistake for cached data.
    """
    ip = ipaddress.ip_address(host)
    root = DomainName(".")
    if ip.version == 6:
        return DnsRecord(root, DnsRType.AAAA, DnsRClass.IN, 0, rdata=RData_AAAA(ip))
    return DnsRecord(root, DnsRType.A, DnsRClass.IN, 0, rdata=RData_A(ip))


class StubResolver(Resolver):
    """Forward queries to a list of recursive servers and return their answers.

    The transport is :class:`~namespy.resolver.Resolver`'s -- one bound UDP
    socket, the pending-question table, the TC/timeout fallback to TCP --
    pointed at a configured upstream instead of a delegation walk. That reuse
    is the whole argument for the class layout: forwarding and recursing
    differ in whom they ask and what they make of the answer, not in how a DNS
    message crosses a network.

    Like its recursive sibling an instance is an ``asyncio`` protocol, bound
    by the driver::

        loop = asyncio.get_running_loop()
        _transport, resolver = await loop.create_datagram_endpoint(
            lambda: StubResolver([Upstream("10.1.1.1")]),
            local_addr=("0.0.0.0", 0),
        )
        response = await resolver.forward([question])

    A UDP transport is used by the ``udp`` transport; a list of purely
    ``transport="tcp"`` upstreams never touches it, so a stub may be built and
    asked without a bound socket in that case.
    """

    log = LOGGER

    def __init__(
        self,
        upstreams=(),
        *,
        dnssec_ok: bool = False,
        edns_payload_size: int | None = None,
        query_timeout: float | None = None,
        doh_method: str = "POST",
    ) -> None:
        #: The pending-question tables and transports the inherited send/receive
        #: plumbing writes. Declared here because a stub never runs
        #: :meth:`RecursiveResolver.__init__`, which is where the walk sets its
        #: own copies of the same four names.
        self.queue: dict[tuple, tuple] = {}
        self.queue_v6: dict[tuple, tuple] = {}
        self._tcp_sessions: dict = {}
        self.transport = None
        self.transport_v6 = None
        self._v6_ready = None
        self.upstreams = tuple(Upstream.parse(u) if isinstance(u, str) else u for u in upstreams)
        self.dnssec_ok = bool(dnssec_ok)
        if doh_method not in ("POST", "GET"):
            raise ValueError("doh_method is POST or GET (RFC 8484 §4.1's two methods)")
        self.doh_method = doh_method
        #: Held encrypted-stream sessions (``dot`` and ``doh``), keyed by the
        #: upstream they belong to. One connection per upstream: RFC 7858
        #: §3.4¶1-¶2 asks for exactly this reuse "to avoid excess TCP
        #: connections, each with a single query", and RFC 8484 §5.2's
        #: HTTP/2 streams make the same connection do more at once.
        self._sessions: dict[Upstream, _Session | _DohSession] = {}
        #: RFC 7858 §3.1¶4's memory of servers that refused the encrypted
        #: transport -- DoH keeps the same hour, for the same reason.
        #: keyed by upstream, valued by the monotonic deadline before which
        #: retrying is rude. Only ``dot`` failures earn a note: a dead UDP
        #: upstream is retried because the next packet may simply be the one
        #: that gets through, while a TLS handshake that completed badly has
        #: told us something durable about this host.
        self._stream_dead: dict[Upstream, float] = {}
        if edns_payload_size is not None:
            self.edns_payload_size = int(edns_payload_size)
        if query_timeout is not None:
            self.query_timeout = float(query_timeout)

    async def forward(self, questions, *, client_cd: bool = False, rd: bool = True):
        """Ask the upstreams, in order, and return the first answer that speaks.

        Returns the upstream's :class:`~namespy.packet.Response` exactly as it
        arrived -- ``RA``, ``AD``, TTLs and all: a forwarder that edits answers
        stops being one -- or ``None`` when no upstream answered at all.
        *rd* stays True because recursion *is* the arrangement; passing False
        asks the upstream authoritatively instead, which is what a forwarder
        feeding a walk would want and nothing else.
        """
        refused = None
        now = asyncio.get_running_loop().time()
        for upstream in self.upstreams:
            deadline = self._stream_dead.get(upstream)
            if deadline is not None:
                if now < deadline:
                    # §3.1¶4: this host said it cannot do TLS recently
                    # enough that asking again is re-pounding a door we
                    # know is shut. Silence here is the remembered answer.
                    self.log.debug(
                        "stub_stream_remembered_dead(host=%s port=%d retry_in=%.0fs)",
                        upstream.host,
                        upstream.port,
                        deadline - now,
                    )
                    continue
                del self._stream_dead[upstream]
            response = await self._ask(upstream, questions, rd=rd, client_cd=client_cd)
            if response is None:
                self.log.debug(
                    "stub_upstream_silent(host=%s port=%d transport=%s)",
                    upstream.host,
                    upstream.port,
                    upstream.transport,
                )
                continue
            if int(response.extended_rcode) == int(DnsResponseCode.REFUSED):
                # §4.1.1's optional-recursion clause in the clear: this server
                # declined the arrangement itself. Keep the first refusal to
                # return if nobody else will do the work, and ask the next.
                if refused is None:
                    refused = response
                continue
            return response
        if refused is not None:
            self.log.debug("stub_all_upstreams_refused(n=%d)", len(self.upstreams))
        return refused

    async def _ask(self, upstream, questions, *, rd: bool, client_cd: bool):
        kwargs = {"RD": rd}
        if client_cd:
            kwargs["CD"] = True
        if upstream.transport in ("dot", "doh"):
            return await self._ask_stream(upstream, questions, **kwargs)
        return await self.query(
            list(questions),
            None,
            _host_address_record(upstream.host),
            port=upstream.port,
            force_tcp=upstream.transport == "tcp",
            # edns-tcp-keepalive belongs to stream transports only: RFC 7828
            # §3.2.1¶1 forbids it in a UDP query ("MUST ignore" is the
            # server's half of the same sentence, §3.3.1¶1, and this client
            # does not make servers do paperwork). The udp transport's TCP
            # *fallback* goes without the option -- that connection is
            # opened to rescue one answer, not arranged for a future, and
            # §3.2.1¶2's permission to signal a desire to hold a connection
            # is not an obligation to invent one mid-fallback.
            extra_edns_options=(keepalive_option(),) if upstream.transport == "tcp" else (),
            **kwargs,
        )

    async def _ask_stream(self, upstream, questions, **kwargs):
        """One query over a held encrypted stream: §3.3's framing, §3.4's reuse.

        The composition is the same ``Query`` + EDNS advertisement the
        cleartext transports send -- a TLS answer is a DNS answer -- and the
        *stream* is the stub's, outliving the exchange. Reuse is eager and
        shared: the session lives in the map from the moment it connects, so
        a second concurrent query finds it and *waits on its lock* rather
        than opening a rival connection (RFC 7858 §3.4¶1: reuse one
        connection, don't pile them up); §3.3¶2's preference for pipelining
        over waiting is left unexercised deliberately -- with one exchange
        in flight per stream, §3.3¶3's matching duty is dischargeable by ID
        alone, and a stub's tail latency is its client's.
        After the answer the idle timer is re-armed with whatever RFC 7828
        says: the server's offered TIMEOUT (floored at
        :data:`_KEEPALIVE_FLOOR_S`), or :data:`_KEEPALIVE_DEFAULT_S` when it
        named none or the conversation did not happen; a TIMEOUT of 0 closes
        now (§3.2.2¶3's "send no more queries on that connection").

        Failures split the way §3.1¶4 splits them: a connection or handshake
        that never came up marks this upstream dead for
        :data:`_DOT_REMEMBER_S`, because that is the document's own remedy
        for servers that "don't support DNS over TLS"; a stream that died
        while it waited its turn (the idle timer fired mid-queue) is
        invisible -- one fresh attempt, then success, or silence. A live
        answer always clears the dead-note: it is the retry the paragraph
        intends.
        """
        dns_packet = Query(questions=list(questions), **kwargs)
        if self.edns_payload_size:
            dns_packet.add_edns(
                int(self.edns_payload_size),
                # edns-tcp-keepalive is a conversation about the *TCP
                # connection*; under DoH the connection belongs to HTTP,
                # which keeps its own (RFC 8484 asks it of no DNS option).
                options=(keepalive_option(),) if upstream.transport == "dot" else (),
                flags=EDNS_DO_BIT if self.dnssec_ok else 0,
            )
        if upstream.transport == "doh":
            dns_packet.ID = 0  # RFC 8484 §4.1¶8: HTTP correlates; 0 unifies caches
        wire = bytes(dns_packet)
        for attempt in (1, 2):
            session = self._sessions.get(upstream)
            if session is not None and session.closed:
                self._drop_session(upstream, session)
                session = None
            fresh = session is None
            if fresh:
                try:
                    session = await self._stream_connect(upstream)
                except Exception as exc:
                    self._note_stream_dead(upstream, exc)
                    return None
                self._sessions[upstream] = session
            try:
                if session.multiplexed:
                    # HTTP/2: this query rides its own stream beside any
                    # other in flight (RFC 8484 §4.2¶3's multi-streaming).
                    pkt = await self._stream_one(session, dns_packet, wire, upstream)
                    self._note_stream_success(session, pkt, upstream)
                else:
                    async with session.lock:
                        if session.closed:
                            # idle-timed-out (or died) while this call queued
                            # for the lock -- a network event, not a statement
                            raise ConnectionError("session ended before its turn")
                        pkt = await self._stream_one(session, dns_packet, wire, upstream)
                        self._note_stream_success(session, pkt, upstream)
            except Exception as exc:
                self._drop_session(upstream, session)
                if fresh:
                    self._note_stream_dead(upstream, exc)
                    return None
                if attempt == 2:
                    self.log.debug(
                        "stub_stream_failed(host=%s port=%d transport=%s err=%s)",
                        upstream.host,
                        upstream.port,
                        upstream.transport,
                        type(exc).__name__,
                    )
                    return None
                continue  # the shared session died mid-queue: retry on a fresh one
            self._stream_dead.pop(upstream, None)  # a live answer clears the note
            return pkt
        return None  # unreachable: both attempts return or continue above

    async def _stream_connect(self, upstream):
        if upstream.transport == "doh":
            return await self._doh_connect(upstream)
        return await self._dot_connect(upstream)

    async def _stream_one(self, session, dns_packet, wire, upstream):
        """The transport's own question-and-answer, one per call or per stream."""
        if isinstance(session, _DohSession):
            return await session.exchange(dns_packet, wire)
        pkt = await self._stream_exchange(
            session.reader, session.writer, wire, dns_packet, upstream.host
        )
        if pkt is None:
            raise ConnectionError("upstream answered something else")
        return pkt

    def _note_stream_success(self, session, pkt, upstream) -> None:
        """Re-arm the connection's idle life after an answer -- or let it stay."""
        loop = asyncio.get_running_loop()
        if isinstance(session, _DohSession):
            session.keep_alive(loop)  # HTTP/1.1 arms its timer; HTTP/2 stays open
            return
        timeout = keepalive_of(pkt.edns_options())
        if timeout == 0:
            self._drop_session(upstream, session)
        else:
            session.arm_idle(_idle_seconds(timeout), loop)

    def _drop_session(self, upstream, session) -> None:
        """Retire *session*, and only it, from the reuse map."""
        if self._sessions.get(upstream) is session:
            del self._sessions[upstream]
        session.close_now()

    async def _dot_connect(self, upstream) -> _Session:
        """TLS to an authenticated name: BCP195, exactly as §3.2¶1 prescribes.

        :func:`ssl.create_default_context` *is* BCP195's default posture
        (protocol floor, chain validation, hostname match), and
        ``server_hostname`` carries the identity the certificate must answer
        to -- §5's requirement that the server "be authenticated based on
        its presented certificate" against the name the configuration
        intended, not the address it happened to reach.
        """
        context = self._tls_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                upstream.host,
                upstream.port,
                ssl=context,
                server_hostname=upstream.server_name,
            ),
            timeout=self.query_timeout,
        )
        self.log.debug(
            "stub_dot_connected(host=%s port=%d name=%s)",
            upstream.host,
            upstream.port,
            upstream.server_name,
        )
        return _Session(reader, writer)

    async def _doh_connect(self, upstream):
        """HTTPS to an authenticated name, in whatever HTTP it negotiates.

        The TLS posture is :meth:`_dot_connect`'s (BCP195 through
        :meth:`_tls_context`) with the ALPN offer of RFC 8484 §5.2 added --
        and §8.1¶1's requirement that the server be authenticated is the
        same door ``dot`` walks through: no name, no connection.
        """
        context = doh_alpn(self._tls_context())
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                upstream.host,
                upstream.port,
                ssl=context,
                server_hostname=upstream.server_name,
            ),
            timeout=self.query_timeout,
        )
        session = await open_doh_session(reader, writer, upstream, method=self.doh_method)
        self.log.debug(
            "stub_doh_connected(host=%s port=%d name=%s method=%s)",
            upstream.host,
            upstream.port,
            upstream.server_name,
            self.doh_method,
        )
        return session

    def _tls_context(self) -> ssl.SSLContext:
        """The trust the ``dot`` transport extends.

        A method rather than a call site because trust is exactly the part
        an application must be able to edit: a stub behind an enterprise
        TLS-inspecting resolver loads its private CA the same way a test
        loads the certificate it generated, and both want BCP195's settings
        around that extra root rather than instead of them. Subclasses add
        their cafile; the checks stay on.
        """
        return ssl.create_default_context()

    def _note_stream_dead(self, upstream, exc) -> None:
        self._stream_dead[upstream] = asyncio.get_running_loop().time() + _DOT_REMEMBER_S
        self.log.debug(
            "stub_stream_unavailable(host=%s port=%d err=%s remembered=%ds)",
            upstream.host,
            upstream.port,
            type(exc).__name__,
            int(_DOT_REMEMBER_S),
        )

    async def aclose(self) -> None:
        """Release the sockets this protocol bound, and the v6 bring-up task."""
        task, self._v6_ready = self._v6_ready, None
        if task is not None and not task.done():
            task.cancel()
        for session in self._sessions.values():
            session.close_now()
        self._sessions.clear()
        self._close_tcp_sessions()  # the cleartext pool the base transport holds
        self._stream_dead.clear()
        for transport in (self.transport, self.transport_v6):
            if transport is not None:
                try:
                    transport.close()
                except Exception as exc:  # best-effort teardown, said not raised
                    # A socket that refuses to close is already gone or going;
                    # the lookup it served is over and there is nobody left to
                    # notify louder than the log.
                    self.log.debug("stub_close_failed(err=%s)", type(exc).__name__)
        self.transport = None
        self.transport_v6 = None

    async def __aenter__(self) -> StubResolver:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
