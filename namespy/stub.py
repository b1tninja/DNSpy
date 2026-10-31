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

import dataclasses
import ipaddress
import logging

from .enums import DnsRClass, DnsResponseCode, DnsRType
from .names import DomainName
from .packet import DnsRecord
from .rdata import RData_A, RData_AAAA
from .resolver import Resolver

LOGGER = logging.getLogger("namespy.stub")

#: The transports this build can speak to a recursive server. "dot" (RFC 7858)
#: and "doh" (RFC 8484) join the tuple as their transports land; refusing an
#: unimplemented name at the door of :class:`Upstream` is kinder than
#: accepting a configuration that would fail mid-query.
TRANSPORTS: tuple[str, ...] = ("udp", "tcp")


@dataclasses.dataclass(frozen=True)
class Upstream:
    """One recursive server the stub was configured to ask.

    *host* is an IP literal -- the stub does not resolve its own bootstrap
    servers, which is the same reason the root hints are addresses rather
    than names. *port* leaves 53 for the plain transports; the encrypted
    transports' defaults (853, 443) belong to the transports, not to this
    record. *transport* is validated against :data:`TRANSPORTS` at
    construction so a typo is a startup sentence, not a silent fallback.
    """

    host: str
    port: int = 53
    transport: str = "udp"

    def __post_init__(self) -> None:
        ip = ipaddress.ip_address(self.host)  # ValueError is the right refusal
        object.__setattr__(self, "host", str(ip))  # one canonical text form
        port = int(self.port)
        if not 0 < port <= 65535:
            raise ValueError(f"upstream port {self.port!r} is not a usable port number")
        object.__setattr__(self, "port", port)
        if self.transport not in TRANSPORTS:
            raise ValueError(
                f"unknown upstream transport {self.transport!r}; "
                f"this build forwards over {', '.join(TRANSPORTS)}"
            )

    @classmethod
    def parse(cls, text: str) -> Upstream:
        """Read one upstream from configuration text.

        ``1.0.0.1``, ``1.0.0.1:5353``, ``2606:4700:4700::1001`` and
        ``[2606:4700:4700::1001]:853`` -- brackets around the IPv6 wherever a
        port follows, because a colon is otherwise doing two jobs.
        """
        text = text.strip()
        port: int | None = None
        if text.startswith("["):
            host, sep, rest = text[1:].partition("]")
            if not sep:
                raise ValueError(f"unbalanced brackets in upstream {text!r}")
            if rest:
                if not rest.startswith(":"):
                    raise ValueError(f"expected ':' before the port in upstream {text!r}")
                port = _parse_port(rest[1:], text)
        elif text.count(":") == 1:
            host, _, digits = text.partition(":")
            port = _parse_port(digits, text)
        else:
            host = text
        if port is None:
            return cls(host=host)
        return cls(host=host, port=port)


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
    ) -> None:
        #: The pending-question tables and transports the inherited send/receive
        #: plumbing writes. Declared here because a stub never runs
        #: :meth:`RecursiveResolver.__init__`, which is where the walk sets its
        #: own copies of the same four names.
        self.queue: dict[tuple, tuple] = {}
        self.queue_v6: dict[tuple, tuple] = {}
        self.transport = None
        self.transport_v6 = None
        self._v6_ready = None
        self.upstreams = tuple(Upstream.parse(u) if isinstance(u, str) else u for u in upstreams)
        self.dnssec_ok = bool(dnssec_ok)
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
        for upstream in self.upstreams:
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
        return await self.query(
            list(questions),
            None,
            _host_address_record(upstream.host),
            port=upstream.port,
            force_tcp=upstream.transport == "tcp",
            **kwargs,
        )

    async def aclose(self) -> None:
        """Release the sockets this protocol bound, and the v6 bring-up task."""
        task, self._v6_ready = self._v6_ready, None
        if task is not None and not task.done():
            task.cancel()
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
