"""A DNS server that answers by recursing with :class:`RecursiveResolver`.

Two transports answer: :class:`DnsServer` is the datagram half (a protocol
on a UDP endpoint), and :class:`DnsStreamServer` fronts it with one
instance per accepted TCP connection -- the length-framed conversation of
RFC 1035 section 4.2.2, the edns-tcp-keepalive schedule of RFC 7828
section 3.3, and the idle management BCP 235 asks servers to make
configurable. One responder pipeline serves both: a response leaves
through whichever channel the question arrived on, and the recursion, the
bounds, and the option rules below are transport-blind.

Serving has a different risk profile from resolving. A resolver receives input
from servers it chose; a server receives input from anyone, and every unanswered
query it forwards is a candidate for a reflection/amplification attack. Three
consequences shape this module:

* **Never emit output the operator did not ask for.** The module previously built
  a fresh ``logging.Logger("server")`` and attached a module-global handler to it,
  so importing namespy and constructing a server produced output regardless of
  application configuration -- and an ``INFO`` line per query plus a ``print`` of
  every response turned a query flood into a log flood.
* **Bound the in-flight upstream lookups.** Each inbound datagram previously
  spawned ``asyncio.create_task`` with no reference kept, so the task could be
  garbage-collected mid-flight, and concurrency was whatever the sender chose.
* **Fail closed on malformed input.** A parse failure gets a ``FORMERR`` and a
  debug-level note rather than a traceback.

Serving also means *answering honestly about what this host supports*. A
responder that ignores OPT tells an EDNS requestor nothing about its reassembly
limit and hides the upper eight bits of any RCODE above 15, so
:meth:`DnsServer._apply_edns` builds the reply's OPT from this server's own
numbers -- and sends none at all to a requestor that never asked, which RFC
6891 section 7 makes the correct answer rather than an oversight.

Options inside that OPT are handled by the same rule, applied in two
directions. This server answers a query whose option it does not understand by
ignoring it -- "Any OPTION-CODE values not understood by a responder or
requestor MUST be ignored" (section 6.1.2) -- and answers one whose
option is *misformed* with FORMERR, because section 7 asks for exactly that and
insists the error response still carry an OPT, so a requestor can tell "this
server has EDNS and disliked what you sent" from "this server has no EDNS". The
one option it implements is NSID (RFC 5001): an identity string configured at
construction, returned only to a query that asked for it, never invented on its
own. Padding (RFC 7830) is deliberately *not* honoured here: section 4 says a
responder must pad when asked, section 6 says an implementation must not use
the option over an unencrypted transport, and both of this server's
transports -- datagram and stream -- are plaintext -- the second MUST is the
one that can be obeyed without lying about the
encryption, so padding is dropped and the reply stays its natural size.

MQTYPE (RFC 10029) is implemented in both directions: a malformed request is
refused and a well-formed one is *answered*. A query carrying a broken
MQTYPE-Query option -- an odd-length type list, a Meta RRTYPE inside it, a
repeated QTx, a second copy of the option -- gets FORMERR, because section 3.3
enumerates eight such conditions and requires that answer for each. A valid one
gets section 3.4's combination: the primary question is resolved first and its
RCODE and flags fixed at that moment, each extra QTx is resolved by its own
standalone query, and a result is merged only if it matches the primary on every
one of those values. What survives goes into the section it would have occupied
had it been asked alone (RFC 1035 section 4.1), deduplicated within that section
and deliberately not across sections. The reply carries a MQTYPE-Response option
listing exactly the QTx values folded in whole -- possibly an empty list, which
section 3.4 permits while still requiring the option, because the option's
presence is the entire message a client can read about support.

Three of section 3.4's sentences are load-bearing and easy to get backwards. The
option "MUST NOT itself trigger a truncated response", so a QTx that would push
the answer past what the client advertised is withdrawn and left off the list --
TC is never set on its account -- and processing stops there, which is also what
keeps section 4's amplification worry bounded: a client that asked for eight
types is refused the remaining seven without seven more outbound queries. A
primary answer that is already truncated gets no extra lookups at all, while
still getting the option. And the obligation to send it is not conditional on
success: a server that supports the extension must answer *every* valid query
with the option, including the SERVFAIL that a failed resolution produces, so
that path carries an empty list rather than silence.

.. rubric:: References

* RFC 1035 section 4.1.1 (header), section 4.3 (server behaviour)
* RFC 5001 section 2.2 (send NSID only when it was asked for, ignore any
  payload the requestor put in the request form of the option)
* RFC 5358 section 3 (why a recursing server is an amplification instrument),
  section 4 (BCP 140: give recursive service to intended clients only)
* RFC 5625 section 6.2 (do not listen on interfaces you do not control), section
  6.3 (intrinsically malformed traffic MAY be dropped rather than answered)
* RFC 6891 section 6.1.1 (one OPT per message, OPT is never forwarded, an OPT
  request must be answered with an OPT), section 6.1.2 (option format; unknown
  codes must be ignored), section 6.1.3 (BADVERS for a VERSION this server does
  not implement), section 6.2.3 (the requestor's advertised payload size is what
  it can reassemble, values under 512 read as 512, and the number belongs to
  one transaction), section 7 (an OPT-free request must be answered without OPT;
  an option that is badly formatted or out of range must be answered FORMERR,
  with an OPT; header, question, and OPT are a truncated response's floor)
* RFC 7830 sections 4, 6 (a responder must pad when asked -- and must not use
  the option at all on an unencrypted transport, which both of this server's
  transports are)
* RFC 7873 section 5.2 (COOKIE lengths, and the FORMERR for an illegal one)
* RFC 8914 section 2 (an Extended DNS Error may ride in any response to a query
  that carried an OPT), section 3 (drop EDE options before other data when the
  response outgrows the requestor's payload size), sections 4.22-4.23 (the codes
  this server's own failures earn)
* RFC 10001 section 4.2 paragraph 4 (a resolver answering recursive queries
  follows section 4.1 paragraph 4's fragmentation-avoidance guidance
  analogously -- which lands as: a UDP answer never outgrows what the client
  advertised, truncation works back from the end of the datagram setting TC
  (with RFC 1035 sections 4.2.1 and 6.2), and the TCP fallback that promise
  needs is the stream this server already serves)
* RFC 10029 section 3.3 (the MQTYPE-Query conditions that oblige a FORMERR),
  section 3.4 (combining several QTYPEs into one answer: the flag-matching test,
  the per-section duplicate rule, and the rule that the option must never itself
  cause truncation), section 3.5 (how a client reads a QTx missing from the
  answer, which is what makes declining one quietly legitimate), section 4 (the
  operator-configurable limit on how many QTx values one query may ask for)
* RFC 6895 section 3.1 (the data/QTYPE/Meta split a QTx is validated against)
"""

import asyncio
import ipaddress
import logging
import struct
from dataclasses import dataclass

from . import enable_path_mtu_discovery
from .anchors import sentinel_expectation, trusted_anchor_tags
from .dnssec import DNSSEC_SECURITY_TYPES
from .edns import (
    COOKIE_OPTION_CODE,
    ERROR_OPTION_CODE,
    MQTYPE_QUERY_OPTION_CODE,
    NSID_OPTION_CODE,
    EdnsOption,
    cookie_length_valid,
    extended_dns_error_option,
    extended_error_option_valid,
    find_option,
    keepalive_of,
    keepalive_option,
    nsid_of,
)
from .enums import DnsOpCode, DnsQR, DnsQType, DnsResponseCode, DnsRType
from .mqtype import (
    MQTYPE_RECOMMENDED_QTX_LIMIT,
    mqtype_query_rejection,
    mqtype_response_option,
    qtypes_of,
)
from .names import DomainName
from .packet import (
    OPT_RTYPE,
    DnsPacket,
    DnsPacketParseError,
    DnsQuestion,
    DnsRecord,
    Query,
    Response,
)
from .rdata import RData_A, RData_AAAA, RData_TXT
from .resolver import EDNS_PAYLOAD_SIZE, RecursiveResolver

LOGGER = logging.getLogger(__name__)

#: EDNS(0) VERSION this server implements. RFC 6891 section 6.1.3: "If a
#: responder does not implement the VERSION level of the request, then it MUST
#: respond with RCODE=BADVERS", and "the VERSION of each response SHOULD be the
#: highest implementation level of the responder" -- which is this number.
EDNS_VERSION_SUPPORTED = 0

#: Largest RCODE expressible without an OPT record. RFC 6891 section 6.1.3
#: lays OPT's TTL out so that "EXTENDED-RCODE value 0 indicates that an
#: unextended RCODE is in use (values 0 through 15)"; above that, the upper
#: eight bits have nowhere to go unless OPT is present.
MAX_UNEXTENDED_RCODE = 0xF

#: Payload size advertised in this server's own OPT record. Section 6.2.4 makes
#: that field the *responder's* reassembly limit -- it is deliberately not a
#: copy of the requestor's -- and section 6.2.5 asks for a large starting point.
#: The same 1232-octet figure the resolver advertises outbound is reused here so
#: that one number describes this host's stack rather than two.
RESPONDER_PAYLOAD_SIZE = EDNS_PAYLOAD_SIZE

#: RFC 8914 section 4.22: "The requested operation or query is not supported."
EDE_NOT_SUPPORTED = 21

#: RFC 8914 section 4.23: "The resolver could not reach any of the authoritative
#: name servers (or they potentially refused to reply)." Which is precisely the
#: condition this server is in when its resolver hands back nothing.
EDE_NO_REACHABLE_AUTHORITY = 22

#: RFC 8914 section 4.7: "The resolver attempted to perform DNSSEC validation,
#: but validation ended in the Bogus state." The one EDE this server can send for
#: a response that is not an error-of-its-own-composition: the refusal was
#: composed by its resolver side under its own trust anchors, so §4.7's sentence
#: describes this host exactly -- and a validation failure labelled 22 would name
#: the wrong fault ("nobody answered" when somebody answered unforgably).
EDE_DNSSEC_BOGUS = 6

#: RFC 8914 section 4.2: "The response contains data that is stale, i.e. the
#: data's TTL has expired." RFC 8767 §9 rejected a dedicated EDNS option for
#: exactly this signal and RFC 8914 later provided the general one, so a
#: serve-stale answer says what it is in the field built for it -- the client
#: that reads extended errors learns the record is expired; the one that does
#: not still gets the >0 short TTL that makes it retry rather than settle.
EDE_STALE_ANSWER = 2

#: RFC 9824 section 3.5 para 3: a query for the NXNAME Meta-TYPE earns a
#: FORMERR (section 3.5 para 2's MUST) and this code MAY explain it. The MAY
#: is taken, because FORMERR says the message failed to parse when what is
#: wrong is the question -- and section 9's Table 3 registered the code for
#: nothing else.
EDE_INVALID_QUERY_TYPE = 30

#: The Extended DNS Errors this server reports about *itself*.
#:
#: Only its own failures are listed, and that is the deliberate half of RFC 8914
#: section 3: relaying what an upstream server said is left to the forwarder --
#: "whether or not (and how) to pass along EDE information on to their original
#: client is implementation dependent" -- and this one keeps upstream explanations
#: in its log and in its failure cache rather than putting a stranger's words on the
#: wire as its own. Codes 0 through 24 belong to that registry; nothing here invents
#: one.
#:
#: The text is short on purpose (section 3: "implementers and operators creating EDE
#: options SHOULD avoid lengthy EXTRA-TEXT contents") and names this software, which
#: is the attribution the same paragraph asks for and none of the private information
#: section 2 warns against.
_OWN_FAILURE_ERRORS = {
    int(DnsResponseCode.SERVER_FAILURE): (
        EDE_NO_REACHABLE_AUTHORITY,
        b"namespy: no authoritative answer",
    ),
    int(DnsResponseCode.NOT_IMPLEMENTED): (
        EDE_NOT_SUPPORTED,
        b"namespy: only QUERY is supported",
    ),
}

#: How many upstream lookups one server instance allows at once. Bounded on
#: purpose: it is what makes this server's *egress* provably limited relative to
#: its ingress, which is the property an amplification defence needs (RFC 5358
#: section 3). No specification sets a number -- this one is a design decision.
MAX_CONCURRENT_LOOKUPS = 32

#: The idle horizon a :class:`DnsStreamServer` connection keeps by default.
#: RFC 7766 section 6.2.3 paragraph 2 recommends a server idle period "on
#: the order of seconds" and names no number; RFC 7828 section 3.4 leaves
#: the value to the server, requiring only (section 3.3.2 paragraph 1) that
#: what is advertised be what is enforced. Thirty seconds is this build's
#: answer to both, and the same figure the client side rides when a server
#: offers nothing (:data:`namespy.resolver._KEEPALIVE_DEFAULT_S`) -- so a
#: default conversation between the two halves of this package agrees
#: without either reading the other's source.
DEFAULT_TCP_IDLE_S = 30


class StreamChannel:
    """How one response reaches the stream it arrived on, and what to say there.

    A bound method of :class:`DnsStreamServer` for *send*, plus the
    keepalive TIMEOUT this connection advertises (``None`` for a server
    that keeps silent about its idle policy). It rides through
    :meth:`DnsServer.respond_to_packet` as a keyword, and its presence is
    the whole of the difference between the two transports: a response
    that leaves through a channel goes to one client's open stream and may
    carry the keepalive announcement, while a response with no channel is
    the ordinary datagram answer -- on which RFC 7828 section 3.3.1
    paragraph 1 obliges the server to ignore the option even when the
    query carried it, which it does, because ``None`` never reaches the
    option builder.
    """

    __slots__ = ("keepalive", "send")

    def __init__(self, send, keepalive=None):
        self.send = send
        self.keepalive = keepalive


#: The three RR sections of a message, as the attribute that holds each one and
#: the header count that describes it, in the order RFC 1035 section 4.1 lays
#: them out. RFC 10029 section 3.4 is a rule *about sections* -- extra RRs go
#: "into the same sections in which they would have appeared in a standalone
#: query", and duplicates are removed within a section and not across them -- so
#: this is the one place that knows what a section is and how it is counted.
_SECTIONS = (
    ("answers", "ANCOUNT"),
    ("nameservers", "NSCOUNT"),
    ("additional_records", "ARCOUNT"),
)

#: The records a DO=0 client must not receive unless its query named the type.
#:
#: :data:`~namespy.dnssec.DNSSEC_SECURITY_TYPES` plus DS -- and the addition is
#: a decision, taken against the exact text rather than the shared constant's
#: convenience. RFC 4035 §3.1¶1 enumerates what a DO=1 query buys: a signed
#: zone "MUST include additional RRSIG, NSEC, and DS RRs" (NSEC3/NSEC3PARAM
#: join via RFC 5155, DNSKEY via §3.1.2's conditional piggyback), and §3.2.1¶1
#: withdraws the same set for a client that did not ask: "MUST strip any
#: authenticating DNSSEC RRs from the response but MUST NOT strip any DNSSEC RR
#: types that the initiating query explicitly requested." Note how both
#: sentences speak of *types* -- a DS is data when the query names it, and
#: authentication material when it does not.
#:
#: The shared constant keeps DS out because it serves the walk too, and the
#: walk consumes §3.1.4's referral-riding DSes -- a legitimate use, and the
#: only place the omission has ever been about. This is the client-facing hop,
#: the one §3.2.1 addresses: referrals never leave this server, but a DS can
#: still arrive inside a non-authoritative upstream answer that the walk takes
#: as given, and RFC 3225 §2¶3 is on the record about what such clients used to
#: do with records they could not parse -- "failing (in the worst case) or
#: entire responses being ignored (in the better case)". Stripping here costs
#: nothing the recursion needs and closes the class of client the DO bit
#: exists to protect.
_CLIENT_STRIP_TYPES = DNSSEC_SECURITY_TYPES | {int(DnsRType.DS)}


@dataclass(frozen=True)
class ResponderRequest:
    """Everything a bound responder is entitled to know about one query.

    The point of a dedicated context rather than the raw packet is the
    reflex case (U2): what makes a ``whoami`` answer honest is that it can
    only come from the transport -- ``address`` is where the datagram
    arrived *from*, ``transport`` is the socket it arrived on -- facts the
    question itself cannot carry and a zone file cannot hold. *dnssec_ok*
    and *cd* ride along because an answer's shape may legitimately depend
    on whether the client validates; the full *packet* is there for a
    handler that needs more, at its own risk of coupling.
    """

    name: DomainName
    qtype: int
    qclass: int
    address: tuple
    transport: str
    dnssec_ok: bool
    cd: bool
    packet: DnsPacket


@dataclass(frozen=True)
class DynamicResponse:
    """What a responder says. A bare sequence of records is this with defaults.

    *answers* empty is a deliberate NODATA: the handler answered, and its
    answer is "nothing at this name" -- distinct from returning ``None``,
    which means "not mine, ask the network". *rcode* ``None`` reads as
    NO_ERROR; a handler that wants NXDOMAIN or REFUSED says so, and the
    question echo, OPT rules, and EDE mapping that every other response
    gets are applied by the same :meth:`DnsServer._reply` door either way.
    """

    rcode: object = None
    answers: tuple = ()
    authority: tuple = ()


class _ResponderFailed:
    """Sentinel: a bound handler raised. Fall-through is the one answer left
    that must not happen -- the operator bound this name precisely so the
    network would never be asked about it -- so the query dies SERVFAIL."""


_RESPONDER_FAILED = _ResponderFailed()


#: The name :func:`whoami_responder` answers, when ``--serve-reflexive`` binds
#: it. A local invention in the family of ``whoami.cloudflare`` and
#: ``o-o.myaddr.l.google.com`` -- no RFC registers it, and none of those names
#: is standardized either; the reflex *service* is the idea, the name is
#: deployment.
REFLEXIVE_NAME = DomainName("whoami.")


def whoami_responder(request: ResponderRequest) -> DynamicResponse:
    """The calling-number announcement circuit, in DNS.

    TNAC was the telephone network's courtesy: dial a number and the network
    tells you the number you called from -- an answer only the transport can
    give, which is exactly what makes it unforgeable advice. This is that
    service for a DNS server: the source address of the query that arrived,
    as A/AAAA it is visible in, plus a TXT that says so in words. Nothing is
    asserted about the *caller*; only about what this socket saw, which is
    the whole honesty of the design:

    * an A query from an IPv4 peer answers its address; from an IPv6 peer it
      answers NODATA -- the v4 side is not visible here, and inventing it
      would break the one promise the service makes;
    * TXT always answers, and names the port too, because the ephemeral port
      is the fact a debugger actually wants ("did my two queries share a
      socket?") and it cannot be forged by the querier either;
    * every record carries TTL 0: there is nothing to cache about a snapshot
      of someone's own packet, and the next query will differ at least in
      the port.

    The CHaos-class precedent (``version.bind``, ``id.server``) is why TXT is
    the traditional medium; this answers in the IN class, where the resolver
    in front of the demo needs no special handling to fetch it.
    """
    host, port = str(request.address[0]), request.address[1]
    try:
        version = ipaddress.ip_address(host).version
    except ValueError:
        # A peer address this module cannot parse is a bug or a weird scope
        # id; NODATA beats composing a sentence about bytes nobody verified.
        return DynamicResponse()
    records = []
    if request.qtype in (int(DnsQType.A), int(DnsQType.ANY)) and version == 4:
        records.append(DnsRecord(request.name, DnsRType.A, ttl=0, rdata=RData_A(host)))
    if request.qtype in (int(DnsQType.AAAA), int(DnsQType.ANY)) and version == 6:
        records.append(DnsRecord(request.name, DnsRType.AAAA, ttl=0, rdata=RData_AAAA(host)))
    if request.qtype in (int(DnsQType.TXT), int(DnsQType.ANY)):
        sentence = f"namespy saw you at {host}:{port} over {request.transport}"
        if request.dnssec_ok:
            sentence += ", DO set"
        records.append(DnsRecord(request.name, DnsRType.TXT, ttl=0, rdata=RData_TXT([sentence])))
    return DynamicResponse(answers=tuple(records))


class DnsServer(asyncio.Protocol):
    """Answer DNS queries over a datagram transport by recursing.

    :param resolver: the :class:`~namespy.resolver.RecursiveResolver` that does
        the work. It must already be bound to a transport, which is why resolver
        and server are connected to the event loop in that order.
    :param max_concurrent_lookups: cap on outstanding recursive lookups.
    """

    def __init__(
        self,
        resolver,
        max_concurrent_lookups: int = MAX_CONCURRENT_LOOKUPS,
        nsid=None,
        max_qtypes: int | None = MQTYPE_RECOMMENDED_QTX_LIMIT,
        tcp_idle: int | None = DEFAULT_TCP_IDLE_S,
    ):
        """
        :param nsid: the RFC 5001 name-server identifier to advertise when a
            query asks for it — :class:`bytes`, or text to be encoded as UTF-8,
            or :const:`None` for a server that never sends the option.

            Opaque on the wire, and it should stay that way: RFC 5001 section 2
            wants it to identify "the instance of the name server", which is why
            a hostname or a rack name is the usual answer and why nothing here
            tries to parse it. Leaving it unset is the conservative default --
            section 2.2 forbids sending the option unasked, and a server with no
            identity to declare has nothing to leak about which machine in a
            anycast set answered.
        :param max_qtypes:
            how many MQTYPE QTx values one query may have processed (RFC 10029
            section 4: "Implementors SHOULD therefore allow operators to
            configure limits on the number of QTx values specified and/or the
            resulting response size"). The default is the document's own
            public-DNS figure, four; :const:`None` removes the limit, which is
            what the same paragraph advises for DNS-SD and private networks.
            Negative numbers are read as zero.

            Types past the limit are left out of the MQTYPE-Response list rather
            than refused. Exceeding an operator's limit is not one of section
            3.3's eight FORMERRs, and section 3.5 lists "the server was
            unwilling to process the request (for example, because a limit was
            exceeded)" as an ordinary reason for a QTx to be absent -- so a quiet
            omission is the answer the specification already has for this, and it
            costs no outbound lookups either.

            Zero is a configuration rather than a mistake, and it is the one that
            buys the support signal for nothing: a query is still answered, still
            carries a MQTYPE-Response, and the list in it is empty. Silence would
            be the other available message, and section 3.5 makes silence mean the
            option is "unsupported by the server", which is not true of a server that
            simply declined this much work.
        :param tcp_idle:
            how long a :class:`DnsStreamServer` connection to this server may
            sit idle before being closed -- and, since RFC 7828 section 3.3.2
            paragraph 1 obliges an advertising server to advertise the number
            it actually enforces, the TIMEOUT its stream responses carry.
            The default is :data:`DEFAULT_TCP_IDLE_S`. :const:`None` keeps
            the timeout but goes silent about it: stream responses carry no
            option, and clients fall back to RFC 7766 behaviour, which is
            precisely what RFC 7828 section 3.2.2 paragraph 4 tells them to
            do. 0 refuses keepalive outright -- section 3.3.2's "SHOULD send
            an edns-tcp-keepalive option with a timeout of 0" answer for a
            server whose resources cannot hold connections, carried
            honestly -- and each stream closes once the messages it already
            delivered have been answered.

        """
        if not isinstance(resolver, RecursiveResolver):
            raise TypeError(f"resolver must be a RecursiveResolver, got {type(resolver).__name__}")
        self.resolver = resolver
        self.log = LOGGER
        self.max_concurrent_lookups = max(1, int(max_concurrent_lookups))
        # Zero is allowed to mean zero -- it is a deployment choice, not a
        # mis-set knob, and the clamp is against negatives rather than against
        # the floor. A negative would slice the requested list from its wrong
        # end and hand back types the client never asked for.
        self.max_qtypes = None if max_qtypes is None else max(0, int(max_qtypes))
        # Same reading as max_qtypes for the negative clamp -- a negative idle
        # is not a long one, it is the operator saying "hold nothing", which is
        # what 0 already means. None is silence, not a missing number.
        self.tcp_idle = None if tcp_idle is None else max(0, int(tcp_idle))
        if isinstance(nsid, str):
            nsid = nsid.encode("utf-8")
        self.nsid = None if nsid is None else bytes(nsid)
        # asyncio holds only a weak reference to a task, so a task created here
        # without being stored can be collected before it finishes.
        self._tasks: set[asyncio.Task] = set()
        self._slots = asyncio.Semaphore(self.max_concurrent_lookups)
        # Bound dynamic responders, in bind order: (zone, include_subdomains,
        # handler). Empty by default -- a server nobody configured answers
        # nothing of its own, and every query walks the resolver as it always
        # did. See :meth:`bind`.
        self._responders: list[tuple[DomainName, bool, object]] = []

    def connection_made(self, transport):
        self.transport = transport
        enable_path_mtu_discovery(transport, self.log)

    def connection_lost(self, _exc):
        # The task references matter as much as the cancellation: a task that is
        # merely cancelled can still be referenced forever, and every datagram
        # after a reconnect would add another.
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    def _spawn(self, coro):
        """Create a task, keep a reference to it, retire it when it finishes."""
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def bind(self, name, handler, *, include_subdomains=False) -> None:
        """Answer *name* from *handler* instead of recursing for it.

        The handler takes a :class:`ResponderRequest` and returns ``None``
        (not mine -- ask the network), a sequence of
        :class:`~namespy.packet.DnsRecord` (the answer, NOERROR), or a
        :class:`DynamicResponse` to choose the RCODE or an authority section.
        Bindings are consulted in bind order, first non-``None`` wins, and a
        handler is sync-on-purpose: it runs on the reply task between the
        validation gates and the recursion, so anything slow is the operator
        choosing to be slow.

        What a bound answer inherits is the argument for the hook's shape:
        the response re-enters :meth:`_reply` like any other, so the OPT
        echo, CD copy, AD gating, DNSSEC strip, EDE mapping, datagram
        fitting, and stream framing the resolver's answers get are not
        per-caller courtesies a responder can forget to call -- they are
        structural. What a bound answer does *not* inherit is the
        ``max_concurrent_lookups`` semaphore: a responder answers without
        upstream work, so a flood aimed at a bound name cannot spend the
        recursion budget, which is the same reflection defense the module
        docstring draws the semaphore for.

        A handler that raises answers SERVFAIL rather than falling through:
        the operator bound the name precisely so the network would never be
        asked about it, and the failure of the substitute is not a licence
        to consult the original. The exception reaches the debug log, not
        the wire.
        """
        zone = name if isinstance(name, DomainName) else DomainName(str(name))
        if not callable(handler):
            raise TypeError(f"handler must be callable, got {type(handler).__name__}")
        self._responders.append((zone, bool(include_subdomains), handler))

    def _consult_responders(self, dns_packet, addr, channel):
        """The bound handlers' turn, between the gates and the recursion.

        Returns ``None`` (nothing bound answered), a :class:`DynamicResponse`,
        or :data:`_RESPONDER_FAILED`. Name matching is DomainName comparison,
        so it is the case-insensitive folding of RFC 1035 §2.4.4 rather than
        a string equality that would answer ``WHOAMI.`` and walk ``whoami.``.
        """
        question = dns_packet.questions[0]
        request = ResponderRequest(
            name=question.name,
            qtype=int(question.qtype),
            qclass=int(question.qclass),
            address=addr,
            transport="udp" if channel is None else "tcp",
            dnssec_ok=bool(getattr(dns_packet, "dnssec_ok", False)),
            cd=bool(dns_packet.CD),
            packet=dns_packet,
        )
        for zone, include_subdomains, handler in self._responders:
            hit = request.name.is_subdomain_of(zone) if include_subdomains else request.name == zone
            if not hit:
                continue
            try:
                outcome = handler(request)
            except Exception as exc:
                self.log.debug(
                    "server_responder_failed(src=%s name=%s err=%s)",
                    addr[0],
                    request.name,
                    type(exc).__name__,
                )
                return _RESPONDER_FAILED
            if outcome is None:
                continue  # the handler declined; the next binding or the network speaks
            if isinstance(outcome, DynamicResponse):
                return outcome
            return DynamicResponse(answers=tuple(outcome))
        return None

    def _dynamic_reply(self, dns_packet, addr, verdict, asked, channel) -> None:
        """Send a responder's verdict out the one egress door.

        ``AA`` set because this server *is* the authority it is claiming:
        whoami data comes from its own socket and nothing else. ``RD``
        echoes nothing -- recursion remains available whatever this answer
        skipped, and the flag's response-side meaning is that promise
        (RFC 1035 §4.1.1). The MQTYPE signal rides as the empty list when
        the query asked to bundle: §3.4 obliges a supporting server to say
        so on a valid query, and a bound name is one the server refuses to
        combine because combination means looking types up, which is not
        what the operator bound here for.
        """
        response = Response(
            ID=dns_packet.ID,
            QR=DnsQR.RESPONSE,
            AA=True,
            RD=True,
            RCODE=DnsResponseCode.NO_ERROR if verdict.rcode is None else verdict.rcode,
            questions=list(dns_packet.questions),
            answers=list(verdict.answers),
            nameservers=list(verdict.authority),
        )
        self._reply(
            response,
            addr,
            request=dns_packet,
            mqtype_answered=[] if asked is not None else None,
            channel=channel,
        )

    def _reply(
        self, response, addr, request=None, extended_errors=(), mqtype_answered=None, channel=None
    ) -> None:
        if request is not None:
            # RFC 4035 §3.2.2¶2: "The name server side MUST copy the setting of the
            # CD bit from a query to the corresponding response." Verbatim, every
            # response: the bit is the client's claim that it validates for itself,
            # and echoing it is what lets a client tell "the server did what I
            # asked" from a header a middlebox smeared.
            response.CD = bool(request.CD)
            # RFC 6840 §5.8: "validating resolvers SHOULD only set the AD bit when
            # ... the request contained either a set DO bit or a set AD bit." A
            # client that signalled neither does not read the bit -- legacy stubs
            # and middleboxes copy header flags without understanding them -- so
            # an assertion aimed at nobody is an assertion that can be laundered
            # into an answer that was never asked to be trusted.
            if response.AD and not (request.dnssec_ok or request.AD):
                response.AD = False
            # Order matters: the strip judges the answer the resolver produced, while
            # _apply_edns composes a reply OPT from what the client asked for. Stripping after that
            # would examine a record this server just built for the client rather than one that came
            # from the zone. A request of None means the datagram never parsed, and the only caller
            # in that state is _error(), whose response carries no records to withdraw.
            if not request.dnssec_ok:
                self._strip_dnssec(request, response, mqtype_answered)
            if not extended_errors and getattr(response, "dnssec_bogus", False):
                # The resolver side refused this answer under its own anchors (see
                # namespy.resolver's Bogus branch); RFC 8914 §4.7's code is what
                # distinguishes "validation refused" from every other SERVFAIL.
                extended_errors = (
                    extended_dns_error_option(
                        EDE_DNSSEC_BOGUS, b"namespy: DNSSEC validation failed"
                    ),
                )
            elif not extended_errors and getattr(response, "stale_answer", False):
                # RFC 8767 served this from an expired record because the refresh
                # failed; RFC 8914 §4.2's Stale Answer says so in the one field
                # the earlier document's rejected EDNS option never needed -- and
                # unlike Bogus this is a *successful* answer, an NOERROR or
                # NXDOMAIN the client may well act on, which is precisely why it
                # deserves to know the data is past its TTL.
                extended_errors = (
                    extended_dns_error_option(EDE_STALE_ANSWER, b"namespy: served stale"),
                )
            self._apply_edns(
                request,
                response,
                extended_errors,
                mqtype_answered,
                keepalive=None if channel is None else channel.keepalive,
            )
        wire = bytes(response)
        if channel is None:
            wire = self._fit_datagram(request, response, wire)
        self.log.debug(
            "server_reply(dst=%s id=%#06x rcode=%s octets=%d)",
            addr[0],
            response.ID,
            response.RCODE,
            len(wire),
        )
        if channel is None:
            self.transport.sendto(wire, addr)
        else:
            # The answer goes back on the stream the question arrived on:
            # a datagram is addressed, a stream is already addressed -- it
            # is the connection -- and the channel is that fact made
            # callable. No size rule applies here: RFC 1035 §4.2.1's 512
            # ceiling and RFC 6891 §6.2.3's advertised-payload limit are
            # both statements about what a *datagram* can hold, and this
            # stream is the TCP fallback that RFC 10001 §4.1¶4 (via §4.2¶4)
            # requires the truncation to have -- TC over UDP is a promise
            # this path keeps in full.
            channel.send(wire)

    @staticmethod
    def _datagram_cap(request) -> int:
        """Largest UDP payload this client said it can reassemble.

        RFC 6891 §6.2.3¶2: "Values lower than 512 MUST be treated as equal
        to 512." And a request with no OPT at all is §7¶2's unextended
        client -- one that never offered a number -- so it is capped where
        RFC 1035 §4.2.1 capped everyone before EDNS lifted the ceiling:
        512 octets. The size is per-transaction and read from *this*
        request's own OPT: §6.2.3¶7 forbids caching an advertised value
        beyond the transaction that carried it, and this server composes
        each reply's OPT fresh anyway.
        """
        incoming = None if request is None else request.opt()
        if incoming is None:
            return DnsPacket.EDNS_MINIMUM_PAYLOAD
        return max(DnsPacket.EDNS_MINIMUM_PAYLOAD, int(incoming.rclass))

    def _fit_datagram(self, request, response, wire: bytes) -> bytes:
        """Truncate a UDP reply that outgrows the client's payload; set TC.

        The size a client advertised is the size it can reassemble
        (RFC 6891 §6.2.3¶1), and sending past it does not deliver more
        answer -- it delivers an IP fragment, which RFC 10001 §4.1¶4
        (applied to recursive servers by §4.2¶4) tells this server to avoid
        because fragmentation is fragile (RFC 8900). The alternative this
        build had been quietly choosing was worse than truncation: an
        oversized datagram either fragments and dies at a firewall or never
        leaves the socket, and the client times out on an answer that
        existed.

        Records go back, working forward in the datagram from its end
        (RFC 1035 §6.2¶4): additional-section records first, then the
        authority section, then -- only when the answer itself will not fit
        -- the answer's tail. That order is what §6.2¶4's second sentence
        guarantees: while any authority data remains, the answer section is
        whole. The OPT record is never a victim; RFC 6891 §7¶6 makes header,
        question, and OPT the floor a truncated response falls to and MUST
        not fall below, so an extended client always gets its EDNS answer
        version, its DO bit, its EDE options this server declined to eat
        first (§8914 §3's order ran upstream of here, in
        :meth:`_keep_explanation_inside_advertised_size`), and the promise
        TC carries: the rest is on the stream.
        """
        cap = self._datagram_cap(request)
        if len(wire) <= cap:
            return wire
        sections = (
            (response.additional_records, "ARCOUNT", True),
            (response.nameservers, "NSCOUNT", False),
            (response.answers, "ANCOUNT", False),
        )
        dropped = False
        for records, count_attr, protect_opt in sections:
            while len(wire) > cap and records:
                victim = records[-1]
                if protect_opt and int(victim.rtype) == int(DnsRType.OPT):
                    if len(records) == 1:
                        break  # the §7¶6 floor: OPT alone, nothing left to give
                    del records[-2]  # sacrifice the record below the OPT
                else:
                    records.pop()
                dropped = True
                setattr(response, count_attr, len(records))
                wire = bytes(response)
        if dropped and not response.TC:
            response.TC = True
            wire = bytes(response)
            self.log.debug(
                "server_truncated(dst_size=%d cap=%d tc=1)",
                len(wire),
                cap,
            )
        return wire

    def _sentinel_gate(self, request, response) -> bool:
        """RFC 8509 §2: answer the sentinel's question, obey its table.

        The mechanism is a trust-questionnaire: an operator (or a ceremony's
        test harness, §4.3) queries ``root-key-sentinel-is-ta-<tag>`` and
        ``root-key-sentinel-not-ta-<tag>`` and reads the resolver's answer
        as a yes/no about its own anchor store. §2.2¶4's table is the whole
        protocol, and this method enacts its off-diagonal: when the label
        claims ``is-ta`` but the store has no such active root anchor -- or
        claims ``not-ta`` and the store does -- the response is rewritten to
        §2.2¶5's SERVFAIL with an empty Answer Section.

        Every precondition keeps its own exit, because §2.1¶8 makes any
        failure to meet them a MUST NOT alter: CD set (§2.1¶4 -- a client
        validating for itself asked for the data, not the diagnosis), a
        QTYPE other than A or AAAA (§2.1¶5), a label that is not the precise
        five-digit form (§2.1¶7 and §2.1¶9, enforced by
        :func:`namespy.anchors.sentinel_expectation`), and the validation
        state itself: §2.1¶2-¶3 want a response that *was DNSSEC-validated*
        with result Secure, which this walk marks by the AD bit it stamps at
        validation -- read here before RFC 6840 §5.8's courtesy strip in
        :meth:`_reply`, because the precondition concerns what the resolver
        knows, not what this client asked to see. An anchorless resolver
        never sets that bit, so the mechanism is inert without anchors,
        which is §2.1¶8's own silence rather than a policy invented here;
        the OPCODE gate (§2.1¶6) ran earlier in :meth:`respond_to_packet`,
        and QDCOUNT is one by the FORMERR gate, so question zero is the
        original QNAME §2.1¶7 means.
        """
        question = request.questions[0]
        expectation = sentinel_expectation(question.name)
        if expectation is None:
            return False
        if request.CD:
            return False
        if int(question.qtype) not in (int(DnsQType.A), int(DnsQType.AAAA)):
            return False
        if not response.AD or getattr(response, "dnssec_bogus", False):
            return False
        is_ta, key_tag = expectation
        trusted = key_tag in trusted_anchor_tags(self.resolver.trust_anchors)
        if is_ta == trusted:
            return False  # §2.2¶4 diagonal: the original answer, untouched
        response.RCODE = DnsResponseCode.SERVER_FAILURE
        response.answers = []
        response.ANCOUNT = 0
        # §2.2¶5 mandates the RCODE and the empty Answer Section and says
        # nothing about AD -- but AD is an assertion about the answer data,
        # and the data is gone. A refusal that still claimed "validated,
        # trust this" would be laundering the diagonal cell's verdict into
        # the off-diagonal one; the bit goes with what it described.
        response.AD = False
        self.log.debug(
            "server_sentinel_refuse(label=%s tag=%d trusted=%s)",
            "is-ta" if is_ta else "not-ta",
            key_tag,
            trusted,
        )
        return True

    def _error(
        self,
        dns_packet,
        addr,
        rcode: DnsResponseCode,
        mqtype_answered=None,
        channel=None,
        extended_errors=None,
    ) -> None:
        """Reply with *rcode*, echoing the question so the client can match it.

        ``extended_errors`` overrides the self-failure mapping below: an
        ``None`` lets ``_own_failure_errors`` decide, and an explicit tuple is
        for the rejections whose explanation is not a property of the RCODE
        alone -- RFC 9824 section 3.5¶3's EDE 30 beside a FORMERR, for one.
        Pass an empty tuple to force silence.

        ``mqtype_answered`` is the list to put in a MQTYPE-Response option --
        empty on this path, but *present*, because RFC 10029 section 3.4 opens by
        obliging a supporting server to return the option in its response to a
        valid query and attaches no condition to that response being an error. A
        server that goes silent exactly when resolution fails is indistinguishable
        from one that never implemented the extension, which is the confusion the
        option exists to avoid.

        A client correlates a response with its query by ID *and* the echoed
        question (RFC 5452 sections 4.2-4.3 and 9.1), so an error response with an
        empty question section is one the client may discard. *dns_packet* is
        ``None`` when the datagram could not be parsed at all, and there is
        nothing to echo.

        An Extended DNS Error goes along when this server has something to say
        about the RCODE -- see :meth:`_own_failure_errors` for which ones do, and
        :meth:`_apply_edns` for why a client that never sent an OPT never sees it.
        """
        questions = list(dns_packet.questions) if dns_packet is not None else []
        self._reply(
            Response(
                ID=0 if dns_packet is None else dns_packet.ID,
                QR=DnsQR.RESPONSE,
                RCODE=rcode,
                questions=questions,
            ),
            addr,
            request=dns_packet,
            extended_errors=(
                self._own_failure_errors(rcode) if extended_errors is None else extended_errors
            ),
            mqtype_answered=mqtype_answered,
            channel=channel,
        )

    @staticmethod
    def _own_failure_errors(rcode) -> tuple:
        """The EDE option this server sends with *rcode*, or an empty tuple.

        RFC 8914 section 2 lets the option accompany any response, and section 3
        refuses to bind codes to RCODEs ("This document does not allow or prohibit
        any particular extended error codes and information to be matched with any
        particular RCODEs"), so the pairing is the operator's to make. These two are
        the cases where the RCODE alone leaves the client guessing: SERVFAIL says
        "no answer" and not "nobody answered", and NOTIMP says "no" and not "to
        what". FORMERR, BADVERS and the rest already carry their own explanation in
        the code the client can read, so they get nothing.
        """
        explained = _OWN_FAILURE_ERRORS.get(int(rcode))
        if explained is None:
            return ()
        info_code, extra_text = explained
        return (extended_dns_error_option(info_code, extra_text),)

    @staticmethod
    def _opt_count(dns_packet) -> int:
        """How many OPT records a request carried (RFC 6891 section 6.1.1 allows one)."""
        return sum(1 for record in dns_packet.additional_records if int(record.rtype) == OPT_RTYPE)

    def _apply_edns(
        self, request, response, extended_errors=(), mqtype_answered=None, keepalive=None
    ) -> None:
        """Attach the OPT record this server is entitled -- or obliged -- to send.

        Two halves of RFC 6891 meet here. Section 6.1.1: "If an OPT record is
        present in a received request, compliant responders MUST include an OPT
        record in their respective responses." Section 7 is the mirror image:
        "Lack of presence of an OPT record in a request MUST be taken as an
        indication that the requestor does not implement any part of this
        specification and that the responder MUST NOT include an OPT record in
        its response." Answering an unextended client with OPT advertises a
        capability it never asked about; answering an extended client without it
        strands the extended RCODE in the header.

        Whatever OPT the recursive walk collected from an upstream server goes
        in the bin first. Section 6.1.1 says "OPT RRs MUST NOT be cached,
        forwarded, or stored in or loaded from master files", and the record the
        walk left behind carries *that server's* payload size and flags -- which
        this server would be misrepresenting as its own.
        """
        intended = int(response.extended_rcode)
        response.remove_edns()
        incoming = None if request is None else request.opt()
        if incoming is None:
            if intended > MAX_UNEXTENDED_RCODE:
                # Nothing can carry the upper eight bits: section 6.1.3 says
                # EXTENDED-RCODE 0 means "values 0 through 15", and section 7
                # forbids the only carrier this client will accept. Masking the
                # number instead (RCODE 23 would read as 7, FORMERR) would lie
                # about *why* the answer failed, so the client gets SERVFAIL --
                # the honest "there is no answer you can be given". That
                # substitution is a design decision, not a specification
                # instruction, and is logged because it is the one place an
                # answer changes on the way out.
                self.log.debug("server_unextended_rcode_downgrade(rcode=%s)", intended)
                response.RCODE = int(DnsResponseCode.SERVER_FAILURE)
            return

        def attach(options) -> None:
            """Put an OPT record on *response* carrying *options*.

            A closure because RFC 8914 section 3 can make this run twice: the
            explanation is dropped and the record rebuilt when keeping it would have
            pushed the answer past what the client said it could reassemble.
            """
            response.remove_edns()
            response.add_edns(
                RESPONDER_PAYLOAD_SIZE,
                version=EDNS_VERSION_SUPPORTED,
                options=options,
            )
            if intended > MAX_UNEXTENDED_RCODE:
                # Put the effective code back where the dropped OPT used to keep it.
                # Serialisation splits it again -- header nibble here, upper eight
                # in the record we just added (RFC 6891 section 6.1.3).
                response.RCODE = intended

        # The early return above cannot strand a MQTYPE-Response obligation: an
        # MQTYPE-Query option can only arrive inside an OPT record, so a requestor
        # that sent no OPT never asked, and RFC 6891 section 7's "no OPT in, no OPT
        # out" is the whole of what that client is owed. The same return is also
        # what keeps a keepalive announcement off an unextended stream answer --
        # RFC 7828 section 3.3.2 paragraph 1 offers the option only to queries
        # "that include an OPT RR", and RFC 7828 section 3.4 paragraph 6 quotes
        # section 7 to make the point for persistent connections explicitly.
        attach(self._reply_options(request, extended_errors, mqtype_answered, keepalive))
        if extended_errors:
            self._keep_explanation_inside_advertised_size(
                request, response, attach, mqtype_answered, keepalive
            )

    def _keep_explanation_inside_advertised_size(
        self, request, response, attach, mqtype_answered=None, keepalive=None
    ) -> None:
        """Drop the EDE options if they made the response bigger than the client asked for.

        RFC 8914 section 3: "When the response grows beyond the requestor's UDP
        payload size [RFC6891], servers SHOULD truncate messages by dropping EDE
        options before dropping other data from packets." That ordering is the whole
        method: the explanation is the supplemental thing, so it is what goes, and
        what the client asked for is what survives.

        The same paragraph's "Implementations SHOULD set the truncation bit when
        dropping EDE options" is deliberately not followed, and the reason is which
        response this is. TC is a promise that a retry over TCP will find the rest of
        an answer, and on a response carrying nothing but its echoed question there is
        no rest to find -- setting it would buy a TCP handshake and the same SERVFAIL
        back. The log line is the honest record, and the RCODE already said there is
        no answer.
        """
        incoming = None if request is None else request.opt()
        if incoming is None:
            return
        # RFC 6891 section 6.2.3: "Values lower than 512 MUST be treated as equal to
        # 512", so a client advertising something tiny is still measured against the
        # floor it is owed rather than a limit that trims everything away -- the same
        # :meth:`_datagram_cap` the record truncation in :meth:`_fit_datagram` runs on.
        advertised = self._datagram_cap(request)
        size = len(bytes(response))
        if size <= advertised:
            return
        self.log.debug("server_edns_error_dropped(octets=%d advertised=%d)", size, advertised)
        # Rebuild with the explanation gone and everything else left alone --
        # including the MQTYPE-Response. RFC 8914 section 3 names the EDE option as
        # the thing to drop, and RFC 10029 section 3.4 makes its own option the one
        # that may not go: a reply that loses it says "this server does not
        # implement multiple QTYPEs", which is a statement no amount of re-asking
        # takes back from the client's side.
        attach(self._reply_options(request, mqtype_answered=mqtype_answered, keepalive=keepalive))

    def _reply_options(
        self, request, extended_errors=(), mqtype_answered=None, keepalive=None
    ) -> list:
        """The options this server puts in its own OPT for this request.

        NSID, and only when it was asked for. RFC 5001 section 2.2 is
        unambiguous in both directions: "A name server MUST NOT send an NSID
        option back to a resolver which did not request it", and "The name
        server MUST ignore any NSID payload data that might be present in the
        query message" -- so the *presence* of the option is the request, and
        whatever the client put in it is discarded rather than echoed. MQTYPE is
        asked for the same way and answered at the bottom of this docstring.

        Everything else the query carried is dropped on the floor, which is the
        documented treatment of an option a responder has no behaviour for
        ("Any OPTION-CODE values not understood by a responder or requestor MUST
        be ignored", RFC 6891 section 6.1.2). The edns-key-tag option is the one
        "else" that is understood and dropped anyway, because RFC 8145 section
        4.3 paragraph 2 states it flatly: "A responder MUST NOT include the
        edns-key-tag option in any DNS response" -- section 4.2.2.1 paragraph 5
        says the same to a validating recursive server about its final response
        to its client. The signal travels upstream and stops there. Padding is
        the interesting
        case, because here the code *is* understood and the answer is still no:
        RFC 7830 section 4 makes padding a MUST for a responder that is asked,
        while section 6 forbids the option outright on a transport that is not
        encrypted. Both of this server's transports are plaintext, so
        honouring section 4
        would mean obeying one MUST by breaking another; section 6 is the
        sentence that speaks to the situation this server is actually in, and it
        is the one kept. A future DNS-over-TLS front end is where padding belongs.

        An Extended DNS Error, when the caller has one to report, goes last. That
        position is RFC 8914 section 3's ordering made concrete: a server whose
        response has outgrown the requestor's payload size should drop EDE options
        "before dropping other data from packets", and an option already at the end of
        an OPT is the cheapest thing on the wire to give up -- which is how
        :meth:`_keep_explanation_inside_advertised_size` can remove it without
        disturbing anything else.

        A MQTYPE-Response, when ``mqtype_answered`` is not :const:`None`, goes
        immediately ahead of it for the mirror reason: RFC 10029 section 3.4 needs
        that option to survive precisely the response that got too big to carry
        something, and an option the size rule is not allowed to eat has to be
        somewhere the size rule is not looking. ``None`` means the query never
        asked, and sending the option unasked would be a claim about this server
        that no one requested.

        An edns-tcp-keepalive announcement, when ``keepalive`` carries one, sits
        with the response's own statements about this connection -- RFC 7828
        section 3.3.2 paragraph 1 permits it on any stream answer to a query
        that carried OPT, obliges the number to be the one actually enforced
        (the caller reads it straight off this connection's idle policy, so it
        always is), and section 3.3.1 paragraph 1 keeps it off UDP entirely --
        which it is, because the datagram path passes no keepalive at all.
        """
        options = []
        try:
            asked = nsid_of(request.edns_options()) if request is not None else None
        except DnsPacketParseError:
            # Already refused upstream by `_edns_options_or_error`, but the reply
            # to that refusal comes through here, and section 7 requires that
            # reply to carry an OPT -- so a second reading of the same broken
            # option has to answer "nothing asked for", not raise.
            asked = None
        if self.nsid is not None and asked is not None:
            options.append(EdnsOption(NSID_OPTION_CODE, self.nsid))
        if keepalive is not None:
            # The connection's enforced idle number, said as it is -- 0
            # included, because refusing to hold is a policy with a value.
            options.append(keepalive_option(keepalive))
        if mqtype_answered is not None:
            # The empty list is the point of this branch as much as the filled one:
            # section 3.4 allows MQTYPE-Response to be empty while still requiring
            # "the option must still be returned", because presence is the whole of
            # what a client learns about support and absence is what a server that
            # never implemented the extension looks like.
            options.append(mqtype_response_option(mqtype_answered))
        options.extend(extended_errors)
        return options

    def _edns_options_or_error(self, dns_packet, addr, channel=None) -> bool:
        """Whether ``dns_packet``'s options survive a first reading.

        RFC 6891 section 7: "If there is a problem with processing the OPT
        record itself, such as an option value that is badly formatted or that
        includes out-of-range values, a FORMERR MUST be returned. If this
        occurs, the response MUST include an OPT record." The second sentence is
        why this cannot be folded into the generic parse failure path -- that
        one answers with no OPT at all, which would tell the requestor this
        server has no EDNS rather than that it disliked the option it read.

        Two modelled options have a length to get wrong. COOKIE's rule is RFC 7873
        section 5.2.2's: "In summary, valid cookie lengths are 8 and 16 to 40
        inclusive", and nothing else. EDE's is only a floor -- RFC 8914 section 2
        makes the INFO-CODE the one part of the option that is always present, so
        fewer than two octets is a "badly formatted" option value in section 7's
        phrase -- while anything *longer* is somebody else's meaning and is left
        alone, because section 3's "Receivers MUST be able to accept EDE codes and
        EXTRA-TEXT in all messages" covers unassigned and private-use codes alike.
        NSID is opaque and any length is legal, and an unregistered code is not
        evaluated at all -- section 6.1.2's "MUST be ignored" covers its payload too,
        so refusing a private-code option for its contents would be inventing a rule.
        A third modelled option could have joined the refusers: RFC 8145 section
        4.1 paragraph 4 defines edns-key-tag's OPTION-LENGTH as "2 x number of
        key-tag values present", so an odd length is arithmetic nobody meant -- but
        the document orders no rejection anywhere (its only receiving instruction,
        section 4.2 paragraph 7, is "no action needs to be taken and the client MUST
        ignore"), so a malformed instance simply carries no list here
        (:func:`~namespy.edns.key_tag_lists` skips it) and the query proceeds with
        the tags that *were* readable. FORMERR for a signal the RFC lets a responder
        only log would refuse service over a courtesy.

        MQTYPE (RFC 10029) is judged by its own document's list rather than by a
        length, because its option carries a *list* and the ways to get a list wrong
        are not merely "short" and "long": section 3.3 enumerates eight of them and
        mandates FORMERR for each. All eight are checked by
        :func:`namespy.mqtype.mqtype_query_rejection`, shared with the sending side so
        the two can never disagree about what a valid option is. Worth knowing which
        conditions this path can actually reach: a message with QDCOUNT=0 is refused
        earlier for that reason alone (same RCODE), and a non-QUERY opcode earns
        NOTIMP before options are read -- RFC 2929 section 3.1's rule for an opcode a
        receiver does not implement, which outranks a complaint about its options.
        """
        try:
            options = dns_packet.edns_options()
        except DnsPacketParseError as exc:
            self.log.debug("server_bad_edns_option(src=%s err=%s)", addr[0], exc)
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
            return False
        cookie = find_option(options, COOKIE_OPTION_CODE)
        if cookie is not None and not cookie_length_valid(len(cookie.data)):
            self.log.debug("server_bad_cookie_length(src=%s length=%s)", addr[0], len(cookie.data))
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
            return False
        for option in options:
            # Every EDE option, not the first: RFC 8914 section 3 lets a sender put
            # more than one in a message, so a request that carries one good and one
            # unreadable has still shown that its OPT cannot be trusted.
            if option.code == ERROR_OPTION_CODE and not extended_error_option_valid(option):
                self.log.debug(
                    "server_bad_edns_error_length(src=%s length=%s)",
                    addr[0],
                    len(option.data),
                )
                self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
                return False
        reason = mqtype_query_rejection(
            options,
            opcode=dns_packet.OPCODE,
            qdcount=dns_packet.QDCOUNT,
            primary_qtype=dns_packet.questions[0].qtype if dns_packet.questions else None,
        )
        if reason is not None:
            self.log.debug("server_bad_mqtype_query(src=%s reason=%s)", addr[0], reason)
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
            return False
        return True

    # ------------------------------------------------------- MQTYPE (RFC 10029)

    @staticmethod
    def _mqtype_request(dns_packet):
        """The QTx list this query asked for, or ``None`` when it did not ask.

        ``None`` and an empty list are kept apart on purpose. Section 3.3 makes
        "an MQTYPE-Query option with an empty QT list" a FORMERR, so a *request*
        can never legitimately carry no types at all, while section 3.4 says the
        opposite of the answer: that list may be empty and the option must still be
        returned. One falsy value standing in for both would end up sending a
        client an option it never asked for.

        Nothing is validated here. :meth:`_edns_options_or_error` has already run
        section 3.3's eight conditions over the same option and refused the message
        if any of them held, which is what makes
        :func:`~namespy.mqtype.qtypes_of` safe to call without a handler -- and it
        is the reason those two calls cannot change places.
        """
        option = dns_packet.edns_option(MQTYPE_QUERY_OPTION_CODE)
        return None if option is None else qtypes_of(option)

    @staticmethod
    def _standalone_query(dns_packet, qtype: int):
        """A query for one QTx, as it would have looked having been the question.

        Deliberately minimal, and the reason is one line of the resolver rather
        than a paragraph of specification: :meth:`RecursiveResolver.resolve`
        rewrites the OPT of every message it sends with its own payload size and
        its own option list, so copying the client's OPT here would copy a thing
        that is about to be thrown away. It would also say things this server does
        not mean -- forwarding a COOKIE hands an upstream a token this server never
        issued (RFC 7873 section 5.2.1), and forwarding the MQTYPE-Query would ask
        that upstream to do the combining section 3.4 makes the responder's own
        job. Section 3.4 asks for "appropriate outbound queries", plural and
        standalone; this is one of them.
        """
        question = dns_packet.questions[0]
        return Query(
            ID=dns_packet.ID,
            RD=dns_packet.RD,
            questions=[DnsQuestion(question.name, qtype, question.qclass)],
        )

    @staticmethod
    def _recount(response) -> None:
        """Recompute the header's section counts from the sections themselves.

        The counts are stored and not derived: ``DnsPacket.__init__`` sets them from
        whatever lists it is handed, and ``__bytes__`` writes the stored figures
        alongside every record the lists hold. A merged answer whose ANCOUNT still
        says one is therefore a message that claims one record and carries two --
        which is a parse error on the way back in, and a lie on the way out.
        Anything that adds or withdraws records owes this call.
        """
        for section, count in _SECTIONS:
            setattr(response, count, len(getattr(response, section)))

    @staticmethod
    def _strip_dnssec(request, response, mqtype_answered=None) -> None:
        """Withdraw the authenticating records from an answer to a client that did not ask.

        RFC 4035 §3.2.1¶1, second sentence, in the client's terms: "If the DO bit in an initiating
        query is not set, the name server side MUST strip any authenticating DNSSEC RRs from the
        response but MUST NOT strip any DNSSEC RR types that the initiating query explicitly
        requested." The set is :data:`_CLIENT_STRIP_TYPES` -- §3.1¶1's list of what DO buys, DS
        included; the exception is read
        off the question, and the QTx list of a RFC 10029 multi-type query counts with it -- a client
        that named RRSIG among the types it wanted asked for that type explicitly, whatever the OPT
        option's encoding suggests about sections.

        Three details worth their weight:

        * QTYPE=* is not an explicit request for RRSIG. RFC 3225 §2¶5 makes client willingness
          binary -- "either the client is willing to receive all DNSSEC security RRs or it is not
          willing to accept any" -- and DO is the bit that decides which. A wildcard question asks
          for every type at a name, not for permission to receive records the client cannot parse.
        * OPT is not in the set and so is not touched here: RFC 6891 §6.1.1 forbids forwarding it, and
          :meth:`_apply_edns` builds the reply's own copy immediately after.
        * The counts have to be recomputed. ANCOUNT is stored, not derived, so an answer that drops
          two RRSIGs while still claiming four records is a message that lies about its own length
          -- see :meth:`_recount`.
        """
        requested = {int(question.qtype) for question in request.questions}
        requested.update(int(qtype) for qtype in mqtype_answered or ())
        withdraw = _CLIENT_STRIP_TYPES - requested
        if not withdraw:
            return
        changed = False
        for section, _count in _SECTIONS:
            records = getattr(response, section)
            kept = [record for record in records if int(record.rtype) not in withdraw]
            if len(kept) != len(records):
                setattr(response, section, kept)
                changed = True
        if changed:
            DnsServer._recount(response)

    @staticmethod
    def _record_key(record):
        """What makes two RRs the same RR: everything about one except its TTL.

        Section 3.4 obliges a server to "detect duplicate RRs and keep only a single
        copy of each RR in its respective section", and the duplicates it worries
        about -- the CNAME both questions walked, the SOA neither answer needed --
        were read at different moments and may disagree about how long they stay
        true. RFC 2181 section 5.1 then decides which copy survives: an RRset is a
        set of RRs sharing name, type, class *and TTL*, so keeping both copies
        because their TTLs differ would emit an RRset that is not allowed to exist.
        The first copy wins, and the first copy is always the one the primary answer
        already had -- which is the answer whose RCODE and flags the whole response
        is now speaking with.
        """
        return (
            str(record.name).lower(),
            int(record.rtype),
            int(record.rclass),
            bytes(record.rdata),
        )

    @classmethod
    def _new_records(cls, response, other) -> dict:
        """RRs of *other* that *response* does not hold yet, grouped by section.

        Sections are compared with each other and never pooled, which is what the
        same section asks twice over: extra RRs go "into the same sections in which
        they would have appeared in a standalone query", and "RRs can be
        legitimately duplicated in different sections such as for the (SOA,
        TYPE12345) combination at a zone apex". An SOA in the Answer section for one
        QTx and the same SOA in the Authority section as another one's proof of
        nonexistence are two different statements about the name; pooling them
        would silently drop one.

        OPT is the one record that never crosses over. RFC 6891 section 6.1.1: "OPT
        RRs MUST NOT be cached, forwarded, or stored in or loaded from master
        files" -- and even if the walk's OPT had been worth forwarding, which its
        foreign payload size and flags prove it is not, a second OPT in the
        additional section would break that section's one-per-message rule.
        """
        fresh: dict[str, list] = {}
        for section, _count in _SECTIONS:
            held = {cls._record_key(record) for record in getattr(response, section)}
            wanted = []
            for record in getattr(other, section):
                key = cls._record_key(record)
                if int(record.rtype) == OPT_RTYPE or key in held:
                    continue
                held.add(key)
                wanted.append(record)
            fresh[section] = wanted
        return fresh

    @staticmethod
    def _flags_match(primary, other) -> bool:
        """Whether *other* may be folded into *primary* (RFC 10029 section 3.4).

        "For each individual combination, the server MUST evaluate the resulting
        RCODE and other flags and check that they all match the values generated
        from the primary query." Which flags counts is a judgement, and it is worth
        naming because the answer decides what gets thrown away:

        * RCODE, because an answer saying the name exists and one saying it does
          not cannot occupy one message -- section 3.4's own example is a NOERROR
          primary with a SERVFAIL combination;
        * AA, because authority is a claim about which server may make claims, and
          the section's other example -- an NS-plus-DS query at the parent side of a
          zone cut -- differs on this bit and nothing else;
        * AD, because "DNSSEC valid" is a promise the primary cannot make for an
          answer it did not resolve;
        * TC, because a truncated combination is not a complete RRset, and the
          complete RRset is the unit this section merges.

        RA and Z are left out deliberately. RA is this server's statement about
        itself and identical in everything it sends; Z must be zero in both. Either
        comparison could only reject a merge over a difference that says nothing
        about the answer.
        """
        return (
            int(primary.RCODE) == int(other.RCODE)
            and bool(primary.AA) == bool(other.AA)
            and bool(primary.TC) == bool(other.TC)
            # The header's AD, since the bit this list has always named. The line
            # used to read ``dnssec_ok`` -- the OPT DO flag under the property's
            # former, confused name -- which made it a tautology: every QTx of one
            # MQTYPE query shares the one request OPT, so DO can never differ here.
            # Authentic Data can: a validator judges each answer on its own, and
            # "DNSSEC valid" is exactly the promise the merge must not inherit.
            and bool(primary.AD) == bool(other.AD)
        )

    def _prospective_size(self, request, response, answered) -> int:
        """How big *response* would be carrying this server's OPT and *answered*.

        The OPT has to be inside the measurement because the OPT is what carries the
        claim: an option costs four octets of header plus two per QTx, so sizing the
        message without it reports room that the thing being measured then eats. The
        option list comes from :meth:`_reply_options`, the same call that builds the
        real one, so NSID and anything else the reply will carry is paid for here
        rather than discovered by a client.

        The temporary record is put back afterwards, and that is not tidiness. The
        response may still hold the OPT the recursive walk collected, and for an
        RCODE above 15 that record is where the upper eight bits live:
        :meth:`_apply_edns` reads ``extended_rcode`` off the object it is handed a
        moment from now, so an OPT left behind here would quietly change which RCODE
        the client is finally told.
        """
        saved = list(response.additional_records), response.ARCOUNT
        try:
            response.add_edns(
                RESPONDER_PAYLOAD_SIZE,
                version=EDNS_VERSION_SUPPORTED,
                options=self._reply_options(request, mqtype_answered=answered),
            )
            return len(bytes(response))
        finally:
            response.additional_records, response.ARCOUNT = saved

    async def _combine_mqtype(self, request, response, requested) -> list[int]:
        """Fold the extra QTYPEs into *response*; report the ones that made it.

        RFC 10029 section 3.4, followed in the order the document gives its rules.
        *response* is modified in place and the returned list is what goes into the
        MQTYPE-Response option; a QTx joins that list only once its records are
        already in the message and the whole message still fits, which is the one
        ordering that cannot end up claiming a type it did not deliver.

        Running here rather than in :meth:`respond_to_packet` is what keeps the
        egress bound honest. The caller holds one slot of ``self._slots`` across the
        primary lookup and every combination, so a query for five types still has
        exactly one lookup outstanding upstream at any moment -- the ratio the
        amplification defence in RFC 5358 section 3 depends on is unchanged. The
        number of lookups per client does grow, and it is capped twice: by
        ``max_qtypes``, and by the size rule below that stops instead of continuing.
        That is the shape RFC 10029 section 4 asks an operator to be able to
        configure.

        Two kinds of stop run through this, and only one of them is a refusal. The
        size rule stops the loop because the next type cannot be delivered whole;
        ``max_qtypes`` stops it because an operator decided how much work a question
        may cost. A truncated primary is neither: section 3.4's "If this initial
        response results in truncation (TC=1), then the additional queries specified
        in the MQTYPE-Query option MUST NOT be processed" is an instruction about
        *this* exchange, because the full set can only be had over TCP, where this
        method runs again on the answer that arrives there and the option belongs with
        it. Returning the empty list -- rather than nothing -- is what keeps the
        support signal intact on all three paths.
        """
        if response.TC:
            # "If this initial response results in truncation (TC=1), then the
            # additional queries specified in the MQTYPE-Query option MUST NOT be
            # processed." Not one lookup is bought -- and the option still goes out,
            # because the same section opens by requiring it "even if that response
            # is truncated". TC says the answer continues over TCP; it does not say
            # this server implements nothing.
            self.log.debug("server_mqtype_primary_truncated(qtypes=%d)", len(requested))
            return []
        if self.max_qtypes is not None and len(requested) > self.max_qtypes:
            self.log.debug(
                "server_mqtype_over_limit(requested=%d limit=%d)",
                len(requested),
                self.max_qtypes,
            )
            requested = requested[: self.max_qtypes]
        # RFC 6891 section 6.2.3, the same floor the EDE rule and the
        # truncation in _fit_datagram use: "Values lower than 512 MUST be
        # treated as equal to 512", so a requestor advertising a number
        # designed to make the answer empty is owed the minimum instead --
        # and a request with no OPT sizes nothing at all, which is where
        # RFC 1035 section 4.2.1's ceiling still rules.
        budget = self._datagram_cap(request)
        answered: list[int] = []
        for qtype in requested:
            combination = await self.resolver.resolve(self._standalone_query(request, qtype))
            if combination is None or not self._flags_match(response, combination):
                # Nothing to fold in, or a fold the section forbids: "the mismatching
                # additional response MUST NOT be included in the final combined
                # response, and its QTx value MUST NOT be included in the
                # MQTYPE-Response option's list". A lookup that returned no answer at
                # all mismatches by definition -- there are no flags to compare
                # against. The remaining types are still tried, because nothing here
                # says to stop; only the size rule below is allowed to.
                self.log.debug("server_mqtype_mismatch(qtype=%d)", qtype)
                continue
            saved = [list(getattr(response, section)) for section, _count in _SECTIONS]
            for section, records in self._new_records(response, combination).items():
                getattr(response, section).extend(records)
            self._recount(response)
            answered.append(qtype)
            if self._prospective_size(request, response, answered) <= budget:
                self.log.debug("server_mqtype_combined(qtype=%d)", qtype)
                continue
            # "the server MUST NOT include the respective QTx in the MQTYPE-Response
            # option's list and MAY stop processing further QTx combinations". Both
            # halves are kept in step: the records go back, the QTx goes unlisted, and
            # TC is left exactly as the primary answer set it, because "the handling
            # of an MQTYPE-Query option MUST NOT itself trigger a truncated
            # response". Stopping rather than trying the next type is the choice that
            # answers section 4's amplification concern instead of merely tolerating
            # it: a client that asked for eight types is refused the remaining seven
            # without seven queries being made on its behalf.
            answered.pop()
            for index, (section, _count) in enumerate(_SECTIONS):
                setattr(response, section, saved[index])
            self._recount(response)
            self.log.debug("server_mqtype_size_stop(qtype=%d budget=%d)", qtype, budget)
            break
        return answered

    async def respond_to_packet(self, dns_packet, addr, channel=None):
        if DnsQR.QUERY != dns_packet.QR:
            self.log.debug("server_not_query(src=%s id=%#06x)", addr[0], dns_packet.ID)
            return

        if dns_packet.QDCOUNT != 1:
            # The resolver models one Sname at a time, and answering one of N
            # questions without saying which is worse than refusing.
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
            return

        if int(dns_packet.questions[0].qtype) == int(DnsRType.NXNAME):
            # RFC 9824 section 3.5 para 2, in the server's words: "If an
            # explicit query for the NXNAME RR type is received, the DNS
            # server MUST return a Format Error (response code FORMERR)."
            # The Meta-TYPE stores no data in a zone (section 2 para 3), so
            # there is no answer to compose -- and section 3.5 para 3's MAY
            # rides along, because FORMERR would otherwise say the datagram
            # was unreadable when what is wrong is the question itself.
            self.log.debug("server_nxname_query(src=%s)", addr[0])
            self._error(
                dns_packet,
                addr,
                DnsResponseCode.FORMAT_ERROR,
                channel=channel,
                extended_errors=(
                    extended_dns_error_option(
                        EDE_INVALID_QUERY_TYPE, b"namespy: NXNAME is not a queryable type"
                    ),
                ),
            )
            return

        if DnsOpCode.QUERY != dns_packet.OPCODE:
            self.log.debug(
                "server_unsupported_opcode(src=%s opcode=%s)", addr[0], dns_packet.OPCODE
            )
            self._error(dns_packet, addr, DnsResponseCode.NOT_IMPLEMENTED, channel=channel)
            return

        if self._opt_count(dns_packet) > 1:
            # RFC 6891 section 6.1.1: "When an OPT RR is included within any
            # DNS message, it MUST be the only OPT RR in that message. If a
            # query message with more than one OPT RR is received, a FORMERR
            # (RCODE=1) MUST be returned." Checked before any upstream work so
            # one malformed datagram cannot buy any recursive lookups.
            self.log.debug("server_multiple_opt(src=%s:%s)", addr[0], addr[1])
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
            return

        version = dns_packet.edns_version
        if version is not None and int(version) != EDNS_VERSION_SUPPORTED:
            # RFC 6891 section 6.1.3: "If a responder does not implement the
            # VERSION level of the request, then it MUST respond with
            # RCODE=BADVERS." The response's OPT carries version 0 -- "the
            # highest implementation level of the responder" -- which is what
            # tells the requestor how far down this server actually goes.
            self.log.debug("server_edns_version(src=%s:%s version=%s)", addr[0], addr[1], version)
            self._error(dns_packet, addr, DnsResponseCode.BADVERS, channel=channel)
            return

        if not self._edns_options_or_error(dns_packet, addr, channel=channel):
            # Options belong to the OPT, so they are judged with it: after the
            # version check, because options defined for a VERSION this server
            # does not implement cannot be interpreted at all, and before the
            # resolver is touched, because a datagram that cannot be answered
            # should not purchase a recursive walk. A request with no OPT has
            # no options to judge and passes straight through.
            return

        asked = self._mqtype_request(dns_packet)
        verdict = self._consult_responders(dns_packet, addr, channel)
        if verdict is _RESPONDER_FAILED:
            self._error(
                dns_packet,
                addr,
                DnsResponseCode.SERVER_FAILURE,
                mqtype_answered=[] if asked is not None else None,
                channel=channel,
                extended_errors=(),
            )
            return
        if verdict is not None:
            self._dynamic_reply(dns_packet, addr, verdict, asked, channel)
            return
        async with self._slots:
            try:
                response = await self.resolver.resolve(dns_packet)
            except asyncio.CancelledError:
                self.log.debug("server_cancelled(dst=%s)", addr[0])
                raise
            except asyncio.InvalidStateError:
                self.log.debug("server_late_result(dst=%s)", addr[0])
                return
            if response is None:
                # Section 3.4's first paragraph conditions nothing on the answer
                # being a good one: a server that supports multiple QTYPEs returns the
                # option in its response to a valid query. A resolution that produced
                # nothing therefore says so with an empty list, rather than with the
                # silence that means "this server never heard of MQTYPE".
                self._error(
                    dns_packet,
                    addr,
                    DnsResponseCode.SERVER_FAILURE,
                    mqtype_answered=None if asked is None else [],
                    channel=channel,
                )
                return
            answered = None
            if self._sentinel_gate(dns_packet, response):
                # RFC 8509 §2.2¶5's rewrite has spoken: SERVFAIL, empty Answer
                # Section, "ignoring all other documents that specify the
                # content of the Answer Section" -- which includes the MQTYPE
                # combination below: it is not attempted, because a combined
                # answer would violate the sentence that just forbade it. The
                # support claim survives the refusal as an empty list, the
                # same reading §3.4 gets when resolution produced nothing.
                answered = [] if asked is not None else None
            elif asked is not None:
                try:
                    answered = await self._combine_mqtype(dns_packet, response, asked)
                except asyncio.InvalidStateError:
                    # The same race as above, one step later: the transport went away
                    # while extra types were being fetched, and an answer half-built
                    # for a client that has left is not worth finishing.
                    self.log.debug("server_late_result(dst=%s)", addr[0])
                    return
            self._reply(
                response, addr, request=dns_packet, mqtype_answered=answered, channel=channel
            )

    def datagram_received(self, data, addr):
        host, port = addr[0], addr[1]
        try:
            dns_packet, _offset = DnsPacket.parse(data)
        except DnsPacketParseError as exc:
            # Debug, not warning: this is the attacker-controlled path, and a
            # warning per datagram is a free log-flood primitive. The offset and
            # hex stay available to anyone who raises the level.
            self.log.debug(
                "server_parse_failed(src=%s:%s err=%s offset=%s octets=%d hex=%s)",
                host,
                port,
                exc,
                exc.offset,
                len(exc.data),
                exc.wire_hex(),
            )
            self._error(None, addr, DnsResponseCode.FORMAT_ERROR)
            return

        question = dns_packet.questions[0] if dns_packet.questions else None
        self.log.debug(
            "server_query(src=%s:%s id=%#06x q=%s)",
            host,
            port,
            dns_packet.ID,
            getattr(question, "name", "?"),
        )
        if len(self._tasks) >= 2 * self.max_concurrent_lookups:
            # Bound the *spawn*, not only the upstream lookup: taking the
            # semaphore inside the task meant every flooded datagram still
            # minted a coroutine, so ingress -- not the operator -- sized the
            # task set. The 2x margin keeps the semaphore meaningful (a few
            # lookups may wait their turn) while the backlog stays bounded;
            # past it, silent drop is the design's answer for overload -- the
            # same treatment RFC 5625 section 6.3 sanctions for intrinsically
            # malformed traffic: no response, no amplification, no log growth
            # at default level.
            self.log.debug("server_overload_drop(src=%s:%s)", host, port)
            return
        self._spawn(self.respond_to_packet(dns_packet, addr))


class DnsStreamServer(asyncio.Protocol):
    """One TCP connection in front of a :class:`DnsServer`.

    The datagram server answers a request and forgets the client existed;
    a stream is a *relationship*, and this class is what this package
    brings to one. RFC 9210 section 3 updates RFC 1123 to make the TCP
    half of a DNS server non-optional -- "All DNS resolvers and servers
    MUST support and service both UDP and TCP queries", and servers
    "including forwarders MUST support and service TCP for receiving
    queries" -- and RFC 7766 section 6.2.1 paragraph 1 asks both ends to
    make that transport worth having by reusing it. So: the length-
    prefixed framing of RFC 1035 section 4.2.2 read from the stream one
    whole message at a time; the keepalive conversation of RFC 7828
    section 3.3 answered with the idle timeout this connection actually
    enforces (section 3.3.2 paragraph 1's MUST); an idle close on the
    schedule RFC 9210 section 4.2 paragraph 4 asks software to make
    configurable, reset only by a *complete* message because RFC 7766
    section 6.2.3 paragraph 3 named the slow-read trick that partial
    resets invite; and pipelined queries processed concurrently -- RFC
    7766 section 6.2.1.1 paragraph 4's MUST to expect them and SHOULD to
    process them -- while their answers leave in arrival order, the one
    ordering rule TCP DNS has never broken.

    One instance per connection: ``asyncio`` builds one from a factory on
    each :meth:`~asyncio.loop.start_server` accept, and everything here
    -- the framing buffer, the answer ordering, the idle timer -- is the
    state of one client's line, not of the server. The shared server
    beneath stays the single bound on upstream work; this class adds a
    transport, not a policy.
    """

    def __init__(self, dns_server: DnsServer):
        self.server = dns_server
        self.log = LOGGER
        #: The number this connection's answers advertise, straight from the
        #: operator's knob: ``None`` says nothing, 0 refuses, N>0 is both the
        #: promise and the enforcement. Held separate from *what the timer
        #: runs on* only for the silent case: a server advertising nothing
        #: still holds no connection forever (RFC 7766 section 6.2.3 paragraph
        #: 2 recommends a real idle period regardless of what is signalled),
        #: and thirty seconds is the number the rest of this package agrees
        #: on when nobody names one.
        self._advertised = dns_server.tcp_idle
        self._enforced = DEFAULT_TCP_IDLE_S if dns_server.tcp_idle is None else dns_server.tcp_idle
        self._transport: asyncio.Transport | None = None
        self._addr = ("?", 0)
        self._buf = bytearray()
        #: Futures, one per received message, in arrival order; the pump
        #: awaits them one by one, which is how concurrent answers exit in
        #: sequence without any of them waiting to *start*.
        self._outbox: asyncio.Queue = asyncio.Queue()
        self._pump: asyncio.Task | None = None
        self._idle_timer: asyncio.TimerHandle | None = None
        self._tasks: set[asyncio.Task] = set()
        #: Set when this connection has decided its last answer: the
        #: zero-timeout refusal, a client's own close hint, or the pump's
        #: standing read of either. Late-arriving messages find it set and
        #: are answered with nothing -- a client still writing into a
        #: closing stream gets the RFC 7766 section 6.2.4 paragraph 2
        #: outcome, a retry on the next connection, not a half-answer
        #: from this one.
        self._closing = False

    def connection_made(self, transport):
        self._transport = transport
        peer = transport.get_extra_info("peername")
        if peer:
            self._addr = (peer[0], peer[1])
        self.log.debug("server_stream_open(src=%s:%s)", self._addr[0], self._addr[1])
        self._pump = asyncio.ensure_future(self._pump_out())
        # Idle starts at the handshake, not at the first message: a client
        # that connects and says nothing is holding a connection idle right
        # now, and a listener that tolerates that indefinitely is a
        # half-open socket farm (BCP235 section 4.2's whole concern).
        self._arm_idle()

    def connection_lost(self, _exc):
        # The outbox dies here: RFC 7766 section 6.2.4 paragraph 3 is a
        # MUST -- responses still owed to a client that has gone are not
        # sent to the bytes that used to be them -- and the tasks that
        # would have produced them have nothing left to answer to either.
        timer, self._idle_timer = self._idle_timer, None
        if timer is not None:
            timer.cancel()
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        pump, self._pump = self._pump, None
        if pump is not None:
            pump.cancel()

    def data_received(self, data):
        self._buf.extend(data)
        while len(self._buf) >= 2:
            (n,) = struct.unpack("!H", self._buf[:2])
            if n == 0:
                # A length prefix describes a DNS message, and a message of
                # zero octets is not one -- no header, no question, nothing
                # the stream can be read past. No specification hands down
                # the sentence for it, because the sentence is the same for
                # every framed stream: the reading position is wrong by
                # definition, so nothing further on this line is trustworthy.
                # Close; a client may mean it as a probe, and a probe does
                # not owe an answer.
                self.log.debug("server_stream_framing_error(src=%s)", self._addr[0])
                self._shutdown()
                return
            if len(self._buf) < 2 + n:
                return  # the rest of this message is still in flight
            frame = bytes(self._buf[2 : 2 + n])
            del self._buf[: 2 + n]
            self._on_message(frame)

    def _on_message(self, frame):
        if self._closing:
            # The decision is made; RFC 7766 section 6.2.4 paragraph 3 says
            # the same sentence to a connection this side is leaving as to
            # one the client left: nothing further goes out.
            self.log.debug("server_stream_closing_drop(src=%s)", self._addr[0])
            return
        # The idle clock resets here and nowhere earlier: a whole message
        # has just landed, which is the event RFC 7766 section 6.2.3
        # paragraph 3 distinguishes from "a segment arrived" -- the second
        # is what a slow-read attack is made of.
        self._arm_idle()
        try:
            dns_packet, _offset = DnsPacket.parse(frame)
        except DnsPacketParseError as exc:
            # Debug, as on the datagram path: this is the attacker-facing
            # line. The answer mirrors the datagram policy -- FORMERR, and
            # no OPT when there was no parseable request to earn one --
            # but the framing stayed sound, so the stream itself survives.
            self.log.debug("server_stream_parse_failed(src=%s err=%s)", self._addr[0], exc)
            self._enqueue(None)
            return
        self._note_client_hint(dns_packet)
        self._enqueue(dns_packet)

    def _note_client_hint(self, dns_packet):
        """Read a client's own closing signal, if its query carried one.

        RFC 7828's finished client form of the option is the empty one
        (section 3.2.1 paragraph 4's MUST), so a query that arrives with a
        TIMEOUT *in* it is a client written against something older. A 0 in
        that position can only mean what the same value means everywhere
        else in this option -- section 3.2.2 paragraph 3's "send no more
        queries on that connection", spoken by the sender instead of the
        receiver -- so honour the intent the bytes show: answer what has
        been asked, hold nothing further. An empty option, and no option at
        all, say nothing of the kind and change nothing here.
        """
        try:
            wanted = keepalive_of(dns_packet.edns_options())
        except DnsPacketParseError:
            # The same broken option the responder's own gate will refuse
            # with a FORMERR; it cannot also be a close hint. Whatever the
            # answer, this connection has no readable number to act on.
            return
        if wanted == 0:
            self._closing = True

    def _enqueue(self, dns_packet):
        """Give one received message its place in the answer order, and an answer task."""
        slot = asyncio.get_running_loop().create_future()
        self._outbox.put_nowait(slot)
        task = asyncio.ensure_future(self._answer(dns_packet, slot))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _answer(self, dns_packet, slot):
        """Produce this message's response wire, or ``None`` for no answer.

        The channel handed to the shared pipeline carries two facts about
        the stream: how to reach it again (``emit``, which fills the slot
        the pump is holding in order) and what this connection advertises
        for keepalive -- the connection's enforced number verbatim, or
        nothing at all when its operator chose silence. Messages the
        pipeline drops -- a non-query, a cancel mid-recursion, the gates
        that answer with only a log line -- resolve their slot to ``None``,
        because a queue with a hole in it is a stalled pump, and a stalled
        pump is every later answer stuck behind a message that never owed
        one.
        """

        def emit(wire):
            if not slot.done():
                slot.set_result(wire)

        # A connection that has already decided on its last answer -- by the
        # zero policy or a client's own closing hint -- associates no idle
        # time with itself, so section 3.3.2 paragraph 1's honesty clause
        # says 0, and 0 is what it says. Advertising thirty from a stream
        # about to end would be the one sentence the MUST forbids.
        advertised = 0 if self._closing else self._advertised
        channel = StreamChannel(emit, keepalive=advertised)
        try:
            if dns_packet is None:
                # Parse failed: the shared responder's no-OPT FORMERR, sent
                # through the same channel so the datagram path stays what
                # it always was. The sibling's private seam is the honest
                # door here -- the policy "FORMERR with no OPT" belongs to
                # DnsServer, and copying it here is how two transports
                # learn to disagree about it.
                self.server._error(None, self._addr, DnsResponseCode.FORMAT_ERROR, channel=channel)
            else:
                await self.server.respond_to_packet(dns_packet, self._addr, channel=channel)
        except asyncio.CancelledError:
            # connection_lost cancelled the work: the client is gone, and
            # section 6.2.4 paragraph 3 is exactly about answers nobody is
            # left to send. The slot dies unanswered; the pump is already
            # cancelled with us.
            raise
        finally:
            if not slot.done():
                slot.set_result(None)
        if self._advertised == 0:
            # Section 3.3.2 paragraph 1's refusal said, this connection
            # holds nothing -- not even until a timer says so.
            self._closing = True

    async def _pump_out(self):
        """Write answers in message order, framing each as it leaves."""
        while True:
            slot = await self._outbox.get()
            try:
                wire = await slot
            except asyncio.CancelledError:
                return
            if wire is None:
                self._maybe_finish_closing()
                continue
            if self._transport is None:
                return  # gone between answer and write -- 6.2.4 paragraph 3 again
            self._transport.write(struct.pack("!H", len(wire)) + wire)
            self._maybe_finish_closing()

    def _maybe_finish_closing(self):
        if self._closing and self._outbox.empty() and self._transport is not None:
            self._shutdown()

    def _arm_idle(self):
        if self._enforced <= 0:
            return  # zero holds nothing to time out; closing is post-answer work
        timer, self._idle_timer = self._idle_timer, None
        if timer is not None:
            timer.cancel()
        self._idle_timer = asyncio.get_running_loop().call_later(self._enforced, self._on_idle)

    def _on_idle(self):
        self._idle_timer = None
        self.log.debug("server_stream_idle_close(src=%s:%s)", self._addr[0], self._addr[1])
        self._closing = True
        self._shutdown()

    def _shutdown(self):
        transport, self._transport = self._transport, None
        timer, self._idle_timer = self._idle_timer, None
        if timer is not None:
            timer.cancel()
        if transport is not None:
            transport.close()

    def eof_received(self):
        # The client half-closed: no questions will arrive, so no answers
        # are owed, and RFC 7766 section 6.2.4 paragraph 3 forbids pushing
        # the in-flight ones anywhere. Falling off the end returns None,
        # which is asyncio's cue to finish the close.
        self._closing = True
        self._shutdown()
