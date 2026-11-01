"""Opportunistic encryption of the recursive-to-authoritative leg (RFC 9539).

RFC 9539 is a *deployment guidance* document, not a wire protocol: it adds
nothing to DNS, TLS, or the framing of either. What it specifies is a
memory -- one connection-state record per (encrypted transport,
authoritative IP) pair, Table 2 -- and a decision procedure over that
memory, §4.6, that answers three questions for every lookup the walker is
about to make: may this query still go over cleartext, should a new
encrypted connection be attempted, and through which established session
should it ride? The answers are timing formulas, and formulas are worth
extracting from the machinery that consults them, because the machinery is
asyncio and the formulas are testable to the second without any socket at
all. That split is this module: pure state and pure policy, with the
transport living in :mod:`namespy.resolver` where the decisions are acted
on.

Two properties of the policy deserve saying before the code repeats them.

*It is unilateral.* Nothing here is negotiated with the server, and the
policy itself consults no discovery record -- the resolver simply tries
encrypted transport to port 853 and remembers what happened (§4.1¶1).
The discovery-by-SVCB upgrade (RFC 9461, this module's second half)
arrives later and changes only *which port* the probe aims at: every
discovery outcome still routes through this machine's memory and its
fallback, because a record fetched over the channel it describes proves
less than a completed handshake does.

*It trusts the wrong thing on purpose.* The client this policy builds
accepts any certificate (§4.6.3.4's MUST) and sends no SNI (§4.6.3.3¶4's
SHOULD NOT). That is the exact opposite of the stub's strict RFC 7858
client in :mod:`namespy.stub`, which verifies carefully because its user
chose that server for privacy -- and it is right here for the opposite
reason: a *failed* authentication under this policy would mean falling
back to cleartext, and a downgrade an attacker can force by presenting a
bad certificate leaks the whole exchange. The trust this leg needs is
DNSSEC's, which validation supplies (or does not) regardless of what the
TLS layer accepted; encryption here is a privacy nicety, never an
authentication claim. The docstrings repeat this where someone might
"fix" it.

The parameters are Table 1's suggested defaults -- persistence three days,
damping one day, handshake timeout four seconds -- overridable per
instance because §4.3¶5 encourages operators to publish their choices.
Two verified errata (7831, 7832) correct §4.6.1¶2 and §4.6.3¶6 to read the
per-protocol values (E-persistence, E-damping); the formulas below follow
the corrected text and cite the errata at the lines that were wrong.

What this build does *not* yet exercise, recorded at the door: session
resumption (§4.6.3.2's SHOULD -- asyncio's client API offers no way to
present a saved ticket, so the ``resumptions`` field of Table 2 stays
permanently empty rather than pretending), early data (§4.6.3.1, a SHOULD
conditional on a context this build cannot create without resumption),
and DoQ (§4.4's second SHOULD -- no stdlib QUIC, the same deferral the
stub's transport list records; its §5.4 padding counterpart in RFC 9250
defers with it). Query padding (§4.6.8.1's SHOULD) *is* exercised: the
encrypted egress pads per RFC 8467 §4.1's 128-octet block
(:attr:`namespy.resolver.Resolver.query_padding`). §4.5¶7's "retain across
restart" is vacuous
for a library: the table lives in the resolver object, and the process
that ended took the knowledge with it; a daemon that wants restart
persistence owns a serializer this module pointedly does not.
"""

from __future__ import annotations

import enum
import re

from .enums import DnsRType
from .names import DomainName
from .packet import DnsPacketParseError
from .svcb import SvcbCandidate, SvcParamError, select_records

#: Table 1 (§4.3): the document's own suggested defaults, in seconds.
PERSISTENCE_S = 259200.0  # three days of "this server spoke DoT to me"
DAMPING_S = 86400.0  # one day of "do not poke that closed port again"
HANDSHAKE_TIMEOUT_S = 4.0  # one try at a TLS handshake


class ProbeStatus(enum.Enum):
    """Table 2's ``status`` field: success, fail, or timeout; ``None`` is null."""

    SUCCESS = "success"
    FAIL = "fail"
    TIMEOUT = "timeout"


class OpportunisticError(Exception):
    """The encrypted leg could not deliver this query; §4.6.5's fallback owns it.

    Raised by the transport side (in :mod:`namespy.resolver`) after it has
    already recorded *why* into the probe -- a refusal, a handshake alert,
    a timeout. The state machine above has therefore usually seen this
    failure before the racer does; the exception is how the leg says "ask
    Do53 now" without each call site repeating the §4.6.5 bullet list.
    """


class ProbeParams:
    """Table 1's three system values, per encrypted transport.

    One instance per transport (§4.3¶1: "may be set independently for each
    supported encrypted transport"), passed to every decision so the
    formulas read their own protocol's numbers -- which is exactly what
    errata 7831 and 7832 corrected the pseudocode to say.
    """

    __slots__ = ("damping", "persistence", "timeout")

    def __init__(
        self,
        *,
        persistence: float = PERSISTENCE_S,
        damping: float = DAMPING_S,
        timeout: float = HANDSHAKE_TIMEOUT_S,
    ) -> None:
        self.persistence = float(persistence)
        self.damping = float(damping)
        self.timeout = float(timeout)


class AuthorityProbe:
    """Table 2 for one (transport, authoritative IP) pair.

    Timestamps are event-loop monotonic seconds, supplied by the caller
    rather than read from a clock: every formula in §4.6 is about
    differences, and a policy that takes *now* as an argument can be
    driven through a day of fake time in a test that takes no real one.

    The ``session`` field is whatever the transport side uses as a session
    handle (a :class:`namespy.resolver._Session` in this build); this
    module only tracks whether it is null, pending, or established, which
    is the distinction every §4.6 formula actually reads. The ``queries``
    queue is the table's other bookkeeping field, and its work is
    discharged here by the transport side's per-session lock: one query in
    flight at a time collapses "unsent/early/sent" into "the lock holder's
    problem". The ``resumptions`` stack stays empty for the resumption
    reason in the module docstring.
    """

    __slots__ = (
        "completed",
        "initiated",
        "last_activity",
        "last_response",
        "session",
        "session_established",
        "status",
    )

    def __init__(self) -> None:
        #: §4.5 Table 2 ``session``: null, or a handle, plus its
        #: pending/established flag -- the table's own two-state note.
        self.session: object | None = None
        self.session_established = False
        self.initiated: float | None = None
        self.completed: float | None = None
        self.status: ProbeStatus | None = None
        self.last_response: float | None = None
        self.last_activity: float | None = None

    # ------------------------------------------------------------- questions

    def ride(self) -> bool:
        """§4.6.3¶1: an established session takes the query, alone.

        "the recursive resolver SHOULD NOT initiate a new connection ...
        but should instead send queries to X through the existing
        session."
        """
        return self.session is not None and self.session_established

    def send_over_do53(self, now: float, params: ProbeParams) -> bool:
        """Whether Do53 may still carry a query to X (§4.6.1).

        Erratum 7831: the published pseudocode reads ``(T0 -
        E-last-response[X]) < persistence``; the corrected text says
        *E-persistence*, the value for the protocol in use. With one
        supported transport the readings agree, but the argument is named
        ``params`` and taken per decision so a second transport cannot
        inherit this one's memory of a good server.
        """
        if self.ride():
            return False  # §4.6.1¶2 first bullet
        remembered_success = (
            self.status is ProbeStatus.SUCCESS
            and self.last_response is not None
            and (now - self.last_response) < params.persistence
        )
        # §4.6.1¶2 second bullet, as erratum 7831 corrects it.
        return not remembered_success

    def consider(self, now: float, params: ProbeParams) -> None:
        """§4.6.3¶3-¶4: refresh a handshake that has outstayed its timeout.

        A pending initiation older than E-timeout becomes a timeout --
        before any question gets answered from the record, because every
        other formula trusts ``status`` to describe the *current* truth.
        """
        if (
            self.session is not None
            and not self.session_established
            and self.initiated is not None
            and (now - self.initiated) > params.timeout
        ):
            self.session = None
            self.session_established = False
            self.status = ProbeStatus.TIMEOUT

    def may_initiate(self, now: float, params: ProbeParams) -> bool:
        """Whether a fresh encrypted connection to X is permitted (§4.6.3¶5-¶6).

        Erratum 7832: the published "``> damping``" reads "``> E-damping``"
        in the corrected text -- the same per-protocol precision as
        §4.6.1¶2, applied to the retry gate.
        """
        if self.session is not None:
            return False  # one initiation in flight per X
        if self.status is ProbeStatus.SUCCESS:
            return True  # §4.6.3¶6 first bullet
        if self.status in (ProbeStatus.FAIL, ProbeStatus.TIMEOUT):
            return self.completed is not None and (now - self.completed) > params.damping
        return self.status is None and self.initiated is None  # third bullet: never tried

    # ------------------------------------------------------------- answers

    def note_initiating(self, now: float, session: object) -> None:
        """§4.6.3¶9, minus the query handle: the lock holder carries that."""
        self.initiated = now
        self.session = session
        self.session_established = False

    def note_established(self, now: float) -> None:
        """§4.6.4¶3: the handshake completed; success is recorded, timers set."""
        self.session_established = True
        self.status = ProbeStatus.SUCCESS
        self.completed = now
        self.last_response = now  # §4.6.4¶3's "sets E-last-response[X] to T1"
        self.last_activity = now

    def note_failed(self, now: float, *, timed_out: bool = False) -> None:
        """§4.6.5 / §4.6.6: the attempt failed; damp so it repeats slowly."""
        self.session = None
        self.session_established = False
        self.completed = now
        self.status = ProbeStatus.TIMEOUT if timed_out else ProbeStatus.FAIL

    def note_closed(self) -> None:
        """§4.6.7¶3: the peer ended a live connection.

        Status deliberately *survives*: section 4.6.7¶4's note says "Any
        subsequent query to X will retry the encrypted connection
        promptly", which is what a still-SUCCESS status buys through both
        §4.6.1¶2 (Do53 stays quiet while persistence holds) and
        §4.6.3¶6's first bullet (a new initiation is allowed at once).
        """
        self.session = None
        self.session_established = False

    def note_activity(self, now: float) -> None:
        """§4.6.8¶2: a query left through the session."""
        self.last_activity = now

    def note_response(self, now: float) -> None:
        """§4.6.9¶6: an answer arrived on the session; both clocks move."""
        self.last_activity = now
        self.last_response = now


# ------------------------------------------------------------- RFC 9461 discovery
#
# The module docstring's "it is unilateral" describes RFC 9539's own policy;
# this second half is the upgrade the roadmap row names: RFC 9461's discovery
# of encrypted DNS services by SVCB record. The two documents compose in a
# direction worth stating -- 9461 §6¶2's first bullet concedes that an
# authentication name "received over an insecure channel (e.g., a glue NS
# record)" cannot be defended by this specification, which is exactly the
# authority-leg case; the discovery therefore only ever *upgrades* the blind
# probe's target (which port to try), never vetoes it, and the privacy
# argument for the blind probe -- an attacker forcing cleartext by lying
# about SVCB -- is why an unusable answer falls back to probing rather than
# to silence.


#: §4.4¶2 again, from the other document's side: RFC 9461 §4.2¶1 -- "the
#: default port number for each transport protocol (853 for DoT...)".
DOT_DEFAULT_PORT = 853

#: RFC 9461 section 4.2 paragraph 3 is the port key's warning label: a
#: hostile DNS server could steer a client with elevated local access at
#: "a specially crafted TLS Server Name Indication (SNI) or session ticket
#: that can be misparsed as a command or exploit". Paragraph 4's third
#: permission is the one a library can earn without knowing its host:
#: restrict the allowed values to exclude ports where confusion is
#: likely, "e.g., the 'bad ports' list from Section 2.9 ('Port blocking')
#: of [FETCH]". That list is adopted verbatim below -- with one exception
#: argued rather than copied. FETCH blocks 443 because a browser must not
#: treat it as an arbitrary HTTP alternative; RFC 9461 §4.2¶1 calls 443
#: the default port for DoH, the very transport this mapping names, and
#: a TLS client pointing at 443 is pointing at the one service on the
#: machine that expects TLS. Port 53 stays denied: the confusion there is
#: the one this document is about -- encrypted bytes arriving at a
#: cleartext server. Every other listed service -- SMTP on 25, IMAP on
#: 143, the IRC range 6665-6669, X11 on 6000 -- is exactly the misparse
#: target §4.2¶3 describes, and a record demanding one is a record this
#: client treats as incompatible (§4.2¶2's auto-mandatory rule makes
#: declining the port mean declining the record). Enumerated as of the
#: Fetch Living Standard, 2026-10-19.
CONFUSION_RISK_PORTS = frozenset(
    {
        0,
        1,
        7,
        9,
        11,
        13,
        15,
        17,
        19,
        20,
        21,
        22,
        23,
        25,
        37,
        42,
        43,
        53,
        69,
        77,
        79,
        87,
        95,
        101,
        102,
        103,
        104,
        109,
        110,
        111,
        113,
        115,
        117,
        119,
        123,
        135,
        137,
        139,
        143,
        161,
        179,
        389,
        427,
        465,
        512,
        513,
        514,
        515,
        526,
        530,
        531,
        532,
        540,
        548,
        554,
        556,
        563,
        587,
        601,
        636,
        989,
        990,
        993,
        995,
        1719,
        1720,
        1723,
        2049,
        3659,
        4045,
        4190,
        5060,
        5061,
        6000,
        6566,
        6665,
        6666,
        6667,
        6668,
        6669,
        6679,
        6697,
        10080,
    }
    - {443}
)

#: RFC 9460 §2.4.2¶10: alias chains "MUST" be bounded, the limit "MUST NOT
#: be zero", and its value is left to implementations. Five is this one's.
MAX_ALIAS_HOPS = 5

#: How long a discovery verdict may be remembered when the records that
#: justified it are gone: a miss (no ``_dns`` record, NODATA, a failed
#: walk) earns five minutes -- long enough that an authority publishing
#: nothing costs one walk per batch of queries, short enough that a
#: record appearing is noticed within a coffee break -- and a hit is
#: clamped between these bounds around its own RRset TTL, so a
#: zero-TTL novelty does not become a per-query walk and a century-TTL
#: mistake does not become a grudge.
DISCOVERY_MISS_S = 300.0
DISCOVERY_MIN_S = 60.0
DISCOVERY_MAX_S = 86400.0

#: The §3.1 port-prefix form, ``_9953._dns.example``. The walker's binding
#: authority is always port 53 (the §4.6 hook is gated on exactly that),
#: but the naming rule covers both and the construction is free.
_PORT_PREFIX = re.compile(r"^_(\d{1,5})$")


def dns_service_name(server_name: str, port: int = 53) -> DomainName:
    """RFC 9461 §3: Port Prefix Naming with scheme ``dns``.

    "SVCB records for a DNS service identified as dns1.example.com would
    be queried at _dns.dns1.example.com" -- and §3.1's special case,
    "if the binding authority is dns1.example.com:9953, the client would
    query for SVCB records at _9953._dns.dns1.example.com".
    """
    text = str(server_name).rstrip(".") or ""
    if not text:
        raise ValueError("dns_service_name needs a non-empty server name")
    if port == 53:
        return DomainName(f"_dns.{text}.")
    if not 1 <= int(port) <= 65535:
        raise ValueError(f"port {port} is outside 1..65535")
    return DomainName(f"_{int(port)}._dns.{text}.")


def _label_text(name) -> list[str]:
    """A domain name's labels as lowercase text, whatever ``labels()`` returns.

    This codebase's labels are wire octets (``b"_dns"``), and ``str()`` of
    a bytes label is its *repr* -- ``"b'_dns'"`` -- which matches nothing.
    Both naming helpers below route through here once rather than each
    rediscovering the conversion.
    """
    out = []
    for label in name.labels():
        if isinstance(label, (bytes, bytearray)):
            out.append(label.decode("ascii", "replace").lower())
        else:
            out.append(str(label).lower())
    return out


def _binding_name(qname: DomainName) -> str | None:
    """Strip Port Prefix Naming: ``_dns.ns.example`` -> ``ns.example``.

    ``_9953._dns.ns.example`` strips the port prefix too (§3.1); a name
    that does not carry ``_dns`` at all describes no DNS service in this
    mapping and answers ``None``.
    """
    labels = _label_text(qname)
    if labels and _PORT_PREFIX.match(labels[0]):
        labels = labels[1:]
    if not labels or labels[0] != "_dns":
        return None
    return ".".join(labels[1:]) or None


class _SkippedError(Exception):
    """Internal: a candidate with the reason it describes no DoT endpoint."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _endpoint_from_candidate(cand, binding: str, host: str) -> int:
    """One ServiceMode RR through RFC 9461 §4's policy, raising ``_SkippedError``.

    Returns the TCP port to probe; the address to probe stays the
    resolver's own choice, because RFC 9539 §4.2's per-IP state is keyed
    to the address the delegation selected and this client connects
    nowhere else. Each refusal is a decision with a citation, not a whim:

    * a target other than the binding name names a *different machine* --
      §6¶3 steers deployments toward the self-target convention precisely
      because chasing another name means chasing its addresses, which is
      the per-IP state's whole premise dissolving. Such a candidate is
      still survivable when the §4.3 hints vouch for this exact address
      (a CDN that publishes the authority's own IPs as hints), which is
      the one foreign-target case where connecting to X is connecting to
      the service the record describes;
    * an ``alpn`` without ``dot`` is not this transport -- §4.1¶1's
      requirement ("no alpn ... the client MUST treat the SVCB record as
      incompatible", which :func:`select_records` has usually already
      applied) and the refusal of an HTTP-only answer that RFC 9539
      §2.2¶8 makes for the whole authority leg: the document "does not
      pursue" DoH here because a path mechanism was lacking -- and while
      RFC 9461 §5's ``dohpath`` arguably supplies the mechanism §2.2¶8
      wishes for (9539 cites 8484 but never cites 9461), §2.2¶7 binds
      this document's state machine to DoT and DoQ and hands DoH to a
      future update. Running a third transport on that reading would be
      implementing an amendment nobody ratified; this build skips the
      record instead, which is also what §2.2¶8's resource concern says
      a path-guessing client would be spending.
    * a ``port`` inside :data:`CONFUSION_RISK_PORTS` is declined per
      §4.2¶3-¶4, and §4.2¶2's auto-mandatory rule makes declining the port
      mean declining the record.
    """
    params = cand.params
    target_text = ".".join(_label_text(cand.effective_target))
    # Section 2.5's root means "the owner name", and in this mapping the
    # owner is Port Prefix Naming over the binding authority -- so a root
    # target names the binding itself, self-targeted like §7's
    # ``_dns.simple.example. SVCB 1 simple.example.`` and needs no hint
    # to vouch for it.
    if not cand.target_is_root and target_text != binding:
        hints = [str(h) for h in (params.ipv4hint or []) + (params.ipv6hint or [])]
        if str(host) not in hints:
            raise _SkippedError(f"target {target_text or '(root)'} is not {binding}")
    alpn = params.alpn
    if not alpn:
        raise _SkippedError("no alpn SvcParam (RFC 9461 §4.1¶1)")
    if b"dot" not in alpn:
        raise _SkippedError(f"alpn {alpn!r} carries no 'dot'")
    port = params.port
    if port is not None and port in CONFUSION_RISK_PORTS:
        raise _SkippedError(f"port {port} on the confusion-risk list (RFC 9461 §4.2¶3-¶4)")
    return int(port) if port is not None else DOT_DEFAULT_PORT


async def learn_dot_endpoint(fetch, server_name, host, *, alias_limit: int = MAX_ALIAS_HOPS):
    """Run RFC 9460 §3's resolution procedure over ``_dns.<server_name>``.

    ``fetch(qname)`` is the only outside contact: it answers the list of
    answer-section records for that name, or ``None``/empty for NODATA,
    NXDOMAIN, and every failure the walk reports that way. The function is
    therefore the whole §4 policy as a decision over canned records --
    aliases included -- and no socket is required to prove any of it.

    Returns ``(port, ttl)`` for the first compatible, self-targeting,
    confusion-safe candidate -- ``port`` the record's ``port`` value or
    §4.2¶1's 853 -- with ``ttl`` the minimum TTL the answers carried, so
    the caller can remember the verdict without outliving the records
    that justified it. ``None`` means nothing was learned: no records,
    nothing compatible, a chain out of hops. Every ``None`` sends the
    caller back to RFC 9539's blind probe rather than away from
    encryption, because a discovery answer is itself unauthenticated
    (§6¶2's first bullet) and only the probe's own handshake proves a
    port is there.
    """
    qname = dns_service_name(server_name)
    min_ttl: int | None = None
    for _hop in range(int(alias_limit) + 1):
        records = await fetch(qname)
        if not records:
            return None
        svcb = [r for r in records if int(getattr(r, "rtype", 0)) == int(DnsRType.SVCB)]
        if not svcb:
            return None  # CNAMEs or stranger data: the walk followed what it follows
        candidates = []
        for record in svcb:
            try:
                candidates.append(SvcbCandidate.from_wire(record.name, bytes(record.rdata)))
            except (DnsPacketParseError, SvcParamError, ValueError):
                continue  # an unparseable RR is simply not one of the endpoints
        if not candidates:
            return None
        ttl = min(int(getattr(r, "ttl", 0) or 0) for r in svcb)
        min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        selection = select_records(candidates, client_alpn=(b"dot",), shuffle=None)
        if selection.mode == "alias":
            # §2.4.2 step 3: "set $QNAME to its TargetName (without
            # additional prefixes) and loop back". The loop is capped,
            # which is §2.4.2¶10's MUST met with room for the spec's own
            # single-hop ns.example example.
            alias = selection.alias[0]
            if alias.target_is_root:
                return None  # a root alias target announces no service
            qname = alias.target
            continue
        if selection.mode != "service":
            return None
        binding = _binding_name(qname)
        if binding is None:
            return None
        for cand in selection.service:
            try:
                return _endpoint_from_candidate(cand, binding, str(host)), max(min_ttl, 0)
            except _SkippedError:
                continue  # next candidate; §3 step 4's priority order already applied
        return None
    return None  # alias chain outlived the limit: give up; the blind probe has opinions
