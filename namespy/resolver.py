"""Iterative resolution: RFC 1034 section 5.3.3, as a generator plus an async driver.

The module splits cleanly in two, and the split is the point:

* :func:`resolve_steps` is a *synchronous* generator that yields effect and
  trace events (``SendQuery``, ``NeedAddress``, ``Answer``, ``Demote``, ...) and
  receives back whatever the caller fetched. It never touches a socket, a clock,
  or the cache's clock, so the whole algorithm -- including the parts that took
  the longest to get right, like telling a referral from a NODATA and following
  an alias chain across responses -- is testable with a table of canned
  responses. See ``tests/test_resolve_steps.py`` and
  ``tests/test_resolver_alias.py``.
* :class:`Resolver` / :class:`RecursiveResolver` fulfil those effects over UDP
  and TCP and keep the safety-belt list of servers.

Constructing a resolver performs **no network I/O**: root hints come from the
``named.root`` shipped inside the package via :mod:`importlib.resources`. A
constructor that silently called ``urlretrieve`` (as this one did) broke every
offline test, hung on a network-less host with no timeout, and wrote a file into
the current working directory as a side effect of ``Resolver()``. Refreshing
hints from the network is now the explicit, awaited
:meth:`RecursiveResolver.refresh_root_hints`.

.. rubric:: References

* RFC 1034 section 5.3.2 (resolver state: Sname/Slist/Sbelt), section 5.3.3
  (the algorithm), section 3.6.2 (aliases must not loop), section 4.2.1 (glue
  RRs: only necessary for servers below the cut), section 4.2.2 (a zone's
  servers need not have names inside it)
* RFC 1035 section 4.3 (server behaviour), section 5.2 item 3 (delegations
  need their glue), RFC 1034 section 5.3.3 step 4c (CNAME in the answer)
* RFC 2308 section 5 (negative caching from SOA.MINIMUM)
* RFC 5452 section 9.1 (query matching rules), sections 5 and 7 (why a 16-bit ID
  alone is brute-forceable), section 9.2 (source-port randomness), section 6
  (accept only records inside the domain that was asked about -- the
  :class:`GluePolicy` default, and what ``PERMISSIVE`` deliberately switches off)
* RFC 6672 section 5.1 (DNAME plus CNAME makes alias loops easier to build)
* RFC 7766 section 6 (TCP for truncation and for AXFR)
* RFC 8106 section 2 (root hints: an initial address set is required)
* RFC 10001 section 4.2 (a recursive resolver stays dual-stack, and both
  address families keep their turn inside one SLIST entry: see
  :func:`_interleave_families`)
* RFC 9156 (QNAME minimisation -- opt-in via ``qname_min``; see
  :mod:`namespy.minimis` for the probe schedule)
* RFC 8198 / RFC 9077 (aggressive use of validated cached denials -- opt-in via
  ``aggressive_nsec``; see :mod:`namespy.aggressive` for the gates)
* RFC 1034 section 5.3.1 / RFC 1035 section 4.1.1 (the stub resolver: RD and the
  recursive arrangement) -- :class:`Resolver` here is the shared transport the
  walk and :class:`namespy.stub.StubResolver` both drive, so the forwarding
  answer matching and the UDP-to-TCP retry are one implementation, not two
"""

import asyncio
import enum
import io
import ipaddress
import logging
import os
import random
import re
import secrets
import socket
import ssl
import struct
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from socket import gaierror
from typing import Any, NamedTuple

from . import enable_path_mtu_discovery
from .aggressive import synthesize
from .bundle import (
    BundledType,
    BundleResult,
    BundleState,
    bundle_is_void,
    collect_bundle,
    query_option_for,
)
from .cache import FailureCache, MemoryDnsCache, NegativeEntry, PositiveEntry
from .dnssec import DNSSEC_SECURITY_TYPES, signed_owner_name
from .edns import (
    MQTYPE_QUERY_OPTION_CODE,
    QUERY_PAD_BLOCK_OCTETS,
    extended_error_presentation,
    extended_errors_of,
    keepalive_of,
    key_tag_option,
    key_tags_of,
    nsid_of,
    nsid_presentation,
)
from .enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType, is_data_rrtype
from .minimis import QnameMinimiser
from .names import DomainName
from .nsec import collect_proof_records, name_order_key
from .opportunistic import (
    DISCOVERY_MAX_S,
    DISCOVERY_MIN_S,
    DISCOVERY_MISS_S,
    AuthorityProbe,
    OpportunisticError,
    ProbeParams,
    learn_dot_endpoint,
)
from .packet import (
    EDNS_CO_BIT,
    EDNS_DO_BIT,
    OPT_RTYPE,
    DnsPacket,
    DnsPacketParseError,
    DnsQuestion,
    DnsRecord,
    Query,
    Response,
)
from .rdata import RData_A, RData_AAAA, RData_RRSIG, type_name_of
from .trace import Trace
from .validate import SecurityStatus, ValidationVerdict, Validator

LOGGER = logging.getLogger(__name__)

# RFC 1034 §5.3.3 caps; these are the defaults, and RecursiveResolver takes each
# as a constructor argument so a caller can tighten them (a stub resolver serving
# a constrained client wants smaller, not larger).
MAX_HOPS = 32
MAX_DEPTH = 24

# Bound on CNAME/DNAME redirections followed for one lookup.
#
# No RFC states a number. RFC 1034 §3.6.2 only requires that alias loops not be
# followed forever ("a alias name must not map to itself, either directly or
# indirectly"), and RFC 6672 §5.1 notes that DNAME plus CNAME makes loops easier
# to construct than either type alone. Some bound is therefore mandatory; this
# is generous relative to real deployments, where chains of 2--3 are the norm,
# and it is deliberately smaller than MAX_HOPS so a pathological chain fails
# with a clear "alias" error rather than an opaque "max hops".
MAX_ALIAS_HOPS = 16

# Per-query timeout. RFC 1034 §5.3.3 step 3 says the resolver picks the
# "best" server, sends a query, and on timeout moves on to another entry —
# but the spec leaves the wait time to the implementation. A small budget
# is essential: without it, one unreachable anycast NS hangs the whole
# resolution (and any glueless sub-resolution rooted in it) until the
# caller's outer timeout fires. BIND uses 1.5--5 s initially; we pick 5 s.
QUERY_TIMEOUT_S = 5.0

#: EDNS(0) payload advertised on outbound queries (RFC 6891 section 6.2.3).
#: The document calls "between 1280 and 1410 bytes for IP (v4 or v6) over
#: Ethernet" reasonable; 1232 is 1280 -- IPv6's guaranteed minimum link MTU
#: (RFC 8200 section 5) -- minus the 40-octet IPv6 header and the 8-octet
#: UDP header, so an answer at the full advertised size fragments on
#: neither stack. 0 disables EDNS and returns every answer to the 512-octet
#: ceiling of RFC 1035 section 4.2.1.
EDNS_PAYLOAD_SIZE = 1232


class GluePolicy(enum.Enum):
    """How much of a referral's volunteered address data may be believed.

    RFC 5452 section 6 instructs a resolver to "take care to only accept data if
    it is known that the originator is authoritative for the QNAME or a parent of
    the QNAME", because a response "often contain[s] information that is not part
    of the zone for which we deem it authoritative". :attr:`STRICT` is that
    instruction executed: glue is believed only for a nameserver name inside the
    zone that answered, or inside the zone that referral delegated -- RFC 1034
    section 4.2.1 makes a parent responsible for exactly that glue, and for
    nothing else it volunteers.

    :attr:`PERMISSIVE` exists to measure the attack :attr:`STRICT` prevents. A
    researcher reproducing a cache-poisoning vector, or auditing what a parent
    zone actually volunteers about someone else's nameservers, needs the address
    to be *used*: without that it is discarded inside the classifier and the
    evidence never reaches a trace or a send log. It is a research instrument,
    not a compatibility knob -- believing an out-of-zone address hands the rest of
    the lookup, and the queries it sends, to the delegating server's choosing,
    which is the capability RFC 5452 section 6 exists to deny.

    Neither member relaxes three things, and each is a different reason:

    * the **lame check** (a below-cut nameserver with no glue, RFC 1034 section
      4.2.1) -- a reachability fact, not a trust judgement;
    * **response matching** (RFC 5452 section 9.1) -- the defense against an
      off-path forger, a different threat from a parent volunteering data;
    * the **cache** -- glue is recorded nowhere in it, so a permissive descent
      cannot persist a poisoning past the lookup that observed it.
    """

    #: RFC 5452 section 6 as written: in-bailiwick glue only. The default.
    STRICT = "strict"

    #: Believe any name-matching glue. Diagnostics only; see the class docstring.
    PERMISSIVE = "permissive"


class NxdomainPolicy(enum.Enum):
    """How much of a remembered NXDOMAIN may be answered without asking again.

    RFC 8020 §2¶1: "When an iterative caching DNS resolver receives an NXDOMAIN
    response, it SHOULD store it in its cache and then all names and resource
    record sets (RRsets) at or below that node SHOULD be considered unreachable.
    Subsequent queries for such names SHOULD elicit an NXDOMAIN response." The
    operative words are *at or below*: a denial proved for one name is a
    statement about the whole subtree beneath it -- and about every RRset at the
    node itself, which is how a AAAA comes to be answered by the NXDOMAIN that
    arrived for an A. That is also why this needs a lookup of its own rather than
    a cache hit: the denial was written under whichever type happened to be asked
    first, and the cut is not about the type.

    :attr:`ALWAYS` is the §2 SHOULD, and the default.

    :attr:`NEVER` exists because the generalisation is bounded by a TTL rather
    than by the truth: a name created under a denied node stays invisible until
    the negative entry expires, which §2¶4 concedes outright -- "The fact that a
    subtree does not exist is not forever". That makes the cut wrong for one job,
    the same job ``--no-failure-cache`` exists for: watching a zone change. It is
    not a safety knob. Unlike out-of-bailiwick glue it cannot hand a lookup to
    somebody else's choice of server; the worst it can do be briefly stale, and
    RFC 2308 §3 already bounds that.

    :attr:`VALIDATED` is §2¶3: "a validating resolver MAY decide to implement the
    'NXDOMAIN cut' behavior (described in the first paragraph of this section)
    only when the NXDOMAIN response has been validated with DNSSEC". The cut
    requires the *remembered* verdict of :mod:`namespy.validate` -- the chain the
    walk itself composed and judged under its ``trust_anchors`` when the denial
    arrived, stamped into the entry's ``validated`` flag -- and unvalidated
    entries, whether unsigned, bogus, or merely unjudgeable, are not cut: the
    walk descends and asks, as :attr:`NEVER` does. It refuses construction
    without trust anchors, because a validator with no trust point marks
    everything unvalidated, and a policy doing that while named for proof would
    be the silent fallback this door was first built to prevent.

    Three things no stance of this policy changes, in the same spirit as
    :class:`GluePolicy`:

    * **the proof** -- an entry can only exist if an SOA denied the name
      (RFC 2308 §5 refuses to cache a negative without one);
    * **the clock** -- the entry's life is that SOA's negative TTL (§3), so a cut
      can never outlive the answer it came from;
    * **the origin** -- response matching (RFC 5452 §9.1) and the bailiwick
      filter decide what a response is allowed to say in the first place, which
      is a different threat from how long its claims are remembered.
    """

    #: RFC 8020 §2 as written: a denied subtree is unreachable. The default.
    ALWAYS = "always"

    #: Deny only the exact name cached; walk below it. Diagnostics only.
    NEVER = "never"

    #: Cut only on DNSSEC-validated denials (RFC 8020 §2¶3). Requires
    #: ``trust_anchors``; unvalidated entries are walked, never cut.
    VALIDATED = "validated"


#: RFC 7828 §3.2.2's default idle horizon when a keepalive conversation
#: happened but named no timeout, and the floor below which even an offered
#: timeout is not trusted (a server offering 1 second makes reuse a
#: round-trip tax for nothing). §3.4¶2's "some amount of time" is this
#: build's reading of it; §6's 30 seconds is the same number, arrived at
#: independently.
_KEEPALIVE_DEFAULT_S = 30.0
_KEEPALIVE_FLOOR_S = 2.0

#: Placeholder stored in an :class:`~namespy.opportunistic.AuthorityProbe`
#: while a TLS handshake is in flight: §4.6.3¶9 wants a session handle at
#: initiation time, before any stream exists to be one, and the pending/
#: established distinction is what every §4.6 formula reads -- the object
#: itself is never touched, only its identity and ``None``-ness.
_HANDSHAKE_PENDING = object()


def _idle_seconds(timeout: int | None) -> float:
    """How long a stream may rest after an answer offering *timeout*.

    The whole of RFC 7828 §3.2.2's client arithmetic, spelled once: none
    offered (or nothing usable in the option) rides the conservative default,
    an offered number is honoured -- except below :data:`_KEEPALIVE_FLOOR_S`,
    where reuse would cost a handshake per lookup and the server's offer is
    declined in favour of the floor. A ``0`` never arrives here: §3.2.2¶3's
    close-now is a decision the caller acts on before arming anything.
    """
    if timeout is None:
        return _KEEPALIVE_DEFAULT_S
    return max(float(timeout), _KEEPALIVE_FLOOR_S)


class _Session:
    """One held TCP (or TLS) stream to a peer, and its idle life.

    A connection is shared, never snatched: the lock admits one exchange at
    a time (the conservative reading of RFC 7828 §3.3¶3's matching duties --
    every response that arrives is the answer to the query whose lock this
    is, or the stream is discarded), and :attr:`timer` is RFC 7828 §3.2.2¶2's
    "initiate close of the connection before the timeout expires", armed from
    the server's offered TIMEOUT (floored at :data:`_KEEPALIVE_FLOOR_S`,
    defaulted to :data:`_KEEPALIVE_DEFAULT_S`) after each answer. A waiter
    that finds the session closed on winning the lock has lost it to the
    timer, not to the server -- its caller re-opens rather than failing.

    It serves both stream halves of this package from one class: the
    walk's pooled TCP fallbacks (see :meth:`Resolver._query_tcp`) and a
    stub's ``dot`` upstreams (see :mod:`namespy.stub`) hold exactly this
    shape, and the DoH transport (see :mod:`namespy.doh`) borrows its
    lock and timer.
    """

    __slots__ = ("closed", "lock", "reader", "timer", "writer")

    #: Streams are one-exchange-at-a-time; the DoH HTTP/2 session overrides
    #: this to say its queries may ride concurrent streams.
    multiplexed = False

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.lock = asyncio.Lock()
        self.timer: asyncio.TimerHandle | None = None
        self.closed = False

    def arm_idle(self, seconds: float, loop) -> None:
        self.cancel_idle()
        self.timer = loop.call_later(seconds, self._on_idle)

    def _on_idle(self) -> None:
        self.timer = None
        self.close_now()

    def cancel_idle(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def close_now(self) -> None:
        self.closed = True
        self.cancel_idle()
        writer, self.writer = self.writer, None
        if writer is not None:
            try:
                writer.close()
            except Exception as exc:  # best-effort teardown, said not raised
                LOGGER.debug("stream_close_failed(err=%s)", type(exc).__name__)
                del exc


class Resolver(asyncio.Protocol):
    """Send queries to authoritative servers and match the answers.

    The class attributes are the defaults; :class:`RecursiveResolver` overrides
    them from its constructor arguments, and a bare ``Resolver`` -- which tests
    and ad-hoc drivers instantiate without calling ``__init__`` -- therefore
    still has every knob defined.
    """

    #: The instance logger. Deliberately :func:`~logging.getLogger`, not a
    #: freshly-constructed ``logging.Logger``: constructing a Logger directly
    #: puts it outside the hierarchy, so it does not propagate, does not obey a
    #: level or handler the application set on the ``namespy`` logger, and -- with
    #: a module-global handler attached to each instance -- duplicates output.
    log = LOGGER

    #: Seconds to wait for one UDP answer before demoting the server.
    query_timeout = QUERY_TIMEOUT_S

    #: Hop, alias-chain and sub-resolution budgets (see module constants).
    max_hops = MAX_HOPS
    max_alias_hops = MAX_ALIAS_HOPS
    max_depth = MAX_DEPTH

    #: UDP payload advertised by the EDNS(0) OPT record on every outbound
    #: query (RFC 6891 section 6.2.3); ``0`` or ``None`` sends no OPT at all.
    edns_payload_size = EDNS_PAYLOAD_SIZE

    #: RFC 8467 §4.1¶2 block-length padding for queries leaving over an
    #: *encrypted* leg (the transport gate is RFC 7830 §6; RFC 9539 §4.6.8.1
    #: is the sentence that asks a DoT client to authority servers for
    #: exactly this). On by default because the encrypted legs are the ones
    #: an operator chose for privacy, and an unpadded DoT query hands the
    #: name lengths to whoever owns the path anyway; :meth:`...padded_clone`
    #: skips padding when the block boundary would exceed this client's own
    #: advertised payload (RFC 7830 §4¶1). Cleartext legs never see the
    #: option, here or anywhere: §6 says MUST NOT.
    query_padding = True

    #: Whether to set EDNS(0)'s DO bit on outbound queries, asking each server for the DNSSEC
    #: records alongside the answer (RFC 6891 section 6.1.4). Off by default: this package is a
    #: resolver library, not yet the "security-aware recursive name server" RFC 4035 section 3.2.1
    #: addresses when it says the resolver side "MUST set the DO bit when sending requests,
    #: regardless of the state of the DO bit in the initiating request". A caller that *is* serving
    #: DNSSEC-aware clients is exactly the entity that sentence binds, and should turn this on --
    #: otherwise the NSEC/NSEC3 proofs that RFC 8020 section 2 requires echoing back are never sent
    #: in the first place, however well they are cached. Setting it costs extra octets per query and
    #: occasionally a TCP fallback, so it is a decision rather than a default.
    dnssec_ok = False

    #: Whether to ask each authority for RFC 9824's Compact Answers by setting
    #: the CO flag (OPT bit 14) alongside DO. A server that implements compact
    #: denial then answers nonexistent names with the §5.1 shape: the
    #: owner-matching proof whose bitmap asserts NXNAME, and -- when it
    #: implements §5.1's signaling -- the RCODE restored to NXDOMAIN. Off by
    #: default: it asks servers to sign on demand, §8¶2 being candid about
    #: what that costs an authority, and the walk accepts and records the
    #: signal (§2¶4) whether or not it asked -- the validator's judgment of
    #: the shape is the same either way, and no cached compact denial ever
    #: cuts a subtree or feeds §8198 synthesis, because §6¶3 forbids both.
    #: Meaningful only with DNSSEC on (DO), which trust anchors force anyway.
    compact_answers = False

    #: EDNS(0) options to attach to the OPT record of every outbound query --
    #: :class:`~namespy.edns.EdnsOption` instances, or ``(code, value)`` pairs.
    #: Asking for a Name Server Identifier (RFC 5001) is the intended use: an
    #: empty :attr:`~namespy.edns.OPTION_NSID` option asks every server to
    #: identify itself, and its answer is logged and recorded in
    #: :attr:`server_ids`. Section 6 of that RFC makes silence the normal
    #: outcome -- a server that does not implement the option simply omits it,
    #: so asking is free.
    edns_options = ()

    #: Which volunteered glue the classifier believes; see :class:`GluePolicy`.
    #: The safe member is also the class default, so a driver that never sets
    #: it -- and a test that builds a bare ``Resolver()`` -- filters strictly.
    glue_policy = GluePolicy.STRICT
    nxdomain_cut = NxdomainPolicy.ALWAYS

    #: Whether cached validated proofs may deny names they were not written for
    #: (RFC 8198 §5); see :meth:`RecursiveResolver.__init__`. Off is the class
    #: default, so a driver that never sets it synthesises nothing -- the
    #: pre-8198 behaviour RFC 4035 §4.5 originally called prudent.
    aggressive_nsec = False

    #: Trust anchors the walk judges answers under, positive and negative; see
    #: :meth:`RecursiveResolver.__init__`. Empty is the unvalidating default,
    #: and the only one a bare ``Resolver()`` can honestly have.
    trust_anchors = ()

    #: Optional DNS suffix the resolver assumes for *relative* names — those
    #: whose presentation form does not end in the root terminator (``.``).
    #: A trailing ``.`` on the SNAME prevents this suffix from being assumed
    #: (RFC 1035 §3.1's wire form is always absolute; the trailing dot in
    #: presentation form is a hint to the resolver, not a wire identity).
    #: Set to a ``str`` or :class:`~namespy.names.DomainName`; left ``None``,
    #: relative names are simply anchored at the root.
    dns_suffix = None

    #: The datagram plumbing :meth:`query` and the receive methods write.
    #: Declared bare (no values): the instances that use them --
    #: :class:`RecursiveResolver` and :class:`~namespy.stub.StubResolver` --
    #: bind their own in ``__init__``; these lines are only the contract the
    #: shared send and receive paths can rely on. ``Any`` is the honest type:
    #: the transport is asyncio's at runtime and a recording stand-in in the
    #: tests that drive these methods without a socket, exactly as the class
    #: docstring has always promised.
    transport: Any
    transport_v6: Any
    queue: dict
    queue_v6: dict
    _v6_ready: Any

    #: The pooled held streams :meth:`Resolver._query_tcp` reuses, keyed by
    #: ``(host, port)``. Declared bare like the datagram plumbing above: the
    #: instances that bind it -- :class:`RecursiveResolver` and
    #: :class:`~namespy.stub.StubResolver` -- do so in ``__init__``, and
    #: ``_query_tcp`` creates one on demand for anything else (a bare
    #: ``Resolver()`` driven by tests that never bind it).
    _tcp_sessions: dict

    #: RFC 9539 section 4.1: opportunistic encryption of the authority leg
    #: is OPTIONAL for a recursive resolver -- OPTIONAL in the protocol-
    #: design sense, so the default is the one that changes nobody's
    #: egress pattern: off. ``RecursiveResolver(opportunistic_dot=True)``
    #: (and the CLI's ``--dot-authority``, which the server passes through)
    #: turns the walker's per-address queries into the §4.6 decision. The
    #: stub ignores this flag: its upstream is an operator's chosen server
    #: whose transport the operator *named*, which is §7858/§8484
    #: territory, not the unilateral probing this policy governs.
    #: :attr:`opportunistic_dot_port` is §4.4¶2's 853, an instance
    #: attribute only so tests and unusual deployments can move it;
    #: :attr:`opportunistic_params` is Table 1 per §4.3 (shared class
    #: default: the object is read-only, no instance ever mutates it).
    #: The maps behind them -- Table 2 records, per-host initiation locks,
    #: live sessions, and background learners -- are lazily bound by the
    #: accessors, in the style of ``_query_tcp``'s pool, because an
    #: ordinary query path with the flag off must not allocate any of it.
    opportunistic_dot = False
    opportunistic_dot_port = 853
    opportunistic_params = ProbeParams()
    #: Raised while an RFC 9461 discovery walk owns the loop: the §4.6 hook
    #: reads it to keep the bootstrap (which resolves SVCB through the very
    #: authorities whose encryption is being discovered) from recursing
    #: into itself. The conservative direction -- an unrelated concurrent
    #: query may ride cleartext for the length of one discovery -- costs
    #: nothing but a not-yet-encrypted exchange, which is the pre-policy
    #: behavior everywhere, always correct, occasionally slower.
    _dot_discovering = False
    _dot_probes: dict
    _dot_locks: dict
    _dot_sessions: dict
    _probes_learning: set

    async def query(
        self,
        questions,
        nameserver_record,
        address_record,
        *,
        extra_edns_options=(),
        port: int = 53,
        force_tcp: bool = False,
        **kwargs,
    ):
        for label, value in (
            ("nameserver_record", nameserver_record),
            ("address_record", address_record),
        ):
            if value is not None and not isinstance(value, DnsRecord):
                raise TypeError(f"{label} must be a DnsRecord or None, got {type(value).__name__}")

        ip = _answer_address(address_record)
        if ip is None:
            raise ValueError(
                "address_record must carry valid A or AAAA RDATA, got "
                f"{type_name_of(address_record.rtype)} with "
                f"{len(bytes(address_record.rdata))} octet(s)"
            )
        dns_packet = Query(questions=questions, **kwargs)
        options = tuple(self.edns_options) + tuple(extra_edns_options)
        if self.edns_payload_size:
            # RFC 6891 and the practice behind DNS Flag Day: an EDNS-aware
            # requestor advertises OPT on *every* query rather than probing
            # selectively, so the responder never has to guess and the
            # 512-octet truncation regime becomes the fallback rather than
            # the default.
            dns_packet.add_edns(
                self._advertised_payload(ip),
                options=options,
                flags=self._edns_flags,
            )
        else:
            # No OPT record, so nothing can carry an option: RFC 10029 section 3.1's
            # QT list is OPT RDATA, not a section of its own. A bundle asked for under
            # --no-edns therefore degrades to the questions the caller would have sent
            # before this extension existed, and resolve_bundle reports it as
            # unsupported rather than silently reporting an empty combination.
            options = ()
        # RFC 7766 section 6 / RFC 5936: AXFR is a TCP-only operation, and a UDP
        # attempt would be answered with a truncated or refused reply rather
        # than a zone transfer.
        q0 = questions[0] if questions else None
        if force_tcp:
            # The caller chose the transport rather than leaving the choice to
            # this resolver's fallbacks: a stub pointed at a server whose
            # ``transport`` is "tcp" asks over TCP first because that is the
            # configuration it was given, not because UDP failed.
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet, port=port)
        if q0 is not None and getattr(q0, "qtype", None) == DnsQType.AXFR:
            self.log.debug("resolver_force_tcp_axfr(dst=%s id=%s)", ip.exploded, dns_packet.ID)
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet, port=port)

        # RFC 9539 section 4: when the operator has enabled opportunistic
        # encryption of the authority leg, which transport speaks for this
        # address is a policy decision about *X*, not a fixed "UDP first".
        # Both early-outs above outrank the policy -- force_tcp is the
        # caller's own transport choice and AXFR is TCP by definition --
        # and a non-default port is not the cleartext half of the (53, 853)
        # pair the policy is written around. The stub never arrives here
        # with the flag on: its forwarded leg names its transport outright.
        # While an RFC 9461 discovery walk is in flight the policy is off
        # for everything, including this walk's own queries: discovery
        # bootstraps over cleartext -- a nested opportunistic probe could
        # re-enter the very host lock the initiating leg holds (the _dns
        # name lives at the same authority), and an attacker who can lie
        # about _dns records should not be able to steer or stall the
        # probe that was meant to check them.
        if (
            getattr(self, "opportunistic_dot", False)
            and port == 53
            and not getattr(self, "_dot_discovering", False)
        ):
            return await self._query_authority(ip, dns_packet, nameserver_record)
        return await self._query_do53(ip, dns_packet, port=port)

    async def _query_do53(self, ip, dns_packet, port: int = 53):
        """The cleartext half of :meth:`query` -- the ladder the walk has always used.

        Returns the response, or ``None`` when this address said nothing
        usable after every demotion: an EDNS rejection re-asks without the
        OPT (RFC 6891 section 6.2.2), a FORMERR to a well-formed MQTYPE
        query re-asks without the option (RFC 10029 section 3.5), and a
        timeout or TC bit falls through to cleartext TCP (RFC 7766 section
        6.2.1's reuse pool, shared with every other leg). The pending slot
        is registered just before each ``sendto`` and lives until an answer
        matches, a timeout reaps it, or a cancellation pops it -- which is
        also what makes :meth:`_query_authority`'s discard honest: a late
        cleartext answer to a query the encrypted leg already won finds no
        key here and is dropped, the same outcome §4.6.2 of RFC 9539
        prescribes by marking the query "already processed".
        """
        future = asyncio.get_running_loop().create_future()
        key = _pending_key(ip.exploded, dns_packet)
        q0 = dns_packet.questions[0] if dns_packet.questions else None
        self.log.debug(
            "resolver_sendto(dst=%s id=%s q=%s %s %s)",
            ip.exploded,
            dns_packet.ID,
            getattr(q0, "name", ""),
            getattr(getattr(q0, "qtype", None), "name", getattr(q0, "qtype", "")),
            getattr(getattr(q0, "qclass", None), "name", getattr(q0, "qclass", "")),
        )
        if isinstance(ip, ipaddress.IPv6Address):
            # Use IPv6 glue when available.
            if hasattr(self, "_ensure_v6_transport"):
                try:
                    await self._ensure_v6_transport()
                except Exception as exc:
                    # IPv6 glue is an optimisation: without a v6 transport we
                    # simply cannot use a v6 address, and the caller falls back
                    # to the v4 ones. Worth a debug line, not an exception.
                    self.log.debug("resolver_v6_transport_unavailable(err=%s)", type(exc).__name__)
            transport_v6 = getattr(self, "transport_v6", None)
            queue_v6 = getattr(self, "queue_v6", None)
            if transport_v6 is None or queue_v6 is None:
                future.cancel()
                return None
            sendto_addr: tuple
            # On Windows, IPv6 sendto expects the full 4-tuple (host, port, flowinfo, scopeid).
            transport, queue, sendto_addr = transport_v6, queue_v6, (ip.exploded, port, 0, 0)
        elif isinstance(ip, ipaddress.IPv4Address):
            transport, queue, sendto_addr = self.transport, self.queue, (ip.exploded, port)
        else:
            future.cancel()
            return None

        # Three attempts at most, each taken for a different refusal, and each removing
        # one thing the server objected to.
        #
        # The first alternative is the RFC 6891 section 6.2.2 fallback -- "If a
        # requestor detects that the remote end does not support EDNS(0), it MAY issue
        # queries without an OPT record" -- taken only when the answer actually said so
        # (see _edns_rejected).
        #
        # The second is RFC 10029 section 3.5's: "In the above case, or if the server
        # generates a FORMERR response, the client MUST issue additional standalone
        # queries (that is, without using the MQTYPE-Query option) for all QTYPEs for
        # which an answer is still required". A server that FORMERRs a *well-formed*
        # MQTYPE-Query is in breach of RFC 6891 section 6.1.2 ("Any OPTION-CODE values
        # not understood by a responder or requestor MUST be ignored"), but what the
        # document prescribes is asking again without the option rather than punishing
        # the server -- and demotion is the alternative that turns an
        # extension-unfriendly server into a name that stops resolving.
        #
        # The two remedies are mutually exclusive, which is what makes three attempts
        # the worst case rather than a ladder to fall down. A FORMERR *without* an OPT
        # says "no EDNS here" and belongs to _edns_rejected, whose remedy (drop the OPT)
        # drops the option with it; a FORMERR *with* an OPT is section 7's complaint
        # about the contents of the OPT, and with a MQTYPE-Query in flight the option is
        # the thing that was added to it.
        #
        # The pending key cannot shift between attempts: it is built from the
        # transaction ID and the question, and neither retry touches either.
        # The options as this packet actually carries them: rebuilt from the
        # OPT rather than threaded in as a local, because the demotion below
        # edits the packet and must edit the same list it just serialised.
        # A query built under --no-edns has no OPT and so no options, which
        # is also what makes its bundle degrade to plain questions upstream.
        options = tuple(dns_packet.edns_options())
        bundle_in_flight = any(option.code == MQTYPE_QUERY_OPTION_CODE for option in options)
        for attempt in (1, 2, 3):
            if attempt > 1:
                future = asyncio.get_running_loop().create_future()
            queue[key] = (dns_packet, future)
            transport.sendto(bytes(dns_packet), sendto_addr)
            response = await self._await_udp(future, key, dns_packet, ip, queue=queue, port=port)
            if response is not None:
                self._note_server(ip, response)
            if response is None or attempt == 3:
                return response
            if self._edns_rejected(dns_packet, response):
                self.log.debug("resolver_edns_fallback(dst=%s id=%s)", ip.exploded, dns_packet.ID)
                dns_packet.remove_edns()
                bundle_in_flight = False
                continue
            if bundle_in_flight and int(response.extended_rcode) == int(
                DnsResponseCode.FORMAT_ERROR
            ):
                self.log.debug("resolver_mqtype_fallback(dst=%s id=%s)", ip.exploded, dns_packet.ID)
                # EDNS stays: the complaint was about the OPT's contents, and an
                # unextended re-ask would surrender the advertised payload size too.
                dns_packet.remove_edns()
                options = tuple(o for o in options if o.code != MQTYPE_QUERY_OPTION_CODE)
                dns_packet.add_edns(
                    self._advertised_payload(ip),
                    options=options,
                    flags=self._edns_flags,
                )
                bundle_in_flight = False
                continue
            return response
        # Unreachable: attempt 3 always returns above, so the loop is exhaustive by
        # construction. Spelled out so the invariant survives a future edit that might
        # otherwise let a fall-through return a future that was never resolved.
        return None

    #: Cap on the per-server EDNS memos (advertised payload size, NSID). A
    #: resolver walking the delegation tree touches a lot of addresses, and
    #: these are convenience notes rather than state anything depends on: once
    #: a memo reaches a thousand servers, the oldest entries have long stopped
    #: describing a path anyone is still taking.
    _SERVER_MEMO_MAX = 1024

    @property
    def _edns_flags(self) -> int:
        """The OPT FLAGS field for outbound queries: DO when validating, CO
        when asked (RFC 9824 section 5.1¶3 makes CO a promise *under* DNSSEC --
        a compact denial is a signed thing, so the flag travels with DO and
        means nothing without it).
        """
        if not self.dnssec_ok:
            return 0
        flags = EDNS_DO_BIT
        if self.compact_answers:
            flags |= EDNS_CO_BIT
        return flags

    def _advertised_payload(self, ip) -> int:
        """The UDP payload size to advertise to *ip* on this query.

        Starts from :attr:`edns_payload_size` and shrinks it to whatever this
        server has yet said it can receive -- RFC 6891 section 6.2.3 tells a
        requestor to use "their largest configured or implemented values ...
        in the absence of previous knowledge about the destination server",
        which is an instruction to use the smaller number once that knowledge
        exists, and section 6.2.4 treats a responder's advertised size as
        stable enough to be re-used across closely spaced transactions.
        Advertising more than the server will accept buys nothing: it invites
        IP fragmentation, which is the one failure mode section 6.2.3 warns
        "can cause fallback to occur".

        The floor of 512 is applied by :meth:`DnsPacket.add_edns`, so a server
        that advertises something absurd still gets a legal OPT record.
        """
        ours = int(self.edns_payload_size)
        if not ours:
            return 0
        known = getattr(self, "_payload_by_server", None)
        if not known:
            return ours
        theirs = known.get(str(ip))
        return ours if theirs is None else min(ours, theirs)

    def _note_server(self, ip, response) -> None:
        """Record what this answer says about the server that sent it.

        Two things are worth remembering, both learned from the OPT record of
        an extended answer and both keyed by the address we sent to:

        * its advertised UDP payload size (RFC 6891 section 6.2.4), which
          :meth:`_advertised_payload` will honour on the next query;
        * its Name Server Identifier, if we asked for one and it answered
          (RFC 5001 section 1) -- which is how a resolver tracking an anycast
          set or an overloaded pool learns *which* machine replied.

        An answer without an OPT record teaches nothing and changes nothing: a
        server that has fallen back to unextended DNS is still perfectly able
        to receive an EDNS query, and the next one simply re-advertises our
        full size.
        """
        advertised = response.requestor_payload_size
        if advertised is not None:
            # Section 6.2.3: "Values lower than 512 MUST be treated as equal
            # to 512." The responder's number is held to the same reading.
            memo = self._server_memo("_payload_by_server")
            if len(memo) >= self._SERVER_MEMO_MAX:
                memo.clear()
            memo[str(ip)] = max(DnsPacket.EDNS_MINIMUM_PAYLOAD, int(advertised))

        # A malformed option in a *response* is the server's problem, not
        # ours: NSID is what we asked for, so the answer is to ignore it and
        # carry on rather than to fail a lookup that has already succeeded.
        try:
            nsid = nsid_of(response.edns_options())
        except DnsPacketParseError:
            self.log.debug("resolver_nsid_unparsable(src=%s)", ip)
            return
        if nsid is None:
            return
        memo = self._server_memo("_server_ids")
        if len(memo) >= self._SERVER_MEMO_MAX:
            memo.clear()
        if memo.get(str(ip)) != nsid:
            self.log.info("resolver_server_id(dst=%s nsid=%s)", ip, nsid_presentation(nsid))
        memo[str(ip)] = nsid

    def _server_memo(self, attr: str) -> dict:
        """The per-server memo named *attr*, created on first use.

        Created lazily rather than in ``__init__`` because :class:`Resolver`
        is an :class:`asyncio.Protocol` that tests and callers construct
        without arguments, and because a memo defined as a *class* attribute
        would be a single dict shared by every resolver in the process -- one
        resolver would silently inherit what another had learned.
        """
        memo = getattr(self, attr, None)
        if memo is None:
            memo = self.__dict__[attr] = {}
        return memo

    @property
    def server_ids(self) -> dict:
        """Which server answered each way, keyed by the address queried.

        Populated only when NSID was asked for -- see :attr:`edns_options` --
        because a server that has not been invited to identify itself is
        entitled to stay anonymous (RFC 5001 section 2.2). Values are the raw
        octets; :func:`~namespy.edns.nsid_presentation` renders them in the
        hex form section 2.4 requires of any display. A copy is returned: what
        the resolver remembers is its own, and a caller that wants a running
        tally should keep one.
        """
        return dict(self._server_memo("_server_ids"))

    @property
    def server_payload_sizes(self) -> dict:
        """The UDP payload size each server last advertised (RFC 6891, 6.2.4).

        Read this to see what the network will actually carry: a server that
        answers with 512 gets 512 asked of it from here on, which is the
        difference between re-probing a path and learning about it once.
        """
        return dict(self._server_memo("_payload_by_server"))

    @staticmethod
    def _edns_rejected(dns_packet, response) -> bool:
        """True when *response* says the OPT sent in *dns_packet* was not honored.

        RFC 6891 section 7 gives a non-EDNS responder exactly one legal way
        to say so: "Responders that choose not to implement the protocol
        extensions defined in this document MUST respond with a return code
        (RCODE) of FORMERR to messages containing an OPT record in the
        additional section and MUST NOT include an OPT record in the
        response." A FORMERR that *does* carry an OPT is the other event
        section 7 defines -- "a problem with processing the OPT record
        itself ... the response MUST include an OPT record" -- and since the
        OPT built here is empty and machine-generated, treating that as
        non-support would paper over a real protocol event instead of
        reporting it.

        BADVERS (section 6.1.3) rejects the EDNS VERSION rather than the
        mechanism, and NOTIMP is what ossified middleboxes answer an OPT
        query with; both also force the unextended retry, which is the only
        remedy section 6.2.2 offers and is harmless when the answer was
        about something else -- the re-ask gets the same RCODE without EDNS.
        """
        if dns_packet.opt() is None:
            return False
        rcode = int(response.extended_rcode)
        if rcode in (int(DnsResponseCode.BADVERS), int(DnsResponseCode.NOT_IMPLEMENTED)):
            return True
        return rcode == int(DnsResponseCode.FORMAT_ERROR) and response.opt() is None

    async def _await_udp(self, future, key, dns_packet, ip, *, queue=None, port: int = 53):
        """Await one UDP response, retrying over TCP when UDP could not carry it.

        Two outcomes force a TCP retry, and neither is a matter of taste:

        * **Timeout.** UDP may simply be blocked on the path, and RFC 1035
          section 4.2.2 makes TCP the fallback transport for exactly that case.
        * **``TC`` set.** RFC 1123 section 6.1.3.2: "If the Answer section of the
          response is truncated and if the requester supports TCP, it SHOULD try
          the query again using TCP."  Outbound queries advertise EDNS(0), so
          the 512-octet regime of RFC 1035 section 4.2.1 is no longer the
          default -- but truncation stays reachable: servers that ignore
          EDNS, middleboxes that strip OPT, and answers genuinely bigger than
          the advertised payload all still set the bit.

        A truncated response is never returned, even when the TCP retry also
        fails.  RFC 1123 section 6.1.3.2 forbids it outright -- "Truncated
        responses MUST NOT be saved (cached) and later used in such a way that the
        fact that they are truncated is lost" -- and RFC 1035 section 7.4 says a
        resolver which "doesn't know whether it has a complete set ... should not
        cache a possibly partial set of RRs".  Returning ``None`` makes the caller
        demote this nameserver and consult another, which is the right failure
        mode: a single partial answer would otherwise be cached and served to
        every later client as though it were complete.

        RFC 1035 section 6.2 does observe that a server should truncate "at the
        end of the response and work forward in the datagram", so a truncated
        response that still carries an authority section has a complete answer
        section.  Acting on that means trusting the server to implement
        truncation correctly in order to save one TCP exchange; the bit is taken
        at face value instead.

        The pending slot is released on timeout whether or not the retry then
        succeeds, so a late datagram cannot fulfil an abandoned future and the
        slot cannot leak.
        """
        pending = self.queue if queue is None else queue
        version = 6 if isinstance(ip, ipaddress.IPv6Address) else 4
        try:
            response = await asyncio.wait_for(future, timeout=self.query_timeout)
        except TimeoutError:
            pending.pop(key, None)
            self.log.debug(
                "resolver_timeout_udp(dst=%s id=%s ip_version=%d)",
                ip.exploded,
                dns_packet.ID,
                version,
            )
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet, port=port)
        except asyncio.CancelledError:
            # The docstring above promised the slot cannot leak; timeout was
            # covered but cancellation was not, and cancellation is the common
            # case (caller timeout on the outer task, server reconnect, client
            # disconnect). An abandoned future with its key still in `pending`
            # grows the dict for the lifetime of the resolver.
            pending.pop(key, None)
            raise

        if response is not None and response.TC:
            self.log.debug(
                "resolver_truncated_udp(dst=%s id=%s ip_version=%d)",
                ip.exploded,
                dns_packet.ID,
                version,
            )
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet, port=port)
        return response

    async def _query_tcp(self, host, wire, query_packet, port: int = 53):
        """Query over TCP, on a held connection where one is held.

        TCP is reached from three places: a UDP attempt that timed out, a UDP
        response with ``TC`` set (see :meth:`_await_udp`), and zone transfers,
        which are TCP-only (RFC 5936). The timeouts are per-phase rather than one
        budget for the whole exchange, so a server that accepts the connection and
        then stalls cannot hold the lookup open for three times the query timeout.

        The connection is a *session*, not a rite: one per ``(host, port)``,
        held across exchanges, because RFC 7766 section 6.2.1 paragraph 1 asks
        both ends to "support connection reuse by sending multiple queries and
        responses over a single persistent TCP connection" -- the setup RTT the
        same paragraph names as TCP's cost is exactly what this pool pays once
        instead of per lookup. One connection per server is also section 6.2.2
        paragraph 1's "MUST ... minimise the number of concurrent TCP
        connections": the lock makes a second query wait on the session instead
        of opening a rival line. (That document's SHOULD to *pipeline* is left
        unexercised, for the stub's stated reason: with one exchange in flight
        the matching duty of section 6.2.1 paragraph 2 is discharged by ID
        alone, and a resolver's tail latency belongs to its client.) Zone
        transfers are the documented exception -- the same paragraph counts
        them as their own connection -- so an ``AXFR`` query rides a one-shot
        stream that closes when the answer has been read.

        The idle life is RFC 7828's conversation. A response carrying
        edns-tcp-keepalive re-arms the session's timer with the offered
        TIMEOUT, honouring section 3.2.2 paragraph 2 ("SHOULD honour the
        timeout received in that response ... initiate close of the
        connection before the timeout expires"); a TIMEOUT of 0 is paragraph
        3's "send no more queries on that connection", and the session goes
        with it; no option at all rides the conservative default, paragraph
        4's return to RFC 7766 -- where section 6.2.3 leaves the server to
        decide, and this client's 30 seconds is a hold, not a claim. A
        server that closes first is met the way section 6.2.4 paragraph 2
        tells clients to meet it: retry the unanswered query once, invisibly,
        on a fresh connection.

        A response that arrives over TCP with ``TC`` still set is returned as
        it came. RFC 7766 section 8 gives TCP a 65535-octet message field, so
        truncation should not happen, but a server that sets the bit anyway is
        answered honestly rather than silently; :func:`_write_cache` refuses to
        cache it.

        The answer is checked against *query_packet* just as a UDP answer is.
        Point-to-point transport removes the off-path forgery threat that
        RFC 5452 addresses, but not the mundane ones: a middlebox, a stale
        pipelined response, or a server with a broken ID field can all hand
        back something that is not the answer to this question, and silently
        using it would be a wrong answer rather than a failure. On a *shared*
        connection a mismatch also discredits the stream -- a stale response
        in the pipe means the reading position has drifted -- so the session
        is dropped, and a query that had been riding a reused one tries
        again over freshly opened bytes.
        """
        self.log.debug("resolver_tcp_try(dst=%s id=%s)", host, query_packet.ID)
        self.log.debug("resolver_tcp_try(dst=%s id=%s)", host, query_packet.ID)
        q0 = query_packet.questions[0] if query_packet.questions else None
        poolable = getattr(q0, "qtype", None) != DnsQType.AXFR  # 6.2.2 para 1's own line
        sessions = getattr(self, "_tcp_sessions", None)
        if sessions is None:
            sessions = self._tcp_sessions = {}
        key = (host, port)
        for _attempt in (1, 2) if poolable else (1,):
            session = sessions.get(key) if poolable else None
            if session is not None and session.closed:
                self._drop_tcp_session(key, session)  # died idle since it was last held
                session = None
            if session is None:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=self.query_timeout
                    )
                except Exception as e:
                    self.log.debug(
                        "resolver_tcp_connect_failed(dst=%s id=%s err=%s)",
                        host,
                        query_packet.ID,
                        type(e).__name__,
                    )
                    return None
                session = _Session(reader, writer)
                if poolable:
                    sessions[key] = session  # registered now, so a concurrent query waits
                fresh = True
            else:
                fresh = False
            try:
                async with session.lock:
                    if session.closed:
                        # the idle timer (or the server) took the stream while this
                        # call queued -- a network event, not a failure
                        raise ConnectionError("stream ended before its turn")
                    pkt = await self._stream_exchange(
                        session.reader, session.writer, wire, query_packet, host
                    )
                    if pkt is None:
                        raise ConnectionError("server answered something else")
            except Exception as e:
                self.log.debug(
                    "resolver_tcp_failed(dst=%s id=%s err=%s reused=%s)",
                    host,
                    query_packet.ID,
                    type(e).__name__,
                    not fresh,
                )
                self._drop_tcp_session(key, session)
                if fresh or not poolable:
                    return None
                continue  # section 6.2.4 para 2's retry, once, on a fresh stream
            if not poolable:
                session.close_now()
                return pkt
            timeout = keepalive_of(pkt.edns_options())
            if timeout == 0:
                # RFC 7828 section 3.2.2 paragraph 3: send nothing more here.
                self.log.debug("resolver_tcp_keepalive_refused(dst=%s)", host)
                self._drop_tcp_session(key, session)
            else:
                session.arm_idle(_idle_seconds(timeout), asyncio.get_running_loop())
            return pkt
        return None  # unreachable: both attempts return or continue above

    def _drop_tcp_session(self, key, session) -> None:
        """Retire *session*, and only it, from the reuse pool."""
        sessions = getattr(self, "_tcp_sessions", None)
        if sessions is not None and sessions.get(key) is session:
            del sessions[key]
        session.close_now()

    def _close_tcp_sessions(self) -> None:
        """Close every pooled stream; the walk's and a stub's shutdown share this."""
        sessions, self._tcp_sessions = getattr(self, "_tcp_sessions", None), {}
        for session in (sessions or {}).values():
            session.close_now()
        dot, self._dot_sessions = getattr(self, "_dot_sessions", None), {}
        for session in (dot or {}).values():
            session.close_now()

    # ------------------------------------------- RFC 9539: the authority leg,
    # opportunistically encrypted. The policy lives in
    # :mod:`namespy.opportunistic`; these are the hands that act on it.

    def _dot_probe(self, host):
        """This address's Table 2 record, created null as §4.6¶3 demands."""
        probes = getattr(self, "_dot_probes", None)
        if probes is None:
            probes = self._dot_probes = {}
        return probes.setdefault(host, AuthorityProbe())

    def _dot_lock(self, host):
        """One initiation, one exchange at a time per X (§6.2.2's politeness)."""
        locks = getattr(self, "_dot_locks", None)
        if locks is None:
            locks = self._dot_locks = {}
        return locks.setdefault(host, asyncio.Lock())

    async def _dot_endpoint(self, ns_record, host) -> int:  # noqa: ARG002 - seam shape
        """Which port the encrypted leg targets on X: the discovery seam.

        The base answer is RFC 9539's blind one -- §4.4¶2's 853 -- because
        a bare :class:`Resolver` does not walk and so has no way to ask
        ``_dns.<name>`` anything. :class:`RecursiveResolver` overrides
        this with RFC 9461's discovery; the seam exists so the §4.6
        policy never has to know which of the two documents fed it a port,
        and so tests can hand it one directly.
        """
        return self.opportunistic_dot_port

    def _learning(self) -> set:
        """Strong references to background probes the race left running."""
        learning = getattr(self, "_probes_learning", None)
        if learning is None:
            learning = self._probes_learning = set()
        return learning

    def _note_learning(self, task) -> None:
        """A background initiation finished: retire it and land its outcome.

        The set is the strong reference that keeps asyncio from GC-ing an
        unawaited task, so this callback -- registered as the task's own
        done-callback -- is also what releases it; and reading the exception
        back is the other half of the job, because an unretrieved exception
        on a task nobody awaits surfaces as asyncio's "Future exception was
        never retrieved" noise at every damped port. The Table 2 state the
        task wrote is the point of the whole exercise; by this line it is
        already in the probe.
        """
        learning = getattr(self, "_probes_learning", None)
        if learning is not None:
            learning.discard(task)
        if not task.cancelled():
            task.exception()

    @staticmethod
    def _opportunistic_tls_context():
        """The TLS posture §4.6.3.3 and §4.6.3.4 prescribe: no SNI, no trust, ALPN ``dot``.

        ``verify_mode = CERT_NONE`` is section 4.6.3.4's MUST -- "the
        client connecting under this policy MUST accept any certificate
        presented by the server... it MUST NOT reject the connection due
        to the authentication failure, as the result would be falling back
        to cleartext, which would leak the content of the session to a
        passive network monitor." This is the deliberate opposite of the
        stub's RFC 7858 client (:meth:`namespy.stub.StubResolver._dot_initiate`),
        which verifies strictly because its operator chose that named
        server for privacy; here the server is a stranger chosen by a
        delegation, the encryption is a convenience rather than a trust
        claim, and the trust that matters is DNSSEC's. No SNI either:
        section 4.6.3.3 paragraph 4's SHOULD NOT, honoured by simply never
        naming ``server_hostname``. The ALPN offer is section 4.4
        paragraph 2's MUST ("DoT queries... MUST target TCP port 853 using
        an ALPN of 'dot'") -- an offer, not a veto: nothing in 7858 or
        9539 makes a negotiated result other than ``dot`` grounds for
        rejection, and inventing that veto here would be stricter than
        either document.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["dot"])
        return context

    async def _query_authority(self, ip, dns_packet, ns_record=None):
        """The §4.6 decision, and the §4.6¶5 race when both transports may speak.

        The document's bolt-on hooks, expressed in the shapes this resolver
        already has:

        * an established session rides alone (§4.6.3¶1), cleartext silenced
          by §4.6.1¶2's first bullet;
        * a fresh success with no session -- the last connection closed
          cleanly, or a background initiation learned capability without an
          answer -- is the same silence (§4.6.1¶2's second bullet, erratum
          7831's per-protocol persistence), with a new initiation replacing
          the lost session;
        * nothing remembered, or damping elapsed: Do53 and the encrypted
          attempt go out **concurrently** (§4.6¶5's Happy-Eyeballs shape),
          and unlike Happy Eyeballs the loser is not terminated when the
          encrypted leg loses -- §4.6¶5 says so out loud ("they can be
          continued to establish whether the IP address X is capable"), so
          a winning cleartext answer lets the handshake finish in the
          background and fill the table for the next query;
        * damped failure: cleartext alone (§4.6.3¶6 denies initiation,
          §4.6.1 permits Do53);
        * an encrypted failure on a query cleartext was silenced for:
          §4.6.5's bullet list -- "add Q to Do53-queries[X] and send query
          Q to X over Do53" -- the one-line fallback below.

        The "already processed" marking of §4.6.2¶4-¶5 and §4.6.9¶7-¶8
        needs no bookkeeping here, because the cleartext half matches by the
        pending table: the winner's path pops the key, so a loser's late
        answer finds no slot and is dropped by :meth:`datagram_received`
        -- the same instruction, emergent from machinery that predates the
        RFC.
        """
        host = ip.exploded
        loop = asyncio.get_running_loop()
        params = self.opportunistic_params
        probe = self._dot_probe(host)
        probe.consider(loop.time(), params)  # §4.6.3¶3-¶4, before any question
        do53_ok = probe.send_over_do53(loop.time(), params)
        # The encrypted leg speaks when a session can carry the query now,
        # when an initiation is allowed to build one, or while a handshake
        # is already pending -- _dot_query waits on that session rather
        # than racing a second one.
        dot_wanted = (
            probe.ride() or probe.session is not None or probe.may_initiate(loop.time(), params)
        )
        if not dot_wanted:
            return await self._query_do53(ip, dns_packet)  # damped, or policy alone forbade E
        # The port decision belongs to the initiation, not the race: a query
        # riding an established session needs no port and must not pay for a
        # discovery walk, and only _dot_query's initiate branch -- taken
        # under the per-host lock, after a fresh look at the table -- asks.
        # The wire the encrypted leg carries is padded (RFC 9539 §4.6.8.1's
        # SHOULD, sized by RFC 8467 §4.1¶2's 128-octet block); the *packet*
        # stays unpadded, because the cleartext half of the race below reads
        # it and RFC 7830 §6 forbids the option on that wire.
        if self.query_padding:
            wire = bytes(
                dns_packet.padded_clone(QUERY_PAD_BLOCK_OCTETS, self._advertised_payload(ip))
            )
        else:
            wire = bytes(dns_packet)
        if not do53_ok:
            try:
                return await self._dot_query(host, wire, dns_packet, ns_record)
            except OpportunisticError:
                self.log.debug("resolver_opportunistic_fallback(dst=%s)", host)
                return await self._query_do53(ip, dns_packet)  # §4.6.5's "and send over Do53"
        do53_task = asyncio.ensure_future(self._query_do53(ip, dns_packet))
        dot_task = asyncio.ensure_future(self._dot_query(host, wire, dns_packet, ns_record))
        answer = None
        finished = set()
        try:
            pending = {do53_task, dot_task}
            while pending and answer is None:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                finished |= done
                for task in done:
                    answer = self._race_outcome(host, task) or answer
                    if answer is not None:
                        break
            return answer
        finally:
            for loser in (do53_task, dot_task):
                if loser in finished:
                    continue
                if loser is dot_task:
                    # §4.6¶5: keep learning whether X speaks DoT, even
                    # though this query is already answered.
                    self._learning().add(loser)
                    loser.add_done_callback(self._note_learning)
                    if loser.done():
                        # add_done_callback fires only for pending tasks --
                        # one that finished between the race's last wait and
                        # this finally has already had its state land in the
                        # table, and would otherwise sit in the learning set
                        # forever: consume it here and let it go. (Tests
                        # settle on this set; a sticky member is a wall.)
                        self._note_learning(loser)
                else:
                    # Cleartext has nothing to teach: its cancellation pops
                    # the pending slot (_await_udp's CancelledError branch),
                    # so a late answer is dropped as §4.6.2 prescribes.
                    loser.cancel()

    def _race_outcome(self, host, task):
        """One racer's outcome: the answer it brought, or ``None`` for failure."""
        if task.cancelled():
            return None
        error = task.exception()
        if error is not None:
            self.log.debug(
                "resolver_opportunistic_leg_failed(dst=%s err=%s)", host, type(error).__name__
            )
            return None
        return task.result()

    async def _dot_query(self, host, wire, query_packet, ns_record=None):
        """One query over X's DoT session, building it if the table says to.

        Raises :class:`~namespy.opportunistic.OpportunisticError` with the
        probe already updated, so the racer or the §4.6.5 fallback never
        has to repeat the failure taxonomy: handshake refusals and stalls
        are §4.6.5's fail (damped), a session that dies mid-exchange is
        §4.6.6's established-then-broken fail (also damped -- an authority
        that takes queries and then stops answering them is exactly the
        "unreachable or firewalling" server §4.2¶4 warns the timeout away
        from), and a clean EOF is §4.6.7's shutdown, which deliberately
        does *not* damp: status survives so the next query retries
        promptly, this one falls back. A mismatched answer gets the
        fail-damp too: §4.6.9¶12 hands malformed or wrong answers to "the
        resolver's policy for unresponsive or non-compliant authoritative
        servers", and treating a stream that answers other people's
        questions as trustworthy is compliant with nothing.
        """
        params = self.opportunistic_params
        loop = asyncio.get_running_loop()
        probe = self._dot_probe(host)
        async with self._dot_lock(host):
            probe.consider(loop.time(), params)  # truth may have aged while queued
            session = probe.session
            if session is None:
                if not probe.may_initiate(loop.time(), params):
                    raise OpportunisticError(f"{host}: initiation not allowed")
                # The port is chosen here, under the lock and after the
                # table has said *initiate*: a second query waiting on this
                # lock may find the session built and never ask at all, and
                # a discovery walk while this lock is held cannot re-enter
                # _dot_query for X -- the query() hook bows out during
                # discovery (the _dot_discovering flag), which is what
                # keeps a _dns lookup about X from deadlocking on X.
                port = await self._dot_endpoint(ns_record, host)
                session = await self._dot_initiate(host, probe, params, port)
            elif not probe.session_established:
                # Pending, and we hold the lock: the initiation that set it
                # is gone (cancelled mid-handshake, its owner's task torn
                # down). §4.6.3¶4's timer may not have matured yet, but a
                # half-dead session is not worth waiting for.
                probe.note_closed()
                raise OpportunisticError(f"{host}: session abandoned")
            probe.note_activity(loop.time())  # §4.6.8¶2
            try:
                pkt = await self._stream_exchange(
                    session.reader, session.writer, wire, query_packet, host
                )
            except TimeoutError:
                probe.note_failed(loop.time(), timed_out=True)
                self._drop_dot_session(probe, session)
                raise OpportunisticError(f"{host}: session stalled") from None
            except DnsPacketParseError:
                # A malformed answer desyncs a length-prefixed stream as
                # surely as a mismatch does -- §4.6.9¶12's "malformed or a
                # failure", same reading-position logic as the cleartext
                # pool -- so the session goes with it, damped.
                probe.note_failed(loop.time())
                self._drop_dot_session(probe, session)
                raise OpportunisticError(f"{host}: malformed answer") from None
            except Exception as exc:
                self.log.debug(
                    "resolver_opportunistic_closed(dst=%s err=%s)", host, type(exc).__name__
                )
                probe.note_closed()  # §4.6.7: status survives, retry promptly
                self._drop_dot_session(probe, session)
                raise OpportunisticError(f"{host}: session died") from None
            if pkt is None:
                probe.note_failed(loop.time())
                self._drop_dot_session(probe, session)
                raise OpportunisticError(f"{host}: answered something else")
            probe.note_response(loop.time())  # §4.6.9¶6
            self._arm_dot_idle(host, probe, session, pkt)
            self.log.debug("resolver_opportunistic_ok(dst=%s id=%s)", host, pkt.ID)
            return pkt

    def _arm_dot_idle(self, host, probe, session, pkt) -> None:
        """§7828 on the authority leg: honour the offered TIMEOUT, 0 included.

        An authority that answers with keepalive 0 is saying this
        connection holds nothing (§3.2.2¶3) -- the close is §4.6.7's shape
        (status survives, next query initiates fresh), not a failure.
        """
        timeout = keepalive_of(pkt.edns_options())
        if timeout == 0:
            self.log.debug("resolver_opportunistic_keepalive_refused(dst=%s)", host)
            probe.note_closed()
            self._drop_dot_session(probe, session)
        else:
            session.arm_idle(_idle_seconds(timeout), asyncio.get_running_loop())

    async def _dot_initiate(self, host, probe, params, port):
        """One §4.6.3 initiation: the marker first, the handshake, then the truth."""
        loop = asyncio.get_running_loop()
        probe.note_initiating(loop.time(), _HANDSHAKE_PENDING)  # §4.6.3¶9
        try:
            reader, writer = await asyncio.wait_for(
                # server_hostname=None is the whole of §4.6.3.3¶4's SHOULD NOT:
                # leaving it out would make open_connection volunteer the
                # connect address as SNI, which is exactly the leakage the
                # section names.
                asyncio.open_connection(
                    host,
                    port,
                    ssl=self._opportunistic_tls_context(),
                    server_hostname=None,
                ),
                timeout=params.timeout,
            )
        except TimeoutError:
            probe.note_failed(loop.time(), timed_out=True)  # E-timeout, Table 1
            raise OpportunisticError(f"{host}: handshake timeout") from None
        except Exception as exc:
            self.log.debug(
                "resolver_opportunistic_handshake_failed(dst=%s err=%s)",
                host,
                type(exc).__name__,
            )
            probe.note_failed(loop.time())  # §4.6.5: refused, alerted, gone
            raise OpportunisticError(f"{host}: handshake failed") from None
        tls = writer.get_extra_info("ssl_object")
        negotiated = tls.selected_alpn_protocol() if tls is not None else None
        self.log.debug("resolver_opportunistic_handshake(dst=%s alpn=%s)", host, negotiated or "-")
        session = _Session(reader, writer)
        sessions = getattr(self, "_dot_sessions", None)
        if sessions is None:
            sessions = self._dot_sessions = {}
        sessions[host] = session
        probe.session = session
        probe.note_established(loop.time())  # §4.6.4: status and clocks, all at once
        session.arm_idle(_KEEPALIVE_DEFAULT_S, loop)  # until the server's number says otherwise
        return session

    def _drop_dot_session(self, probe, session) -> None:
        """Unlink *session* from the host map and close it; the probe note is the caller's."""
        sessions = getattr(self, "_dot_sessions", None)
        if sessions is not None:
            for host, held in list(sessions.items()):
                if held is session:
                    del sessions[host]
        if probe.session is session:
            probe.session = None
            probe.session_established = False
        session.close_now()

    async def _stream_exchange(self, reader, writer, wire, query_packet, host):
        """One length-prefixed exchange on an already-open stream.

        RFC 1035 section 4.2.2's two-octet framing, with the prefix and the
        message written in a single call: RFC 7766 section 8 and RFC 7828
        section 3.3 paragraph 1 both ask for one TCP segment rather than a
        two-segment message whose first octet a network could, in principle,
        deliver alone. The answer is checked against *query_packet* exactly
        as a UDP answer is -- RFC 7828 section 3.3 paragraph 3 states the
        matching duty for shared connections, and even on a connection used
        once a middlebox, a stale pipelined response or a broken ID field can
        hand back something that is not the answer to this question.

        The caller owns the stream and its teardown; this method only reads
        and writes, raising whatever the transport raises (or returning
        ``None`` for an answer that fails matching) for the caller to turn
        into its own failure path.
        """
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        nbuf = await asyncio.wait_for(reader.readexactly(2), timeout=self.query_timeout)
        (n,) = struct.unpack("!H", nbuf)
        data = await asyncio.wait_for(reader.readexactly(n), timeout=self.query_timeout)
        (pkt, _off) = DnsPacket.parse(data)
        if int(pkt.ID) != int(query_packet.ID) or not _is_expected_response(
            query_packet, pkt, host
        ):
            self.log.warning("resolver_tcp_response_mismatch(dst=%s id=%s)", host, pkt.ID)
            return None
        self.log.debug(
            "resolver_tcp_ok(dst=%s id=%s rcvd_len=%d)", host, getattr(pkt, "ID", -1), len(data)
        )
        return pkt

    # -- the UDP receive plumbing. On the base, not on :class:`RecursiveResolver`,
    # because :meth:`query` above is written against it and a stub resolver (see
    # :mod:`namespy.stub`) drives the very same send path: one socket, one
    # pending-question table, one answer-matching rule, whoever is asking.

    def connection_made(self, transport):
        self.transport = transport
        enable_path_mtu_discovery(transport, self.log)
        # Start bringing up an IPv6 UDP transport in the background so IPv6
        # destinations can be used when the IPv4 path is what is unreachable
        # (for the walk, AAAA glue; for a stub, an upstream that is v6-only).
        try:
            loop = asyncio.get_running_loop()
            if self._v6_ready is None:
                self._v6_ready = loop.create_task(self._ensure_v6_transport())
        except RuntimeError:
            # No running loop (should not happen in normal asyncio usage).
            pass

    async def _ensure_v6_transport(self):
        if self.transport_v6 is not None:
            return self.transport_v6

        parent = self

        class _V6Shim(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                parent.transport_v6 = transport

            def datagram_received(self, data, addr):
                parent._datagram_received_v6(data, addr)

            def error_received(self, exc):
                parent.error_received(exc)

        loop = asyncio.get_running_loop()
        try:
            transport, _proto = await loop.create_datagram_endpoint(
                lambda: _V6Shim(),
                local_addr=("::", 0),
                family=socket.AF_INET6,
            )
            self.transport_v6 = transport
            self.log.debug("resolver_v6_ready(sockname=%s)", transport.get_extra_info("sockname"))
            return transport
        except Exception as e:
            self.log.debug("resolver_v6_failed(err=%s)", type(e).__name__)
            self.transport_v6 = None
            return None

    def _datagram_received_v6(self, data, addr):
        try:
            dns_packet, _offset = DnsPacket.parse(data)
        except DnsPacketParseError:
            # Same policy as the IPv4 path: a malformed datagram is discarded
            # quietly at debug level, since an attacker who can send us garbage
            # should not be able to use our log as an amplifier.
            self.log.debug("resolver_v6_parse_failed(len=%d)", len(data))
            return

        host = addr[0]
        key = _pending_key(host, dns_packet)
        entry = self.queue_v6.get(key)
        if entry is None:
            self.log.debug("resolver_v6_unexpected_packet(src=%s id=%s)", host, dns_packet.ID)
            return

        query_packet, future = entry
        del self.queue_v6[key]
        if not _is_expected_response(query_packet, dns_packet, host):
            self.log.warning("resolver_v6_response_mismatch(src=%s id=%s)", host, dns_packet.ID)
            return
        if not future.done():
            future.set_result(dns_packet)

    def datagram_received(self, data, addr):
        try:
            (dns_packet, _offset) = DnsPacket.parse(data)
        except DnsPacketParseError as e:
            # Debug, not warning: this is the attacker-controlled path, and a
            # warning with a hex dump per datagram is a free log-flood
            # primitive. The v6 path and server.py already stay quiet; this
            # was the last loud one.
            self.log.debug(
                "resolver_parse_failed(err=%s offset=%s len=%d hex=%s)",
                e,
                e.offset,
                len(e.data),
                e.wire_hex(),
            )
            return

        self.log.debug("resolver_datagram_received(packet=%s, addr=%s)", dns_packet, addr)
        host = addr[0]
        entry = self.queue.get(_pending_key(host, dns_packet))
        if entry is None:
            # Nothing asked this server for this (name, type, class) under this
            # ID. Either it is late, duplicated, or forged; all three are handled
            # the same way -- discard.
            self.log.debug("resolver_unexpected_packet(src=%s id=%s)", host, dns_packet.ID)
            return

        query_packet, future = entry
        del self.queue[_pending_key(host, dns_packet)]
        if not _is_expected_response(query_packet, dns_packet, host):
            self.log.warning("resolver_response_mismatch(src=%s id=%s)", host, dns_packet.ID)
            return
        # The future may already be cancelled if the per-query timeout fired
        # before this late response arrived; ignore that race rather than
        # propagating InvalidStateError out of the protocol callback.
        if not future.done():
            future.set_result(dns_packet)


# RFC 1034 §5.3.2 resolver state.
#
# Sname  — the search name, plus QTYPE/QCLASS, plus a `.questions` list ready
#          to drop into a query.
# SlistEntry — one (zone, NS, addresses, history) row.
# Slist  — ordered candidate list for the current zone-cut.
# Sbelt  — safety-belt list seeded from named.root.


class Sname:
    def __init__(self, qname, qtype=DnsQType.A, qclass=DnsRClass.IN):
        if not isinstance(qname, DomainName):
            qname = DomainName(str(qname))
        try:
            qtype = DnsQType(qtype)
        except ValueError:
            pass
        try:
            qclass = DnsRClass(qclass)
        except ValueError:
            pass
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass
        self.questions = [DnsQuestion(qname, qtype, qclass)]

    @classmethod
    def from_question(cls, question):
        return cls(question.name, question.qtype, question.qclass)

    def reanchor(self, qname):
        """Re-root this search name at ``qname``, keeping QTYPE and QCLASS.

        This is RFC 1034 §5.3.3 step 4c: "if the answer contains a CNAME RR, set
        SNAME to the contents of the RDATA field of the displayed CNAME RR, and
        go to step 2". Mutating in place rather than building a new Sname keeps
        every holder of this object -- the driver, the trace, the caller --
        looking at the same search state, which is what the spec's "set SNAME"
        implies.

        QTYPE deliberately survives the redirect: an A query for an aliased name
        becomes an A query for the target, and only the target's RRset can end
        the lookup.
        """
        if not isinstance(qname, DomainName):
            qname = DomainName(str(qname))
        self.qname = qname
        self.questions = [DnsQuestion(qname, self.qtype, self.qclass)]
        return self

    def match_count(self, zone):
        """Number of labels this search name shares with ``zone``, from the root.

        Implements the §5.3.3 step 4b "closer" test that decides whether an
        authority section is a genuine referral.

        Compared over raw labels via :meth:`DomainName._labels` rather than by
        splitting presentation text on ``.``: an escaped label
        (``evil\\.example.com``, or any label containing a dot, which RFC 2181
        §11 permits) previously split into extra "labels" and inflated the count,
        which is exactly the value an attacker needs to make a bogus referral look
        closer than the current zone.
        """
        if not isinstance(zone, DomainName):
            zone = DomainName(str(zone))
        mine = self.qname._labels()
        theirs = zone._labels()
        shared = 0
        for left, right in zip(reversed(mine), reversed(theirs), strict=False):
            if left != right:
                break
            shared += 1
        return shared

    def __repr__(self):
        return f"<Sname {self.qname} {self.qtype} {self.qclass}>"


class SlistEntry:
    def __init__(self, zone, ns, addresses=None):
        self.zone = zone
        self.ns = ns
        self.addresses = list(addresses or [])
        self.history = {"sent": 0, "received": 0, "demoted": False}

    def __repr__(self):
        return (
            f"<SlistEntry zone={self.zone!r} ns={self.ns!r}"
            f" addrs={len(self.addresses)} demoted={self.history['demoted']}>"
        )


class Slist:
    def __init__(self, sname, entries=None):
        self.sname = sname
        self.entries = list(entries or [])
        self.zone = DomainName(".")
        self.match = 0

    def best(self):
        glued = next(
            (e for e in self.entries if not e.history["demoted"] and e.addresses),
            None,
        )
        if glued is not None:
            return glued
        return next(
            (e for e in self.entries if not e.history["demoted"]),
            None,
        )

    def demote(self, entry):
        if entry is not None:
            entry.history["demoted"] = True

    def __repr__(self):
        return f"<Slist zone={self.zone!r} match={self.match} entries={len(self.entries)}>"


class Sbelt(Slist):
    @classmethod
    def from_response(cls, response):
        sb = cls(sname=None)
        sb.zone = DomainName(".")
        sb.match = 0
        if response is None:
            return sb
        for ns in response.nameservers:
            if ns.rtype != DnsRType.NS:
                continue
            ns_target = ns.rdata
            addresses = []
            for ar in response.additional_records:
                if ar.name == ns_target and ar.rtype in (DnsRType.A, DnsRType.AAAA):
                    ip = _answer_address(ar)
                    if ip is not None:
                        addresses.append(ip)
            sb.entries.append(SlistEntry(DomainName("."), ns_target, addresses))
        return sb

    def copy_for(self, sname):
        s = Slist(sname)
        s.zone = DomainName(".")
        s.match = sname.match_count(s.zone) if sname is not None else 0
        s.entries = [self._copy_entry(e) for e in self.entries]
        random.shuffle(s.entries)
        return s

    @staticmethod
    def _copy_entry(entry):
        """Clone an entry, carrying the structural lame marker but not liveness.

        Two different things live in ``history``. ``lame`` is a property of the
        delegation itself -- an in-bailiwick nameserver with no glue is
        unreachable no matter how many times it is retried -- so it must survive,
        otherwise each copy restarts the descent the demotion exists to prevent.
        ``demoted`` from a timeout, by contrast, is an observation about one
        attempt; propagating it would let a single dropped packet retire a root
        server for the lifetime of the resolver, which is why real resolvers use
        backoff instead of permanent exclusion. RFC 1034 section 5.3.3 step 3
        is the ancestor of that: "cycle around all of the addresses for all of
        the servers with a timeout between each transmission", with SLIST
        entries carrying the timeout state.
        """
        clone = SlistEntry(entry.zone, entry.ns, list(entry.addresses))
        lame = entry.history.get("lame")
        if lame:
            clone.history["lame"] = lame
            clone.history["demoted"] = True
        return clone


def _interleave_families(addresses):
    """One entry's addresses, ordered so each family gets its turn before the
    next entry of the family that led.

    RFC 10001 §4.2¶1 asks every recursive resolver to be dual-stack, and §3.2
    describes exactly the condition that makes the order matter: a network
    fault that blacks out one address family while leaving the other up. The
    glue a delegation carries arrives in whatever order the zone's author
    wrote it (§4.1¶2's complaint is about a delegation missing a family
    altogether, which no resolver can fix), and a plain sequential cycle lets
    one family's timeout run out *every* address before the other family is
    consulted -- the walk is dual-stack in the socket and monostack in the
    attempt order this code had until now. Interleaving bounds the damage: a
    black-holed family costs one timeout, not every timeout it owns.

    Deliberately stateless. §4.2 asks the resolver to keep both families in
    play, not to learn a preference between them, and RFC 6724's destination-
    address sorting -- the one document that ranks families -- is §4.3's
    guidance for *stub* resolvers, not for this walk. The order starts with
    whichever family the glue itself leads with, so nothing is biased away
    from what the delegation said; addresses that are neither 4 nor 16 octets
    (a hand-seeded belt's malformed entry) keep their place at the end for
    the caller to skip, rather than being silently dropped here too.
    """
    fours, sixes, others = [], [], []
    first_family = None
    for address in addresses:
        packed = getattr(address, "packed", None)
        if packed is None:
            try:
                packed = bytes(address)
            except (TypeError, ValueError):
                others.append(address)
                continue
        if len(packed) == 4:
            fours.append(address)
            if first_family is None:
                first_family = 4
        elif len(packed) == 16:
            sixes.append(address)
            if first_family is None:
                first_family = 6
        else:
            others.append(address)
    primary, secondary = (sixes, fours) if first_family == 6 else (fours, sixes)
    interleaved = []
    for index in range(max(len(primary), len(secondary))):
        if index < len(primary):
            interleaved.append(primary[index])
        if index < len(secondary):
            interleaved.append(secondary[index])
    return interleaved + others


# Effect / step / trace event types.
#
# A `resolve_steps` generator yields one of these each time it needs the
# driver to do something (SendQuery, NeedAddress) or just wants to record a
# decision (Referral, Answer, Nodata, …). The driver records every yield into
# a Trace, then either fulfills the effect or moves on.


@dataclass(frozen=True)
class SendQuery:
    """Ask the driver to send *questions* to *entry* and hand back the reply.

    The one effect that performs I/O. Corresponds to RFC 1034 section 5.3.3
    step 3 ("query a name server that is further authoritative"), and is also
    how a glueless NS gets its address resolved.
    """

    entry: SlistEntry
    questions: list
    #: True when *questions* is a QNAME-minimisation probe rather than the
    #: real question (RFC 9156 section 3 step 2). Trace rendering marks these
    #: so a reader can tell a probe from a resolution step.
    probe: bool = False
    #: Extra QTYPEs to ask for alongside *questions* in a MQTYPE-Query option
    #: (RFC 10029 section 3.1); empty is the ordinary single-type query.
    #:
    #: It rides on the effect rather than living on the resolver because the option
    #: belongs to one question and not to every query a lookup happens to send. A glue
    #: sub-resolution asks for a nameserver's address; bundling the user's HTTPS and
    #: AAAA into *that* would request another name's data under the wrong name, and a
    #: minimisation probe asks for a shorter child name whose answer says nothing about
    #: the extras' RRsets. Both build their own SendQuery, and neither passes this on.
    extra_qtypes: tuple = ()
    #: True for a DNSSEC chain query -- the DS or DNSKEY a validation needs and the
    #: walk did not already receive (RFC 4035 section 5.2 para 6 makes querying the
    #: parent for an absent DS a MUST). The question is ordinary and the answer is
    #: fed to no cache; the flag exists so a trace can tell a chain fetch from a
    #: resolution step, for the same reason ``probe`` does: a reader counting queries
    #: should be able to count them *by purpose*.
    helper: bool = False
    #: EDNS(0) options belonging to *this* query alone, appended after the
    #: resolver's instance-wide ones. The key tag list of RFC 8145 is the tenant:
    #: §4.2¶2 ties the edns-key-tag option to one question type -- "MUST NOT
    #: include ... for non-DNSKEY queries" -- so a resolver-wide setting could
    #: only either leak the option onto every query or never send it, and both
    #: answers are wrong. The same per-question logic that keeps ``extra_qtypes``
    #: off glue sub-walks and minimisation probes keeps this off them too: those
    #: questions are the walk's own, not the client's.
    extra_edns_options: tuple = ()


@dataclass(frozen=True)
class NeedAddress:
    """The driver must resolve *ns_name* to an address before it can be queried.

    Raised for a glueless NS -- one whose name appears in the authority section
    but whose address did not. Glue is only mandatory for servers *below* the
    cut (RFC 1034 section 4.2.1), and a server outside it is legitimate, not
    lame (RFC 1034 section 4.2.2), so the address has to be chased elsewhere:
    RFC 1034 section 5.3.3 step 2, "the best is to start parallel resolver
    processes looking for the addresses while continuing onward".
    """

    ns_name: DomainName


@dataclass(frozen=True)
class Referral:
    """Slist descended from *old_zone* to *new_zone*.

    *match_before* and *match_after* are label counts matched before and after,
    which is how a trace shows progress. Equal counts mean a referral that did
    not advance, which the algorithm treats as a loop.
    """

    old_zone: DomainName
    new_zone: DomainName
    match_before: int
    match_after: int


@dataclass(frozen=True)
class Answer:
    """The answer section holds RRs of the requested type -- RFC 1034 section 5.3.3(a)."""

    #: Accepts any sequence, since callers naturally hold a list; the value is
    #: always stored as a tuple (see __post_init__), so declaring the narrow
    #: type would contradict the constructor.
    records: Sequence

    def __post_init__(self):
        # Freeze the sequence: these events are recorded in a Trace and read
        # back after the response that produced them is gone, so a caller
        # mutating the list it passed in must not rewrite history.
        object.__setattr__(self, "records", tuple(self.records))


@dataclass(frozen=True)
class Nodata:
    """The name exists but has no RR of the requested type.

    The SOA is carried because RFC 2308 section 5 makes it the source of the
    negative TTL, and because distinguishing this from a referral depends on
    the authority section holding SOA rather than NS (RFC 2308 section 2.2.1).
    """

    soa: object


@dataclass(frozen=True)
class Nxdomain:
    """The name does not exist -- RFC 1034 section 5.3.3(b), RFC 2308 section 3."""


@dataclass(frozen=True)
class NxdomainCut:
    """A cached denial at or above this name answered for it, without asking (RFC 8020 §2).

    *denied_by* is the name whose NXDOMAIN did it, and the pair is the whole
    point of the event. Nothing in RFC 8020 asks for this to be reported -- §2 is
    only about the answer -- but it is reported anyway, because the alternative is
    an operator debugging a denial whose cause is nowhere in the reply: what the
    response carries is the *ancestor's* SOA (Appendix A: "The accompanying SOA
    record indicates the apex of the zone, not the closest existing domain name")
    beside a question naming the deeper name, so a trace line is the only place
    the two names appear together. The reader this is for is the one §5¶1
    describes -- the administrator whose internal machines live under a name the
    TLD has already denied.
    """

    name: str
    denied_by: str


@dataclass(frozen=True)
class CompactDenial:
    """A validated denial arrived as a Compact Answer -- its signed proof asserting
    NXNAME at the queried name (RFC 9824 §2¶3).

    Reported for the same reason :class:`NxdomainCut` is: what the packet says and
    what happened are separable here. *restored* is the §5.1 case -- the zone
    carried an NXDOMAIN RCODE because this resolver asked with CO and the server
    implements the signaling; when it is False the RCODE stayed NOERROR and only
    the signed bit says the name is gone (§5¶2's tools-and-bits problem, §8¶3's
    note that the signed body is the more secure half). Either way the walk
    records the denial name-level only: §6¶3 forbids both the RFC 8020 cut and
    the RFC 8198 synthesis the ordinary shapes earn, because a compact record
    proves one name and its span proves nothing around it.
    """

    name: str
    restored: bool


@dataclass(frozen=True)
class AggressiveDenial:
    """A cached, validated proof denied this name and the resolver wrote the answer (RFC 8198 §5).

    The entry's name and the answer's kind are reported because the synthesised
    packet is otherwise indistinguishable from a fetched one -- same RCODE, same
    authority shape -- while the entry whose bundle proves the answer can carry
    an unrelated name *and* an unrelated RCODE: the denial cached for ``aaa``
    synthesises ``dog``'s NXDOMAIN, the one cached for ``www AAAA`` synthesises
    ``www TXT``'s NODATA. The trace line is the only place the evidence and the
    inference appear together, which is the same reason :class:`NxdomainCut`
    exists and reads more sharply here: with the cut, at least the denying name
    is an ancestor; here it need not be related to the queried name at all.
    """

    name: str
    proven_by: str
    kind: str


@dataclass(frozen=True)
class WildcardSynthesis:
    """A cached wildcard answered this name, and the closer-match proof vouched (RFC 8198 §5.3).

    The positive sibling of :class:`AggressiveDenial`, and harder to see from
    the packet alone: a synthesised answer is byte-honest -- the authority's
    own records and signature, the Labels field carrying the match's proof --
    yet no query revealed the name. The event names the template the answer
    was expanded from, which is where an operator tracing "why does this name
    exist in my cache and not on any wire" will look first, and the only place
    the walk says so.
    """

    name: str
    via: str


@dataclass(frozen=True)
class ServeStale:
    """An expired entry answered because the refresh failed (RFC 8767).

    The one answer this resolver gives from data it cannot currently call
    authentic: the record's TTL ran out, every server that could refresh it
    failed, and §4's amended TTL definition allows the use anyway -- "if the
    data is unable to be authoritatively refreshed when the TTL expires, the
    record MAY be used as though it is unexpired." *age* is how long the data
    has been expired, because that is the number an operator weighing
    resiliency against staleness asks for. The event always carries the
    reason two sections care about: never AD (the claim is present tense and
    this data's verdict is past), and RFC 8914 §4.2's Stale Answer EDE on the
    wire to clients that read extended errors.
    """

    name: str
    age: int


@dataclass(frozen=True)
class DnssecVerdict:
    """The validation layer's answer about a denial this lookup just received.

    *status* is one of the RFC 4035 §4.3 states and *reason* the sentence that
    explains it; *zone* is the apex whose keys the chain ended at. The event is
    emitted only when the resolver has trust anchors configured, and it precedes
    the ``Nxdomain``/``Nodata`` it judged, because that ordering is the argument:
    "secure, therefore this NXDOMAIN may cut" (RFC 8020 §2¶3) or "insecure,
    therefore it proves nothing" -- a verdict printed after the answer reads like
    a comment on it rather than the reason for it.
    """

    zone: str
    status: str
    reason: str


@dataclass(frozen=True)
class ChainFromCache:
    """A chain fetch the verdict demanded was answered by the cache, not the wire.

    RFC 4035 §4.5's atomic-entry rule makes a validated chain record cacheable
    like any other answer, and the walk files its DNSKEY and DS material under
    a secure verdict precisely so the next lookup's §5.2¶6 fetches have
    somewhere to land. The event reports what is otherwise an absence: a hint
    satisfied without a :class:`SendQuery`, invisible in the trace and
    indistinguishable in the answer. Naming the zone and type says which chain
    leg the cache carried, which is the fact an operator comparing two walks'
    query counts needs.
    """

    name: str
    qtype: str
    zone: str


@dataclass(frozen=True)
class Cname:
    """An alias was encountered; *target* must be re-anchored as the new SNAME.

    RFC 1034 section 5.3.3 requires the lookup to continue at the CNAME's
    target rather than returning it, and RFC 6672 section 2.3 adds the DNAME
    case where a synthesized name replaces the alias outright.
    """

    target: DomainName


@dataclass(frozen=True)
class Demote:
    """*entry* is being marked unusable, for *reason*.

    A demotion is a ranking change within the current Slist, not a deletion
    from the name space: RFC 1034 section 5.3.3 step 3 cycles "around all of
    the addresses for all of the servers", and step 4d removes a server from
    SLIST only for the current query, never from the cache.
    """

    entry: SlistEntry | None
    reason: str


@dataclass(frozen=True)
class VolunteeredGlue:
    """A responder offered address RDATA for *ns_name*, and the policy decided it.

    Emitted whenever a referral carries A/AAAA RDATA for a nameserver name the
    answering zone is not authoritative for. Under :attr:`GluePolicy.STRICT` (the
    default) it records what was **discarded**; under
    :attr:`GluePolicy.PERMISSIVE`, what was **used**. This is the research
    surface: the address a delegation volunteered is the datum a cache-poisoning
    analysis is about, and before this event existed the evidence was destroyed
    inside ``classify`` with only the bare fact of the discard left in
    ``entry.history``.

    Nothing is recorded here on clean traffic -- a zone that ships correct glue
    for its own nameservers produces no event at all, so a trace full of these is
    itself the measurement.

    *records* is the evidence as it arrived (an RR that does not decode to an
    address is still evidence that something was offered); *addresses* is what it
    decodes to, which is exactly where the next query would be sent.
    """

    ns_name: DomainName
    records: tuple
    addresses: tuple
    #: False when the policy refused the addresses, True when it believed them.
    used: bool
    reason: str

    def __post_init__(self):
        # Frozen like `Answer`: these are recorded in a Trace and read back long
        # after the response that produced them is gone.
        object.__setattr__(self, "records", tuple(self.records))
        object.__setattr__(self, "addresses", tuple(self.addresses))


@dataclass(frozen=True)
class Done:
    """Resolution finished; *response* is the answer to hand back."""

    response: object


@dataclass(frozen=True)
class Fail:
    """No answer can be produced; *reason* is for the trace and the log."""

    reason: str


def _answer_address(record):
    """The address in an ``A``/``AAAA`` answer, or ``None`` for anything else.

    Re-runs the codec over the record's wire octets rather than trusting
    ``record.rdata`` to already be an :class:`~namespy.rdata.RData_A`, because a
    caller may have built the record by hand with a bare :class:`bytes` or a
    :class:`~namespy.names.DomainName`. A malformed address yields "no address"
    here instead of raising inside a resolution loop: one bad glue record must
    not abort the lookup that happened to receive it.
    """
    rtype = int(record.rtype)
    if rtype not in (int(DnsRType.A), int(DnsRType.AAAA)):
        return None
    try:
        codec = RData_A if rtype == int(DnsRType.A) else RData_AAAA
        return codec(bytes(record.rdata)).ip
    except (DnsPacketParseError, ValueError):
        return None


def _canonical_address(host) -> str:
    """An address in the one text form both sides of a lookup can agree on.

    Needed because the two sides do not naturally produce the same string. On
    send we hold an :class:`ipaddress.IPv6Address` and tend to use ``.exploded``;
    what a socket reports as a sender comes from the OS and Python renders in
    *compressed* form. ``2001:db8:0:0:0:0:0:53`` and ``2001:db8::53`` are the same
    server and would never compare equal as text -- which silently made every
    IPv6 response miss its pending query, so an IPv6 lookup always timed out.
    IPv4 is unaffected, where the two forms coincide.

    Anything that does not parse as an address is returned unchanged, so a caller
    passing an already-canonical string, or a hostname, still gets a stable key.
    """
    text = str(host)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _pending_key(dst, packet):
    """The identity a response must match for us to accept it as *the* answer.

    Keyed on destination address, transaction ID, **and the question**, not just
    address and ID. RFC 5452 section 9.1 is the reason: it tells a client to
    match a response against source address, destination address, destination
    port, ID, QNAME, QCLASS and QTYPE before crediting it to a query. The ID on
    its own is 16 bits, and sections 5 and 7 of that document are the birthday
    arithmetic that makes it brute-forceable by an off-path sender, whereas a
    response must also reproduce the QNAME, QTYPE and QCLASS we asked about
    before it can be taken for an answer. That turns a 65k-guess problem into one
    that also requires knowing the name being resolved, and it is the difference
    between a resolver that can be poisoned by a stray or forged packet and one
    that cannot.

    The source and destination ports are not in the key because they are not free
    to vary here: the response arrives on the socket the query left from, so the
    transport already enforced RFC 5452 section 4.5 for us, and only the peer
    address is ours to check.

    The key is derived from whichever packet it is handed, so the same function
    serves both sides: the outgoing query registers under it, and an incoming
    response is looked up by it. A response that omits the question section
    entirely therefore never matches -- which is the intended strictness. RFC 1035
    section 4.1 says the question section "MUST be present in any DNS query or
    DNS response message", and RFC 5452 sections 4.2 and 9.1 tell a client to
    verify it rather than assume it.
    """
    question = packet.questions[0] if packet.questions else None
    address = _canonical_address(dst)
    if question is None:
        return (address, int(packet.ID), None, None, None)
    return (
        address,
        int(packet.ID),
        question.name,
        int(question.qtype),
        int(question.qclass),
    )


def _is_expected_response(query_packet, response_packet, dst) -> bool:
    """Whether *response_packet* may be credited to *query_packet*.

    Checks, in order of cost: the QR bit says this is a response and not some
    unrelated query that happens to share an ID; the question section is echoed
    faithfully. Both are required by RFC 1035 section 4.1.1 and both are named as
    client-side matching rules by RFC 5452 sections 4.2-4.3 and 9.1.
    """
    if DnsQR.RESPONSE != response_packet.QR:
        return False
    if not response_packet.questions:
        return False
    return _pending_key(dst, response_packet) == _pending_key(dst, query_packet)


def _records_by_owner(response):
    """Group a response's answer-section records by owner name.

    Keyed on :class:`~namespy.names.DomainName`, whose equality and hash are
    case-insensitive over raw labels, so ``WWW.Example.COM`` and
    ``www.example.com.`` land in the same bucket without normalising twice.
    """
    index = {}
    for record in response.answers:
        index.setdefault(record.name, []).append(record)
    return index


def _dname_expansion(qname, owner, target):
    """Apply a DNAME substitution to ``qname`` (RFC 6672 §2.2, §3.1).

    The part of the name *below* the DNAME's owner is prepended to the DNAME's
    target; the owner itself is never redirected (§2.3: "the owner name of a
    DNAME RR is not redirected itself"). So with
    ``bar.example.com. DNAME baz.net.``:

    * ``foo.bar.example.com.`` becomes ``foo.baz.net.``
    * ``bar.example.com.`` stays as it is -- and the caller must not call this
      for it.

    Rebuilt through :meth:`DomainName.from_labels`, so a label containing a dot
    cannot change the number of labels on the way through.
    """
    labels = list(qname.labels())
    owner_labels = owner.labels()
    below = labels[: len(labels) - len(owner_labels)]
    return DomainName.from_labels([*below, *target.labels()])


def _closest_dname(index, current):
    """The DNAME applying to ``current``: the most specific enclosing owner.

    A DNAME sits at the top of the subtree it redirects, so the record that
    applies to a name is almost never owned by that name. For
    ``foo.bar.example.com`` with ``bar.example.com. DNAME baz.net.``, the DNAME
    is at ``bar.example.com`` and nothing at all is at the QNAME unless the
    server also sent the synthesised CNAME of RFC 6672 §3.1. Looking only in the
    QNAME's own records therefore finds nothing, which is why this scans the
    owners actually present in the response.

    The closest encloser wins when several levels carry a DNAME, matching what a
    server would apply. Owners equal to ``current`` are excluded: RFC 6672 §2.3
    is explicit that "the owner name of a DNAME RR is not redirected itself", so
    a DNAME never fires for its own owner.
    """
    best_owner = None
    best_record = None
    for owner, records in index.items():
        if not current.is_subdomain_of(owner, include_self=False):
            continue
        record = next((r for r in records if int(r.rtype) == int(DnsRType.DNAME)), None)
        if record is None:
            continue
        if best_owner is None or len(owner.labels()) > len(best_owner.labels()):
            best_owner, best_record = owner, record
    return best_record, best_owner


class AliasWalk(NamedTuple):
    """Outcome of walking an answer section's alias chain.

    ``records``
        The final answer -- every alias traversed, followed by the RRset that
        matches QTYPE. RFC 1034 §3.6.2 requires the aliases to be returned with
        it: "the response to a query for a alias name includes the response to a
        query for the primary name, plus a CNAME RR at the original query name",
        and a caller that dropped them could not tell an aliased answer from a
        direct one.
    ``events``
        One :class:`Cname` per redirection taken, for the trace.
    ``continued_at``
        The name the walk stopped on when no QTYPE RRset was found, or ``None``
        when ``records`` is a complete answer. The driver re-anchors SNAME here
        and queries again (RFC 1034 §5.3.3 step 4c, "go to step 2").
    ``failure``
        A reason string when the chain is *broken* rather than merely unfinished
        -- a loop, or longer than :data:`MAX_ALIAS_HOPS`. These are not the same
        condition and must not be conflated: falling through with
        ``continued_at=None`` made a broken chain look like an empty answer, so a
        CNAME loop was classified as NODATA and passed on as a cacheable negative
        (RFC 2308 §5 would store it under the SOA's TTL) when the zone is simply
        broken. A resolver should fail here; Unbound answers SERVFAIL.
    """

    records: list | None
    events: list
    continued_at: DomainName | None = None
    failure: str | None = None


def _follow_aliases(response, sname, max_alias_hops: int = MAX_ALIAS_HOPS) -> AliasWalk:
    """Walk the CNAME/DNAME chain in a response's answer section.

    A DNAME is honoured even without the synthesised CNAME a server is supposed
    to include (RFC 6672 §3.1), because resolvers must cope with servers that
    omit it; where both are present the real CNAME wins, since it is what the
    server actually chose to answer with.
    """
    index = _records_by_owner(response)
    qtype = int(sname.qtype)
    any_type = qtype == int(DnsQType.ANY)

    current = sname.qname
    traversed: list[DomainName] = []
    events: list[Cname] = []
    seen = {current}

    while True:
        candidates = index.get(current, [])

        if any_type:
            # QTYPE=ANY is answered by whatever exists at the name; there is
            # nothing to match, so following an alias would be wrong.
            return AliasWalk(candidates or None, events)

        direct = [r for r in candidates if int(r.rtype) == qtype]
        if direct:
            # Data at this name wins over a redirection rooted here. That order
            # is mandated for DNAME (RFC 6672 §2.3: when QTYPE matches a type
            # owned by the DNAME's owner name, "the response is sourced from the
            # owner name"); for CNAME it is unreachable, since nothing may
            # coexist with a CNAME.
            return AliasWalk([*traversed, *direct], events)

        alias = next((r for r in candidates if int(r.rtype) == int(DnsRType.CNAME)), None)
        redirection = "cname"
        owner = current
        if alias is None:
            # No CNAME here. A DNAME may still redirect this name from further
            # up the tree, and it will be owned by an ancestor rather than by
            # `current`, so it cannot be found in `candidates`.
            alias, owner = _closest_dname(index, current)
            redirection = "dname"
        if alias is None:
            return AliasWalk(None, events, None if not traversed else current)

        target = alias.rdata
        if not isinstance(target, DomainName):
            # A hand-built record may hold raw octets; there is no name to follow.
            return AliasWalk(None, events)
        if redirection == "dname":
            target = _dname_expansion(current, owner, target)

        traversed.append(alias)
        events.append(Cname(target))
        if target in seen:
            # RFC 1034 §3.6.2 forbids an alias mapping to itself "either directly
            # or indirectly". This is a broken zone, not a negative answer: the
            # name exists, and data of QTYPE may well exist past the loop, so
            # reporting NODATA would cache a falsehood for the SOA's MINIMUM.
            return AliasWalk(None, events, failure=f"alias loop at {target}")
        seen.add(target)
        current = target

        if len(traversed) >= max_alias_hops:
            # Same reasoning: no answer of this shape deserves another query, and
            # returning `current` here would merely move the decision to the
            # driver's own counter instead of failing where the evidence is.
            return AliasWalk(None, events, failure=f"alias chain longer than {max_alias_hops}")


def _find_closer_delegation(response, sname, slist):
    """The authority section's referral, if it genuinely gets us closer.

    Returns ``(new_zone, ns_targets, match_after)`` or ``None``. RFC 1034
    §5.3.3 step 5 defines a referral as an authoritative-section NS set whose
    name is *closer* to SNAME than the zone we are already querying — "closer"
    being the label-count test of step 4b. Requiring the name to actually
    advance is what stops a server from bouncing a query back to itself, and it
    is the guard that makes a NODATA response with stray NS records
    unambiguous (RFC 2308 §2.2.1).
    """
    new_zone = None
    ns_targets = []
    for record in response.nameservers:
        if int(record.rtype) != int(DnsRType.NS):
            continue
        if new_zone is None:
            new_zone = record.name
        ns_targets.append(record.rdata)

    if new_zone is None:
        return None

    match_after = sname.match_count(new_zone)
    if match_after <= slist.match:
        return None
    return new_zone, ns_targets, match_after


def classify(
    response,
    sname,
    slist,
    entry,
    max_alias_hops: int = MAX_ALIAS_HOPS,
    glue_policy: GluePolicy = GluePolicy.STRICT,
):
    """Apply RFC 1034 §5.3.3 step 4 to a single response.

    Yields a sequence of trace events. Mutates `slist` for valid referrals
    (extends entries, advances zone/match). Each yielded `Demote` carries
    the entry the caller should mark demoted; each terminal `Done`
    completes the lookup.

    ``glue_policy`` decides only the credibility of address RDATA that a referral
    volunteers for a nameserver outside the answering zone -- see
    :class:`GluePolicy`. Either way a :class:`VolunteeredGlue` event is yielded
    after the `Referral`, because what a parent offered is worth recording even
    when it is refused.

    A trailing `Cname` with no `Done` after it is **not** an error and not a
    conclusion: it means SNAME must be re-anchored at that target and the lookup
    restarted from step 2 (RFC 1034 §5.3.3 step 4c). The driver in
    :func:`resolve_steps` owns that loop, because only it can bound the chain
    across successive responses; `classify` stays a pure per-response classifier
    so it remains directly testable.
    """
    if response is None:
        yield Demote(entry, "no response")
        return

    if DnsResponseCode.NAME_ERROR == response.RCODE:
        yield Nxdomain()
        yield Done(response)
        return

    if DnsResponseCode.NO_ERROR != response.RCODE:
        # Not response.RCODE.name: RCODE is a plain int whenever the header held
        # a value this enum has no member for, and .name on an int is an
        # AttributeError inside the classifier -- which, reached from a datagram,
        # would turn "unfamiliar RCODE" into a crash instead of a demotion.
        # RFC 2929 section 3.1 makes unassigned codes a routine occurrence, so
        # this is the normal path for a server ahead of the registry, not an edge.
        yield Demote(entry, "rcode " + DnsResponseCode.mnemonic(response.RCODE))
        return

    # Answer section: either a complete answer, or a chain parked on an alias
    # whose target still needs looking up (RFC 1034 §5.3.3 step 4c: "if the
    # answer contains a CNAME RR, set SNAME to the contents of the RDATA field
    # of the displayed CNAME RR, and go to step 2").
    walk = _follow_aliases(response, sname, max_alias_hops=max_alias_hops)
    yield from walk.events
    if walk.failure is not None:
        # A loop or an over-long chain is a broken zone, not a negative answer.
        # Letting this fall through reached the ANCOUNT > 0 branch below and
        # yielded Nodata, which RFC 2308 §5 would have cached against the SOA --
        # so one malformed alias set would hide a name for the length of the
        # zone's MINIMUM. Fail instead, and let the caller try another server.
        yield Fail(walk.failure)
        return
    if walk.records is not None:
        yield Answer(walk.records)
        yield Done(response)
        return
    if walk.continued_at is not None:
        # Neither terminal nor a Demote — the lookup is still alive and the
        # driver has a new SNAME to try. Ending the chain here is what made
        # every aliased name (www.cdn.example, most SMTP hosts) unresolvable.
        return

    if response.ANCOUNT == 0:
        soa = next(
            (r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)),
            None,
        )
        if response.AA:
            # A server that claims authority for the zone of QNAME cannot
            # simultaneously be referring us onward, so an empty answer here is
            # NODATA no matter what else the authority section holds. RFC 2308
            # §2.2.1 decides the response type by the *content* of the authority
            # section rather than by AA, and §3 requires the zone SOA to be
            # present so the negative answer can be cached.
            yield Nodata(soa)
            yield Done(response)
            return

        delegation = _find_closer_delegation(response, sname, slist)
        if delegation is None:
            if soa is None:
                # Nothing to answer with, nowhere to go, and no TTL: RFC 2308 §5
                # says a negative answer without an SOA "SHOULD NOT be cached as
                # there is no way to prevent the negative responses looping
                # forever", so it is not trustworthy enough to return. Try
                # another server.
                has_ns = any(int(r.rtype) == int(DnsRType.NS) for r in response.nameservers)
                yield Demote(
                    entry,
                    "referral not closer" if has_ns else "no answer and no referral",
                )
                return
            # TYPE 2 NODATA (SOA present, no NS) from a non-authoritative
            # server. RFC 2308 §2.2.1 recommends authoritative servers send this
            # shape precisely because the alternative is so often misread as a
            # referral.
            yield Nodata(soa)
            yield Done(response)
            return

        new_zone, ns_targets, match_after = delegation
        old_zone = slist.zone
        match_before = slist.match

        new_entries = []
        glue_notes = []
        for ns_target in ns_targets:
            # RFC 5452 section 6: a response "often contain[s] information that
            # is not part of the zone for which we deem it authoritative", and
            # the remedy it prescribes is to "only accept data if it is known
            # that the originator is authoritative for the QNAME or a parent of
            # the QNAME". Here the originator serves ``old_zone``. The one name
            # space it may additionally speak for is ``new_zone``, because RFC
            # 1034 section 4.2.1 makes a parent responsible for the glue of
            # every nameserver below the cut.
            in_bailiwick = ns_target.is_subdomain_of(old_zone) or ns_target.is_subdomain_of(
                new_zone
            )
            addresses = []
            volunteered = []
            for ar in response.additional_records:
                # Glue must be for *this* target: RFC 1034 section 5.3.3 step
                # 4 caches "the NS delegation RRs and any address RRs *for the
                # servers*", which excludes every other owner name the extra
                # section may carry. An address lookup on an NS name can also
                # surface a CNAME, and a CNAME is not an address RR.
                if ar.name != ns_target:
                    continue
                if in_bailiwick:
                    ip = _answer_address(ar)
                    # _answer_address validates the family against the RR type, so a
                    # 16-octet "A" or a 4-octet "AAAA" contributes nothing rather
                    # than raising out of the resolution loop.
                    if ip is not None:
                        addresses.append(ip)
                    continue
                # ... and it must be *credible*, which is the question
                # :class:`GluePolicy` answers. Out-of-bailiwick data is not
                # believed by default: the delegating server is not authoritative
                # for this name, so the address it volunteered is exactly the
                # "data from an untrusted source" RFC 5452 section 6 warns about,
                # and accepting it lets any delegation point the rest of this
                # lookup -- and the queries it will send -- at an address of the
                # delegating server's choosing. The target name itself remains
                # perfectly usable (RFC 1034 section 4.2.2: a delegated server's
                # name need not lie inside the zone), so it is simply left without
                # an address, which sends resolve_steps into the NeedAddress
                # sub-resolution that asks the servers who *are* authoritative.
                #
                # Refusing it is not a reason to forget it: the RRs a parent
                # volunteers about someone else's nameservers are the measurement,
                # and GluePolicy.PERMISSIVE is the switch that turns this same list
                # into a next hop.
                volunteered.append(ar)
            entry = SlistEntry(new_zone, ns_target, addresses)
            new_entries.append(entry)
            if volunteered:
                believed = glue_policy is GluePolicy.PERMISSIVE
                offered = [
                    ip for ip in (_answer_address(ar) for ar in volunteered) if ip is not None
                ]
                if believed:
                    entry.addresses.extend(offered)
                entry.history["bailiwick"] = (
                    "out-of-bailiwick glue accepted (unverified)"
                    if believed
                    else "out-of-bailiwick glue discarded"
                )
                glue_notes.append(
                    VolunteeredGlue(
                        ns_name=ns_target,
                        records=tuple(volunteered),
                        addresses=tuple(offered),
                        used=believed,
                        reason=(
                            "believed under GluePolicy.PERMISSIVE"
                            if believed
                            else "not authoritative for this name (RFC 5452 section 6)"
                        ),
                    )
                )
            if not addresses and in_bailiwick:
                # RFC 1034 section 4.2.1: glue is "only necessary if the name
                # server's name is 'below' the cut", and RFC 1035 section 5.2
                # item 3 requires a zone to ship it. A below-cut target with
                # no glue is therefore a broken delegation -- *lame* -- because
                # reaching it would require having reached it. Demote it
                # immediately: sub-resolving would descend into the very zone
                # we are trying to reach, and with an A and an AAAA attempt per
                # level that is a 2x branching blowup rather than a lookup that
                # simply fails.
                entry.history["demoted"] = True
                entry.history["lame"] = "in-bailiwick without glue"
        random.shuffle(new_entries)

        slist.entries = new_entries
        slist.zone = new_zone
        slist.match = match_after

        yield Referral(old_zone, new_zone, match_before, match_after)
        # The glue notes come after the Referral, not before: the descent is the
        # event a reader follows, and these are the footnotes explaining what the
        # delegation volunteered on the way. resolve_steps lets them through even
        # during a QNAME-minimisation probe, for the same reason -- they are an
        # observation about a referral that was already accepted, never a
        # statement about the probe that must not be mistaken for one.
        yield from glue_notes
        for entry in new_entries:
            if entry.history.get("lame"):
                yield Demote(entry, entry.history["lame"])
        return

    # ANCOUNT > 0, yet nothing matched QTYPE and no alias chain led anywhere.
    if response.AA:
        # "Name exists, but no data of the requested type" (RFC 2308 §2.1): the
        # server answered authoritatively and the answer simply is not our type.
        yield Nodata(
            next(
                (r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)),
                None,
            )
        )
        yield Done(response)
        return

    # A partial answer from an upstream cache. Take it as given rather than
    # second-guessing a server that never claimed authority for the zone.
    yield Answer(list(response.answers))
    yield Done(response)


#: How many chain queries a single validating lookup may send. The chain to the
#: root is at most 127 labels and in practice four hops deep; eight missing records
#: means something is deeply unusual, and a loop that kept asking was the failure
#: mode this bound exists against -- the walk gives up and reports Indeterminate,
#: which costs a re-ask later, never a spin now.
_MAX_SEC_FETCHES = 8


def _judge_answer(validator, response, zone, qtype: int) -> ValidationVerdict:
    """One verdict for a positive answer: every RRset the response asserts.

    RFC 4035 §3.2.3 makes AD mean "all RRsets in the Answer and Authority
    sections are authentic", so judging only the queried RRset could never
    license the claim -- a response carrying a CNAME beside its target asserts
    two things, a bundle answering A and AAAA from one walk asserts two, and an
    SOA riding in the authority section is a third the rule names. Each distinct
    (owner, type) pair those sections carry is judged by
    :meth:`~namespy.validate.Validator.validate_rrset`, whose signer-driven
    chain needs no help from *zone* except for the unsigned case -- which is
    exactly the case where *zone* decides whether unsigned means Insecure or
    Bogus. The DNSSEC types stay unjudged in passing, because there RRSIG is the
    evidence and NSEC the denial's material; a client that queried one directly
    makes it the answer, and then it is judged like any RRset.

    The composite follows the sections' own logic, not a majority: one forged
    RRset makes the response Bogus (RFC 4033 §5 -- a response is one thing, and
    an attacker who can sign anything in it can pick), otherwise one
    Indeterminate part keeps the whole undetermined and its hint becomes the
    loop's next question, otherwise one Insecure part is the ceiling -- an
    unsigned answer below a proved-unsigned parent is authentic data in an
    unauthenticated dress -- and only an all-secure set is SECURE. Via Opt-Out
    anywhere, and §9.2¶1 withholds the bit even from an all-secure set: the
    wildcard answer's closer-match proof is a closest-encloser proof like any
    other, and its next closer may hide an unsigned delegation.
    """
    judged: list[ValidationVerdict] = []
    seen: set = set()
    sections = [*response.answers, *response.nameservers]
    for record in sections:
        rtype = int(record.rtype)
        if rtype == OPT_RTYPE:
            continue  # never an RRset (RFC 6891 §6.2.1), and its owner is the root by convention
        if rtype in DNSSEC_SECURITY_TYPES and rtype != qtype:
            continue
        key = (DomainName(record.name).canonical_text, rtype)
        if key in seen:
            continue
        seen.add(key)
        judged.append(validator.validate_rrset(key[0], rtype, zone=zone))
    if not judged:
        # Nothing left to judge (a response of nothing but OPT): nothing to vouch for.
        return ValidationVerdict(
            SecurityStatus.INDETERMINATE,
            "the answer carried no RRset this resolver could judge",
            zone=zone,
        )
    worst = judged[0]
    for verdict in judged[1:]:
        worst = _combine_verdicts(worst, verdict)
    if len(judged) > 1:
        worst = ValidationVerdict(
            worst.status,
            f"all {len(judged)} RRsets judged: {worst.reason}",
            zone=worst.zone if worst.zone is not None else zone,
            matched_key_tag=worst.matched_key_tag,
            fetch_hint=worst.fetch_hint,
            via_opt_out=any(v.via_opt_out for v in judged),
        )
    else:
        worst = ValidationVerdict(
            worst.status,
            worst.reason,
            zone=worst.zone if worst.zone is not None else zone,
            matched_key_tag=worst.matched_key_tag,
            fetch_hint=worst.fetch_hint,
            via_opt_out=worst.via_opt_out,
        )
    return worst


def _combine_verdicts(left: ValidationVerdict, right: ValidationVerdict) -> ValidationVerdict:
    """The section-wide rank: bogus poisons, indeterminate defers, insecure caps.

    SECURE survives only by meeting SECURE. The reason carried is the one that
    explains the surviving status -- the bogus verdict's, failing that an
    indeterminate one's (its hint rides along: one question at a time, and the
    re-run reconsiders every RRset anyway) -- so a trace line reads as a
    sentence about the response, not a tally.
    """
    rank = {
        SecurityStatus.SECURE: 0,
        SecurityStatus.INSECURE: 1,
        SecurityStatus.INDETERMINATE: 2,
        SecurityStatus.BOGUS: 3,
    }
    winner = left if rank[left.status] >= rank[right.status] else right
    if winner.status is SecurityStatus.INDETERMINATE:
        for verdict in (left, right):
            if verdict.status is SecurityStatus.INDETERMINATE and verdict.fetch_hint is not None:
                winner = verdict
                break
    return winner


def resolve_steps(
    sname,
    slist,
    cache=None,
    max_hops: int = MAX_HOPS,
    max_alias_hops: int = MAX_ALIAS_HOPS,
    qname_min: bool = False,
    glue_policy: GluePolicy = GluePolicy.STRICT,
    nxdomain_cut: NxdomainPolicy = NxdomainPolicy.ALWAYS,
    failures=None,
    extra_qtypes: tuple = (),
    dnssec_ok: bool = False,
    anchors: tuple = (),
    now: float | None = None,
    client_cd: bool = False,
    client_key_tags: tuple = (),
    aggressive_nsec: bool = False,
    serve_stale: float = 0.0,
):
    """Drive resolution as a generator of effect/trace events.

    The generator is fully synchronous; it never touches sockets. The async
    driver `RecursiveResolver._drive` fulfills `SendQuery` / `NeedAddress`
    yields and feeds results back via `gen.send(...)`.

    If ``cache`` is provided (a :class:`namespy.cache.DnsCache`), every hop
    first consults it (RFC 1034 §5.3.3 step 1) and short-circuits with
    ``Answer``/``Done`` or ``Nxdomain``/``Nodata``/``Done`` on a hit. After
    a real authoritative response classifies as a terminal event, the
    result is written back to the cache.

    ``dnssec_ok`` says this resolver asked the authorities for DNSSEC data, and it is what lets a
    cached denial answer a lookup with the NSEC/NSEC3 records that prove it attached rather than as a
    bare RCODE 3 (RFC 8020 §2¶5 makes those records part of the answer). It is the instance knob and
    not a client's DO bit: the walk has no client. What a particular client may see is decided once,
    on the way out, by :class:`namespy.server.DnsServer` -- see RFC 4035 §3.2.1.

    ``anchors`` switches on validation of the answers this walk receives: the
    records every response carries are bucketed into one ``DnssecStore`` per walk
    (a referral's DS rides along for free -- RFC 4035 §3.1.4 obliges signed
    delegations to carry it), and a terminal answer -- denial or positive -- is
    judged under the anchors by ``namespy.validate``, the positive as a
    composite over every RRset RFC 4035 §3.2.3 makes the response stand or fall
    on together. Whatever the chain lacks is asked for, one query at a
    time, of the zone that holds it -- §5.2¶6's "MUST query the name servers for
    the parent zone for the DS RRset" is this loop's name -- and the verdict both
    precedes the terminal event (a ``DnssecVerdict``), raises the response's AD
    bit if it is fully verified, and travels into the cached
    entry's ``validated`` flag, which is what :attr:`NxdomainPolicy.VALIDATED`
    reads at the cut. Empty anchors, the default, keeps the walk exactly as it
    was: gathering, judging, and stamping nothing. ``now`` pins the signature
    window for the whole lookup; ``None`` takes the cache's clock, then the wall
    clock.

    ``client_cd`` is the initiating query's CD bit, and it rewrites what a
    failure means. RFC 4035 §3.2.2¶3 makes the set bit a request to be *passed
    through*: "the recursive name server should not interfere", so a Bogus denial
    is answered rather than refused, no failure is noted (nothing failed -- §4.2¶2
    exempts a CD lookup from validating, and an unexecuted check is not a cached
    failure), the remembered *validation* failures in the failure cache do not
    suppress it (§3.2.2¶5: withholding the raw data "does not help the client"
    that can check it), and -- because this package caches no unvalidated data a
    later non-CD lookup might inherit -- nothing from a CD lookup is written to
    the response cache at all. Its own answer never claims AD either: with CD set
    the walk validates nothing it must stand behind. Clear, with anchors, the walk
    is the client's validator: a Bogus denial becomes a SERVFAIL carrying a
    ``dnssec_bogus`` marker (the serve side reads it to attach RFC 8914 §4.7's EDE
    6), the forged answer is kept out of the cache where RFC 8020's ALWAYS cut
    could serve it, and the failure is noted -- RFC 9520 §3.4 turned 4035 §4.7's
    MAY into a MUST, with §3.2's backoff as the TTL guidance, which is the
    amplification guard §4.7¶4 wanted.

    ``client_key_tags`` is the key-tag list from the initiating query's
    edns-key-tag option(s) (RFC 8145), and it travels for exactly one question
    type: §4.2¶2's "MUST NOT include the edns-key-tag option for non-DNSKEY
    queries" gates it, and nothing else in a lookup of any other type could use
    it anyway. Even among DNSKEY queries it rides only the hop whose server is
    the zone's own -- §4.2¶3 wants the tags of the KSKs of "the zone for which
    the server is authoritative", and before the answer arrives the walk can
    know that only where the queried name is the zone itself. On the hops it
    does ride, the two forwarding rules of §4.2.2 apply: a validating
    recursive server sends its own list and the client's as separate instances
    when they differ (§4.2.2.1¶2, own list first as in the section's example),
    and one that validates nothing copies the client's list as an act of
    respect for "the wishes of the validating downstream resolver" (§4.2.2.2).
    The chain fetches the validator makes for itself carry only its own list:
    those answers judge this resolver's chain, and a client's tags say something
    about the client that a parent's name server has no use hearing second-hand.

    ``nxdomain_cut`` decides whether a denial cached at or above the name may
    answer for it without a query (RFC 8020 §2 -- see :class:`NxdomainPolicy`). It
    is consulted after the exact-key lookup, which is also §2¶2's allowance that
    "if a resolver has cached data under the NXDOMAIN cut, it MAY continue to send
    it as a reply (until the TTL of this cached data expires)": data already filed
    under a cut is a better answer than the cut. It precedes the failure cache
    because a cached NXDOMAIN is a proof with an SOA behind it, where a failure
    note is only a promise not to ask again. The cut is checked on every hop rather
    than once at the top, because §2¶6 warns that "if there is a chain of CNAME (or
    DNAME), the name that does not exist is the last of the chain ... and not the
    QNAME" -- checking at the origin would miss a denial reached through an alias.

    ``aggressive_nsec`` turns on the aggressive use of cached proofs (RFC 8198
    §5, TTLs per RFC 9077 §3.4): when nothing matches ``(qname, qtype)`` and no
    cut applies, the cached denials' NSEC/NSEC3 bundles are examined -- by the
    same response validators a live answer faces -- and a validated bundle that
    proves *this* denial synthesises the answer without a query. Every gate
    (:mod:`namespy.aggressive` states them with their texts): validated entries
    only (Appendix B ¶2), a complete proof for the queried name or nothing
    (§5.4/§8.4-§8.7 in full, with Appendix A ¶4's MUST-fallback on an incomplete
    one), no Opt-Out span (§5.2¶3), unexpired signatures (§7's "until the
    effective TTLs or signatures expire"), and the CD client never answered this
    way (Appendix A ¶1's exemption). Off by default, and it falls silent on any
    backend that cannot supply candidates -- asking the query is still the
    correct behaviour, which is all RFC 8198 promises when it cannot act.

    ``serve_stale`` is the maximum-stale timer (RFC 8767 §5¶11): a positive
    number both lets the walk answer from an expired-but-retained cache entry
    when refreshing fails and sets that retention window on the cache. Zero,
    the default, discards on expiry and never serves stale -- the whole
    feature is opt-in because it trades correctness for resiliency, and §6
    leaves the timer's value to the operator. It answers only when the refresh
    genuinely failed (a name whose servers are gone, §7¶1), never in place of
    a reachable authority, never with the AD bit, and always with a
    greater-than-zero TTL (§4¶4) so a client that honours it retries on the
    recommended half-minute rather than hammering an answer it knows is old.

    If ``failures`` is provided (a :class:`namespy.cache.FailureCache`), the
    same loop also refuses to *start* a query whose failure is already
    remembered, and records the failures it hits (RFC 9520 §3.2). Two shapes are
    recorded, because two things fail: a lookup that runs out of servers for a
    zone it had reached and never heard back from notes the **zone**, so the
    next lookup -- which will be for a different name under that zone, and would
    otherwise climb all the way back down -- is stopped at the top (§3.3: "the
    resolver MUST limit queries to the non-responsive zone's parent zone"); a
    lookup that ends because the *name* is unusable (an alias loop, a spent hop
    budget) notes the ``(qname, qtype, qclass)``. A zone that answered anything
    useful is never marked dead, which is what keeps a spent QNAME-minimisation
    probe walk -- servers answering too well, not too badly -- from poisoning a
    healthy delegation. Suppression never refreshes an entry: a client hammering
    a dead name must not be able to hold the failure open past the five-minute
    ceiling. Left ``None``, the generator behaves as it always has.

    ``qname_min`` enables QNAME minimisation (RFC 9156): servers not known
    to be authoritative for the full QNAME are probed with progressively
    deeper children -- see :mod:`namespy.minimis` for the schedule. The
    default ``False`` is deliberate: it changes the questions every
    downline server sees, and it earns its default in the field.

    ``glue_policy`` decides whether a referral's out-of-bailiwick address data
    may be used as glue (see :class:`GluePolicy`). It is a parameter of this
    function rather than ambient state because a single lookup can spawn
    sub-resolutions, and a policy that failed to reach them would quietly stop
    applying halfway down -- which in the permissive direction means the
    measurement records an adoption that did not happen.

    ``extra_qtypes`` asks each server that receives the *real* question to combine
    those QTYPEs into the same answer (RFC 10029; see :mod:`namespy.bundle`). The
    option goes out on full-QNAME queries and on nothing else: not on a
    QNAME-minimisation probe, which asks about a shorter name, and not on a glue
    sub-resolution, which asks about a nameserver's address rather than the caller's.
    A server that merely delegates does still see it, because there is no way to know
    from here which server is the zone's, and asking costs nothing that the protocol
    has not already made legal -- RFC 6891 section 6.1.2 says "Any OPTION-CODE values
    not understood by a responder or requestor MUST be ignored". Whatever a referral
    hop combines is not read: the caller harvests the bundle from the terminal answer,
    which is the only response in the walk that is an answer about those types at all.
    """
    # RFC 9824 §3.5¶2, the walk's half of the meta-type refusal: "A resolver
    # MUST NOT forward these queries upstream or attempt iterative resolution."
    # NXNAME stores no data in any zone and "cannot be usefully queried"
    # (§2¶3) -- it is a signal that rides in NSEC(3) bitmaps -- and an
    # iterative descent is exactly the attempt the sentence forbids. The
    # stub's half lives in namespy.stub; a served query bounces at
    # namespy.server with FORMERR (§3.5¶2) and EDE 30 (§3.5¶3).
    if int(sname.qtype) == int(DnsRType.NXNAME):
        raise ValueError(
            "NXNAME (128) is a Meta-TYPE a resolver MUST NOT ask about: it "
            "exists only in NSEC type bitmaps to signal a nonexistent name "
            "(RFC 9824 sections 2, 3.5); a server answering the question must "
            "reply FORMERR, so there is nothing to walk toward"
        )
    # Alias state lives here, not in classify: a CNAME in one response can point
    # at a name that another response aliases again, so only the loop spanning
    # responses can tell a long chain from a loop. `seen` catches the two-name
    # ping-pong (a -> b -> a) that a hop counter alone would ride out for the
    # full budget.
    alias_hops = 0
    seen_names = {sname.qname}
    minimiser = QnameMinimiser(sname.qname) if qname_min else None
    # RFC 9520 §3.2 bookkeeping. `origin` is captured before the first re-anchor
    # so that a failure reached through an alias can be remembered against the
    # name the client actually asked about, not only the alias target it died on
    # -- without it, a repeat query for the original name re-walks the whole
    # delegation tree before the cache stops it one hop too late.
    origin = sname.qname
    #: Zones this lookup sent a query to, and zones that answered something
    #: usable. A zone is declared dead only when it is in the first set and not
    #: the second, which is RFC 9520 §2.1's "the servers are not answering" and
    #: not merely "this lookup stopped needing them".
    attempted = set()
    answered = set()
    #: Why each zone's candidate servers stopped being usable, in the order first
    #: seen, so a zone failure reads as a diagnosis ("no response; rcode
    #: SERVFAIL") rather than the bare fact that the list ran dry.
    demotions: dict = {}

    #: Whether a denial cached above a name may answer for it (RFC 8020 §2).
    #: Decided once: a policy cannot change partway down a walk.
    cut_enabled = nxdomain_cut is NxdomainPolicy.ALWAYS
    #: ...and whether such a cut additionally requires the remembered SECURE verdict
    #: that only a validating walk writes (RFC 8020 §2¶3, NxdomainPolicy.VALIDATED).
    require_validated = nxdomain_cut is NxdomainPolicy.VALIDATED

    #: The evidence one lookup accumulates for :mod:`namespy.validate`, and the
    #: servers of every zone it reached, kept so a chain fetch has somebody
    #: authoritative to ask. The clock is pinned once per lookup: a climb that
    #: straddled a signature window mid-way would judge the same bytes two ways
    #: in one verdict, and RFC 4035 §5.3.1 offers no rule for which of the two
    #: the answer was supposed to be.
    sec_validator: Validator | None = None
    sec_servers: dict = {}
    #: Chain-shaped records seen during this lookup -- DNSKEY and DS data with
    #: the RRSIGs that cover them -- kept in arrival order beside the validator's
    #: store because the store buckets rdatas and drops the TTLs a cache entry
    #: must carry. A lookup that ends secure files these into the cache (RFC 4035
    #: §4.5: helper queries are responses like any other, and §4.5¶1's atomic
    #: entry is exactly an RRset travelling with its signatures), so the next
    #: lookup's §5.2¶6 fetches consult data this resolver already verified
    #: rather than re-climbing the chain from the root.
    sec_material: dict = {}
    clock = now if now is not None else (cache.time_fn() if cache is not None else None)
    if anchors:
        sec_validator = Validator(anchors=tuple(anchors), now=clock)

    def _offer(zone, reply, server=None):
        """File everything *reply* carried as the data of the zone that sent it.

        *server* is the :class:`SlistEntry` it was asked of: the first server seen
        for a zone is the one later chain fetches go to, because the walk has
        already proved it answers for that zone.
        """
        if sec_validator is None or reply is None:
            return
        arrived = [*reply.answers, *reply.nameservers, *reply.additional_records]
        sec_validator.store.add(arrived, zone=zone)
        for record in arrived:
            _file_chain_record(sec_material, record)
        if server is not None:
            sec_servers.setdefault(str(DomainName(zone)), server)

    def _fetch_chain(judge):
        """Run *judge*, fetching chain records as its hints demand, until decided or spent.

        A generator because the fetching is the walk's own :class:`SendQuery`
        effect: the verdict loop asks the driver, in the middle of this lookup,
        for the DS or DNSKEY that RFC 4035 §5.2¶6 says a resolver MUST go and ask
        for. *judge* is any callable returning a :class:`~namespy.validate.
        ValidationVerdict` -- a denial, or the composite over a positive
        answer's RRsets -- and it re-runs whole after every fetch, because the
        one record that was missing may unlock the verdict anywhere in the
        response. Each hint is offered once per (name, type, zone) -- the
        :class:`~namespy.validate.Validator`'s side of the bargain -- and
        ``_MAX_SEC_FETCHES`` bounds the pathological zone besides. A hint whose
        zone the walk never reached is terminal: DNS offers no way to ask
        somebody else for authoritative data, and §4.3¶5's "not able to obtain"
        is the honest end of that road.
        """
        fetches = 0
        while True:
            verdict = judge()
            hint = verdict.fetch_hint
            if hint is None or fetches >= _MAX_SEC_FETCHES:
                return verdict
            name, rtype, from_zone = hint
            if cache is not None:
                hit = cache.get(name, rtype, sname.qclass)
                if (
                    isinstance(hit, PositiveEntry)
                    and getattr(hit, "validated", False)
                    and _chain_is_live(hit.records, clock)
                ):
                    # The stamped, signature-live chain entry this resolver (or
                    # one it trusts the cache of) verified before: §5.2¶6's MUST
                    # is to *obtain* the record, and a cache the same validator
                    # filled is obtaining. The validator will re-verify these
                    # bytes against its own anchors as it always does -- the
                    # stamp licenses the load, never the verdict -- and the
                    # window check above is the load-time filter the two clocks
                    # make necessary: an entry alive on the cache clock can carry
                    # a signature that died on the signature's, and §4.5¶1's
                    # discard-the-atomic-entry rule plus 8198 §7's "or signatures"
                    # make the older of the two the usable life.
                    fetches += 1
                    sec_validator.store.add(hit.records, zone=from_zone)
                    sec_validator.invalidate()
                    yield ChainFromCache(
                        str(DomainName(name)),
                        getattr(DnsRType(int(rtype)), "name", str(rtype)),
                        str(DomainName(from_zone)),
                    )
                    continue
            server = sec_servers.get(str(DomainName(from_zone)))
            if server is None:
                return verdict
            fetches += 1
            helper_options = ()
            if int(rtype) == int(DnsRType.DNSKEY):
                # RFC 8145 §4.2.2.1¶1: "a recursive resolver SHOULD include the
                # edns-key-tag option in its DNSKEY queries as described above" --
                # and "above" is §4.2¶3, whose only admitted sources are this
                # validator's anchors and the zone's DS records, which is exactly
                # what key_tags_for reads (§4.2¶6's MUST NOT forbids more). The
                # client's list is deliberately absent here: this answer judges
                # the walk's own chain and never reaches the client, so the
                # client's tags would be second-hand telemetry at a server the
                # client will never ask directly.
                tags = sec_validator.key_tags_for(name)
                if tags:
                    helper_options = (key_tag_option(tags),)
            reply = yield SendQuery(
                server,
                [DnsQuestion(name, rtype, sname.qclass)],
                helper=True,
                extra_edns_options=helper_options,
            )
            _offer(from_zone, reply)
            sec_validator.invalidate()

    def _remember(reason):
        """Note that this name cannot be resolved right now (RFC 9520 §3.2)."""
        if failures is None:
            return
        failures.note_query(sname.qname, sname.qtype, sname.qclass, reason)
        if origin != sname.qname:
            failures.note_query(origin, sname.qtype, sname.qclass, reason)

    def _note_demotion(entry, reason):
        if entry is None:
            return
        reasons = demotions.setdefault(entry.zone, [])
        if reason not in reasons:
            reasons.append(reason)

    def _remember_dnssec(reason):
        """Note that this name failed *validation* (RFC 9520 §2.6, §3.4's MUST).

        Split from :func:`_remember` only by the entry's flag: the backoff, the
        key and the suppression are 9520's ordinary machinery, while the flag lets
        a CD query walk past it, which RFC 4035 §3.2.2¶5's reasoning demands. The
        reason is capped -- a verdict sentence is longer than the network phrases
        this field usually holds, and it reappears inside every suppressed
        lookup's failure line.
        """
        if failures is None:
            return
        note = f"DNSSEC bogus: {reason}"[:200]
        failures.note_query(sname.qname, sname.qtype, sname.qclass, note, dnssec=True)
        if origin != sname.qname:
            failures.note_query(origin, sname.qtype, sname.qclass, note, dnssec=True)

    def _stale_fallback():
        """Answer from an expired-but-retained entry, or say so and let the caller fail.

        RFC 8767 §7¶1's stricture shapes the placement: stale data answers
        only where refreshing has failed -- reached from the remembered-
        failure seam (§5¶7's failure recheck: inside the backoff window "the
        cache may be immediately consulted for stale data") and from the
        out-of-servers seam (an outage in progress). A hit answers with
        §4¶4's refreshed TTLs and no AD; a miss costs one lookup in the cache
        and the SERVFAIL the resolver already owed. The duck-typed guard is
        the base cache's documented fallback: a backend without a stale door
        simply never gets here.
        """
        if serve_stale <= 0 or cache is None:
            return False
        hit = cache.stale(sname.qname, sname.qtype, sname.qclass)
        if hit is None:
            return False
        age = int(max(0.0, cache.time_fn() - hit.expires_at))
        yield ServeStale(str(sname.qname), age)
        if isinstance(hit, PositiveEntry):
            yield Answer(list(hit.records))
        elif hit.rcode == DnsResponseCode.NAME_ERROR:
            yield Nxdomain()
        else:
            yield Nodata(hit.soa)
        yield Done(_synthesize_stale(sname, hit, dnssec_ok))
        return True

    for _ in range(max_hops):
        if cache is not None:
            hit = cache.get(sname.qname, sname.qtype, sname.qclass)
            if hit is not None:
                if isinstance(hit, PositiveEntry):
                    yield Answer(hit.records)
                elif hit.rcode == DnsResponseCode.NAME_ERROR:
                    yield Nxdomain()
                else:
                    yield Nodata(hit.soa)
                # A cached denial's stamp is this resolver's own recorded verdict,
                # and RFC 4035 §3.2.3 lets AD ride on exactly that -- "considers
                # all RRsets ... to be authentic" is a claim about this server's
                # knowledge, not about the wire a packet arrived on. A resolver
                # with no anchors reading a stamp somebody else wrote asserts
                # nothing: it has no trust point of its own to have checked
                # against, and §3.1.6¶3 forbids authenticating what it cannot.
                yield Done(
                    _synthesize_response(
                        sname,
                        hit,
                        dnssec_ok,
                        validated=bool(sec_validator is not None)
                        and bool(getattr(hit, "validated", False)),
                    )
                )
                return
            if cut_enabled or require_validated:
                cut = _nxdomain_cut(cache, sname.qname, sname.qclass, require_validated)
                if cut is not None:
                    # RFC 8020 §2¶1: the cached NXDOMAIN for an ancestor makes
                    # this name "unreachable", so the lookup ends here without
                    # touching the network. The event order matters as much as
                    # the answer: NxdomainCut first, because it is what makes the
                    # bare Nxdomain below it traceable to someone else's denial.
                    entry, denied_by = cut
                    yield NxdomainCut(str(sname.qname), str(denied_by))
                    yield Nxdomain()
                    yield Done(
                        _synthesize_response(
                            sname,
                            entry,
                            dnssec_ok,
                            validated=bool(sec_validator is not None)
                            and bool(getattr(entry, "validated", False)),
                        )
                    )
                    return
            if aggressive_nsec and not client_cd:
                # RFC 8198 Appendix A ¶1's second check, run in its stated
                # place: before any query, does a cached proof -- a denial's
                # NSEC/NSEC3 span or a validated wildcard template -- resolve
                # this name? The CD exemption rides with it: "unless the CD
                # bit was set on the incoming query" is Appendix A's own
                # clause, and §3.2.2¶3's "should not interfere" says the same
                # in this server's voice -- a client that validates for itself
                # asked for the wire, not for an inference, however well the
                # inference was proven. `synthesize` tries the denials first
                # and the wildcard after; either yields a response and names
                # the cache material it stood on.
                synthesis = synthesize(
                    cache,
                    sname,
                    now=clock,
                    dnssec_ok=dnssec_ok,
                    assert_ad=sec_validator is not None,
                )
                if synthesis is not None:
                    if synthesis.kind == "wildcard":
                        yield WildcardSynthesis(str(sname.qname), synthesis.proven_by)
                        yield Answer(synthesis.response.answers)
                    elif synthesis.kind == "nxdomain":
                        yield AggressiveDenial(str(sname.qname), synthesis.proven_by, "nxdomain")
                        yield Nxdomain()
                    else:
                        yield AggressiveDenial(str(sname.qname), synthesis.proven_by, "nodata")
                        yield Nodata(synthesis.soa)
                    yield Done(synthesis.response)
                    return
        if failures is not None:
            blocked = failures.match(sname.qname, sname.qtype, sname.qclass)
            if blocked is not None and not (client_cd and getattr(blocked, "dnssec", False)):
                # RFC 9520 §3.2: "When an incoming query matches a cached
                # resolution failure, the resolver MUST NOT send any
                # corresponding outgoing queries until after the cache entries
                # expire." Nothing above this line touched the network and, since
                # this returns, nothing below it will. The entry is deliberately
                # *not* re-noted here: a client hammering a dead name would
                # otherwise keep pushing its expiry out to the five-minute
                # ceiling and hold a recovered zone shut.
                #
                # One exception, and one entry kind: a remembered validation
                # failure does not stop a CD query. §3.2's sentence was written
                # about failures of *resolution*, and a CD client has not asked
                # for ours -- RFC 4035 §3.2.2¶5 says outright that shielding a
                # client that can validate for itself "does not help the client".
                # A dead zone is still a dead zone for everyone: the bypass is
                # keyed on the entry's dnssec flag, not on the client's wishes
                # about zones that never answered.
                if (yield from _stale_fallback()):
                    return
                yield Fail(_cached_failure_reason(blocked))
                return
        entry = slist.best()
        if entry is None:
            # Every candidate server has been demoted. RFC 9520 §2.1 names the
            # condition -- a zone's authoritative servers not answering, with
            # nothing left to try instead -- and §3.3 makes the remedy a
            # zone-shaped one, because the next lookup will be for a *different*
            # name under the same zone: "the resolver MUST limit queries to the
            # non-responsive zone's parent zone (and to other ancestor zones)
            # just as it would limit subsequent queries to the non-responsive
            # zone." Only a zone key can express that, so it is the zone that is
            # remembered, for as long as §3.2's backoff allows.
            #
            # Two exclusions, both to avoid inventing an outage:
            #   * a zone this lookup never queried (an empty Slist -- no root
            #     hints -- leaves `.` in scope, and poisoning the root turns a
            #     local misconfiguration into a five-minute blackout);
            #   * a zone that answered something usable along the way, which is
            #     the case a spent QNAME-minimisation probe walk produces: the
            #     servers answered, they simply were not referred onward.
            # In both, the narrower query-keyed note is still worth recording --
            # this exact name demonstrably did not resolve.
            reason = "; ".join(demotions.get(slist.zone, ())) or "no servers"
            if failures is not None and slist.zone in attempted and slist.zone not in answered:
                failures.note_zone(slist.zone, reason)
            elif failures is not None:
                _remember(reason)
            if (yield from _stale_fallback()):
                # The outage case RFC 8767 was written for: every server that
                # could refresh this name failed, its notes are recorded, and
                # the only thing left that can answer is the cache's own
                # expired memory. Serving it is the whole point; failing the
                # lookup instead is the outage the resolver chooses to join.
                return
            yield Fail("no servers")
            return
        if not entry.addresses:
            addrs = yield NeedAddress(entry.ns)
            if not addrs:
                _note_demotion(entry, "no address")
                yield Demote(entry, "no address")
                slist.demote(entry)
                continue
            entry.addresses.extend(addrs)
            continue
        probe = minimiser.probe(sname.match_count(entry.zone)) if minimiser is not None else None
        if probe is not None:
            # RFC 9156 section 3 step 2: the probe is a QTYPE=A query for
            # CHILD, which keeps any referral in the exact shape classify()
            # already parses. The original QTYPE travels only when the
            # minimiser returns None -- CHILD has reached QNAME, the zone
            # server is in hand, or the probe budget is spent (section 3
            # step 3: "resolve the original query as normal").
            questions = [DnsQuestion(probe, DnsQType.A, sname.qclass)]
            # And no bundle with it. A probe asks about a shorter name than the
            # extras were requested for, so a MQTYPE-Query here would have a server
            # combine RRsets for the *child* -- records for a name nobody asked
            # about, arriving under a question that is not the caller's.
            bundle = ()
        else:
            questions = sname.questions
            bundle = extra_qtypes
        attempted.add(entry.zone)
        query_options: tuple = ()
        if probe is None and int(sname.qtype) == int(DnsRType.DNSKEY) and entry.zone == sname.qname:
            # Two gates before the stance. RFC 8145 §4.2¶2: the option is for
            # DNSKEY queries and nothing else (a §9156 probe is QTYPE=A, so it
            # never carries one). And §4.2¶3 describes the list as "the Key
            # Tag(s) of the KSK(s) of the zone *for which the server is
            # authoritative*" -- which on a walk from the roots is true of one
            # hop only, the zone's own server. Sending zone.test.'s tags to a
            # root server that is merely routing the question would answer a
            # question nobody there is asking. Then the stance: with anchors,
            # this server's own list goes first and the client's follows as a
            # second instance, which is §4.2.2.1¶2's transmitted shape ("the
            # two Key Tag lists using separate instances of the edns-key-tag
            # option code"); with none, the client's list rides as §4.2.2.2
            # asks a non-validating recursive resolver to copy it.
            own_opt = None
            client_opt = None
            if sec_validator is not None:
                own = sec_validator.key_tags_for(sname.qname)
                own_opt = key_tag_option(own) if own else None
            if client_key_tags:
                client_opt = key_tag_option(tuple(client_key_tags))
                if own_opt is not None and own_opt.data == client_opt.data:
                    # §4.2.2.1¶2 conditions the two-list forwarding on a list
                    # "that differs from its own"; identical lists travel once.
                    client_opt = None
            query_options = tuple(o for o in (own_opt, client_opt) if o is not None)
        response = yield SendQuery(
            entry,
            questions,
            probe=probe is not None,
            extra_qtypes=bundle,
            extra_edns_options=query_options,
        )
        if sec_validator is not None:
            # Every response is evidence, whatever the walk makes of it: a referral's
            # authority section carries the child's DS under the parent's signature
            # (RFC 4035 §3.1.4), which is chain data the descent hands over for free
            # and the only place most lookups ever see it. Even a discarded probe
            # referral carries a DS worth keeping.
            _offer(entry.zone, response, server=entry)
        # Whatever this server offered as an explanation, kept for the reason
        # strings built below. It decides nothing in this loop -- see
        # :func:`_extended_error_note` for the sentence that forbids that.
        ede_note = _extended_error_note(response)
        if bundle and bundle_is_void(response, primary_qtype=int(sname.qtype), requested=bundle):
            # RFC 10029 section 3.5: an answer whose MQTYPE-Response arrives twice,
            # repeats a QTx, or repeats the primary QTYPE is "invalid (equivalent to
            # FORMERR)". Equivalent, so it is handled the way a FORMERR is handled: this
            # server drops out and the next one is asked.
            #
            # Where the check sits matters more than the rule. Before classify, and so
            # before the cache write below, an answer the client has been told to discard
            # is never stored -- and a later lookup that found it waiting in the cache
            # would make the discard a formality, which is exactly the bug this branch
            # replaced. Asking somewhere else is also the only remedy that can succeed:
            # the server that contradicted itself will contradict itself again.
            LOGGER.debug("resolver_mqtype_invalid(dst=%s)", entry.ns)
            _note_demotion(entry, "invalid MQTYPE-Response")
            yield Demote(entry, "invalid MQTYPE-Response")
            slist.demote(entry)
            continue
        terminal = False
        alias_target = None
        for step in classify(
            response,
            sname,
            slist,
            entry,
            max_alias_hops=max_alias_hops,
            glue_policy=glue_policy,
        ):
            if probe is not None and not isinstance(step, (Demote, Referral, VolunteeredGlue)):
                # A probe response is not a statement about the original
                # QNAME: "com. has no A record" must never become the final
                # NODATA for www.example.com. RFC 9156 section 3 step 4 is
                # the instruction -- take the next name in Slist -- which in
                # this codebase is a demote: the probed entry drops in rank,
                # the response is discarded, and nothing about a probe may
                # reach the cache keyed on the QNAME. Referrals (slist has
                # already descended inside classify) and the volunteered-glue
                # notes that annotate them fall through normally.
                #
                # The zone is recorded as having answered, and its demotion is
                # deliberately *not* recorded: a server that answered a probe
                # too well is not the "non-responsive zone" RFC 9520 section 3.3
                # is written about, and a finished probe walk across every
                # server of a healthy zone must not leave that zone marked dead.
                answered.add(entry.zone)
                yield Demote(entry, f"probe {probe} returned no referral")
                slist.demote(entry)
                break
            if not isinstance(step, (Demote, Fail)):
                # Anything a caller can act on is proof that this zone is
                # talking -- a referral, an answer, an alias, glue offered. That
                # proof outlives a later demotion of another server in the same
                # lookup, which is what keeps the exclusion above honest.
                answered.add(entry.zone)
            # Write to cache *before* yielding the terminal event so callers
            # (including tests) can observe a populated cache the moment the
            # Answer/Nxdomain/Nodata is visible — the generator pauses at
            # ``yield step`` and may never be resumed past Done.
            sec_verdict = None
            sec_zone = None
            if (
                sec_validator is not None
                and response is not None
                and isinstance(step, (Answer, Nodata, Nxdomain))
            ):
                # The verdict is computed here, at the moment the response and
                # every record that can judge it are both in hand -- not later at
                # the cut or the cache read, when the keys may have aged out of
                # cache and the walk would be re-judging a memory with fresh
                # questions about data it can no longer see. RFC 4035 §4.5's
                # atomic-entry guidance caches a response as one unit for one
                # TTL; the verdict rides along as the entry's own history of
                # that check. Positive answers joined the same machinery when AD
                # needed them: §3.2.3 makes the bit speak for every RRset in the
                # answer, so the judgment is the composite over them all.
                if isinstance(step, Answer):
                    # The zone an authoritative answer speaks for. validate_rrset
                    # consults it only for the unsigned case -- a signed RRset's
                    # own Signer's Name drives the chain -- and the unsigned case
                    # is exactly where "which zone is answering" decides Insecure
                    # from Bogus. entry.zone is what the walk believes; classify
                    # has already refused to treat a non-authoritative packet
                    # this way, so an answer reaching here came from the zone it
                    # claims.
                    sec_zone = entry.zone if entry is not None else None
                    # The defaults bind what the one-and-only call of this thunk
                    # needs; nothing here outlives the iteration, but a closure
                    # over loop-reassigned names would be a bug waiting for a
                    # `break` to be added, and B023 is right to call it.
                    sec_verdict = yield from _fetch_chain(
                        lambda sec_zone=sec_zone, response=response, qtype=int(sname.qtype): (
                            _judge_answer(sec_validator, response, sec_zone, qtype)
                        )
                    )
                else:
                    denial_rcode = (
                        DnsResponseCode.NAME_ERROR
                        if isinstance(step, Nxdomain)
                        else DnsResponseCode.NO_ERROR
                    )
                    soa = getattr(step, "soa", None) or next(
                        (r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)),
                        None,
                    )
                    # The SOA the answer carries is the denying zone's own apex (RFC 8020
                    # Appendix A: "The accompanying SOA record indicates the apex of the
                    # zone"), which beats trusting the Slist's idea of the current zone
                    # when a server has answered for a name it does not control.
                    sec_zone = soa.name if soa is not None else entry.zone
                    sec_verdict = yield from _fetch_chain(
                        lambda sec_zone=sec_zone, denial_rcode=denial_rcode, response=response: (
                            sec_validator.validate_denial(
                                sname.qname,
                                int(sname.qtype),
                                rcode=denial_rcode,
                                zone=sec_zone,
                                # The response's own CO echo, not this resolver's
                                # knob: §5.1's shape stands on what the server
                                # said back, and an unsolicited one is no less
                                # signed for not having been asked.
                                co_signaled=response.compact_answers_ok,
                            )
                        )
                    )
                if sec_verdict.status is SecurityStatus.BOGUS and not client_cd:
                    # The walk is this client's validator (RFC 4035 §3.2.2¶3
                    # inverted: CD is clear, so the authentication duty is
                    # ours), and a response that failed validation is not an
                    # answer. It is also not cacheable: RFC 4035 §4.7's
                    # BAD-data cache is the optional one, and storing forged
                    # evidence would let the RFC 8020 cut -- which ALLOWS
                    # serving an ancestor's denial for every name beneath it --
                    # launder one poisoned packet into a subtree-wide lie, and
                    # let the next reader of a poisoned positive RRset serve it
                    # as the name's own answer. What §9520 §3.4 does make
                    # mandatory is caching the *failure*, which the note below
                    # files with §3.2's backoff -- 4.7¶4's amplification guard,
                    # met by the machinery 9520 was written to standardise.
                    yield DnssecVerdict(str(sec_zone), sec_verdict.status.value, sec_verdict.reason)
                    _remember_dnssec(sec_verdict.reason)
                    refused = Response(
                        QR=DnsQR.RESPONSE,
                        RCODE=DnsResponseCode.SERVER_FAILURE,
                        questions=list(sname.questions),
                    )
                    # A marker, not an option: the OPT record a walk collects
                    # is stripped on egress and rebuilt (RFC 6891 §6.1.1 says
                    # OPT is never forwarded), so the reason rides as this
                    # attribute and the serving side turns it into RFC 8914
                    # §4.7's EDE 6 -- "the resolver attempted DNSSEC
                    # validation, but validation ended in the Bogus state" is
                    # precisely what happened, and 22 (no reachable authority)
                    # would name the wrong fault.
                    refused.dnssec_bogus = True
                    yield Done(refused)
                    return
            # A CD lookup validated nothing -- §4.2¶2 waived the checks -- and data
            # nobody checked must not enter the cache this validator's other
            # answers are drawn from. The strip-a-signature attacker's cheapest
            # move is to poison through a CD client; refetching for CD callers is
            # the whole cost of closing it.
            if (
                cache is not None
                and isinstance(step, (Answer, Nodata, Nxdomain))
                and not (sec_validator is not None and client_cd)
            ):
                validated_flag = bool(sec_verdict is not None and sec_verdict.ad_worthy)
                cache_step = step
                if (
                    sec_verdict is not None
                    and sec_verdict.via_compact
                    and isinstance(step, Nxdomain)
                ):
                    # RFC 9824 §6¶3, in the walk's own words: no NXDOMAIN
                    # synthesis "in the style described by [RFC8020]" survives
                    # compact denial, because the evidence here is a record
                    # that asserts exactly one name -- its successor form
                    # (§3.1¶2's null-label prepend, §4¶5's hash plus one) is
                    # the empty span §8¶4 counts on. A Nxdomain entry is the
                    # shape that cuts subtrees at read time, so the restored
                    # RCODE the client may see in the packet is not a license
                    # for the cache: stored as the name-level denial the
                    # proof actually is.
                    cache_step = Nodata(soa=soa)
                _write_cache(
                    cache,
                    sname,
                    cache_step,
                    response,
                    validated=validated_flag,
                )
                if validated_flag and sec_material:
                    # The verdict is secure and the chain it stood on is in
                    # hand: file it (see `_file_chain_record`'s ledger and
                    # `_cache_chain`'s rules). An insecure verdict writes
                    # nothing -- its chain evidence is the signed no-DS proof,
                    # and that already lives in the denial's bundle; a bogus
                    # one never reaches here at all.
                    _cache_chain(cache, sec_material, clock)
            if (
                failures is not None
                and isinstance(step, (Answer, Nodata, Nxdomain))
                # Forgetting says "this name resolved after all" -- a claim a CD
                # lookup cannot make, having checked nothing (§4.2¶2). Clearing a
                # validation failure on the strength of unvalidated data would let
                # one CD query unlock the suppression every non-CD query needs.
                and not (sec_validator is not None and client_cd)
            ):
                # Recovery, and it has to be explicit rather than left to the clock.
                # An answer is direct evidence that whatever was remembered about
                # this name is stale and that every zone which spoke during this
                # lookup is alive, so both the suppression and the strike counts go.
                # Leaving the counts behind would let a zone that flapped once meet
                # its next genuine outage already at the ceiling, which is the bad
                # trade: slow to notice the second failure of something that has
                # since recovered. RFC 9520 section 3.3's worry -- that cached
                # failures make a resolver slow to see recovery -- is answered here,
                # not by the five-minute ceiling alone.
                failures.forget(sname.qname, sname.qtype, sname.qclass)
                if origin != sname.qname:
                    failures.forget(origin, sname.qtype, sname.qclass)
                for zone in answered:
                    failures.forget_zone(zone)
            if isinstance(step, Fail):
                # Recorded, not yielded yet: `classify` fails for a reason that
                # belongs to the name rather than to a server -- an alias loop or
                # a chain past the budget, from `_follow_aliases` -- so this is
                # the query key's business, and RFC 9520 section 2.5 lists alias
                # loops among the failures worth remembering.
                _remember(step.reason)
            if sec_verdict is not None:
                if response is not None and sec_verdict.ad_worthy:
                    # RFC 4035 §3.2.3: AD means this server considers the Answer
                    # and relevant negative-response RRs authentic -- and this is
                    # the only moment in the walk entitled to say so, with the
                    # verdict freshly derived under this resolver's own anchors.
                    # `ad_worthy` carries the second half of the rule too: an
                    # Opt-Out next closer proves the denial without proving the
                    # name absent (RFC 5155 §9.2¶1's MUST NOT), so the bit stays
                    # down on an otherwise-secure verdict.
                    response.AD = True
                # Before the event it judged: the verdict is why the NXDOMAIN below
                # may cut, and a reader should meet the reason before the fact.
                yield DnssecVerdict(str(sec_zone), sec_verdict.status.value, sec_verdict.reason)
                if sec_verdict.secure and sec_verdict.via_compact:
                    # Between the verdict and the denial it judged: this line
                    # is the only place the trace says why an NXDOMAIN from
                    # here will not cut, and the word `restored` separates
                    # §5.1's moved RCODE from the NOERROR shape that carries
                    # the signal alone.
                    yield CompactDenial(str(sname.qname), restored=isinstance(step, Nxdomain))
            yield step
            if isinstance(step, (Done, Fail)):
                # Fail is terminal for the same reason Done is: classify emits it
                # when the response itself is unusable, and any Cname recorded a
                # moment earlier in the same response must not then be re-anchored
                # and queried again.
                terminal = True
                break
            if isinstance(step, Demote):
                # The server's own words ride along with the reason this demotion is
                # remembered for, so a zone declared dead reads as "rcode SERVFAIL;
                # EDE 22 (No Reachable Authority)" instead of repeating the RCODE the
                # trace already shows. RFC 9520 section 3.2 governs how long the entry
                # lives and says nothing about its text, so this is a pure gain in what
                # an operator learns about why the walk stopped.
                _note_demotion(step.entry, f"{step.reason}{ede_note}")
                slist.demote(step.entry)
            elif isinstance(step, Cname):
                # Recorded, not acted on yet: classify also emits Cname when a
                # chain completes inside one response, and that case must not
                # restart anything. Only a chain that stopped short of Done
                # leaves the lookup needing a new SNAME.
                alias_target = step.target
        if terminal:
            return
        if alias_target is None:
            continue
        if alias_target in seen_names:
            # RFC 1034 §3.6.2 forbids an alias resolving to itself "directly or
            # indirectly"; a server offering that is broken, and re-querying it
            # is how a resolver hangs rather than fails.
            _remember(f"alias loop at {alias_target}")
            yield Fail(f"alias loop at {alias_target}")
            return
        if alias_hops >= max_alias_hops:
            _remember(f"alias chain longer than {max_alias_hops}")
            yield Fail(f"alias chain longer than {max_alias_hops}")
            return
        seen_names.add(alias_target)
        alias_hops += 1
        sname.reanchor(alias_target)
        if minimiser is not None:
            # The QNAME changed, and RFC 9156 section 2's CHILD is defined
            # against the QNAME -- so the schedule restarts for the target.
            # A completed probe walk against the old name must not leave a
            # spent budget narrowing probes against the new one.
            minimiser = QnameMinimiser(sname.qname)
    _remember("max hops")
    yield Fail("max hops")


#: How many upstream EDEs a single failure reason will carry. RFC 8914 section 3
#: leaves the number of options in a message to the sender ("Senders MAY include
#: more than one EDE option"), and a reason that quotes twenty of them has stopped
#: reading as a reason.
_MAX_NOTED_ERRORS = 3


def _extended_error_note(response) -> str:
    """What the server said about why it failed, as a fragment of a reason string.

    Empty unless the response carried an ERROR option. Note what it is *not*: a
    code to branch on. RFC 8914 section 3 -- "Applications MUST continue to follow
    requirements from applicable specifications on how to process RCODEs no matter
    what EDE values are also received" -- is why this returns text, and section 6's
    "EDE content should be treated only as diagnostic information and MUST NOT
    alter DNS protocol processing" is why a malformed option, or a malformed OPT,
    is swallowed here rather than becoming a failure the client never saw.

    The words are somebody else's, so they arrive escaped and capped
    (:func:`~namespy.edns.extended_error_presentation`) and go only into a reason
    string that a trace or a log prints.
    """
    if response is None:
        return ""
    try:
        options = response.edns_options()
    except DnsPacketParseError:
        return ""
    errors = extended_errors_of(options)
    if not errors:
        return ""
    noted = "; ".join(
        f"EDE {extended_error_presentation(error)}" for error in errors[:_MAX_NOTED_ERRORS]
    )
    if len(errors) > _MAX_NOTED_ERRORS:
        noted += f" (+{len(errors) - _MAX_NOTED_ERRORS} more)"
    return "; " + noted


def _cached_failure_reason(entry) -> str:
    """Render a remembered failure as the reason a trace and a log can use.

    The two shapes read differently on purpose: a zone failure names the zone,
    because that -- not the QNAME in front of the operator -- is the thing that
    is not answering, and the strike count says whether this is a first
    one-second refusal or a name that has been refused for five minutes.
    """
    subject = f"zone {entry.zone}" if entry.zone is not None else "this name"
    return f"cached failure for {subject}: {entry.reason} (strike {entry.strikes})"


def _nxdomain_cut(cache, name, qclass, require_validated=False):
    """The cached NXDOMAIN that denies *name*, or ``None`` (RFC 8020 §2¶1).

    Walks the name's ancestors from the closest down, the name itself included,
    and stops at the first denial.

    ``require_validated`` is :attr:`NxdomainPolicy.VALIDATED`'s filter, and it is a
    filter on the *entry*, not a re-check: RFC 8020 §2¶3 lets the cut stand only
    "when the NXDOMAIN response has been validated with DNSSEC", and the answer to
    that question was decided -- with the chain data still in hand -- when the
    denial arrived. An entry without the flag is not disbelieved, merely unproved:
    the walk continues as :attr:`NxdomainPolicy.NEVER` would, which is the stance
    the policy promises when it cannot honour its own. ``getattr`` rather than an
    attribute read because third-party cache backends may predate the flag, and a
    backend that never stamped anything must not crash the cut -- it simply never
    grants it.

    Including the name is not redundancy with :meth:`~namespy.cache.DnsCache.get`,
    and it took a failing test to see why. §2¶1 covers "all names and resource
    record sets (RRsets) *at* or below that node", and the node is the name that
    was denied -- so the denial that arrived for an A is also a statement about
    every other RRset at that name, which a per-type lookup (RFC 2308's model)
    cannot see. Appendix A is the other half of why the key is this name: "we
    deduce the nonexistence of a domain only for NXDOMAIN answers where the denied
    name was the exact domain ... The accompanying SOA record indicates the apex of
    the zone, not the closest existing domain name."

    Closest-first is not cosmetic either. The SOA the answer carries has to come
    from the zone that made the denial, and a denial at ``example.com`` proves
    less than one at ``foo.example.com``: taking the outermost match would answer
    for a subtree using evidence about a smaller one. Stopping at the first hit is
    also what keeps this cheap -- each step is one indexed lookup, and the walk is
    as long as the name has labels.

    The ancestor is returned alongside the entry, and it is the ancestor *as the
    queried name spells it*, not as the cached entry happens to be stored: case
    is not significant (RFC 1035 §3.1) but it is very visible in a trace line, and
    "www.Foo.EXAMPLE denied by FOO.example" reads like two names when it is one.

    Only NXDOMAIN may cut. :meth:`~namespy.cache.DnsCache.nxdomain_at` is what
    enforces that per backend, so a cache that cannot answer the question returns
    ``None`` and the walk continues: RFC 8020 is a SHOULD, and asking again is
    never wrong.
    """
    for ancestor in reversed(DomainName(name).hierarchy()):
        hit = cache.nxdomain_at(ancestor, qclass)
        if hit is None:
            continue
        if require_validated and not getattr(hit, "validated", False):
            continue
        return hit, ancestor
    return None


def _synthesize_response(sname, hit, dnssec_ok: bool = False, validated: bool = False):
    """Build a synthetic :class:`Response` from a cache hit.

    The resolver's outer code expects a :class:`Response` from a successful
    resolution (it stamps the original packet's ``ID`` onto it); we manufacture
    one whose AN/NS sections reflect the cached entry.

    *validated* is the caller's decision, not this function's reading of the
    entry: it means "this resolver is a validator, and this entry carries its
    SECURE stamp", and it sets the header's AD bit (RFC 4035 §3.2.3 — the claim
    is that *this server* considers the answer authentic, which a remembered
    verdict supports for exactly as long as the entry lives). Left false for a
    non-validating resolver even when a stamp is present: without anchors of its
    own this server has no basis to vouch, and §3.1.6¶3 says so in MUSTNOT terms.

    *dnssec_ok* decides whether the denial's proof records travel with it, and it means "this
    resolver asked the authorities for DNSSEC data" -- the instance knob, not a client's DO bit.
    RFC 8020 §2¶5 is a MUST with a condition on the *query*: "the iterative, caching resolver MUST
    return these NSEC or NSEC3 records in the response to the triggering query if the query had the
    DNSSEC OK (DO) bit set". Answering the condition here by looking at the client would split the
    policy across two components, so the full answer is assembled now and a server that served a
    DO=0 client withdraws it on the way out (RFC 4035 §3.2.1, ``DnsServer._strip_dnssec``). One
    place decides what a client may see; the cache, which knows nothing about clients, just does not
    lose the evidence.

    A known limitation of echoing the bundle: the SOA that rides along is unsigned, because an RRSIG
    covering the SOA is not a proof of anything and so was never stored with the proofs. RFC
    4035 §3.1.1¶3's "MUST also place its RRSIG RRs in the Authority section" is addressed to an
    authoritative server composing a reply from the zone, not to a recursive server's synthetic
    response, so this is a gap in what a client could validate rather than a rule broken -- and it is
    on the roadmap next to the response-level validators, which will want that signature anyway.
    """
    questions = list(sname.questions)
    if isinstance(hit, PositiveEntry):
        return Response(
            QR=DnsQR.RESPONSE,
            AA=hit.authoritative,
            AD=validated,
            RCODE=DnsResponseCode.NO_ERROR,
            questions=questions,
            answers=list(hit.records),
        )
    rcode = hit.rcode if isinstance(hit.rcode, DnsResponseCode) else DnsResponseCode(int(hit.rcode))
    nameservers = [hit.soa] if hit.soa is not None else []
    if dnssec_ok:
        # getattr, not an attribute read: the cache protocol is duck-typed, and a third-party
        # backend written before proofs existed must answer lookups rather than raise.
        nameservers.extend(getattr(hit, "proofs", ()) or ())
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        AD=validated,
        RCODE=rcode,
        questions=questions,
        nameservers=nameservers,
    )


#: RFC 8767 §4¶4's recommended client-facing TTL for served-stale records --
#: §6¶6 explains the number: 0 broke old implementations and tiny values
#: invite a TTL-honouring client to re-query in a loop, while 30 seconds both
#: sidesteps that and rate-limits the retry.
_STALE_TTL = 30


def _synthesize_stale(sname, hit, dnssec_ok: bool = False) -> Response:
    """The response a failed refresh delivers from an expired entry (RFC 8767 §4, §7¶3).

    The assembly is the cached-answer one -- a stale positive is still a
    positive, a stale denial still carries its SOA and, under DO, its proof
    records. Three differences, each a section of its own. No record keeps
    its stored TTL: every one has expired, and §4¶4's MUST replaces them with
    a value greater than 0 (the records are *rebuilt*, never edited -- the
    originals belong to the cache entry, which must still serve its window to
    every other question). ``AD`` never rides: RFC 4035 §3.2.3's claim is
    present tense, and this data outlived the verdict that earned it;
    §10¶1's calculus accepts serving stale signatures for reachability, not
    asserting them. And the ``stale_answer`` marker rides the response so the
    serve side can tell the client what happened (RFC 8914 §4.2's EDE, and
    the reason §9's rejected opt-in EDNS option is not missed: the extended
    error says in one field what the option would have signalled in two).
    """
    response = _synthesize_response(sname, hit, dnssec_ok, validated=False)
    response.stale_answer = True
    response.answers = [
        DnsRecord(
            record.name,
            record.rtype,
            record.rclass,
            min(int(record.ttl), _STALE_TTL),
            rdata=record.rdata,
        )
        for record in response.answers
    ]
    response.nameservers = [
        DnsRecord(
            record.name,
            record.rtype,
            record.rclass,
            min(int(record.ttl), _STALE_TTL),
            rdata=record.rdata,
        )
        for record in response.nameservers
    ]
    return response


# ------------------------------------------------------------------ chain records (§4.5)
#
# RFC 4035 §4.5¶1 asks for the atomic entry -- the RRset and its signatures as
# one cacheable unit, discarded whole when any part expires -- and every query
# the walk sends, helper ones included, receives such a response. The chain
# fetches §5.2¶6 demands are therefore cacheable like any other answer, and
# the resolver's own secure verdicts are what license the write: these exact
# bytes were verified against this resolver's anchors end to end a moment ago.

#: The two RR types the authentication chain is made of: the DS that vouches
#: for a zone's keys (RFC 4033 §5's first link) and the DNSKEY the signatures
#: verify against. Proofs ride elsewhere (denial bundles), and NSEC3 needs no
#: parameter record -- each NSEC3 carries its own (RFC 5155 §3).
CHAIN_CACHE_TYPES: frozenset[int] = frozenset({int(DnsRType.DNSKEY), int(DnsRType.DS)})


def _file_chain_record(material: dict, record) -> None:
    """Add one chain-shaped record to the lookup's ledger, deduplicated.

    Grouped by owner and the RRset it belongs to -- a DNSKEY/DS by its own
    type, an RRSIG by its Type Covered, which is how §4.5¶1's atomic entry
    reassembles: owner plus type is exactly the <QNAME, QTYPE> pair the entry
    will be stored under, and the signature's owner is the RRset owner by
    §3.1.1, so data and covering signatures meet in one group whatever zone
    signed them (the DS at a cut is signed by the parent; the group is still
    the DS's).
    """
    code = int(record.rtype)
    if code in CHAIN_CACHE_TYPES:
        group_type = code
    elif code == int(DnsRType.RRSIG):
        covered = int(getattr(record.rdata, "type_covered", 0) or 0)
        if covered not in CHAIN_CACHE_TYPES:
            return
        group_type = covered
    else:
        return
    slot = material.get((name_order_key(record.name), group_type))
    if slot is None:
        slot = material[(name_order_key(record.name), group_type)] = {
            "name": record.name,
            "rtype": group_type,
            "rclass": record.rclass,
            "records": [],
            "seen": set(),
        }
    blob = bytes(record.rdata)
    if blob not in slot["seen"]:
        slot["seen"].add(blob)
        slot["records"].append(record)


def _chain_is_live(records, now) -> bool:
    """Whether the group carries at least one RRSIG and every one still covers *now*.

    Both halves bite. A group with no signature could not have passed the
    verification whose verdict licenses the write, so its presence means
    someone hand-built the entry -- unusable. A signature outside its window
    ends the record's usable life however long its TTL runs: §4.5¶1 counts the
    signatures as part of the atomic entry, and RFC 8198 §7's sentence says
    "or signatures" for a reason §9¶4's poisoned-long-TTL scenario makes
    practical. This is a window read, not a re-verification: the validator
    still checks the bytes themselves when the chain next runs.
    """
    signatures = [record for record in records if int(record.rtype) == int(DnsRType.RRSIG)]
    if not signatures:
        return False
    return all(
        isinstance(record.rdata, RData_RRSIG) and record.rdata.within_validity(now)
        for record in signatures
    )


def _cache_wildcard_template(cache, sname, response, now) -> None:
    """Store the wildcard an expanded answer came through, if it came through one.

    RFC 4035 §4.5¶4 spells this entry out by name: "By using the RRSIG record,
    it is possible to deduce that an answer was synthesized from a wildcard.
    A security-aware recursive name server could store this wildcard data and
    use it to generate positive responses to queries other than the name for
    which the original answer was first received." The deduction is the Labels
    field (§4.5¶4's "by using the RRSIG record"): a signature taken through a
    wildcard carries the wildcard's label count, one short of the expanded
    owner's -- the same arithmetic §5.4¶3 reads on the NSEC side and
    ``_validate_wildcard`` read at judgment time, and the name is rebuilt the
    identical way with ``signed_owner_name``.

    It reads the wire packet, not the cached entry, because the entry is the
    *queried* name's data without its signature (AD rides the stamp); the
    answer section is where the covering RRSIG still sits beside the records it
    signed. The records are then stored at the wildcard's own name, which is
    who they really belong to -- the wire's owner is a presentation of an
    expansion this entry will use for other names too, and the signature was
    computed over the wildcard's canonical RRset. Two types never template: a
    wildcard owning SOA "can never be a source of synthesis" (RFC 4592 §4.1¶1)
    and a wildcard owning NS has semantics RFC 4592 §4.2¶3 leaves deliberately
    undefined. The gate is the caller's ``validated``: an answer this resolver
    judged secure is the only warrant a template needs -- the judgment already
    verified the closer-match proof (§5.3.4) for these exact bytes.
    """
    qtype = int(sname.qtype)
    if response is None or qtype in (int(DnsRType.SOA), int(DnsRType.NS)):
        return
    data = [r for r in response.answers if int(r.rtype) == qtype]
    sigs = [
        r
        for r in response.answers
        if int(r.rtype) == int(DnsRType.RRSIG)
        and int(getattr(r.rdata, "type_covered", 0) or 0) == qtype
    ]
    if not data or not sigs:
        return
    sig = sigs[0].rdata
    owner = data[0].name
    try:
        wildcard, from_wildcard = signed_owner_name(owner, int(sig.labels))
    except ValueError:
        return  # Labels exceeds the owner's count: a signature over nothing anyone named
    if not from_wildcard:
        # Equal counts mean the name signed itself: the answer is this name's,
        # not a wildcard's, and nothing wider may be deduced from it (§5.4¶3's
        # "wildcard expansion could not have been used").
        return
    template = [
        DnsRecord(wildcard, r.rtype, r.rclass, r.ttl, rdata=r.rdata) for r in (*data, *sigs)
    ]
    ttl = min(int(getattr(r, "ttl", 0) or 0) for r in template)
    if ttl <= 0:
        return
    existing = cache.get(wildcard, qtype, sname.qclass)
    if isinstance(existing, PositiveEntry) and existing.expires_at >= now + ttl:
        return  # a live template -- or the name's own explicit answer -- already speaks
    cache.put(
        PositiveEntry(
            wildcard,
            qtype,
            sname.qclass,
            template,
            now + ttl,
            authoritative=True,  # the zone signed this RRset at this owner name
            validated=True,
        )
    )


def _cache_chain(cache, material, now) -> None:
    """File the lookup's verified chain material, one atomic entry per RRset.

    The gate is the caller's: it has just seen a secure verdict, which is what
    makes these bytes ones this resolver verified, and the write stamps them so
    the read side can tell verified material from some other client's DNSKEY
    query that merely resolved. Unsigned groups are refused entry rather than
    half-cached (§3.1.4¶2's DS-with-its-RRSIGs is the shape secure chains
    arrive in). TTL is the group's own minimum -- §4.5¶1's atomic discard,
    measured on the cache's clock; the signature window on the signature's
    clock is filtered at load by `_chain_is_live`, the same two-clock honesty
    the aggressive layer learned. A fresher stamped entry already filed for
    the same RRset is kept: a lookup that re-verified nothing newer must not
    age out data a later signature extends.
    """
    cache_now = cache.time_fn()
    for slot in material.values():
        records = slot["records"]
        has_data = any(int(r.rtype) != int(DnsRType.RRSIG) for r in records)
        if not has_data or not _chain_is_live(records, now):
            continue
        ttl = min(int(getattr(r, "ttl", 0) or 0) for r in records)
        if ttl <= 0:
            continue
        owner = slot["name"]
        rclass = slot["rclass"]
        existing = cache.get(owner, slot["rtype"], rclass)
        if (
            isinstance(existing, PositiveEntry)
            and getattr(existing, "validated", False)
            and existing.expires_at >= cache_now + ttl
        ):
            continue
        cache.put(
            PositiveEntry(
                owner,
                slot["rtype"],
                rclass,
                records,
                cache_now + ttl,
                authoritative=True,  # it came straight from the zone that signs it
                validated=True,
            )
        )


def _negative_ttl_seconds(soa_record):
    """RFC 2308 §5: cap negative-cache TTL at ``min(SOA.MINIMUM, SOA.TTL)``.

    §3 puts the obligation on the authoritative server ("the TTL of this record
    is set from the minimum of the MINIMUM field of the SOA record and the TTL of
    the SOA itself"), but a cache must not be more generous than the spec allows,
    so the same clamp is applied here on the way in.

    Returns ``0`` when no SOA is present, which callers treat as "do not cache":
    §5 says negative responses without an SOA "SHOULD NOT be cached as there is
    no way to prevent the negative responses looping forever between a pair of
    servers even with a short TTL".
    """
    if soa_record is None:
        return 0
    ttl = int(getattr(soa_record, "ttl", 0) or 0)
    minimum = getattr(getattr(soa_record, "rdata", None), "minimum", None)
    if minimum is not None:
        return max(0, min(int(minimum), ttl))
    return max(0, ttl)


def _write_cache(cache, sname, terminal_event, response, validated=False):
    """Populate ``cache`` from a terminal classify event.

    ``terminal_event`` is the most recent of (Answer, Nodata, Nxdomain)
    yielded for this response; ``response`` is the corresponding wire
    packet (used for the AA flag and to dig the SOA out of the authority
    section on NXDOMAIN). ``validated`` is the walk's verdict on this response
    under its trust anchors -- fully verified, AD-worthy and (for a denial)
    cut-worthy -- and ``False`` whenever nothing was checked or what was
    checked came up short, which is the only state a non-validating resolver
    may assert.

    A truncated response is never stored. RFC 1123 section 6.1.3.2 states it as
    a prohibition -- "Truncated responses MUST NOT be saved (cached) and later
    used in such a way that the fact that they are truncated is lost" -- and
    RFC 1035 section 7.4 explains why: a partial RRset is indistinguishable from
    a complete one once stored, so caching one lets a single truncated answer
    masquerade as authority for the whole RRset. This is a second line of defence
    behind the TCP retry in :meth:`RecursiveResolver.query`, because TCP can also
    carry ``TC`` from a misbehaving server, and a caller that drives
    :func:`resolve_steps` directly has no transport layer to protect it.
    """
    if response is not None and getattr(response, "TC", False):
        return
    now = cache.time_fn()
    if isinstance(terminal_event, Answer):
        # RFC 6891 section 6.2.1: "The OPT record MUST NOT be cached, and
        # MUST NOT be treated as a normal RRset while caching." This resolver
        # never asks QTYPE=OPT, but resolve_steps is public and a diagnostic
        # caller can; the cache is where that has to bounce.
        records = [r for r in terminal_event.records if int(r.rtype) != OPT_RTYPE]
        if not records:
            return
        ttl = min(int(getattr(r, "ttl", 0) or 0) for r in records)
        if ttl <= 0:
            return
        cache.put(
            PositiveEntry(
                sname.qname,
                sname.qtype,
                sname.qclass,
                records,
                now + ttl,
                authoritative=bool(getattr(response, "AA", False)),
                validated=validated,
            )
        )
        if validated:
            _cache_wildcard_template(cache, sname, response, now)
        return
    if isinstance(terminal_event, Nodata):
        ttl = _negative_ttl_seconds(terminal_event.soa)
        if ttl <= 0:
            return
        cache.put(
            NegativeEntry(
                sname.qname,
                sname.qtype,
                sname.qclass,
                DnsResponseCode.NO_ERROR,
                terminal_event.soa,
                now + ttl,
                collect_proof_records(response.nameservers) if response is not None else (),
                validated=validated,
            )
        )
        return
    if isinstance(terminal_event, Nxdomain):
        soa = None
        if response is not None:
            soa = next(
                (r for r in response.nameservers if r.rtype == DnsRType.SOA),
                None,
            )
        ttl = _negative_ttl_seconds(soa)
        if ttl <= 0:
            return
        cache.put(
            NegativeEntry(
                sname.qname,
                sname.qtype,
                sname.qclass,
                DnsResponseCode.NAME_ERROR,
                soa,
                now + ttl,
                collect_proof_records(response.nameservers) if response is not None else (),
                validated=validated,
            )
        )


class RecursiveResolver(Resolver):
    def error_received(self, exception):
        if isinstance(exception, gaierror):
            pass
        self.log.critical(exception)

    def record_reader(self, zone_file, source=None):
        """Read NS and address records from a root-hints style master file.

        Accepts a filesystem path, an :mod:`importlib.resources` traversable, or
        any readable file-like object -- the packaged hints are read through a
        traversable, fetched hints come from a string, and a user's own file comes
        as a path, and none of those three should need a temp file to reach here.

        Unrecognised lines are skipped with a warning naming the line number. The
        file is authoritative-server documentation rather than attacker input, but
        the two-line comment header in ``named.root`` is *not* unusual, and a
        previous version treated a blank line as an unrecognised entry and warned
        once per blank line.

        Deliberately unimplemented: ``$ORIGIN``/``$TTL`` directives and the
        owner-name inheritance rules of RFC 2308 section 2, because root hints use
        neither -- every line is fully qualified. Do not use this to load a real
        zone file.
        """
        source_name = source if source is not None else str(zone_file)
        lines = self._master_file_lines(zone_file)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            tokens = re.split(r"\s+", stripped)
            if len(tokens) == 5:
                (name, ttl, rclass, rtype, rdata) = tokens
                try:
                    rclass = DnsRClass[rclass]
                except KeyError:
                    self.log.warning(
                        "Unrecognized class %r on line %d of zone file: %s",
                        rclass,
                        i,
                        source_name,
                    )
                    continue
            elif len(tokens) == 4:
                (name, ttl, rtype, rdata) = tokens
                rclass = DnsRClass.IN  # hints are IN-class; RFC 8106 section 2
            else:
                self.log.warning("Unrecognized entry on line %d of zone file: %s", i, source_name)
                continue

            try:
                rtype = DnsRType[rtype]
                ttl = int(ttl)
            except (KeyError, ValueError):
                self.log.warning(
                    "Skipping line %d of %s: unrecognized type %r or TTL %r",
                    i,
                    source_name,
                    rtype,
                    ttl,
                )
                continue

            try:
                record_name = DomainName(name)
                if rtype == DnsRType.NS:
                    yield DnsRecord(record_name, rtype, rclass, ttl, rdata=DomainName(rdata))
                elif rtype == DnsRType.A:
                    yield DnsRecord(
                        record_name,
                        rtype,
                        rclass,
                        ttl,
                        rdata=RData_A(ipaddress.IPv4Address(rdata)),
                    )
                elif rtype == DnsRType.AAAA:
                    yield DnsRecord(
                        record_name,
                        rtype,
                        rclass,
                        ttl,
                        rdata=RData_AAAA(ipaddress.IPv6Address(rdata)),
                    )
                else:
                    self.log.debug(
                        "Skipping %s record for %s on line %d of %s",
                        rtype,
                        record_name,
                        i,
                        source_name,
                    )
            except (ValueError, TypeError) as exc:
                self.log.warning(
                    "Skipping malformed glue on line %d of %s: %s", i, source_name, exc
                )
                continue

    @staticmethod
    def _master_file_lines(zone_file):
        """Yield the text lines of a path, traversable, or readable object.

        Every branch that opens something closes it. The traversable branch used
        to be ``zone_file.open("r", encoding="utf-8").read()`` with no close at
        all, which leaked a descriptor on every hints load -- a ResourceWarning
        under CI, and a real leak for a resolver that refreshes its root hints in
        a long-lived process. An object handed in already open is *not* closed
        here: the caller opened it, so the caller keeps ownership.
        """
        if hasattr(zone_file, "read"):
            data = zone_file.read()
        elif hasattr(zone_file, "open"):  # importlib.resources.Traversable
            with zone_file.open("r", encoding="utf-8") as handle:
                data = handle.read()
        else:
            with open(zone_file, encoding="utf-8") as handle:
                data = handle.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        return iter(data.splitlines())

    #: Where the root server address set comes from (RFC 8106 section 2: a
    #: resolver needs an initial set of root server addresses, and the only
    #: questions are where it got them and how stale they are).
    ROOT_HINTS_URL = "https://www.internic.net/domain/named.root"

    def __init__(
        self,
        root_hints_path=None,
        dns_suffix=None,
        cache=None,
        failure_cache=None,
        max_hops: int = MAX_HOPS,
        max_depth: int = MAX_DEPTH,
        max_alias_hops: int = MAX_ALIAS_HOPS,
        query_timeout: float = QUERY_TIMEOUT_S,
        edns_payload_size: int | None = EDNS_PAYLOAD_SIZE,
        edns_options: Sequence = (),
        qname_min: bool = False,
        glue_policy: GluePolicy = GluePolicy.STRICT,
        nxdomain_cut: NxdomainPolicy = NxdomainPolicy.ALWAYS,
        aggressive_nsec: bool = False,
        serve_stale: float = 0.0,
        dnssec_ok: bool = False,
        compact_answers: bool = False,
        trust_anchors=(),
        opportunistic_dot: bool = False,
        opportunistic_discover: bool = True,
        query_padding: bool = True,
    ):
        """Build a resolver without touching the network.

        :param root_hints_path: a master-file path to read hints from. Left
            ``None``, the copy packaged inside Namespy is used, which is what makes
            ``RecursiveResolver()`` work offline, in a test, and on a host with no
            route to internic. A path that is given but does not exist is an
            error rather than a licence to fetch: silently downloading during
            ``__init__`` also wrote a file into the current working directory.
        :param query_timeout: seconds per UDP attempt (and per TCP phase).
        :param failure_cache: a :class:`~namespy.cache.FailureCache` holding the
            failures this resolver is not to ask about again (RFC 9520). Left
            ``None``, one is created for this resolver, which is what makes the
            second query for a dead name free rather than merely slow. Pass
            ``False`` to switch failure caching off entirely -- wanted when the
            resolver exists to *observe* a broken zone, because a resolver that
            has stopped asking is, from outside, indistinguishable from one that
            is itself broken. Pass an existing cache to share one across
            resolvers, or to choose the TTL bounds and capacity.
        :param edns_payload_size: UDP payload advertised by the EDNS(0) OPT
            record on every outbound query (RFC 6891 section 6.2.3). ``0`` or
            ``None`` sends no OPT at all -- the pre-EDNS behaviour, still
            occasionally wanted against ossified infrastructure, though the
            section 6.2.2 fallback already handles the servers that would
            otherwise need it.
        :param edns_options: EDNS(0) options to send on every outbound query,
            as :class:`~namespy.edns.EdnsOption` instances or ``(code, value)``
            pairs. Asking for a Name Server Identifier -- ``edns_options=(
            nsid_option(),)`` -- makes each server say which instance of itself
            answered, and its reply is logged at INFO and kept in
            :attr:`server_ids`. An empty tuple, the default, sends the same
            bare OPT record this resolver has always sent.
        :param qname_min: enable QNAME minimisation (RFC 9156): servers not
            known to be authoritative for the full QNAME are probed with
            progressively deeper children instead of being handed the whole
            name. Default ``False`` is deliberate -- it changes the question
            every downline server sees, so it earns its default in the field.
        :param glue_policy: whether address data that a referral volunteers for
            a nameserver outside the answering zone may be used as glue. The
            default, :attr:`GluePolicy.STRICT`, is RFC 5452 section 6: only glue
            inside the answering zone or below the cut it delegated is believed.
            :attr:`GluePolicy.PERMISSIVE` believes any name-matching address; it
            is a research instrument rather than a production setting, and
            :class:`GluePolicy` says what accepting costs and what it does not.
            Also accepted as the equivalent string, so a config file or CLI flag
            can hand it over directly.
        :param nxdomain_cut: whether a NXDOMAIN already in the cache may deny the
            names below it without a query. The default,
            :attr:`NxdomainPolicy.ALWAYS`, is RFC 8020 section 2's SHOULD.
            :attr:`NxdomainPolicy.NEVER` answers only the exact name cached and
            walks everything beneath it: correct for watching a zone change, and
            wrong for serving, because it throws away the reason the negative
            cache has a subtree-wide claim at all. :class:`NxdomainPolicy` says
            what each stance costs. Also accepted as the equivalent string.
        :param aggressive_nsec: whether the NSEC/NSEC3 bundles already cached
            with validated denials may answer names and types they were not
            written for -- RFC 8198's aggressive use, gate by gate in
            :mod:`namespy.aggressive`. Off by default because it widens the
            blast radius §9 of that document names: "one successful attack would
            be able to suppress many queries for new names, up to the negative
            TTL", where the default must repeat the attack per query. It also
            does nothing without something to widen: the entries it reads are
            stamped only under trust anchors, so without ``trust_anchors`` set
            this flag is honestly inert.
        :param serve_stale: the maximum-stale timer of RFC 8767 §5¶11, in
            seconds -- 0 (default) never serves expired data; a positive
            value both widens the cache's retention of expired rows to this
            window and lets a walk answer from one when refreshing fails
            (every server for the name spent, or the failure remembered and
            not yet due for a retry). The answer carries §4¶4's greater-than-
            zero TTLs (the recommended 30 seconds), never the AD bit, and is
            marked for RFC 8914 §4.2's Stale Answer EDE on the way out.
        :param trust_anchors: :class:`~namespy.anchors.TrustAnchor` objects to
            validate answers against -- the trust point RFC 4035 §4.4 calls
            "configured" and §4.3 makes the origin of every Secure verdict.
            With any present, every terminal answer this walk receives, positive
            and negative, is judged by :mod:`namespy.validate` (chain composed
            from the walk's own responses, §5.2¶6 gaps fetched; a positive
            answer is judged as a whole, every RRset §3.2.3 names), a fully
            verified one carries the header's AD bit, and the verdict is traced
            as a ``DnssecVerdict`` and stamped ``validated`` into the answer's
            cache entry. Empty,
            the default, validates nothing -- and :attr:`NxdomainPolicy.VALIDATED`
            refuses construction without it. Setting anchors turns on ``dnssec_ok``:
            a security-aware resolver MUST ask for the records it means to validate
            (RFC 4035 §4.1¶1), and DO-off proves nothing.
        :raises ValueError: if *glue_policy* or *nxdomain_cut* is not a
            :class:`GluePolicy` / :class:`NxdomainPolicy` (or its name/value), or
            if *nxdomain_cut* is :attr:`NxdomainPolicy.VALIDATED` without
            *trust_anchors* -- a policy that silently failed to apply would be
            worse than one refused at the door.
        :raises FileNotFoundError: if *root_hints_path* is named but missing.
        :param opportunistic_dot: try encrypted transport to authoritative
            servers per RFC 9539 section 4 -- probe DoT to port 853, race it
            against cleartext while the outcome is unknown, remember success
            for a persistence period and failure for a damping period, and
            accept the server's certificate whatever it is, because under
            this policy a verification failure would mean falling back to
            cleartext and a forced fallback is the leak (:mod:`namespy.
            opportunistic` is the door). Off by default: §4.1¶1 makes the
            whole exercise OPTIONAL, it puts new egress connections on the
            network, and its privacy dividend is DNSSEC's to confirm.
        :param opportunistic_discover: when the policy above is on, ask RFC
            9461's question first -- SVCB at ``_dns.<NS name>`` -- and probe
            the port the answer names (its own, or the §4.2¶1 default of
            853) instead of the blind one. On by default with the policy,
            because the record costs one cached lookup and says which port
            the operator actually meant; discovery never vetoes encryption,
            it only retargets the probe, since the unauthenticated record
            (§9461 §6¶2) proves less than a completed handshake does. Walks
            made for discovery run cleartext-only, so this can never
            recurse into itself.
        :param query_padding: pad queries leaving over an *encrypted* leg to
            RFC 8467 §4.1¶2's 128-octet block (RFC 9539 §4.6.8.1 asks a DoT
            client to authority servers for exactly this SHOULD). True by
            default -- the encrypted leg is the privacy choice, and RFC 7830
            §6 keeps the option off cleartext whatever this is set to; False
            is the resource-conservation exit of RFC 8467 §3¶2.
        """
        self.queue: dict[tuple, tuple] = {}
        self.queue_v6: dict[tuple, tuple] = {}
        self._tcp_sessions: dict = {}
        self.opportunistic_dot = bool(opportunistic_dot)
        self.opportunistic_discover = bool(opportunistic_discover)
        self.query_padding = bool(query_padding)
        self._dot_memo: dict = {}
        self.transport_v6 = None
        self._v6_ready = None
        self.log = LOGGER
        self.max_hops = max(1, int(max_hops))
        self.max_depth = max(1, int(max_depth))
        self.max_alias_hops = max(1, int(max_alias_hops))
        self.query_timeout = max(0.05, float(query_timeout))
        self.edns_payload_size = 0 if edns_payload_size is None else max(0, int(edns_payload_size))
        self.dnssec_ok = bool(dnssec_ok)
        # CO rides with DO by construction (see Resolver.compact_answers and
        # _edns_flags), so a resolver with this on and DNSSEC off asks nothing
        # different -- and the walk still reads and honors a server's unsolicited
        # compact signal, because what makes it trustworthy is the signature,
        # not the ask.
        self.compact_answers = bool(compact_answers)
        # Frozen into a tuple: the value is read once per outbound query and a
        # caller who mutates the list they passed in would otherwise be
        # changing the wire format of queries already in flight.
        self.edns_options = tuple(edns_options)
        self.qname_min = bool(qname_min)
        # Coerce here, at the door: GluePolicy("permissive") and
        # GluePolicy.PERMISSIVE both arrive, and anything else raises now rather
        # than leaving a resolver that believes it has a policy.
        self.glue_policy = GluePolicy(glue_policy)
        if self.glue_policy is not GluePolicy.STRICT:
            # A warning, deliberately: this switch turns off a defense the RFC
            # specifies, so the log of any run that measured with it should say
            # so without anyone having to ask for -v.
            self.log.warning(
                "resolver_glue_policy=%s: out-of-bailiwick glue will be believed "
                "(RFC 5452 section 6 filtering disabled) -- diagnostics only",
                self.glue_policy.value,
            )
        # Same coercion, same reason: NxdomainPolicy("never") from a config file
        # and NxdomainPolicy.NEVER must arrive as one thing, and a typo must not
        # leave a resolver that thinks it has a policy.
        self.nxdomain_cut = NxdomainPolicy(nxdomain_cut)
        self.aggressive_nsec = bool(aggressive_nsec)
        self.serve_stale = float(serve_stale or 0.0)
        # Frozen like edns_options: the walk reads these per lookup, and an
        # anchor list a caller mutates mid-flight would silently change what
        # "validated" meant partway down a delegation chain.
        self.trust_anchors = tuple(trust_anchors)
        if self.trust_anchors:
            # RFC 4035 §4.1¶1: a security-aware resolver MUST set DO when it
            # means to validate. An operator who configured anchors but left
            # --dnssec off asked for verification of records that would never
            # arrive; turning DO on is honoring the request, refusing it would
            # be honoring the flag over the intent.
            self.dnssec_ok = True
        if self.nxdomain_cut is NxdomainPolicy.VALIDATED and not self.trust_anchors:
            # Refused rather than degraded, and for the reason the original
            # door stated: VALIDATED without anchors marks every denial
            # unvalidated, which emits exactly NEVER's packets while printing
            # a policy name that promises DNSSEC proof was what stopped the
            # cut. The gap that kept this door shut -- no fetching, no
            # verdicts -- has closed; this one condition is left, and it is
            # configuration, not capability.
            raise ValueError(
                "NxdomainPolicy.VALIDATED needs trust anchors to validate against: "
                "pass trust_anchors=(...) (see namespy.anchors for reading the RFC "
                "9718 root document); without any, no denial can ever be marked "
                "validated and the policy would only ever behave like "
                "NxdomainPolicy.NEVER"
            )
        if self.nxdomain_cut is NxdomainPolicy.NEVER:
            # Not a warning: unlike permissive glue this disables an efficiency,
            # not a defense, and leaves the resolver strictly more chatty.
            self.log.info(
                "resolver_nxdomain_cut=never: names below a cached NXDOMAIN will be "
                "walked again (RFC 8020 section 2 disabled) -- for watching a zone change",
            )
        self.root_hints = self.bootstrap(root_hints_path)
        self.sbelt = Sbelt.from_response(self.root_hints)
        self.last_trace = None
        self.cache = cache if cache is not None else MemoryDnsCache()
        if self.serve_stale > 0:
            # The retention half of the timer belongs to the cache (§5¶11
            # files it under cache management, "independent of the query
            # resolution process") and the decision half to the walk. A cache
            # already keeping rows longer is left alone -- widen, never
            # narrow; a duck-typed backend with no such attribute simply
            # retains nothing, and the walk's stale door will find no key
            # behind it (§9's fallback to honest failure).
            current = float(getattr(self.cache, "stale_ttl", 0.0) or 0.0)
            if current < self.serve_stale:
                self.cache.stale_ttl = self.serve_stale
        # RFC 9520 §3.2. `False`, rather than `None`, switches this off, because
        # `None` already means "make me the default one" everywhere else in this
        # constructor -- and a resolver built to watch a zone fail has to be able
        # to keep asking it about the failure.
        if failure_cache is False:
            self.failure_cache = None
        elif failure_cache is None:
            self.failure_cache = FailureCache()
        else:
            self.failure_cache = failure_cache
        if dns_suffix is not None:
            self.dns_suffix = dns_suffix

    async def aclose(self):
        """Release every socket and pending query this resolver owns.

        asyncio hands a protocol its endpoint transport, and this class opens a
        second one privately, for AAAA glue (:meth:`_ensure_v6_transport`).
        Neither closes itself. An unclosed transport is an unclosed socket: it
        surfaces as a ``ResourceWarning`` when garbage-collected, and as a leaked
        descriptor in anything that builds resolvers in a loop -- a measurement
        harness, a server. This is why the class is an async context manager:
        :meth:`__aexit__` calls this method, so forgetting is not the default.

        Safe to call twice, and safe on a resolver that never connected --
        closing an already-closed transport is a no-op in asyncio, and the
        transports are read defensively because a protocol that never saw
        ``connection_made`` has none to read.

        Pending queries are *failed*, not cancelled. Cancelling the future would
        surface as ``CancelledError`` in whoever is awaiting it, and inside
        :func:`asyncio.wait_for` that makes the caller's own task look cancelled
        -- a wrong story about who is shutting down.
        """
        # Stop the background IPv6 bring-up first: it may be sitting inside
        # create_datagram_endpoint, and finishing a socket we are about to stop
        # using would only create one more thing to close.
        task, self._v6_ready = self._v6_ready, None
        if task is not None and not task.done():
            task.cancel()

        # Transports before the futures, and before the one ``await`` below: if a
        # cancellation reaches this coroutine while it is suspended, the sockets
        # are already gone.
        for transport in (getattr(self, "transport", None), self.transport_v6):
            if transport is not None:
                transport.close()
        self.transport = None
        self.transport_v6 = None

        # The pooled TCP fallback streams are the second socket family this
        # class owns privately, and they close here too -- same reason as the
        # v6 bring-up above: nothing else holds them, and the docstring
        # above promised no leaks on this path.
        self._close_tcp_sessions()

        for queue in (getattr(self, "queue", None), getattr(self, "queue_v6", None)):
            for _key, (_query, future) in list((queue or {}).items()):
                if future.done():
                    continue
                future.set_exception(RuntimeError("resolver closed"))
                # Reading the exception back is what keeps asyncio from logging
                # "Future exception was never retrieved" for every query that was
                # in flight when the caller stopped caring. The future's state --
                # and therefore what an awaiting caller sees -- is unchanged.
                future.exception()
            if queue is not None:
                queue.clear()

        if task is not None:
            # Let the cancellation land rather than leaving a task pending when
            # the loop stops. The handler swallows this one cancellation because
            # this method is the one that asked for it.
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def __aenter__(self):
        """Enter an ``async with`` block that guarantees :meth:`aclose`."""
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Close the resolver on the way out, including down the error path."""
        await self.aclose()
        # Do not swallow: an exception raised inside the block is the caller's
        # business, not this method's.

    @staticmethod
    def packaged_root_hints():
        """The ``named.root`` shipped inside the package, as a readable path.

        :mod:`importlib.resources` rather than ``os.path.dirname(__file__)`` so it
        also works when Namespy is installed as a zip or wheel, where there may be no
        directory on disk to name.
        """
        return resources.files("namespy").joinpath("named.root")

    def bootstrap(self, root_hints_path=None):
        """Build the root-hints ``Response`` from a master file, offline.

        The result is a synthetic ``Response`` whose authority section holds the
        root NS set and whose additional section holds the glue, because
        :class:`Sbelt` is built from responses and reusing that shape avoids a
        second, parallel representation of the same information.

        :raises FileNotFoundError: if *root_hints_path* is given and missing. The
            message names the packaged alternative so the fix is obvious.
        """
        if root_hints_path is None:
            source = self.packaged_root_hints()
            self.log.debug("root_hints_source(source=packaged)")
        else:
            if not os.path.isfile(root_hints_path):
                raise FileNotFoundError(
                    f"root hints file not found: {root_hints_path!r}. Omit "
                    f"root_hints_path to use the copy packaged with Namespy, or "
                    f"call refresh_root_hints() to fetch a current one."
                )
            source = root_hints_path
            self.log.debug("root_hints_source(source=%s)", root_hints_path)

        nameservers = []
        additional_records = []
        for record in self.record_reader(source):
            if record.rtype == DnsRType.NS:
                nameservers.append(record)
            if record.rtype in (DnsRType.A, DnsRType.AAAA):
                additional_records.append(record)

        if not nameservers:
            raise ValueError(f"root hints from {str(source)!r} contained no NS records")
        if not additional_records:
            # RFC 8106 section 2: hints without addresses are unusable -- the
            # resolver would have to resolve the root servers' own names, which is
            # the circular problem hints exist to avoid.
            raise ValueError(
                f"root hints from {str(source)!r} contained no glue addresses (RFC 8106 section 2)"
            )

        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]
        query = Query(QR=DnsQR.QUERY, RD=False, questions=questions)
        return Response(
            QR=DnsQR.RESPONSE,
            ID=query.ID,
            AA=True,
            RD=False,
            RA=False,
            questions=questions,
            nameservers=nameservers,
            additional_records=additional_records,
        )

    async def refresh_root_hints(self, url: str | None = None, timeout: float | None = None):
        """Fetch current root hints and replace the safety-belt list.

        Explicitly awaited, unlike the ``urlretrieve`` this replaces: root hints
        change rarely (RFC 8106 section 3 suggests a two-week refresh), so the
        caller decides when to pay for a fetch, and doing it inside ``__init__``
        made every resolver construction a network event.

        The fetched file is parsed and *validated* before :attr:`sbelt` is
        replaced, so a truncated or empty download cannot leave the resolver
        unable to start a lookup.

        :return: the synthetic hints ``Response`` now in use, or ``None`` if the
            fetch or parse failed, in which case the previous hints remain.
        """
        url = url or self.ROOT_HINTS_URL
        timeout = self.query_timeout if timeout is None else timeout
        try:
            text = await asyncio.wait_for(
                asyncio.to_thread(self._fetch_text, url, timeout), timeout + 1.0
            )
        except Exception as exc:
            self.log.warning("root_hints_fetch_failed(url=%s err=%s)", url, type(exc).__name__)
            return None

        try:
            response = self.bootstrap_from_text(text)
        except (ValueError, DnsPacketParseError) as exc:
            self.log.warning("root_hints_parse_failed(url=%s err=%s)", url, exc)
            return None

        self.root_hints = response
        self.sbelt = Sbelt.from_response(response)
        self.log.info(
            "root_hints_refreshed(url=%s ns=%d glue=%d)",
            url,
            len(response.nameservers),
            len(response.additional_records),
        )
        return response

    @staticmethod
    def _fetch_text(url: str, timeout: float) -> str:
        with urllib.request.urlopen(url, timeout=timeout) as handle:  # noqa: S310
            return handle.read().decode("utf-8", "replace")

    def bootstrap_from_text(self, text: str):
        """Same contract as :meth:`bootstrap`, from master-file text in memory."""
        nameservers = []
        additional_records = []
        for record in self.record_reader(io.StringIO(text), source="<fetched>"):
            if record.rtype == DnsRType.NS:
                nameservers.append(record)
            if record.rtype in (DnsRType.A, DnsRType.AAAA):
                additional_records.append(record)
        if not nameservers or not additional_records:
            raise ValueError("fetched root hints had no NS records or no glue addresses")

        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]
        return Response(
            QR=DnsQR.RESPONSE,
            ID=secrets.randbits(16),
            AA=True,
            RD=False,
            RA=False,
            questions=questions,
            nameservers=nameservers,
            additional_records=additional_records,
        )

    async def _send_for_entry(self, entry, questions, extra_qtypes=(), edns_options=()):
        """Send the query to this entry, trying all known addresses."""
        if not entry.addresses:
            return None

        ns_record = DnsRecord(entry.zone, DnsRType.NS, DnsRClass.IN, 0, rdata=entry.ns)

        extra_options = tuple(edns_options)
        if extra_qtypes:
            primary = getattr(questions[0], "qtype", None) if questions else None
            try:
                option = query_option_for(primary, extra_qtypes)
            except ValueError as exc:
                # An optional extension must never be the reason a name fails to
                # resolve. resolve_bundle validates the list where the caller can still
                # hear about it, so reaching here means somebody drove resolve_steps
                # directly with a list a conforming server is obliged to refuse --
                # section 3.3's FORMERRs. Send the query that list was meant to
                # accompany and say why the option is not in it.
                self.log.debug("resolver_mqtype_undone(dst=%s err=%s)", entry.ns, exc)
            else:
                extra_options = (option,) if option is not None else ()

        # Family-interleaved, not glued-order: one black-holed family should
        # cost this entry one timeout, not every timeout its addresses own
        # (RFC 10001 §4.2¶1, §3.2; see :func:`_interleave_families`).
        for address in _interleave_families(entry.addresses):
            # Addresses arrive either as ipaddress objects (glue, root hints) or
            # as raw packed octets (a caller that seeded the belt by hand).
            packed = address.packed if hasattr(address, "packed") else bytes(address)
            if len(packed) not in (4, 16):
                continue

            addr_rtype = DnsRType.A if len(packed) == 4 else DnsRType.AAAA
            addr_record = DnsRecord(entry.ns, addr_rtype, DnsRClass.IN, 0, rdata=packed)
            try:
                response = await self.query(
                    questions,
                    ns_record,
                    addr_record,
                    RD=False,
                    extra_edns_options=extra_options,
                )
            except asyncio.InvalidStateError:
                response = None

            if response is not None:
                self._note_upstream_errors(response)
                return response

        return None

    def _note_upstream_errors(self, response) -> None:
        """Log any Extended DNS Error a server sent alongside its answer.

        DEBUG and nothing louder, which is this project's rule for text a stranger
        wrote. RFC 8914 section 6 calls the option "unauthenticated information"
        that "an attacker (e.g., a man in the middle (MITM) or malicious recursive
        server) could insert", and RFC 5358 section 4.2's reasoning is the same one
        the parser paths already follow: a warning per response is a free flood
        primitive. Escaping handles the octets, the level handles the volume.

        It lives here rather than in the resolution generator because this is where
        every response passes through, glue sub-resolutions included, and because
        the answer it is attached to may still be a perfectly good NOERROR --
        section 3 expects an EDE to be readable "in all messages, including those
        with a NOERROR RCODE", and a walk that logs only on failure would miss the
        Stale Answer and Cached Error codes entirely.
        """
        try:
            options = response.edns_options()
        except DnsPacketParseError:
            return
        for error in extended_errors_of(options):
            self.log.debug(
                "resolver_extended_error(rcode=%s ede=%s)",
                DnsResponseCode.mnemonic(response.extended_rcode),
                extended_error_presentation(error),
            )

    async def _drive(self, gen, trace, depth=0, client_cd=False, client_key_tags=()):
        """Pump the resolve_steps generator and fulfill its effects.

        *depth* bounds sub-resolutions (a glueless NS whose address must itself be
        looked up, which may in turn need glue). Returning ``None`` rather than
        raising is deliberate: the caller treats it as "no address found" and
        demotes the entry, so a deep chain degrades instead of aborting the
        lookup that triggered it.

        *client_cd* is the initiating query's CD bit, passed down so a glue
        sub-walk inherits the policy that governs the lookup it serves: a CD
        request that exempts the outer answer from validation and cache writes
        exempts the address of the nameserver that answers it too, and a
        sub-resolution that silently re-imposed the validating stance would
        change the client's request halfway down. *client_key_tags* inherits the
        same reasoning -- it is carried down for completeness and honesty about
        whose request a sub-walk serves, though RFC 8145 §4.2¶2's type gate means
        it can only ever ride on a DNSKEY question, which glue lookups (A and
        AAAA) never are.
        """
        if depth > self.max_depth:
            self.log.debug("resolver_depth_exceeded(depth=%d limit=%d)", depth, self.max_depth)
            return None
        sent = None
        while True:
            try:
                step = gen.send(sent)
            except StopIteration:
                return None
            trace.record(step)

            if isinstance(step, SendQuery):
                sent = await self._send_for_entry(
                    step.entry,
                    step.questions,
                    step.extra_qtypes,
                    edns_options=step.extra_edns_options,
                )
                if isinstance(sent, Response):
                    # RFC 4035 §4.6¶3: "A resolver MUST disregard the meaning of
                    # the CD and AD bits in a response unless the response was
                    # obtained by using a secure channel" -- and UDP to an
                    # authority with no TSIG is not one. An upstream's AD is
                    # somebody else's assertion over an authenticable-free wire;
                    # forwarding it would launder a forged "I validated this" into
                    # our client's answer. The bits are cleared on arrival so no
                    # later path can forward one by accident, and any AD this
                    # resolver returns was set here, under our own anchors.
                    sent.AD = False
                    sent.CD = False
                continue
            if isinstance(step, NeedAddress):
                # RFC 1034 section 5.3.3 step 2: glue may be absent (a
                # "glueless" referral) for a server outside the new zone, which
                # is legitimate per section 4.2.2, and "the best is to start
                # parallel resolver processes looking for the addresses". Ask
                # for A *and* AAAA so a target reachable only over IPv6 is not
                # silently skipped, and read the payloads through the RDATA
                # codecs rather than assuming every answer is four octets.
                addrs = []
                for rtype in (DnsQType.A, DnsQType.AAAA):
                    child_sname = Sname(step.ns_name, rtype, DnsRClass.IN)
                    child_slist = self.sbelt.copy_for(child_sname)
                    child_trace = trace.child(child_sname)
                    # qname_min deliberately off here: the name being chased
                    # is an NS server's address, not the user's QNAME, so the
                    # privacy motivation of RFC 9156 section 1 does not apply
                    # and the extra probes would only slow glue resolution.
                    #
                    # glue_policy, by contrast, *is* inherited. This is where a
                    # refused address goes to be looked up properly, and a policy
                    # that stopped at the top of the descent would be a policy
                    # that silently changes meaning halfway down -- in the
                    # permissive direction, one that reports an adoption the
                    # sub-resolution never performed. nxdomain_cut is inherited
                    # for the same reason and more simply: a nameserver name
                    # beneath a cached denial has no address to find, and walking
                    # it anyway is exactly the traffic RFC 8020 section 2 asks a
                    # resolver to stop sending.
                    sub_gen = resolve_steps(
                        child_sname,
                        child_slist,
                        self.cache,
                        glue_policy=self.glue_policy,
                        nxdomain_cut=self.nxdomain_cut,
                        failures=self.failure_cache,
                        dnssec_ok=self.dnssec_ok,
                        anchors=self.trust_anchors,
                        client_cd=client_cd,
                        client_key_tags=client_key_tags,
                        aggressive_nsec=self.aggressive_nsec,
                        serve_stale=self.serve_stale,
                    )
                    sub_response = await self._drive(
                        sub_gen,
                        child_trace,
                        depth + 1,
                        client_cd=client_cd,
                        client_key_tags=client_key_tags,
                    )
                    if not isinstance(sub_response, Response):
                        continue
                    for record in sub_response.answers:
                        # RFC 5452 section 6: only records in the domain that was
                        # asked about may be accepted, so an answer section that
                        # happens to carry some other name's address is refused
                        # here -- a server (or an attacker) must not be able to
                        # steer where the next query goes.
                        if record.name != step.ns_name:
                            continue
                        address = _answer_address(record)
                        if address is not None:
                            addrs.append(address)
                sent = addrs
                continue
            if isinstance(step, Done):
                return step.response
            if isinstance(step, Fail):
                return None
            sent = None

    async def _dot_endpoint(self, ns_record, host) -> int:
        """The RFC 9461 answer for this authority: probe which port, if any.

        The seam's recursive implementation: consult the memo, and on a
        miss run :func:`~namespy.opportunistic.learn_dot_endpoint` over a
        fetcher that walks the ``_dns.<NS name>`` SVCB question through
        this resolver's own machinery. Three properties the code must keep
        and each other's reasons:

        * the discovery walk runs while ``_dot_discovering`` is raised, so
          every query that walk makes -- including one to X itself, since
          the ``_dns`` name lives at the authority being probed -- goes
          straight cleartext (the ``query`` hook's gate); no recursion, no
          host-lock re-entry, and an unusable or forged answer can at
          worst make the blind probe, never silence encryption (§6¶2's
          first bullet read as a design rule: the record that arrives over
          the very channel it describes proves less than the handshake);
        * the memo is keyed by (name, address) -- RFC 9539 §4.2's "keep
          this state per IP address", applied to the discovery half of
          the row -- because a hints-checked verdict about one address of
          a multihomed NS says nothing about another;
        * misses are remembered too, briefly: an authority with no ``_dns``
          record should cost one walk, not one per query.
        """
        blind = self.opportunistic_dot_port
        if not self.opportunistic_discover or self._dot_discovering or ns_record is None:
            return blind
        ns_name = ns_record.rdata
        if not isinstance(ns_name, DomainName):
            return blind  # a caller seeded the belt with something else: probe blind
        key = (ns_name.canonical_text, str(host))
        now = asyncio.get_running_loop().time()
        remembered = self._dot_memo.get(key)
        if remembered is not None and remembered[0] > now:
            return remembered[1]

        async def fetch(qname):
            probe_query = Query(questions=[DnsQuestion(qname, DnsRType.SVCB)], RD=False)
            try:
                response = await self.resolve(probe_query)
            except Exception as exc:
                self.log.debug(
                    "resolver_dot_discovery_failed(qname=%s err=%s)", qname, type(exc).__name__
                )
                return None
            return list(response.answers) if response is not None else None

        self._dot_discovering = True
        try:
            learned = await learn_dot_endpoint(fetch, str(ns_name), host)
        finally:
            self._dot_discovering = False
        if learned is None:
            self._dot_memo[key] = (now + DISCOVERY_MISS_S, blind)
            self.log.debug("resolver_dot_undiscovered(dst=%s name=%s)", host, ns_name)
            return blind
        port, ttl = learned
        self._dot_memo[key] = (now + min(max(float(ttl), DISCOVERY_MIN_S), DISCOVERY_MAX_S), port)
        self.log.debug("resolver_dot_discovered(dst=%s name=%s port=%s)", host, ns_name, port)
        return port

    async def resolve(self, dns_packet):
        """Resolve the first question of *dns_packet* iteratively.

        Validation here raises :class:`TypeError` / :class:`ValueError` rather
        than asserting: these guard a public API against caller mistakes, and an
        ``assert`` vanishes under ``python -O``, which would let a
        zero-question packet through to ``questions[0]`` and surface as an
        ``IndexError`` far from its cause.

        Multiple questions are accepted only when they share a name and class --
        :meth:`resolve_steps` tracks a single Sname, so silently resolving just
        the first of several unrelated questions would be a quiet wrong answer.
        """
        response, _sname = await self._walk(dns_packet)
        return response

    @staticmethod
    def _sole_question(dns_packet, method="resolve"):
        """Validate that *dns_packet* asks one (name, class), and return its question.

        The validation raises :class:`TypeError` / :class:`ValueError` rather than
        asserting: these guard a public API against caller mistakes, and an ``assert``
        vanishes under ``python -O``, which would let a zero-question packet through to
        ``questions[0]`` and surface as an ``IndexError`` far from its cause.

        Multiple questions are accepted only when they share a name and class --
        :func:`resolve_steps` tracks a single Sname, so silently resolving just the
        first of several unrelated questions would be a quiet wrong answer.
        """
        if not isinstance(dns_packet, DnsPacket):
            raise TypeError(f"{method}() expects a DnsPacket, got {type(dns_packet).__name__}")
        if not dns_packet.questions:
            raise ValueError(f"{method}() needs a packet with at least one question")

        first = dns_packet.questions[0]
        if len(dns_packet.questions) > 1 and any(
            question.name != first.name or question.qclass != first.qclass
            for question in dns_packet.questions[1:]
        ):
            raise ValueError(
                f"{method}() handles one (name, class) per call; multi-question "
                "packets must agree on name and class"
            )
        return first

    async def _walk(self, dns_packet, extra_qtypes=(), trace=None):
        """Drive one walk from the roots; return ``(response, terminal sname)``.

        The SNAME comes back because it mutates on the way down. After a CNAME it holds
        the name the answer is really about, which is the name the extras' records are
        owned by and therefore the name a bundle must be harvested against -- asking
        AAAA for an aliased name gets the target's AAAA, exactly as asking A does.

        *trace* records this walk into somebody else's tree instead of starting a fresh
        ``last_trace``. Only :meth:`resolve_bundle` uses it: a re-ask is a lookup in its own
        right, but it exists because the bundle did not answer a type, and a trace that
        showed only the bundling descent would leave a reader counting one query when the
        run sent four.
        """
        question = self._sole_question(dns_packet)

        # Apply the resolver's DNS suffix. Names already terminated by a
        # trailing ``.`` pass through unchanged; relative names are promoted
        # to absolute by appending :attr:`dns_suffix` (or just the root).
        qname = question.name.qualify(dns_suffix=self.dns_suffix)
        sname = Sname(qname, question.qtype, question.qclass)
        if trace is None:
            self.last_trace = Trace(sname)
        else:
            # The child was made before this walk knew what it would ask, so the title is
            # filled in here rather than by the caller re-deriving the qualification rules:
            # a diagram that read "resolve example AAAA" for a query that went out as
            # "example.com. AAAA" is a small lie in the one place a reader goes for the
            # truth about a descent.
            trace.sname = sname
            self.last_trace = trace
        slist = self.sbelt.copy_for(sname)
        client_cd = bool(getattr(dns_packet, "CD", False))
        # The initiating query's edns-key-tag instance(s), flattened per
        # key_tags_of's reading of RFC 8145 §4.2.2.2. A walk started from a name
        # rather than a client packet -- the CLI, a library caller, a glue
        # sub-resolution -- has no packet options and so sends no list of its
        # own beyond the validator's, which is §4.2.1.2's MUST NOT for a
        # non-validating stub honoured by construction: there is no downstream
        # validator here whose wishes could be copied.
        packet_options = getattr(dns_packet, "edns_options", None)
        client_key_tags = key_tags_of(packet_options()) if packet_options is not None else ()
        gen = resolve_steps(
            sname,
            slist,
            self.cache,
            max_hops=self.max_hops,
            max_alias_hops=self.max_alias_hops,
            qname_min=self.qname_min,
            glue_policy=self.glue_policy,
            nxdomain_cut=self.nxdomain_cut,
            failures=self.failure_cache,
            extra_qtypes=tuple(extra_qtypes),
            dnssec_ok=self.dnssec_ok,
            anchors=self.trust_anchors,
            client_cd=client_cd,
            client_key_tags=client_key_tags,
            aggressive_nsec=self.aggressive_nsec,
            serve_stale=self.serve_stale,
        )
        response = await self._drive(
            gen, self.last_trace, client_cd=client_cd, client_key_tags=client_key_tags
        )
        if isinstance(response, Response):
            response.ID = dns_packet.ID
            # RFC 4035 §3.2.2¶2: "The name server side MUST copy the setting of
            # the CD bit from a query to the corresponding response." Doing it
            # here as well as at the server's egress keeps a bare resolve()
            # caller -- a test, a script, an embedder without namespy.server --
            # reading the same honest header the served client gets, and the
            # copy is idempotent when both halves run.
            response.CD = client_cd
            response.trace = self.last_trace
        return response, sname

    async def resolve_bundle(self, dns_packet, extra_qtypes=(), *, ask_separately=True):
        """Resolve one question and, in the same exchange, the QTYPEs in *extra_qtypes*.

        This is RFC 10029's asking side. The Question section still holds exactly one
        question -- QDCOUNT stays one, and RFC 9619's argument that it usually is one
        survives untouched -- while the extra types ride in a MQTYPE-Query option. One
        walk down the delegation tree then answers for all of them, which is the point:
        a resolver that asks A, AAAA and HTTPS separately walks the same servers the
        same way three times, and the walk is the expensive part.

        What comes back is a :class:`~namespy.bundle.BundleResult`, whose two most
        important fields are the ones most often conflated. A server that has never
        heard of the extension is ``supported=False`` with every extra type still needed
        and a primary answer in perfect health -- RFC 6891 section 6.1.2 requires that
        "Any OPTION-CODE values not understood by a responder or requestor MUST be
        ignored", so asking costs a few octets and nothing else. A server whose answer
        contradicts itself is ``void=True``, and its primary answer is not usable either.

        ``ask_separately`` carries out section 3.5's own instruction -- "The client MUST
        subsequently initiate separate standalone queries for all QTx values for which an
        answer is still required" -- by resolving each uncovered type with its own query,
        without the option. Pass ``False`` to keep the work list and decide later; nothing
        else about the result changes. A re-ask is an ordinary lookup and inherits the
        ordinary rules, so if this lookup left the name's zone remembered as a failure
        (RFC 9520 section 3.2) the re-ask is suppressed and the type stays on the work
        list: the result admitting it finished nothing, rather than a verdict nobody was
        allowed to earn.

        Raises :exc:`ValueError` for a list that could not be sent. Section 3.3 makes
        "An MQTYPE-Query option in a query where the primary question is a non-data
        RRTYPE (e.g., ANY, AXFR)" a FORMERR and section 3.2 obliges a client not to send
        one, so bundling behind an ANY is refused here rather than discovered by a server
        that is required to reject it.
        """
        question = self._sole_question(dns_packet, "resolve_bundle")
        asked = tuple(int(qtype) for qtype in extra_qtypes)
        if asked:
            if not is_data_rrtype(int(question.qtype)):
                raise ValueError(
                    f"cannot bundle a MQTYPE-Query behind a {question.qtype} question: "
                    "RFC 10029 section 3.3 obliges a server to answer FORMERR when the "
                    "primary question is not a data RRTYPE"
                )
            # Built and discarded for the sake of its validation: every section 3.3
            # condition on the list is checked here, at the boundary where the caller can
            # still be told, rather than at the socket where all that can be done about
            # it is to drop the option quietly.
            query_option_for(question.qtype, asked)

        response, sname = await self._walk(dns_packet, asked)
        # Held while the re-asks run, so the trace the caller sees is the descent that
        # did the bundling rather than whichever standalone query happened to be last.
        bundle_trace = self.last_trace
        if not asked:
            return BundleResult(supported=False, primary=response)

        if isinstance(response, Response):
            bundle = collect_bundle(
                response,
                primary_qtype=int(question.qtype),
                requested=asked,
                terminal_name=sname.qname,
            ).with_primary(response)
            # A self-contradictory answer does not get this far. :func:`resolve_steps`
            # reads one as the FORMERR section 3.5 says it is equivalent to, demotes that
            # server and asks another -- and that is the only place the rule can be
            # honoured, because an answer the client has been told to discard must not
            # already have been cached by the time somebody decides to discard it. What
            # is left to handle here is the ordinary pair of outcomes: it combined, or it
            # did not.
            self._cache_bundle(response, sname, bundle)
        else:
            # Nothing answered the primary. After a discarded answer this is the usual
            # shape -- one server, no second opinion, the walk out of candidates. The
            # extras are still owed their queries: section 3.5 asks for a standalone one
            # "for all QTx values for which an answer is still required". But a re-ask is
            # an ordinary lookup and inherits the ordinary rules, including RFC 9520
            # section 3.2: a zone this lookup just watched fail is remembered as dead, and
            # the re-ask is stopped before it sends. What comes back then says every type
            # is still needed, which is the truth, rather than a verdict nobody earned.
            bundle = BundleResult(
                supported=False,
                primary=response,
                still_needed=asked,
                types=tuple(BundledType(qtype, BundleState.NEEDED) for qtype in asked),
            )
        self.last_trace = bundle_trace
        if not ask_separately:
            return bundle

        for entry in bundle.types:
            if entry.state is not BundleState.NEEDED:
                continue
            # A standalone query, without the option -- section 3.5 is explicit: "that
            # is, without using the MQTYPE-Query option". It asks for the name the
            # *caller* asked about, not the name the bundle happened to end at: this
            # query has its own alias chain to walk, and starting it at the terminal name
            # would be re-using somebody else's route.
            single = Query(
                questions=[DnsQuestion(question.name, entry.qtype, question.qclass)], RD=True
            )
            answer, _terminal = await self._walk(
                # Recorded as a child of the bundling descent rather than as a fresh
                # last_trace: the two belong together, and ``--trace`` is where a reader
                # finds out that the bundle was only half a bundle.
                single,
                trace=bundle_trace.child(Sname(question.name, entry.qtype, question.qclass)),
            )
            if not isinstance(answer, Response):
                # Unfinished, so it stays NEEDED. A work list is allowed to say that: a
                # type nobody answered is not a type with no records.
                continue
            records = tuple(r for r in answer.answers if int(r.rtype) == entry.qtype)
            if int(answer.RCODE) == int(DnsResponseCode.NAME_ERROR):
                state = BundleState.NXDOMAIN
            elif records:
                state = BundleState.COMBINED
            else:
                state = BundleState.NODATA
            bundle = bundle.reasked(entry.qtype, state=state, records=records, response=answer)

        self.last_trace = bundle_trace
        return bundle

    def _cache_bundle(self, response, sname, bundle) -> None:
        """Store what a combined answer delivered for the extra QTYPEs.

        Section 3.5 is what licenses caching these at all: "any authoritative answers
        received MUST be ranked the same as the answer for the primary question" (RFC
        2181 section 5.4.1, cited there by name). The same, and not better -- so an
        extra's entry is authoritative exactly when the response claimed authority, and a
        NODATA learned this way is cached with the same SOA-derived ceiling RFC 2308
        section 5 imposes on the primary's own negative answer. Both rules are already
        :func:`_write_cache`'s for the primary; this extends the same treatment to the
        types that arrived in its shadow, keyed by the name the walk ended at, because
        that is the name the records are owned by and the name a later query for AAAA
        will arrive at by following the same CNAME.

        What is never cached here is :attr:`~namespy.bundle.BundleState.NEEDED`. A QTx
        the server did not list has section 3.5's four innocent reasons, none of which is
        "no such records", and storing a negative for it would hide a name for the length
        of the zone's MINIMUM on the strength of a server having said nothing at all.
        """
        cache = self.cache
        if cache is None or response.TC:
            # RFC 1123 section 6.1.3.2: "Truncated responses MUST NOT be saved (cached)".
            # A combination is the last place a partial RRset could hide, since section
            # 3.4 lets a server stop early precisely because the answer grew too large.
            return
        now = cache.time_fn()
        soa = next((r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)), None)
        for entry in bundle.types:
            if entry.state is BundleState.COMBINED:
                records = tuple(r for r in entry.records if int(r.rtype) != OPT_RTYPE)
                if not records:
                    continue
                ttl = min(int(getattr(r, "ttl", 0) or 0) for r in records)
                if ttl <= 0:
                    continue
                cache.put(
                    PositiveEntry(
                        sname.qname,
                        entry.qtype,
                        sname.qclass,
                        records,
                        now + ttl,
                        authoritative=entry.authoritative,
                    )
                )
            elif entry.authoritative:
                # NODATA and NXDOMAIN, and only from a server that claimed authority --
                # the bar RFC 2308 section 2.2.1 sets for the primary's own negative.
                ttl = _negative_ttl_seconds(soa)
                if ttl <= 0:
                    continue
                rcode = (
                    DnsResponseCode.NAME_ERROR
                    if entry.state is BundleState.NXDOMAIN
                    else DnsResponseCode.NO_ERROR
                )
                cache.put(
                    NegativeEntry(
                        sname.qname,
                        entry.qtype,
                        sname.qclass,
                        rcode,
                        soa,
                        now + ttl,
                        collect_proof_records(response.nameservers),
                    )
                )
