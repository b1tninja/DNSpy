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

*It is unilateral.* Nothing here is negotiated with the server, and no
discovery record is consulted -- the resolver simply tries encrypted
transport to port 853 and remembers what happened (§4.1¶1). Discovery by
SVCB (RFC 9461's ``dot`` SvcParam over ``_dns``-prefixed names) is a
different, later mechanism and a different roadmap row.

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
query padding (§4.6.8.1's SHOULD -- that is the RFC 8145 section 5 row),
and DoQ (§4.4's second SHOULD -- no stdlib QUIC, the same deferral the
stub's transport list records). §4.5¶7's "retain across restart" is vacuous
for a library: the table lives in the resolver object, and the process
that ended took the knowledge with it; a daemon that wants restart
persistence owns a serializer this module pointedly does not.
"""

from __future__ import annotations

import enum

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
