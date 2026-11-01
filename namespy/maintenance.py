"""RFC 5011: trust anchors that maintain themselves, per the state table and nothing else.

A configured trust anchor is a decision frozen at installation time, and key
rollovers were outliving the decision. RFC 5011 lets existing anchors authenticate
new ones at the same trust point (§2¶1), hedged against a compromised key
self-authorizing a successor: additions must survive a hold-down timer whose
original validators staying trustworthy is part of the condition (§2.2¶2), and
revocations are immediate and permanent (§2.1¶2). The mechanism is a state table --
§4¶2 says so outright, "The table is a normative part of this specification" -- and
this module is that table and nothing more: a pure function of validated DNSKEY
observations and an injected clock, with no sockets and no scheduler. The
caller's cron, or a scheduler a deployment builds, owns §2.3's cadence; this file
owns what a fetch *means*.

What the object accepts is, by construction, only validated RRSets: §2¶1 makes
validation by an existing trust anchor the precondition of the whole mechanism, and
§4.1 names each event in terms of "a valid DNSKEY RRSet". Handing the state machine
unvalidated keys is not a degraded mode, it is a different protocol; :meth:`observe`
says so in its contract rather than pretending to check what only the validation
walk can know.

The wire side needed no new work: bit 8 of DNSKEY Flags, the REVOKE bit that §3
designates, is `RData_DNSKEY.is_revoked` already, and §2.1¶4's warning that a
revoked key "has a different fingerprint" is why keys here are identified by
(algorithm, public key) and not by key tag -- revoking a key changes its tag, and a
state machine that indexed on the tag would watch a revocation resurrect the key it
just killed. SEP-bit-only tracking (§2¶1, §4.2¶2), five-keys-per-point support
(§2.4.3's floor is met by having no ceiling), and §5¶1's deletion of an
all-revoked trust point are the rest of the letter; the scenarios of §6 are the
tests.

Persistence is deliberately plain: a JSON document of states and timestamps, our
own format (the document specifies none), because the state -- especially "Valid",
which §2.2¶4 makes permanent-until-revoked -- MUST survive restarts or the
mechanism silently re-downgrades every accepted anchor.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from .dnssec import DNSKEY_FLAG_REVOKED, DNSKEY_FLAG_SEP
from .rdata import RData_DNSKEY

__all__ = [
    "ADD_HOLD_DOWN_SECONDS",
    "REMOVE_HOLD_DOWN_SECONDS",
    "TRUST_POINT_DELETE_AFTER_SECONDS",
    "KeyState",
    "ManagedKey",
    "TrustPointMaintenance",
    "query_interval",
    "retry_interval",
]

#: RFC 5011 §2.4.1¶1: the add hold-down is "30 days or the expiration time of the
#: original TTL of the first trust point DNSKEY RRSet that contained the new key,
#: whichever is greater" -- the 30 days are this floor; the per-key greater-of is
#: computed at NewKey time from the observed TTL. The paragraph states the purpose
#: outright: "at least two validated DNSKEY RRSets that contain the new key MUST be
#: seen by the resolver prior to the key's acceptance."
ADD_HOLD_DOWN_SECONDS = 30 * 86400.0

#: RFC 5011 §2.4.2¶1: "The remove hold-down time is 30 days", and the paragraph is
#: candid that it is "solely a key management database bookkeeping parameter" --
#: defunct keys lingering in the database cost security nothing, so this timer is
#: housekeeping and is named as such.
REMOVE_HOLD_DOWN_SECONDS = 30 * 86400.0

#: RFC 5011 §5¶2: a subordinate trust point that validly chains to a superior one
#: MAY be deleted after 180 days -- a permission and a "local configuration
#: decision", which is why it is exposed as an elapsed-time predicate rather than
#: an automatic action.
TRUST_POINT_DELETE_AFTER_SECONDS = 180 * 86400.0


class KeyState(Enum):
    """§4.2's six states, named as the document names them."""

    START = "Start"
    ADD_PENDING = "AddPend"
    VALID = "Valid"
    MISSING = "Missing"
    REVOKED = "Revoked"
    REMOVED = "Removed"


@dataclass
class ManagedKey:
    """One key's row in the state table, with the timers the transitions need.

    Identity is (§2.1¶4's reason) the algorithm plus the key material, never the
    key tag: flipping the REVOKE bit changes the tag, and a rollover ceremony
    publishes the same material under both. *validating_tags* remembers §2.2¶2's
    "all the keys that validated the RRSet" at the moment the hold-down started,
    and *absent_since* is the shared hourglass for the two absence-timed edges --
    Missing keys waiting to be presumed retired (housekeeping only, §2.4.2¶1) and
    Revoked keys waiting for the RemTime event (§4.1¶5).
    """

    algorithm: int
    public_key: bytes
    state: KeyState = KeyState.START
    flags: int = 0
    key_tag: int = 0
    seen_tags: set[int] = field(default_factory=set)
    first_seen: float | None = None
    accept_deadline: float | None = None
    validating_tags: frozenset[int] = frozenset()
    absent_since: float | None = None
    revoked_at: float | None = None
    removed_at: float | None = None

    @property
    def identity(self) -> tuple[int, bytes]:
        return (self.algorithm, self.public_key)


class TrustPointMaintenance:
    """One trust point's managed-key set, advanced by validated observations.

    Constructed with whatever the operator configured (those keys begin Valid --
    a configured trust point is trusted by definition, the way RFC 4035 §4.4
    means it) and thereafter driven only by :meth:`observe`. Timestamps are
    caller-supplied seconds, so a test can replay §6's rollover scenarios at any
    clock speed a suite can afford.
    """

    def __init__(
        self,
        zone: str,
        *,
        configured: Iterable[RData_DNSKEY] = (),
        add_hold_down: float = ADD_HOLD_DOWN_SECONDS,
        remove_hold_down: float = REMOVE_HOLD_DOWN_SECONDS,
    ) -> None:
        self.zone = str(zone)
        self.add_hold_down = float(add_hold_down)
        self.remove_hold_down = float(remove_hold_down)
        self._keys: dict[tuple[int, bytes], ManagedKey] = {}
        self._by_tag: dict[int, ManagedKey] = {}
        for key in configured:
            row = self._track(key)
            if row.state is KeyState.START:
                row.state = KeyState.VALID

    # ------------------------------------------------------------------ internals

    def _track(self, key: RData_DNSKEY) -> ManagedKey:
        row = self._keys.get((int(key.algorithm), bytes(key.public_key)))
        if row is None:
            row = ManagedKey(algorithm=int(key.algorithm), public_key=bytes(key.public_key))
            self._keys[row.identity] = row
        row.flags = int(key.flags)
        row.key_tag = int(key.key_tag)
        row.seen_tags.add(int(key.key_tag))
        self._by_tag[int(key.key_tag)] = row
        return row

    def _validator_still_honest(self, tag: int) -> bool:
        """§2.2¶2's third clause, per validating key: a remembered validator that
        has since been seen Revoked disqualifies the pending addition.

        Tags the resolver cannot attribute to a managed key count as honest --
        "all of the keys that were originally used to validate this key are
        revoked" is a test over known-revoked, not over unknown.
        """
        row = self._by_tag.get(tag)
        return row is None or row.state is not KeyState.REVOKED

    def observe(
        self,
        keys: Iterable[RData_DNSKEY],
        *,
        validated_by: Iterable[int],
        orig_ttl: float | None = None,
        now: float,
    ) -> list[str]:
        """Advance the table by one *validated* fetch of the trust point DNSKEY RRSet.

        ``keys`` is the RRSet as received and ``validated_by`` the key tags whose
        RRSIGs over it verified -- the caller is the validation walk, and this is
        the precondition §2¶1 states ("when that RRSet is validated by an existing
        trust anchor") in parameter form. Returns the transitions taken, each as a
        trace string naming the §4.1 event that fired.

        The transitions run absence-first, then presence, exactly as the §4¶3 table
        reads, with one ordering rule of its own: a RevBit observation outranks
        every other event for that key, because §3¶1's "permanently invalid for all
        purposes" admits no state it must pass through first.
        """
        received = list(keys)
        validators = frozenset(int(tag) for tag in validated_by)
        # Only SEP keys (§2¶1, §4.2¶2), already-managed keys, and revocations
        # (§3¶1 reaches a never-trusted key) enter the table at all; the ordinary
        # ZSK in the same RRSet is not a trust-anchor candidate and gets no row.
        rows = [
            self._track(key)
            for key in received
            if (int(key.algorithm), bytes(key.public_key)) in self._keys
            or key.is_secure_entry_point
            or key.is_revoked
        ]
        present = {row.identity for row in rows}
        trace: list[str] = []

        # -- KeyRem (§4.1¶3): absent from a validated RRSet.
        for row in self._keys.values():
            if row.identity in present:
                continue
            was = row.state
            if row.absent_since is None:
                row.absent_since = now
            if was is KeyState.ADD_PENDING:
                # §2.2¶2: "it stops the acceptance process for that key and
                # resets the acceptance timer" -- Start again, timers cleared.
                row.state = KeyState.START
                row.first_seen = None
                row.accept_deadline = None
                row.validating_tags = frozenset()
                row.absent_since = None
            elif was is KeyState.VALID:
                row.state = KeyState.MISSING  # §4.2¶4's abnormal-but-trusted state
            elif was is KeyState.REVOKED and now - row.absent_since >= self.remove_hold_down:
                row.state = KeyState.REMOVED  # RemTime, §4.1¶5
                row.removed_at = now
            if row.state is not was:
                trace.append(f"{row.key_tag}: {was.value} -> {row.state.value} (KeyRem)")

        # -- presence events, in two passes: RevBit first for every key, then
        # everything else. §3¶1's bit outranks each other event (and §2.2¶2's
        # validator test has to see revocations taken *this* observation, not
        # only earlier ones), so no receive order may change the outcome.
        revoked_now: set[tuple[int, bytes]] = set()
        for row in rows:
            was = row.state
            row.absent_since = None  # presence interrupts every absence timer
            if row.flags & DNSKEY_FLAG_REVOKED and row.key_tag in validators:
                # RevBit (§4.1¶6): the key signed the RRSet carrying its own
                # revocation. §2.1¶2: "revocation is immediate and permanent";
                # §3¶1 reaches a never-trusted key too, hence no state guard.
                row.state = KeyState.REVOKED
                row.revoked_at = now
                row.first_seen = None
                row.accept_deadline = None
                row.validating_tags = frozenset()
                revoked_now.add(row.identity)
                if was is not KeyState.REVOKED:
                    trace.append(f"{row.key_tag}: {was.value} -> Revoked (RevBit)")
        for row in rows:
            if row.identity in revoked_now:
                continue
            was = row.state
            if (
                was is KeyState.START
                and not (row.flags & DNSKEY_FLAG_REVOKED)
                and (row.flags & DNSKEY_FLAG_SEP)
            ):
                # NewKey (§4.1¶1): an SEP key (§2¶1's "DNSKEY with the Secure
                # Entry Point bit set"), first seen in a validated RRSet.
                row.state = KeyState.ADD_PENDING
                row.first_seen = now
                hold_down = self.add_hold_down
                if orig_ttl is not None:  # §2.4.1¶1's greater-of, first RRSet only
                    hold_down = max(hold_down, float(orig_ttl))
                row.accept_deadline = now + hold_down
                row.validating_tags = validators
            elif was is KeyState.ADD_PENDING:
                if not all(self._validator_still_honest(tag) for tag in row.validating_tags):
                    # §2.2¶2's last clause: every original validator revoked
                    # before expiry aborts and resets the acceptance.
                    row.state = KeyState.START
                    row.first_seen = None
                    row.accept_deadline = None
                    row.validating_tags = frozenset()
                elif row.accept_deadline is not None and now >= row.accept_deadline:
                    # AddTime (§4.1¶4) arriving inside an observation *is*
                    # §2.2¶3's post-hold-down validated fetch containing the
                    # key: "retrieved and validated a DNSKEY RRSet after the
                    # hold-down time that contains the new key" -- the two
                    # conditions can only coincide here, in observe().
                    row.state = KeyState.VALID
            elif was is KeyState.MISSING:
                row.state = KeyState.VALID  # KeyPres (§4.1¶2): back, still trusted
            # VALID staying VALID, REVOKED staying REVOKED (permanent, §4.2¶5),
            # and REMOVED staying REMOVED (terminal: §4.2¶6 keeps it as "the
            # holding state for all the old keys", and re-introducing a
            # previously used key is the bad practice that note names).
            if row.state is not was:
                trace.append(f"{row.key_tag}: {was.value} -> {row.state.value}")
        return trace

    # ---------------------------------------------------------------- reading it

    def trust_anchors(self) -> list[RData_DNSKEY]:
        """The keys to validate with: Valid and Missing, per §4.2¶4 and §2.1¶1.

        Missing is included on purpose. An anchor that simply was not in the last
        RRSet stays a trust anchor -- §4.2¶4 says "the key remains a valid
        trust-point key", and the whole point of §2.1¶1 is that *absence* is not
        revocation: a compromised key B could otherwise invalidate honest key A by
        publishing a key set without A in it. Only the REVOKE bit, self-signed,
        removes an anchor, and it removes it immediately (§2.1¶2).
        """
        out: list[RData_DNSKEY] = []
        for row in self._keys.values():
            if row.state in (KeyState.VALID, KeyState.MISSING):
                out.append(RData_DNSKEY(row.flags, 3, row.algorithm, row.public_key))
        return out

    def state_of(self, key: RData_DNSKEY) -> KeyState | None:
        row = self._keys.get((int(key.algorithm), bytes(key.public_key)))
        return row.state if row is not None else None

    def trust_point_deleted(self) -> bool:
        """§5¶1: "A trust point that has all of its trust anchors revoked".

        The quantifier runs over *anchors* -- keys in Valid or Missing -- not over
        everything tracked: a Start or AddPend key is not a trust anchor yet and
        nothing about it is unrevoked, while §5¶1's consequence ("data at and
        below ... considered insecure") is exactly true while no anchor stands.
        """
        rows = list(self._keys.values())
        return not any(row.state in (KeyState.VALID, KeyState.MISSING) for row in rows) and any(
            row.state in (KeyState.REVOKED, KeyState.REMOVED) for row in rows
        )

    def deletable_subordinate(self, now: float) -> bool:
        """§5¶2's permission, as a predicate: every key Removed for 180 days.

        Whether this trust point is in fact subordinate and validly chaining to a
        superior is something only the validator can say, and the paragraph makes
        the deletion "a local configuration decision" anyway -- so the module
        reports readiness and the operator decides.
        """
        rows = list(self._keys.values())
        if not rows:
            return False
        return all(
            row.state is KeyState.REMOVED
            and row.removed_at is not None
            and now - row.removed_at >= TRUST_POINT_DELETE_AFTER_SECONDS
            for row in rows
        )

    # -------------------------------------------------------------- persistence

    def to_document(self) -> str:
        """The managed-key database, written out. RFC 5011 specifies no format;
        this one is ours, and its only duty is that state and timers survive the
        restart -- §2.2¶4's "until explicitly revoked" is a promise a process
        boundary would otherwise break."""
        return json.dumps(
            {
                "zone": self.zone,
                "add_hold_down": self.add_hold_down,
                "remove_hold_down": self.remove_hold_down,
                "keys": [
                    {
                        "algorithm": row.algorithm,
                        "public_key": base64.b64encode(row.public_key).decode("ascii"),
                        "state": row.state.value,
                        "flags": row.flags,
                        "key_tag": row.key_tag,
                        "seen_tags": sorted(row.seen_tags),
                        "first_seen": row.first_seen,
                        "accept_deadline": row.accept_deadline,
                        "validating_tags": sorted(row.validating_tags),
                        "absent_since": row.absent_since,
                        "revoked_at": row.revoked_at,
                        "removed_at": row.removed_at,
                    }
                    for row in self._keys.values()
                ],
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_document(cls, document: str) -> TrustPointMaintenance:
        data = json.loads(document)
        machine = cls(
            data["zone"],
            add_hold_down=float(data.get("add_hold_down", ADD_HOLD_DOWN_SECONDS)),
            remove_hold_down=float(data.get("remove_hold_down", REMOVE_HOLD_DOWN_SECONDS)),
        )
        for entry in data.get("keys", ()):
            row = ManagedKey(
                algorithm=int(entry["algorithm"]),
                public_key=base64.b64decode(entry["public_key"]),
                state=KeyState(entry["state"]),
                flags=int(entry.get("flags", 0)),
                key_tag=int(entry.get("key_tag", 0)),
                seen_tags={int(t) for t in entry.get("seen_tags", ())},
                first_seen=entry.get("first_seen"),
                accept_deadline=entry.get("accept_deadline"),
                validating_tags=frozenset(int(t) for t in entry.get("validating_tags", ())),
                absent_since=entry.get("absent_since"),
                revoked_at=entry.get("revoked_at"),
                removed_at=entry.get("removed_at"),
            )
            machine._keys[row.identity] = row
            for tag in row.seen_tags:
                machine._by_tag[tag] = row
        return machine


# ------------------------------------------------------------------ §2.3's cadence


def query_interval(orig_ttl: float, rrsig_intervals: Iterable[float]) -> float:
    """§2.3¶1: queryInterval = MAX(1 hr, MIN(15 days, 1/2*OrigTTL, 1/2*expInterval)).

    *rrsig_intervals* are the expiration intervals -- "the amount of time from
    when the RRSIG was last retrieved until the expiration time in the RRSIG" --
    of every signature covering the RRSet; the formula's single term takes the
    tightest, because one short-lived signature shortens the whole set's life.
    An empty iterable leaves the term inert (15 days, the formula's own ceiling).
    """
    intervals = [float(x) for x in rrsig_intervals]
    tightest = min(intervals) if intervals else 15 * 86400.0
    return max(3600.0, min(15 * 86400.0, float(orig_ttl) / 2.0, tightest / 2.0))


def retry_interval(orig_ttl: float, rrsig_intervals: Iterable[float]) -> float:
    """§2.3¶2: retryTime = MAX(1 hour, MIN(1 day, .1*origTTL, .1*expireInterval))."""
    intervals = [float(x) for x in rrsig_intervals]
    tightest = min(intervals) if intervals else 86400.0
    return max(3600.0, min(86400.0, float(orig_ttl) * 0.1, tightest * 0.1))
