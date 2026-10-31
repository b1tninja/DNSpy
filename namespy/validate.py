"""Validation: the four states RFC 4035 §4.3 says a security-aware resolver must name.

Everything before this module answers a local question -- does *this signature* hold
under *these keys* (`namespy.verify`), does *this key* match *this trusted digest*
(`namespy.anchors`, `verify.authenticate_dnskey_rrset`). The questions a resolver
actually asks are global: **may I believe this answer?** §4.3¶1 makes that a four-way
answer, and RFC 9499 §11 keeps both published versions of it side by side -- RFC 4033 §5's
resolver-centred one and RFC 4035 §4.3's RRset-centred one -- without reconciling them.
This module follows 4035 §4.3, with 4033 §5 supplying one detail §4.3 omits: *missing
signatures* are Bogus there, and an authenticated secure zone that served an unsigned
RRset is exactly that.

* **SECURE** -- a chain of signed DNSKEY and DS RRs from a configured trust anchor to
  the data, every signature on it verified (§4.3¶2).
* **INSECURE** -- the chain exists up to a delegation point whose parent has *signed
  proof of the non-existence of a DS record* (§4.3¶3; 4033 §5: "subsequent branches in
  the tree are provably insecure"). Proof matters: an unsigned child you cannot prove
  unsigned is not Insecure, it is Indeterminate.
* **BOGUS** -- data that ought to have authenticated and did not: a failed signature, a
  missing one, contradictory proof (§4.3¶4). May be an attack or a botched key rollover;
  the resolver cannot tell, and must not pretend.
* **INDETERMINATE** -- the resolver could not obtain what it needs to decide (§4.3¶5):
  the missing category, the missing RRSIG over data whose zone is unknown, the backend
  that is not installed. It is not a verdict on the data, and the states never launder
  into each other: this module's whole reason to exist is keeping the four apart.

The inputs are the records a walk accumulated -- not one packet, because RFC 4035
§3.1.1-§3.1.4 promise only what *a* response carries, and a chain usually arrives across
several (§5.3.2¶18 is explicit that even two NSEC RRs at one name must not be merged,
which is why every RRset in a `DnssecStore` remembers the zone it arrived from). The
walk up from a zone stops at a trust anchor (DS or DNSKEY form, RFC 4033 §2), at an
authenticated parent's DS, or at a signed proof that no DS exists; the walk down --
answers and denials -- then needs only names.

The fetching itself lives in the caller, and this module's half of that contract is the
:attr:`ValidationVerdict.fetch_hint`: an Indeterminate born of a *missing record* names
the one query (RFC 4035 §5.2¶6's MUST-query for a DS is the canonical case), offered
once per triple so the loop above terminates. `namespy.resolver` is that caller for the
walk; anything that can send a query can be one too.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .anchors import TrustAnchor
from .dnssec import rrsig_label_count
from .enums import DnsResponseCode, DnsRType
from .names import DomainName
from .nsec import (
    ContradictoryProofError,
    IncompleteProofError,
    name_order_key,
    nsec3_proves_no_data,
    nsec3_proves_no_ds,
    nsec3_proves_nxdomain,
    nsec3_proves_wildcard_answer,
    nsec_proves_no_data,
    nsec_proves_nxdomain_response,
    nsec_proves_wildcard_answer,
    proof_entries,
    usable_nsec3,
)
from .verify import (
    ChainOutcome,
    SignatureOutcome,
    authenticate_dnskey_rrset,
    verify_rrsig,
)

if TYPE_CHECKING:  # pragma: no cover - typing only; the records arrive duck-typed
    pass

__all__ = [
    "DnssecStore",
    "SecurityStatus",
    "ValidationVerdict",
    "Validator",
    "ZoneVerdict",
]


class SecurityStatus(enum.Enum):
    """The four states RFC 4035 §4.3¶2-¶5 requires a security-aware resolver to name."""

    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ValidationVerdict:
    """A state, a reason an operator can act on, and the zone the decision was made at."""

    status: SecurityStatus
    reason: str
    zone: DomainName | None = None
    matched_key_tag: int | None = None
    #: ``(name, rtype, from_zone)`` -- the one authoritative query that could turn this
    #: Indeterminate into a decision, or ``None`` when no query can: a trust point that
    #: contradicted the data (Bogus), a zone with no anchor configured, or a question
    #: this :class:`Validator` has already asked once (hints are offered once per triple,
    #: so a resolver loop cannot spin on a server that keeps not answering). RFC 4035
    #: §5.2¶6 is the named case: a referral carrying neither a DS nor a proof of none
    #: means the resolver MUST query the parent, and this field says so in terms a
    #: caller can act on rather than only in prose.
    fetch_hint: tuple | None = None
    #: True when a SECURE denial rests on an NSEC3 Opt-Out span at the next closer.
    #: The verdict stays SECURE -- §7.2.8 permits Opt-Out to prove the absence of a
    #: DS, which is all a next-closer denial needs -- but RFC 5155 §9.2¶1 is then
    #: explicit: the AD bit "MUST NOT be set when returning a response containing a
    #: closest (provable) encloser proof in which the NSEC3 RR that covers the
    #: 'next closer' name has the Opt-Out bit set", because names inside that span
    #: may exist as insecure delegations and "not all the data ... will have been
    #: cryptographically verified". A resolver reads this to withhold the bit it
    #: otherwise earns from :attr:`secure`.
    via_opt_out: bool = False

    @property
    def secure(self) -> bool:
        return self.status is SecurityStatus.SECURE

    @property
    def ad_worthy(self) -> bool:
        """Whether this verdict lets a server set the AD bit.

        ``secure`` is the necessary half; ``via_opt_out`` subtracts the case RFC
        5155 §9.2¶1 forbids. Kept as one property because a caller that remembers
        to check the first and not the second produces a response that lies about
        being fully verified -- which is the entire content of the rule.
        """
        return self.status is SecurityStatus.SECURE and not self.via_opt_out

    def __repr__(self) -> str:
        where = f" @{self.zone}" if self.zone is not None else ""
        return f"<ValidationVerdict {self.status.value}{where}: {self.reason}>"


@dataclass(frozen=True)
class ZoneVerdict(ValidationVerdict):
    """A :class:`ValidationVerdict` about a zone's keys, carrying them when secure.

    ``keys`` is only ever populated on SECURE: they are the whole product of the walk --
    the apex DNSKEY RRset a caller can now safely feed to :func:`namespy.verify.verify_rrsig`
    -- and an insecure, bogus or indeterminate zone has handed back nothing worth using.
    """

    keys: tuple = ()


# ------------------------------------------------------------------------------ the record set


class _Bucket:
    """One RRset: an owner name, a class, and the RDATA of every record in it.

    RDATA is deduplicated on its wire bytes -- the same RR learned from two responses is
    one RR -- while insertion order survives, because :func:`namespy.dnssec.rrsig_signed_data`
    sorts into canonical order itself and a stable bucket makes debugging stable too.
    """

    __slots__ = ("owner", "rclass", "rdatas", "rtype", "seen")

    def __init__(self, owner, rtype: int, rclass: int) -> None:
        self.owner = DomainName(owner)
        self.rtype = int(rtype)
        self.rclass = int(rclass)
        self.rdatas: list = []
        self.seen: set[bytes] = set()


class _AsRecord:
    """The minimal record shape :meth:`DnssecStore.proof_records` hands back."""

    __slots__ = ("name", "rclass", "rdata", "rtype")

    def __init__(self, name, rtype: int, rclass: int, rdata) -> None:
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.rdata = rdata


class DnssecStore:
    """Records a validation may be built from, bucketed into RRsets that remember their origin.

    The origin is the point. RFC 4035 §5.3.2¶18 is the sharpest case: at a delegation
    there are **two NSEC RRsets with the same owner name and type**, one in the parent
    and one in the child, distinguishable only by which zone signed them ("only a child
    NSEC RR will indicate that an SOA RRset exists", and the two "MUST NOT be combined").
    A store keyed by (name, type) alone would merge them into one RRset that matches
    neither signature -- a self-inflicted bogus for every walk through a signed
    delegation. So :meth:`add` takes the zone the records came from, :meth:`rdatas` hands
    back one origin's view, and an RRSIG's own Signer's Name is its origin, so
    signatures bucket themselves.

    Records arrive as anything with ``name``/``rtype``/``rclass``/``rdata`` attributes --
    a :class:`namespy.packet.DnsRecord` qualifies, and tests hand in lighter stand-ins.
    OPT records are refused (RFC 6891 §6.2.1: never an RRset), and RRSIGs are filed by
    the RRset they cover -- owner plus Type Covered -- not by their own rtype, because an
    RRSIG bucket nobody can find is a bucket nobody uses.
    """

    def __init__(self, records: Iterable | None = None, *, zone=None) -> None:
        self._sets: dict[tuple[tuple, int, tuple | None], _Bucket] = {}
        self._sigs: dict[tuple[tuple, int], list] = {}
        if records is not None:
            self.add(records, zone=zone)

    @staticmethod
    def _key(name) -> tuple:
        return name_order_key(DomainName(name))

    def add(self, records: Iterable, *, zone=None) -> None:
        """File records, remembering that they came from *zone*'s data.

        ``zone=None`` means "origin not stated": those RRsets stay usable as a fallback
        when no origin-tagged set competes with them, which keeps single-source callers
        (a packet at a time, a test with one fixture) from having to declare what the
        data already implies.
        """
        origin = None if zone is None else (str(DomainName(zone)),)
        for record in records:
            rtype = int(record.rtype)
            if rtype == int(DnsRType.OPT):
                continue  # RFC 6891 §6.2.1: the OPT pseudo-RR is never RRset data
            rdata = record.rdata
            key = self._key(record.name)
            if rtype == int(DnsRType.RRSIG):
                covered = int(rdata.type_covered)
                self._sigs.setdefault((key, covered), []).append(rdata)
                continue
            bucket = self._sets.get((key, rtype, origin))
            if bucket is None:
                bucket = self._sets[(key, rtype, origin)] = _Bucket(
                    record.name, rtype, record.rclass
                )
            blob = bytes(rdata)
            if blob not in bucket.seen:
                bucket.seen.add(blob)
                bucket.rdatas.append(rdata)

    def rdatas(self, name, rtype: int, *, origin=None) -> tuple:
        """The RDATA of the (name, rtype) RRset, *origin*'s view if it has one.

        An ``origin`` of a zone prefers that zone's records absolutely -- that is the
        §5.3.2¶18 split -- and falls back to origin-unknown records when the zone never
        claimed them. Without an origin, every view is merged; callers that verify a
        signature always pass one, so the merge answers "does anything here assert X?"
        and never an authentication question.
        """
        key = self._key(name)
        wanted = int(rtype)
        if origin is not None:
            bucket = self._sets.get((key, wanted, (str(DomainName(origin)),)))
            if bucket is not None:
                return tuple(bucket.rdatas)
            bucket = self._sets.get((key, wanted, None))
            return () if bucket is None else tuple(bucket.rdatas)
        merged = []
        for (bucket_key, rtype_at, _origin), bucket in self._sets.items():
            if bucket_key == key and rtype_at == wanted:
                merged.extend(bucket.rdatas)
        return tuple(merged)

    def signatures(self, name, covered_type: int, *, signer=None) -> tuple:
        """RRSIGs covering (name, covered_type); with *signer*, only that zone's."""
        found = self._sigs.get((self._key(name), int(covered_type)), ())
        if signer is None:
            return tuple(found)
        want = str(DomainName(signer))
        return tuple(sig for sig in found if str(DomainName(sig.signer_name)) == want)

    def has_rrset(self, name, rtype: int) -> bool:
        return bool(self.rdatas(name, rtype))

    def names_with(self, rtype: int) -> tuple[DomainName, ...]:
        """Every owner name with data of *rtype*, any origin, deduplicated."""
        seen: dict[tuple, DomainName] = {}
        for (key, bucket_type, _origin), bucket in self._sets.items():
            if bucket_type == int(rtype) and key not in seen:
                seen[key] = bucket.owner
        return tuple(seen.values())

    def proof_records(self, zone) -> tuple:
        """NSEC and NSEC3 records *zone*'s data holds, as record-shaped objects.

        The origin rule does the sifting here, and it is §5.3.2¶18's again: a parent's
        NSEC for a delegated name and the child's NSEC for its own apex share an owner
        and a type, and handing the geometry predicates the wrong one of the pair is how
        a walk invents denials the zone never made. Records whose arrival carried no
        origin are included as the fallback view, signed or not -- a denial nobody signed
        is evidence of *something*, and it is this layer's job to call that Bogus, not
        the record-keeping layer's job to quietly drop it.
        """
        origin_key = (str(DomainName(zone)),)
        proof_types = (int(DnsRType.NSEC), int(DnsRType.NSEC3))
        records = []
        for (_name_key, rtype_at, origin), bucket in self._sets.items():
            if rtype_at not in proof_types:
                continue
            if origin is not None and origin != origin_key:
                continue
            for rdata in bucket.rdatas:
                records.append(_AsRecord(bucket.owner, bucket.rtype, bucket.rclass, rdata))
        return tuple(records)


# ------------------------------------------------------------------------------ the validator

_PRIORITY = {
    SecurityStatus.SECURE: 3,
    SecurityStatus.BOGUS: 2,
    SecurityStatus.INSECURE: 1,
    SecurityStatus.INDETERMINATE: 0,
}


def _choose[TV: ValidationVerdict](results: list[TV]) -> TV:
    """Combine per-path verdicts: proof beats suspicion beats absence of evidence.

    SECURE wins outright (any one authenticated path authenticates the zone -- RFC 4035
    §5.2¶7 explicitly allows a configured key to "re-establish an authentication path"
    past a parent that proves nothing). BOGUS outranks INSECURE because a zone that
    matches a configured anchor while its parent denies any DS is exactly the state a
    half-finished key rollover -- or an attacker deleting a DS -- produces, and quietly
    trusting the denial is the louder failure (§4.3¶4's "configuration error or data
    corruption" warning is written for precisely this ambiguity). INSECURE outranks
    INDETERMINATE because a signed proof of no DS is positive evidence, and the rest
    cannot be decided from what was supplied.
    """
    return max(results, key=lambda verdict: _PRIORITY[verdict.status])


class Validator:
    """Decides what a collected set of records proves, under a set of trust anchors.

    One instance holds the anchors and the clock for a lookup (``now`` pinned so a
    long-running process cannot straddle a signature window mid-chain) and memoises
    per-zone authentication, because every chain passes through the same handful of
    zones and re-verifying the root's self-signature per answer is theatre. The store is
    shared state: feed it from each response as the walk descends -- or in one shot --
    and the verdicts are identical either way, which is the point of bucketing by origin
    rather than by arrival.
    """

    def __init__(
        self,
        *,
        anchors: Iterable[TrustAnchor] = (),
        store: DnssecStore | None = None,
        now: float | None = None,
        rclass: int = 1,
    ) -> None:
        self.store = store if store is not None else DnssecStore()
        self.now = now
        self.rclass = int(rclass)
        self._anchors: dict[str, list[TrustAnchor]] = {}
        for anchor in anchors:
            self._anchors.setdefault(str(DomainName(anchor.zone)), []).append(anchor)
        self._memo: dict[str, ZoneVerdict] = {}
        self._asked: set[tuple] = set()

    def invalidate(self) -> None:
        """Drop the memo, keep the questions already asked.

        A caller that has just added records to the store -- a resolver acting on a
        :attr:`ValidationVerdict.fetch_hint` -- must re-run the climb before trusting
        a verdict again, or the fresh DS in the store buys nothing. ``_asked``
        survives deliberately: this reopens the *conclusions*, not the *requests*,
        so a fetch loop still terminates after one query per (name, type, zone).
        """
        self._memo.clear()

    def _need(self, name, rtype: int, from_zone) -> tuple | None:
        """One offer per missing record: the hint a fetch loop should act on, or None.

        The deduplication key is the query, not the conclusion -- after
        :meth:`invalidate` the same absence re-raises, and the second verdict must
        say "Indeterminate, and nothing left to ask" rather than queue the same
        query again against a server that already failed to answer it.
        """
        triple = (str(DomainName(name)), int(rtype), str(DomainName(from_zone)))
        if triple in self._asked:
            return None
        self._asked.add(triple)
        return (DomainName(name), int(rtype), DomainName(from_zone))

    def _trusted_for(self, zone):
        """The zone's configured anchors as the two trust shapes RFC 4033 §2 allows."""
        ds_records = []
        keys = []
        for anchor in self._anchors.get(str(zone), ()):
            if anchor.public_key is not None and anchor.flags is not None:
                from .rdata import RData_DNSKEY  # deferred: only key-shaped anchors need it

                keys.append(RData_DNSKEY(anchor.flags, 3, anchor.algorithm, anchor.public_key))
            if anchor.comparable:
                ds_records.append(anchor.ds_record())
        return ds_records, keys

    def _verify(self, name, rtype: int, rdatas: tuple, keys, *, signer) -> tuple[str, str]:
        """Check one RRset's signatures under keys already known authentic.

        Returns ``("valid" | "bogus" | "indeterminate", reason)``. Missing signatures are
        *bogus*, not merely unprovable: RFC 4033 §5 lists "missing signatures" under
        Bogus outright, and an RRset inside a zone this validator has already
        authenticated as secure that arrived unsigned is a contradiction, not an absence
        -- the same reasoning that makes an unsigned DS under a secure parent a refusal
        rather than a shrug.
        """
        sigs = self.store.signatures(name, rtype, signer=signer)
        if not sigs:
            return (
                "bogus",
                f"the {DnsRType(rtype).name} RRset at {name} carries no signature from "
                f"{signer}, and RFC 4033 §5 counts missing signatures as bogus material",
            )
        bogus_reason: str | None = None
        indet_reason: str | None = None
        for sig in sigs:
            verdict = verify_rrsig(sig, name, rdatas, keys, now=self.now, rclass=self.rclass)
            if verdict.verified:
                return ("valid", f"signed by key tag {verdict.key_tag}")
            if verdict.outcome is SignatureOutcome.INVALID:
                bogus_reason = verdict.reason
            elif verdict.outcome is SignatureOutcome.UNSUPPORTED:
                indet_reason = verdict.reason
        if bogus_reason is not None:
            return ("bogus", bogus_reason)
        return ("indeterminate", indet_reason or "no candidate signature could be attempted")

    def authenticate_zone(self, zone) -> ZoneVerdict:
        """Walk from *zone*'s apex up to a trust point, per RFC 4035 §5.2 and RFC 4033 §2.

        At each zone three things can end the climb: a configured anchor for that zone
        (either RFC 4033 §2 shape), an authenticated DS from the parent introducing a
        key that self-signs this apex, or the parent's signed proof that no DS exists --
        which stops the climb as Insecure rather than continuing it (§4.3¶3's descendants
        of an unsigned zone are Insecure too, and this recursion falls out of simply
        propagating the parent's state). A zone with no anchor and no parent data is
        Indeterminate -- the resolver could not obtain what it needed (§4.3¶5) -- and
        only *contradicted* data is Bogus (§4.3¶4). RFC 4035 §5.1's islands get their
        second chance: the parent's verdict is a result among results, never a veto, so a
        directly-anchored zone stays secure below a parent the walk could not verify.
        """
        zone = DomainName(zone)
        key = str(zone)
        if key in self._memo:
            return self._memo[key]
        apex = int(DnsRType.DNSKEY)
        records = self.store.rdatas(zone, apex)
        results: list[ZoneVerdict] = []

        def zone_from_chain(cv, *, default_zone):
            if cv.secure:
                return ZoneVerdict(
                    SecurityStatus.SECURE,
                    cv.reason,
                    zone=default_zone,
                    matched_key_tag=cv.matched_key_tag,
                    keys=records,
                )
            status = (
                SecurityStatus.BOGUS
                if cv.outcome is ChainOutcome.BOGUS
                else SecurityStatus.INDETERMINATE
            )
            return ZoneVerdict(status, cv.reason, zone=default_zone)

        ds_trusted, key_trusted = self._trusted_for(zone)
        if records and (ds_trusted or key_trusted):
            chain = authenticate_dnskey_rrset(
                zone,
                records,
                self.store.signatures(zone, apex),
                ds_trusted,
                now=self.now,
                rclass=self.rclass,
                trusted_dnskeys=key_trusted,
            )
            results.append(zone_from_chain(chain, default_zone=zone))

        if not zone.labels():  # the root: labels() is empty, hierarchy() has one entry
            if not results:
                if not records:
                    verdict = ZoneVerdict(
                        SecurityStatus.INDETERMINATE,
                        "no DNSKEY RRset for the root was supplied to authenticate against",
                        zone=zone,
                        fetch_hint=self._need(zone, apex, zone),
                    )
                else:
                    verdict = ZoneVerdict(
                        SecurityStatus.INDETERMINATE,
                        "the top of the tree was reached with no trust anchor configured "
                        "for it: nothing here can say whether this root is the trusted one "
                        "(RFC 4035 §4.3¶5)",
                        zone=zone,
                    )
            else:
                verdict = _choose(results)
            self._memo[key] = verdict
            return verdict

        parent = zone.hierarchy()[-2]
        above = self.authenticate_zone(parent)
        if above.status is SecurityStatus.SECURE:
            ds_set = self.store.rdatas(zone, int(DnsRType.DS), origin=parent)
            if ds_set:
                kind, reason = self._verify(
                    zone, int(DnsRType.DS), ds_set, above.keys, signer=parent
                )
                if kind != "valid":
                    results.append(
                        ZoneVerdict(
                            SecurityStatus.BOGUS
                            if kind == "bogus"
                            else SecurityStatus.INDETERMINATE,
                            f"the DS RRset at the parent {parent} does not authenticate: {reason}",
                            zone=parent,
                        )
                    )
                elif not records:
                    results.append(
                        ZoneVerdict(
                            SecurityStatus.INDETERMINATE,
                            f"the parent {parent} authenticates a child key set for {zone} "
                            f"that was not supplied -- the DNSKEY RRset must be asked for",
                            zone=zone,
                            fetch_hint=self._need(zone, apex, zone),
                        )
                    )
                else:
                    chain = authenticate_dnskey_rrset(
                        zone,
                        records,
                        self.store.signatures(zone, apex),
                        ds_set,
                        now=self.now,
                        rclass=self.rclass,
                    )
                    results.append(zone_from_chain(chain, default_zone=zone))
            else:
                results.append(self._prove_no_ds(zone, parent, above))
        else:
            results.append(
                ZoneVerdict(
                    above.status,
                    f"the walk stops at the parent {parent}: {above.reason}",
                    zone=parent,
                    fetch_hint=above.fetch_hint,
                )
            )

        verdict = (
            _choose(results)
            if results
            else ZoneVerdict(
                SecurityStatus.INDETERMINATE,
                f"no DNSKEY RRset for {zone} was supplied, and no anchor or parent DS "
                f"reaches it (RFC 4035 §4.3¶5)",
                zone=zone,
                fetch_hint=self._need(zone, apex, zone),
            )
        )
        self._memo[key] = verdict
        return verdict

    # ------------------------------------------------------------------ denial machinery

    def _verify_proofs(self, zone, records, keys) -> tuple[str, str]:
        """Verify every proof record's RRset under *zone*'s authentic keys.

        All of them, not just the ones the geometry predicate happened to consult: RFC
        4033 §5's Secure definition is "able to verify **all** the signatures in the
        response", and a bundle with one forged NSEC alongside the right one is a bundle
        to refuse, not one to cherry-pick.
        """
        seen: set[tuple] = set()
        worst: tuple[str, str] | None = None
        for record in records:
            key = (name_order_key(DomainName(record.name)), int(record.rtype))
            if key in seen:
                continue
            seen.add(key)
            rdatas = self.store.rdatas(record.name, int(record.rtype), origin=zone)
            kind, reason = self._verify(record.name, int(record.rtype), rdatas, keys, signer=zone)
            if kind == "bogus":
                return ("bogus", reason)
            if kind == "indeterminate" and worst is None:
                worst = (kind, reason)
        return worst or ("valid", "every proof record verifies")

    def _prove_no_ds(self, zone, parent, above: ZoneVerdict) -> ZoneVerdict:
        """Ask the parent to prove the delegation is unsigned (RFC 4035 §5.2¶7).

        The two proof families get their own branch because their shapes disagree: an
        NSEC at the delegated name with the DS bit clear, or an NSEC3 chain over the
        hashed name -- and only after the geometry holds does this check the signatures,
        because a proof that names the wrong span is bogus material whoever signed it.
        """
        records = self.store.proof_records(parent)
        entries3 = proof_entries(records, rtype=int(DnsRType.NSEC3))
        entries1 = proof_entries(records, rtype=int(DnsRType.NSEC))
        if not entries3 and not entries1:
            return ZoneVerdict(
                SecurityStatus.INDETERMINATE,
                f"the parent {parent} holds neither a DS for {zone} nor any NSEC/NSEC3 "
                f"records proving none exists -- RFC 4035 §5.2¶6 makes going and asking "
                f"for the DS the resolver's next move",
                zone=parent,
                fetch_hint=self._need(zone, int(DnsRType.DS), parent),
            )
        try:
            if entries3:
                nsec3_proves_no_ds(zone, usable_nsec3(entries3), parent)
            else:
                nsec_proves_no_data(zone, int(DnsRType.DS), entries1)
        except IncompleteProofError as exc:
            return ZoneVerdict(SecurityStatus.INDETERMINATE, str(exc), zone=parent)
        except ContradictoryProofError as exc:
            return ZoneVerdict(SecurityStatus.BOGUS, str(exc), zone=parent)
        kind, reason = self._verify_proofs(parent, records, above.keys)
        if kind == "bogus":
            return ZoneVerdict(
                SecurityStatus.BOGUS,
                f"the no-DS proof from {parent} fails to verify: {reason}",
                zone=parent,
            )
        if kind == "indeterminate":
            return ZoneVerdict(
                SecurityStatus.INDETERMINATE,
                f"the no-DS proof from {parent} could not be verified: {reason}",
                zone=parent,
            )
        return ZoneVerdict(
            SecurityStatus.INSECURE,
            f"{zone} is provably unsigned: {parent} holds signed proof that no DS "
            f"record exists here (RFC 4035 §5.2¶7)",
            zone=zone,
        )

    # ------------------------------------------------------------------ public decisions

    def validate_rrset(self, name, rtype: int, *, zone=None) -> ValidationVerdict:
        """May this answer be believed? -- RFC 4035 §4.3 applied to one RRset.

        The RRSIG's own Signer's Name says which zone the chain must reach, so the
        caller usually owes nothing but the name and type; ``zone`` is only consulted
        when the RRset arrives *unsigned*, because "unsigned" is Insecure below a proved
        unsigned parent and Bogus inside an authenticated secure one, and with no zone
        and no signature there is nobody to ask (RFC 4033 §5's Indeterminate: no trust
        point even indicates the question). A verified signature with fewer Labels than
        its owner has names a wildcard-expanded answer, and §5.3.4¶1 then requires the
        closer-match denial -- verified like every other proof here, because a wildcard
        is only as good as the proof that nothing closer exists.
        """
        name = DomainName(name)
        rtype = int(rtype)
        rdatas_all = self.store.rdatas(name, rtype)
        type_name = DnsRType(rtype).name
        if not rdatas_all:
            return ValidationVerdict(
                SecurityStatus.INDETERMINATE,
                f"no {type_name} RRset for {name} is present in the supplied records",
            )
        sigs = self.store.signatures(name, rtype)
        if not sigs:
            if zone is None:
                return ValidationVerdict(
                    SecurityStatus.INDETERMINATE,
                    f"the {type_name} RRset at {name} carries no signature and no zone "
                    f"was stated: cannot distinguish unsigned from not-yet-asked-about",
                    zone=name,
                )
            zv = self.authenticate_zone(zone)
            if zv.status is SecurityStatus.SECURE:
                return ValidationVerdict(
                    SecurityStatus.BOGUS,
                    f"the {type_name} RRset at {name} is unsigned inside the "
                    f"authenticated secure zone {zv.zone} (RFC 4033 §5: missing "
                    f"signatures are bogus material)",
                    zone=zv.zone,
                )
            return ValidationVerdict(
                zv.status,
                zv.reason,
                zone=zv.zone,
                matched_key_tag=zv.matched_key_tag,
                fetch_hint=zv.fetch_hint,
            )

        by_signer: dict[str, list] = {}
        signers: dict[str, object] = {}
        for sig in sigs:
            label = str(DomainName(sig.signer_name))
            by_signer.setdefault(label, []).append(sig)
            signers.setdefault(label, sig.signer_name)
        results: list[ValidationVerdict] = []
        for label in by_signer:
            results.extend(
                self._rrset_under_signer(name, rtype, signers[label], by_signer[label], rdatas_all)
            )
        return _choose(results)

    def _rrset_under_signer(self, name, rtype, signer, signer_sigs, rdatas_all):
        """One signer's share of :meth:`validate_rrset`: chain, then arithmetic."""
        zv = self.authenticate_zone(signer)
        if zv.status is not SecurityStatus.SECURE:
            return [
                ValidationVerdict(
                    zv.status,
                    f"signer {signer}: {zv.reason}",
                    zone=zv.zone,
                    fetch_hint=zv.fetch_hint,
                )
            ]
        rrset = self.store.rdatas(name, rtype, origin=signer) or rdatas_all
        results: list[ValidationVerdict] = []
        bogus_reason: str | None = None
        indet_reason: str | None = None
        for sig in signer_sigs:
            verdict = verify_rrsig(sig, name, rrset, zv.keys, now=self.now, rclass=self.rclass)
            if verdict.verified:
                if int(sig.labels) >= rrsig_label_count(name):
                    return [
                        ValidationVerdict(
                            SecurityStatus.SECURE,
                            f"signed under {signer} by key tag {verdict.key_tag}: {verdict.reason}",
                            zone=DomainName(signer),
                            matched_key_tag=verdict.key_tag,
                        )
                    ]
                wildcard = self._validate_wildcard(name, sig, signer, zv)
                if wildcard.secure:
                    return [wildcard]
                results.append(wildcard)
            elif verdict.outcome is SignatureOutcome.INVALID:
                bogus_reason = verdict.reason
            elif verdict.outcome is SignatureOutcome.UNSUPPORTED:
                indet_reason = verdict.reason
        if bogus_reason is not None:
            return [
                ValidationVerdict(
                    SecurityStatus.BOGUS,
                    f"the signature over {name}/{DnsRType(rtype).name} fails under its "
                    f"authenticated signer {signer}: {bogus_reason}",
                    zone=DomainName(signer),
                )
            ]
        if indet_reason is not None:
            return [
                ValidationVerdict(
                    SecurityStatus.INDETERMINATE,
                    f"the signature over {name}/{DnsRType(rtype).name} could not be "
                    f"checked: {indet_reason}",
                    zone=DomainName(signer),
                )
            ]
        return results

    def _validate_wildcard(self, qname, sig, signer, zv: ZoneVerdict) -> ValidationVerdict:
        """RFC 4035 §5.3.4¶1: a synthesised answer owes proof that nothing closer exists."""
        labs = [label for label in qname.labels() if label]
        keep = int(sig.labels)
        wildcard = DomainName.from_labels([b"*"] + (labs[len(labs) - keep :] if keep else []))
        records = self.store.proof_records(signer)
        entries3 = proof_entries(records, rtype=int(DnsRType.NSEC3))
        entries1 = proof_entries(records, rtype=int(DnsRType.NSEC))
        if not entries3 and not entries1:
            return ValidationVerdict(
                SecurityStatus.INDETERMINATE,
                f"the answer at {qname} arrived through the wildcard {wildcard}, and "
                f"{signer} supplied no NSEC/NSEC3 records to prove no closer name exists "
                f"(RFC 4035 §5.3.4¶1)",
                zone=DomainName(signer),
            )
        try:
            if entries3:
                nsec3_proves_wildcard_answer(qname, wildcard, usable_nsec3(entries3), signer)
            else:
                nsec_proves_wildcard_answer(qname, wildcard, entries1)
        except IncompleteProofError as exc:
            return ValidationVerdict(
                SecurityStatus.INDETERMINATE, str(exc), zone=DomainName(signer)
            )
        except ContradictoryProofError as exc:
            return ValidationVerdict(SecurityStatus.BOGUS, str(exc), zone=DomainName(signer))
        kind, reason = self._verify_proofs(signer, records, zv.keys)
        if kind == "bogus":
            return ValidationVerdict(SecurityStatus.BOGUS, reason, zone=DomainName(signer))
        if kind == "indeterminate":
            return ValidationVerdict(
                SecurityStatus.INDETERMINATE,
                f"the closer-match proof for {qname} could not be verified: {reason}",
                zone=DomainName(signer),
            )
        return ValidationVerdict(
            SecurityStatus.SECURE,
            f"wildcard-expanded answer at {qname} via {wildcard}: the closer-match "
            f"denial from {signer} is present and signed (RFC 4035 §5.3.4, §5.4¶4)",
            zone=DomainName(signer),
            matched_key_tag=zv.matched_key_tag,
        )

    def validate_denial(self, qname, qtype: int, *, rcode, zone) -> ValidationVerdict:
        """Is this denial of existence proved -- and proved by the right zone?

        ``zone`` is the apex of the zone that answered (its servers, its SOA), which the
        resolver always knows; the geometry then runs on the shape the nsec.py module was
        built for -- RFC 5155 §8.4 for a Name Error, §8.5 for No Data, RFC 4035 §5.4 for
        their NSEC originals -- and only a response whose proofs both *name* the denial
        and *verify* under authenticated keys comes back SECURE.

        Two refusals stay distinct because a resolver treats them differently, which is
        the whole lesson of RFC 8020 §2¶3 for the NXDOMAIN cut: a denial whose chain
        reaches only an INSECURE verdict is a denial of nothing (an unsigned zone can
        deny whatever it likes), and one whose proof is missing is a question to ask
        again, not a verdict to cache. A zone that is secure but contradicts itself -- a
        bitmap listing the type it denies, a proof signed by somebody else -- is Bogus
        even when the answer it carries happens to be correct.
        """
        zone = DomainName(zone)
        zv = self.authenticate_zone(zone)
        if zv.status is not SecurityStatus.SECURE:
            return ValidationVerdict(
                zv.status,
                f"the denial from {zone} rests on unauthenticated keys: {zv.reason}",
                zone=zone,
                fetch_hint=zv.fetch_hint,
            )
        records = self.store.proof_records(zone)
        entries3 = proof_entries(records, rtype=int(DnsRType.NSEC3))
        entries1 = proof_entries(records, rtype=int(DnsRType.NSEC))
        if not entries3 and not entries1:
            return ValidationVerdict(
                SecurityStatus.INDETERMINATE,
                f"{zone} is a secure zone but this answer carries no NSEC/NSEC3 proof "
                f"at all (RFC 4035 §3.1.3 obliges a signed zone to send one)",
                zone=zone,
            )
        error = DnsResponseCode(int(rcode))
        via_opt_out = False
        try:
            if error is DnsResponseCode.NAME_ERROR:
                if entries3:
                    via_opt_out = nsec3_proves_nxdomain(
                        qname, usable_nsec3(entries3), zone
                    ).via_opt_out
                else:
                    nsec_proves_nxdomain_response(qname, entries1)
            elif error is DnsResponseCode.NO_ERROR:
                if entries3:
                    via_opt_out = nsec3_proves_no_data(
                        qname, int(qtype), usable_nsec3(entries3), zone
                    ).via_opt_out
                else:
                    nsec_proves_no_data(qname, int(qtype), entries1)
            else:
                raise ValueError(
                    f"validate_denial takes NAME_ERROR or NO_ERROR answers, got {error!r}"
                )
        except IncompleteProofError as exc:
            return ValidationVerdict(SecurityStatus.INDETERMINATE, str(exc), zone=zone)
        except ContradictoryProofError as exc:
            return ValidationVerdict(SecurityStatus.BOGUS, str(exc), zone=zone)
        kind, reason = self._verify_proofs(zone, records, zv.keys)
        if kind == "bogus":
            return ValidationVerdict(
                SecurityStatus.BOGUS,
                f"the proof of denial from {zone} fails to verify: {reason}",
                zone=zone,
            )
        if kind == "indeterminate":
            return ValidationVerdict(
                SecurityStatus.INDETERMINATE,
                f"the proof of denial from {zone} could not be verified: {reason}",
                zone=zone,
            )
        return ValidationVerdict(
            SecurityStatus.SECURE,
            f"{error.name} for {qname} is proved by {zone} and every proof signature "
            f"verifies under key tag {zv.matched_key_tag}",
            zone=zone,
            matched_key_tag=zv.matched_key_tag,
            via_opt_out=via_opt_out,
        )
