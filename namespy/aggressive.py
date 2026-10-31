"""Aggressive NSEC/NSEC3 caching: denials synthesised from validated cached proofs.

RFC 8198 rewrote the paragraph RFC 4035 §4.5 had ended with "it seems prudent for
resolvers to avoid blocking new authoritative data or synthesizing new data on
their own". The replacing sentence (8198 §7): \"Once the records are validated,
DNSSEC-enabled validating resolvers SHOULD use wildcards and NSEC/NSEC3 resource
records to generate positive and negative responses until the effective TTLs or
signatures for those records expire.\" This module does the negative half of that
sentence -- a single cached, validated denial is evidence about every other name
and type its proof spans, and Appendix A ¶3 places exactly this check at the
cache-lookup step of a recursive resolver. The positive half (wildcard answers,
§5.3) lives on the roadmap still.

What conditions the licence, and where each guard lives here:

* Only validated data. Appendix B ¶2 is the first instruction of the procedure:
  "If the NSEC record has not been verified as secure, discard it." The cache's
  ``validated`` stamp -- this resolver's own fully-verified verdict at write
  time -- is what answers that question, and an entry without it is not
  disbelieved, merely unusable here.
* The proof must prove *this* name, not the one the bundle arrived for. 8198
  §5.1/§5.2 adopt RFC 4035 §5.4 and RFC 5155 §8.4-§8.7 whole, so the candidate
  bundle is fed to the same response validators the live walk uses and only a
  complete proof synthesises; an incomplete one falls back to the network, which
  Appendix A ¶4 makes a MUST ("as though it does not implement aggressive
  negative caching").
* Opt-Out spans deny nothing aggressively (§5.2¶3), so a proof whose next closer
  rests on an Opt-Out record is refused -- the same refusal that keeps AD off
  those answers, read here on the proof in hand rather than on the entry's
  stamp, because the flag belongs to the covering record, not to the file.
* Signatures count as well as TTLs ("until the effective TTLs or signatures
  expire", §7): the entry's own expiry is the TTL half and the caller's honour;
  the RRSIG windows are read here -- a timestamp, not a re-verification, which
  the stamp-at-write doctrine still forbids.
* TTL: RFC 9077 §3.4 (which *replaced* 8198 §5.4 whole) keeps the 3-hour
  recommendation for the effective TTL of aggressively used negative data,
  §9¶3 the same for the poison blast-radius. The synthesised answer clamps to
  it, and to the entry's remaining life.

The CD bit exemption is the caller's, not this module's: Appendix A ¶1 answers
"whenever it has an applicable validated NSEC in its cache unless the CD bit was
set on the incoming query", and the walk knows the client's bit; this function
only ever sees entries and a name.
"""

from __future__ import annotations

from .cache import NegativeEntry
from .enums import DnsQR, DnsResponseCode, DnsRType
from .names import DomainName
from .nsec import (
    NodataProof,
    ProofError,
    WildcardNodataProof,
    nsec3_proves_no_data,
    nsec3_proves_no_ds,
    nsec3_proves_nxdomain,
    nsec3_proves_wildcard_no_data,
    nsec3_record_is_from_proper_zone,
    nsec_proves_no_data,
    nsec_proves_nxdomain_response,
    nsec_record_is_from_proper_zone,
    proof_entries,
)
from .packet import DnsRecord, Response
from .rdata import RData_RRSIG

#: RFC 8198 §5.4¶2 as replaced by RFC 9077 §3.4: "It is RECOMMENDED that
#: validating resolvers limit the maximum effective TTL value of negative
#: responses (NSEC/NSEC3 RRs)" to RFC 2308 §5's three hours. Applied to the
#: synthesised answer -- the one this feature adds to the world -- rather than
#: to stored entries, whose TTL the 2308 §5 clamp already owns.
MAX_AGGRESSIVE_TTL = 10800


def _at_or_under(name, apex) -> bool:
    """Whether *name* sits at or below *apex* (case-folded label suffix)."""
    labels = DomainName(name)._labels()
    top = DomainName(apex)._labels()
    if not top:
        # The root zone's empty label tuple is a suffix of everything -- and
        # ``labels[-0:]`` is the whole tuple, not nothing, so the general test
        # below would exclude exactly the zone that includes every name.
        return True
    return len(labels) >= len(top) and labels[-len(top) :] == top


def _proof_is_live(entry, now: float) -> bool:
    """Whether every RRSIG in the bundle is still inside its validity window.

    Reading ``SIGNATURE EXPIRATION`` is not re-validation -- it is the second
    half of §7's "until the effective TTLs or signatures for those records
    expire", the half the entry's own expiry does not cover: §9¶4 spells out
    that "the TTL of NSEC/NSEC3 records is typically fairly short (minutes or
    hours)" while "their RRSIG expiration time can be much further in the
    future", and a bundle whose signature died young proves nothing at any TTL.
    """
    for record in entry.proofs:
        if int(record.rtype) != int(DnsRType.RRSIG):
            continue
        rdata = record.rdata
        if isinstance(rdata, RData_RRSIG) and not rdata.within_validity(now):
            return False
    return True


def _capped(record: DnsRecord, ttl: int) -> DnsRecord:
    """The same record with its TTL reduced to *ttl* if it claimed longer."""
    if int(record.ttl) <= ttl:
        return record
    return DnsRecord(record.name, record.rtype, record.rclass, ttl, rdata=record.rdata)


def _covering_nsec_rrsig(entry, qname):
    """The bundle's RRSIG for the NSEC at *qname*, for §5.4¶3's Labels check."""
    for record in entry.proofs:
        if int(record.rtype) != int(DnsRType.RRSIG):
            continue
        if DomainName(record.name) != DomainName(qname):
            continue
        rdata = record.rdata
        if isinstance(rdata, RData_RRSIG) and int(rdata.type_covered) == int(DnsRType.NSEC):
            return rdata
    return None


def _nxdomain_from(qname, nsec_entries, nsec3_entries, zone) -> bool:
    """Whether the bundle proves *qname* absent, per §5.1/§5.2's adopted rules.

    The NSEC branch needs no Opt-Out gate (the flag is an NSEC3 invention) and no
    cut guard of its own: both closest-encloser walks already refuse a DNAME or
    an NS-without-SOA at the encloser -- RFC 5155 §8.3¶12, which 8198 Appendix B
    ¶4 states for the same reason in the same words, "it is from a parent zone".
    A zone that owns records below a cut may deny names in its own spans; a zone
    that stopped being authoritative there may not, and the walk says so.
    """
    if nsec_entries:
        try:
            nsec_proves_nxdomain_response(qname, nsec_entries)
            return True
        except ProofError:
            return False
    if nsec3_entries:
        try:
            nsec_proof = nsec3_proves_nxdomain(qname, nsec3_entries, zone)
        except ProofError:
            return False
        # §5.2¶3: "the covering NSEC3 RR does not prove the non-existence of
        # the domain name and the aggressive negative caching is not possible
        # for the domain name."
        return not nsec_proof.via_opt_out
    return False


def _nodata_from(entry, qname, qtype, nsec_entries, nsec3_entries, zone) -> bool:
    """Whether the bundle proves no RRset of *qtype* at *qname*.

    §5.4¶3 and §8.5/§8.6 run whole, which imports their refusals with them: a
    bitmap listing the type, or CNAME, contradicts and aborts; NSEC and RRSIG
    queries are unprovable by a bitmap (§5.4¶7, which tells the validator to
    ignore those bits -- here, to ask the network instead). The one thing the
    response-time validators did not need and this path does is the cut check:
    a server that is not authoritative below *qname* may answer a type query
    with a referral and never from its own bitmap, so an NS-without-SOA matching
    record may not synthesise anything -- except for a DS query, the one type
    for which the delegation point itself is the authoritative owner, and whose
    proven absence is the whole of an insecure-delegation answer (§5.4¶5, §8.6).
    """
    if nsec_entries:
        try:
            nsec_proof = nsec_proves_no_data(
                qname, qtype, nsec_entries, rrsig=_covering_nsec_rrsig(entry, qname)
            )
        except ProofError:
            return False
        at_a_cut = (
            nsec_proof.matching is not None
            and int(qtype) != int(DnsRType.DS)
            and not nsec_record_is_from_proper_zone(nsec_proof.matching)
        )
        return not at_a_cut
    if nsec3_entries:
        nsec3_proof: NodataProof | WildcardNodataProof
        try:
            if int(qtype) == int(DnsRType.DS):
                nsec3_proof = nsec3_proves_no_ds(qname, nsec3_entries, zone)
            else:
                nsec3_proof = nsec3_proves_no_data(qname, qtype, nsec3_entries, zone)
        except ProofError:
            # §8.7 is the third NODATA shape 8198 §5.2 calls for: the name exists
            # only through a wildcard, and it is the wildcard's bitmap that
            # lacks the type -- a different bundle than §8.5's match, asked when
            # that one is not in the cache rather than guessed at.
            try:
                nsec3_proof = nsec3_proves_wildcard_no_data(qname, qtype, nsec3_entries, zone)
            except ProofError:
                return False
        if nsec3_proof.via_opt_out:
            return False
        matching = getattr(nsec3_proof, "matching", None)
        at_a_cut = (
            matching is not None
            and int(qtype) != int(DnsRType.DS)
            and not nsec3_record_is_from_proper_zone(matching)
        )
        return not at_a_cut
    return False


def synthesize_denial(
    entry,
    sname,
    *,
    now,
    remaining: int | None = None,
    dnssec_ok: bool = False,
    assert_ad: bool = False,
):
    """The denial *entry*'s cached proof establishes for *sname*, or ``None``.

    A synthesised answer is not a cached one: its TTL is computed now from the
    evidence's remaining life (capped at :data:`MAX_AGGRESSIVE_TTL`), its
    RCODE is whatever the proof says (*entry* was cached under someone else's
    question), and it is never written back -- one proof, one source of truth,
    and no second generation of negative data quietly outliving the first.

    *now* answers the RRSIG windows and lives on the signature's clock;
    *remaining* is the entry's life left, in seconds, measured by the caller on
    the clock the cache itself keeps -- the two clocks are different things
    (RFC 1982 serials versus whichever timer expires entries) and conflating
    them reads every entry as expired or none. When *remaining* is not given
    the function falls back to ``entry.expires_at - now``, the single-clock
    reading a caller with one clock means by. Entry expiry is otherwise not
    re-checked here: the backends forget expired entries on read, and a second
    opinion with the wrong clock is worse than none.

    ``assert_ad`` means "this resolver is a validator" -- the entry's stamp is a
    fact about whoever wrote it, and RFC 4035 §3.2.3's AD is a claim about the
    one answering; a non-validating reader synthesises the denial (RFC 8198's
    answer stands on the entry's validation) but asserts nothing, the same split
    the cache-hit path already makes.
    """
    if not isinstance(entry, NegativeEntry) or not getattr(entry, "validated", False):
        # Appendix B ¶2 in one line: unverified means discarded. Not believed
        # false -- just never the basis for a proof this resolver did not make.
        return None
    if entry.soa is None:
        return None
    if remaining is None:
        remaining = int(max(0.0, entry.expires_at - now))
    if remaining <= 0:
        return None
    zone = entry.soa.name
    qname = DomainName(sname.qname)
    if not _at_or_under(qname, zone):
        # A bundle is evidence about the zone that signed it. Its NSEC chain
        # says nothing about a name another zone owns, however tidy the ranges
        # look, and §5.4's geometry cannot tell the difference -- the SOA's
        # owner can.
        return None
    if not _proof_is_live(entry, now):
        return None

    nsec_entries = proof_entries(entry.proofs, int(DnsRType.NSEC))
    nsec3_entries = proof_entries(entry.proofs, int(DnsRType.NSEC3))
    qtype = int(sname.qtype)

    # NXDOMAIN first: it is the stronger claim, and where the name exists the
    # walk's ContradictoryProofError falls through to the NODATA attempt the
    # right way -- by proving the name, not by guessing it.
    if _nxdomain_from(qname, nsec_entries, nsec3_entries, zone):
        rcode = DnsResponseCode.NAME_ERROR
    elif _nodata_from(entry, qname, qtype, nsec_entries, nsec3_entries, zone):
        rcode = DnsResponseCode.NO_ERROR
    else:
        return None

    ttl = min(remaining, MAX_AGGRESSIVE_TTL)
    nameservers = [_capped(entry.soa, ttl)]
    if dnssec_ok:
        nameservers.extend(_capped(record, ttl) for record in entry.proofs)
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        AD=assert_ad,
        RCODE=rcode,
        questions=list(sname.questions),
        nameservers=nameservers,
    )
