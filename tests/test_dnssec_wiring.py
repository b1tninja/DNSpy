"""The walk that fetches its own chain -- the resolver-side DNSSEC wiring.

The validator of :mod:`namespy.validate` judges the records it is handed; these tests
drive the *handing*: a scripted descent from the root through two signed referrals
into a signed zone's NXDOMAIN or its signed answer, the chain-fetch loop the walk runs
when the chain is
incomplete (RFC 4035 §5.2¶6: "A security-aware resolver MUST query the name servers
for the parent zone for the DS RRset"), the verdict stamped into the cached
answer -- denial or positive --, :attr:`NxdomainPolicy.VALIDATED` finally consuming
it (RFC 8020 §2¶3), and the header's AD/CD pair lit or withheld according to all of
it (RFC 4035 §3.2.2-§3.2.3).

The keys, signatures, and trust anchor are the fixture tree of
:mod:`tests.test_dnssec_validate` -- imported rather than duplicated, following the
precedent of its live-root test -- restated as wire :class:`DnsRecord` so the walk
can carry them inside :class:`Response` packets exactly as a server sends them.
"""

import ipaddress

import pytest
import test_dnssec_validate as tree

from namespy.cache import FailureCache, MemoryDnsCache
from namespy.crypto import crypto_available
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.rdata import (
    RData_A,
    RData_AAAA,
    RData_DS,
    RData_NS,
    RData_RRSIG,
    RData_SOA,
)
from namespy.resolver import (
    DnssecVerdict,
    Done,
    Fail,
    Nxdomain,
    NxdomainCut,
    NxdomainPolicy,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    resolve_steps,
)
from namespy.trace import Trace

pytestmark = pytest.mark.skipif(not crypto_available(), reason="namespy[crypto] is not installed")

TTL = tree.TTL
NOW = tree.NOW  # the fixture tree's pinned signature-window clock

ROOT = DomainName(".")
ROOT_NS = DomainName("a.root-servers.net")
ROOT_IP = ipaddress.IPv4Address("198.41.0.1")
TEST_NS = DomainName("ns1.test.")
TEST_IP = ipaddress.IPv4Address("10.0.0.1")
ZONE_NS = DomainName("ns1.zone.test.")
ZONE_IP = ipaddress.IPv4Address("10.0.0.2")
SUB_NS = DomainName("ns1.sub.zone.test.")
SUB_IP = ipaddress.IPv4Address("10.0.0.3")


class Clock:
    """A settable clock for the cache's expiry arithmetic, separate from NOW.

    The validator's clock (the signature window) and the cache's clock (entry
    expiry) are deliberately different numbers: they share no units in the field,
    and a test that let them collapse into one would miss an expiry bug by accident.
    """

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# --------------------------------------------------------------------------- wire fixtures


def _rec(owner, rtype, rdata, ttl=TTL):
    return DnsRecord(DomainName(owner), int(rtype), DnsRClass.IN, ttl, rdata=rdata)


def _signed(zone, owner, rtype, rdatas, which, *, flip=False):
    """The fixture's ``serve`` in wire form: the RRset plus its covering RRSIG."""
    sig = tree._sign(tree._pk(which), zone, owner, int(rtype), rdatas)
    if flip:
        signature = bytearray(sig.signature)
        signature[-1] ^= 0x01
        sig = RData_RRSIG(
            sig.type_covered,
            sig.algorithm,
            sig.labels,
            sig.original_ttl,
            sig.expiration,
            sig.inception,
            sig.key_tag,
            sig.signer_name,
            bytes(signature),
        )
    return [_rec(owner, rtype, data) for data in rdatas] + [_rec(owner, int(DnsRType.RRSIG), sig)]


def root_keys():
    return _signed(".", ".", DnsRType.DNSKEY, [tree._pub("root")], "root")


def tld_keys():
    return _signed("test.", "test.", DnsRType.DNSKEY, [tree._pub("test")], "test")


def zone_keys():
    return _signed("zone.test.", "zone.test.", DnsRType.DNSKEY, [tree._pub("zone")], "zone")


def ds_test():
    return _signed(
        ".", "test.", DnsRType.DS, [RData_DS.for_dnskey("test.", tree._pub("test"))], "root"
    )


def ds_zone():
    return _signed(
        "test.",
        "zone.test.",
        DnsRType.DS,
        [RData_DS.for_dnskey("zone.test.", tree._pub("zone"))],
        "test",
    )


def soa(owner="zone.test."):
    return _rec(
        owner,
        DnsRType.SOA,
        RData_SOA(
            DomainName(f"ns1.{owner}"),
            DomainName(f"hostmaster.{owner}"),
            1,
            7200,
            3600,
            1209600,
            300,
        ),
    )


def _nsec(next_domain, types):
    return tree._nsec(DomainName(next_domain), types)


APEX_TYPES = [
    int(DnsRType.SOA),
    int(DnsRType.NS),
    int(DnsRType.DNSKEY),
    int(DnsRType.NSEC),
]


def zone_denials(*, flip_apex=False):
    """The four NSEC RRsets of the fixture's unsigned-child tree, wire-shaped.

    The walk names under test are ``aaa.zone.test.`` (no such name: denied by the
    apex NSEC, apex -> sub) and descendants of it; ``sub.zone.test.`` carries only
    the NS bit, which is what makes its delegation provably unsigned (§5.2¶9's
    parent NSEC).
    """
    return (
        _signed(
            "zone.test.",
            "zone.test.",
            DnsRType.NSEC,
            [_nsec("sub.zone.test.", APEX_TYPES)],
            "zone",
            flip=flip_apex,
        )
        + _signed(
            "zone.test.",
            "sub.zone.test.",
            DnsRType.NSEC,
            [_nsec("www.zone.test.", [int(DnsRType.NS)])],
            "zone",
        )
        + _signed(
            "zone.test.",
            "www.zone.test.",
            DnsRType.NSEC,
            [_nsec("y.zone.test.", [int(DnsRType.A)])],
            "zone",
        )
        + _signed(
            "zone.test.",
            "y.zone.test.",
            DnsRType.NSEC,
            [_nsec("zone.test.", [int(DnsRType.TXT)])],
            "zone",
        )
    )


def _resp(
    qname,
    qtype,
    *,
    aa=False,
    rcode=DnsResponseCode.NO_ERROR,
    answers=(),
    nameservers=(),
    additional=(),
):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=aa,
        RCODE=rcode,
        questions=[DnsQuestion(DomainName(qname), qtype)],
        answers=list(answers),
        nameservers=list(nameservers),
        additional_records=list(additional),
    )


def root_referral(qname):
    """The root referring ``test.`` with the child's DS riding along (§3.1.4)."""
    return _resp(
        qname,
        DnsQType.A,
        nameservers=[_rec("test.", DnsRType.NS, RData_NS(TEST_NS)), *ds_test()],
        additional=[_rec("ns1.test.", DnsRType.A, RData_A(TEST_IP))],
    )


def tld_referral(qname):
    return _resp(
        qname,
        DnsQType.A,
        nameservers=[_rec("zone.test.", DnsRType.NS, RData_NS(ZONE_NS)), *ds_zone()],
        additional=[_rec("ns1.zone.test.", DnsRType.A, RData_A(ZONE_IP))],
    )


def zone_referral_sub(qname, *, with_proof=True):
    """``zone.test.`` referring its *unsigned* child.

    With ``with_proof`` the referral carries the parent NSEC that proves the absent
    DS (RFC 4035 §3.1.4), and no query is needed; without it, §5.2¶6 obliges the
    resolver to go ask -- which is what the DS-fetch test scripts.
    """
    nameservers = [_rec("sub.zone.test.", DnsRType.NS, RData_NS(SUB_NS))]
    if with_proof:
        nameservers += _signed(
            "zone.test.",
            "sub.zone.test.",
            DnsRType.NSEC,
            [_nsec("www.zone.test.", [int(DnsRType.NS)])],
            "zone",
        )
    return _resp(
        qname,
        DnsQType.A,
        nameservers=nameservers,
        additional=[_rec("ns1.sub.zone.test.", DnsRType.A, RData_A(SUB_IP))],
    )


def key_answer(zone, rrset):
    qtype = DnsQType(int(DnsRType.DNSKEY))
    return _resp(zone, qtype, aa=True, answers=rrset)


def ds_nodata(zone, rrset):
    """The parent's NODATA answer to the §5.2¶6 DS query: SOA plus the proving NSEC."""
    qtype = DnsQType(int(DnsRType.DS))
    return _resp(f"sub.{zone}", qtype, aa=True, nameservers=[soa(zone), *rrset])


def nxdomain(qname, records):
    return _resp(
        qname,
        DnsQType.AAAA,
        aa=True,
        rcode=DnsResponseCode.NAME_ERROR,
        nameservers=records,
    )


def nodata(qname, records):
    return _resp(qname, DnsQType.AAAA, aa=True, nameservers=records)


# --------------------------------------------------------------------------- the driver


def _seed_slist(sname, zone=ROOT, ns_name=ROOT_NS, addr=ROOT_IP):
    slist = Slist(sname)
    slist.zone = zone
    slist.match = sname.match_count(zone)
    slist.entries = [SlistEntry(zone, ns_name, [addr])]
    return slist


def _drive(generator, responses):
    """Run a resolve_steps generator, answering each SendQuery FIFO from *responses*.

    Once the script runs out, SendQuery is answered with ``None`` -- the same thing
    the async driver's failure path hands back -- so a walk that asks for more than
    the scenario allows finishes instead of spinning.
    """
    events = []
    pending = next(generator)
    events.append(pending)
    index = 0
    while True:
        try:
            if isinstance(pending, SendQuery) and index < len(responses):
                pending = generator.send(responses[index])
                index += 1
            else:
                pending = generator.send(None)
        except StopIteration:
            break
        events.append(pending)
    return events


def _walk(
    cache,
    name,
    *,
    responses=(),
    anchors=(),
    policy=None,
    qtype=DnsQType.AAAA,
    client_cd=False,
    failures=None,
):
    sname = Sname(DomainName(name), qtype)
    kwargs = {"dnssec_ok": True, "anchors": tuple(anchors), "now": NOW}
    if policy is not None:
        kwargs["nxdomain_cut"] = policy
    if client_cd:
        kwargs["client_cd"] = True
    if failures is not None:
        kwargs["failures"] = failures
    return _drive(
        resolve_steps(sname, _seed_slist(sname), cache, **kwargs),
        list(responses),
    )


def _anchor():
    return tree._anchor()


def _secure_script(name):
    """Root -> test. -> zone.test. -> NXDOMAIN, then the three DNSKEY fetches the chain needs."""
    return [
        root_referral(name),
        tld_referral(name),
        nxdomain(name, [soa(), *zone_denials()]),
        key_answer(".", root_keys()),
        key_answer("test.", tld_keys()),
        key_answer("zone.test.", zone_keys()),
    ]


def _queries(events):
    return [event for event in events if isinstance(event, SendQuery)]


def _helpers(events):
    return [event for event in _queries(events) if event.helper]


def _verdict(events):
    return next((event for event in events if isinstance(event, DnssecVerdict)), None)


def _done(events):
    """The response the walk ended with, or ``None`` if it ended in a bare failure."""
    end = next((event for event in events if isinstance(event, Done)), None)
    return None if end is None else end.response


# --------------------------------------------------------------------------- secure walk


def test_a_secure_denial_is_judged_stamped_and_traced():
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(
        cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."), anchors=(_anchor(),)
    )
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "secure", verdict.reason
    assert verdict.zone == "zone.test."
    # The verdict precedes the denial it judges, and the denial still ends the walk.
    kinds = [type(event).__name__ for event in events]
    assert kinds.index("DnssecVerdict") < kinds.index("Nxdomain")
    entry = cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry is not None
    assert entry.validated is True
    # The descent's DS records were enough: only DNSKEYs were fetched, one per zone,
    # each asked of that zone's own server -- and each marked as a chain query.
    asked = [(str(q.questions[0].name), int(q.questions[0].qtype)) for q in _helpers(events)]
    assert asked == [(".", 48), ("test.", 48), ("zone.test.", 48)]
    assert len(_queries(events)) - len(_helpers(events)) == 3  # the descent itself stays unmarked
    # RFC 4035 §3.2.3: the walk judged every RRset of this answer and its proofs
    # under its own anchors, which is the only claim AD is allowed to make.
    response = _done(events)
    assert response.AD is True
    assert response.RCODE == DnsResponseCode.NAME_ERROR


def test_validated_policy_cuts_a_descendant_on_the_stamped_verdict():
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."), anchors=(_anchor(),))
    events = _walk(
        cache,
        "deeper.aaa.zone.test.",
        responses=[],
        anchors=(_anchor(),),
        policy=NxdomainPolicy.VALIDATED,
    )
    kinds = [type(event).__name__ for event in events]
    assert "NxdomainCut" in kinds
    assert "Nxdomain" in kinds
    cut = next(event for event in events if isinstance(event, NxdomainCut))
    assert cut.denied_by == "aaa.zone.test."
    assert not _queries(events)  # RFC 8020 §2¶1: the lookup never touched the network


def test_always_policy_also_stamps_when_anchors_are_configured():
    """Validation is the resolver's own decision; the cut policy only consumes it."""
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."), anchors=(_anchor(),))
    entry = cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is True
    # And with the default ALWAYS policy, a later name cuts on it like any denial.
    events = _walk(cache, "deeper.aaa.zone.test.", responses=[])
    assert any(isinstance(event, NxdomainCut) for event in events)


def test_no_anchors_no_verdict_no_stamp():
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."))
    assert _verdict(events) is None
    assert not _helpers(events)
    entry = cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False


# --------------------------------------------------------------------------- refusals


def test_a_non_validating_reader_of_a_stamped_cache_never_asserts_ad():
    """RFC 4035 §3.1.6¶3: authenticity without a trust point is a copy, not a claim.

    The stamp stays in the entry -- it records the validator that wrote it, and
    that record is the basis of the VALIDATED cut -- but a server reading it with
    no anchors of its own has validated nothing and MUST NOT say otherwise.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."), anchors=(_anchor(),))
    events = _walk(cache, "deeper.aaa.zone.test.", responses=[])
    assert any(isinstance(event, NxdomainCut) for event in events)
    assert _done(events).AD is False
    assert _verdict(events) is None


def test_the_stamp_answers_ad_when_a_cache_hit_serves_the_very_name():
    """The exact-key hit path judges from the stamp too, not only the cut path."""
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."), anchors=(_anchor(),))
    events = _walk(cache, "aaa.zone.test.", responses=[], anchors=(_anchor(),))
    assert not _queries(events)
    assert _done(events).AD is True
    assert _verdict(events) is None  # nothing was re-judged; the stamp is what speaks


def test_a_forged_proof_is_refused_and_the_failure_is_cached():
    """Bogus is not an answer to a client that asked for validation, and not data to keep.

    RFC 4035 §3.2.2¶3 assigns the authentication duty to this server when CD is
    clear, and a denial that failed it must not masquerade as a denial; §4.7's
    BAD-data cache stays optional, and unexercised here on purpose -- a cached
    forged denial would let the RFC 8020 cut spread one bad packet across a whole
    subtree. What RFC 9520 §3.4 made a MUST is caching the *failure*, with §3.2's
    backoff as the TTL guidance, so the repeat lookup is suppressed at the top of
    the walk and answers the same SERVFAIL without touching the network.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    failures = FailureCache()
    script = _secure_script("aaa.zone.test.")
    script[2] = nxdomain("aaa.zone.test.", [soa(), *zone_denials(flip_apex=True)])
    events = _walk(
        cache,
        "aaa.zone.test.",
        responses=script,
        anchors=(_anchor(),),
        failures=failures,
    )
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "bogus"
    assert not any(isinstance(event, Nxdomain) for event in events)  # the lie is not served
    response = _done(events)
    assert response is not None
    assert response.RCODE == DnsResponseCode.SERVER_FAILURE
    assert response.dnssec_bogus is True  # the serve side reads this to attach EDE 6
    assert cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN)) is None
    note = failures.lookup_query("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert note is not None
    assert note.dnssec is True
    assert "DNSSEC bogus" in note.reason
    # A repeat of the same name asks nothing (§9520 §3.2's sentence, earned by §3.4's MUST).
    events2 = _walk(cache, "aaa.zone.test.", responses=[], anchors=(_anchor(),), failures=failures)
    assert not _queries(events2)
    assert any(isinstance(event, Fail) for event in events2)


def test_a_cd_query_collects_the_forged_data_it_asked_to_judge():
    """§3.2.2¶3: with CD set, "the recursive name server should not interfere".

    The same forged denial arrives at a client that validates for itself, so it is
    *delivered* -- stripped of any claim (AD stays down), un-noted (nothing failed:
    §4.2¶2 waived the checks, and an unexecuted check is not a cacheable failure),
    and uncached, because a validator that files unvalidated data for its later
    non-CD clients is the opening the strip-a-signature attacker pays for. The
    remembered validation failure from the earlier CD-clear lookup does not stop
    this walk: §3.2.2¶5's "does not help the client" is the whole reason.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    failures = FailureCache()
    forged = _secure_script("aaa.zone.test.")
    forged[2] = nxdomain("aaa.zone.test.", [soa(), *zone_denials(flip_apex=True)])
    _walk(cache, "aaa.zone.test.", responses=forged, anchors=(_anchor(),), failures=failures)
    assert failures.lookup_query("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    fresh = _secure_script("aaa.zone.test.")
    fresh[2] = nxdomain("aaa.zone.test.", [soa(), *zone_denials(flip_apex=True)])
    events = _walk(
        cache,
        "aaa.zone.test.",
        responses=fresh,
        anchors=(_anchor(),),
        failures=failures,
        client_cd=True,
    )
    assert _queries(events)  # the bypass, keyed on the entry's dnssec flag
    response = _done(events)
    assert response.RCODE == DnsResponseCode.NAME_ERROR  # the data, warts and all
    assert response.AD is False
    assert cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN)) is None
    note = failures.lookup_query("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert note.strikes == 1  # the CD walk added no failure to remember


def test_a_cd_query_still_answers_from_an_unvalidated_cache_like_anyone_elses():
    """The CD bypass is of *validation-failure suppression*, not of the response cache.

    A denial cached by an ordinary walk (no anchors, nothing judged) is an ordinary
    answer; CD changes who validates, not what a lookup may remember.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "aaa.zone.test.", responses=_secure_script("aaa.zone.test."))  # no anchors
    events = _walk(cache, "aaa.zone.test.", responses=[], client_cd=True)
    assert not _queries(events)
    assert isinstance(_done(events), Response)


def test_a_second_walk_rejudges_rather_than_laundering_the_first():
    """Re-walking a forged denial yields bogus again -- repetition proves nothing."""
    cache = MemoryDnsCache(time_fn=Clock())
    script = _secure_script("deeper.aaa.zone.test.")
    script[2] = nxdomain("deeper.aaa.zone.test.", [soa(), *zone_denials(flip_apex=True)])
    events = _walk(cache, "deeper.aaa.zone.test.", responses=script, anchors=(_anchor(),))
    assert _verdict(events).status == "bogus"
    assert _done(events).RCODE == DnsResponseCode.SERVER_FAILURE


def test_an_unsigned_child_is_insecure_and_earns_no_cut():
    """The referral proved no DS, so the child's bare NXDOMAIN is Insecure (§5.2¶7)."""
    cache = MemoryDnsCache(time_fn=Clock())
    name = "bob.sub.zone.test."
    script = [
        root_referral(name),
        tld_referral(name),
        zone_referral_sub(name),  # NS + proving NSEC, no DS
        nxdomain(name, [soa("sub.zone.test.")]),  # the unsigned child answers, proofless
        key_answer(".", root_keys()),
        key_answer("test.", tld_keys()),
        key_answer("zone.test.", zone_keys()),
    ]
    events = _walk(
        cache, name, responses=script, anchors=(_anchor(),), policy=NxdomainPolicy.VALIDATED
    )
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "insecure", verdict.reason
    assert (
        verdict.zone == "sub.zone.test."
    )  # the denying zone; the verdict leans on zone.test.'s proof
    entry = cache.get(name, int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False
    assert _done(events).AD is False  # RFC 4035 §3.2.3: an Insecure answer never claims AD


def test_an_unproved_absent_ds_sends_the_must_query_of_section_5_2():
    """A referral with neither DS nor proof obliges a DS query of the parent (§5.2¶6)."""
    cache = MemoryDnsCache(time_fn=Clock())
    name = "bob.sub.zone.test."
    proof = _signed(
        "zone.test.",
        "sub.zone.test.",
        DnsRType.NSEC,
        [_nsec("www.zone.test.", [int(DnsRType.NS)])],
        "zone",
    )
    script = [
        root_referral(name),
        tld_referral(name),
        zone_referral_sub(name, with_proof=False),  # NS only: neither DS nor proof
        nxdomain(name, [soa("sub.zone.test.")]),
        key_answer(".", root_keys()),
        key_answer("test.", tld_keys()),
        key_answer("zone.test.", zone_keys()),
        ds_nodata("zone.test.", proof),  # the §5.2¶6 query's NODATA answer
    ]
    events = _walk(
        cache, name, responses=script, anchors=(_anchor(),), policy=NxdomainPolicy.VALIDATED
    )
    ds_queries = [q for q in _helpers(events) if int(q.questions[0].qtype) == int(DnsRType.DS)]
    assert len(ds_queries) == 1
    assert str(ds_queries[0].questions[0].name) == "sub.zone.test."
    assert str(ds_queries[0].entry.zone) == "zone.test."  # asked of the parent, §5.2¶6
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "insecure"
    entry = cache.get(name, int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False


def test_a_chain_that_cannot_be_fetched_is_indeterminate():
    """When the DNSKEY answers never arrive the walk gives up and says so (§4.3¶5)."""
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(
        cache,
        "aaa.zone.test.",
        responses=_secure_script("aaa.zone.test.")[:3],  # the fetches all get nothing
        anchors=(_anchor(),),
    )
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "indeterminate"
    entry = cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False
    assert _done(events).AD is False  # "could not tell" never claims otherwise


def test_a_hint_pointing_at_an_unvisited_zone_stops_instead_of_spinning():
    """A chain can demand data from a zone the walk never spoke to.

    Seeding straight at the terminal zone -- what a primed name-server belt does
    when it holds the child's servers but the parents came from no referral this
    lookup saw -- the first hint names the root's DNSKEY, and there is no server
    on record for it. DNS offers no way to ask somebody else for authoritative
    data, so the loop returns the Indeterminate it already has rather than
    querying the child's own server for the root's keys: that answer would be
    wrong, not merely useless.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    sname = Sname(DomainName("aaa.zone.test."), DnsQType.AAAA)
    events = _drive(
        resolve_steps(
            sname,
            _seed_slist(sname, DomainName("zone.test."), ZONE_NS, ZONE_IP),
            cache,
            dnssec_ok=True,
            anchors=(_anchor(),),
            now=NOW,
        ),
        [nxdomain("aaa.zone.test.", [soa(), *zone_denials()])],
    )
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "indeterminate"
    assert not _helpers(events)  # no query was sent to a server for the wrong zone
    entry = cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False


def test_a_nodata_answer_is_stamped_when_it_proves():
    """NODATA is a denial too -- it carries proofs and gets a verdict (RFC 4035 §5.3.2)."""
    cache = MemoryDnsCache(time_fn=Clock())
    name = "www.zone.test."  # exists, with A but no AAAA: the www NSEC denies AAAA
    script = [
        root_referral(name),
        tld_referral(name),
        nodata(name, [soa(), *zone_denials()]),
        key_answer(".", root_keys()),
        key_answer("test.", tld_keys()),
        key_answer("zone.test.", zone_keys()),
    ]
    events = _walk(cache, name, responses=script, anchors=(_anchor(),))
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "secure", verdict.reason
    entry = cache.get(name, int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is True


# --------------------------------------------------------------------------- the trace side


def test_the_trace_marks_chain_queries_and_renders_the_verdict():
    cache = MemoryDnsCache(time_fn=Clock())
    sname = Sname(DomainName("aaa.zone.test."), DnsQType.AAAA)
    trace = Trace(sname)
    script = _secure_script("aaa.zone.test.")
    generator = resolve_steps(
        sname, _seed_slist(sname), cache, dnssec_ok=True, anchors=(_anchor(),), now=NOW
    )
    pending = next(generator)
    trace.record(pending)
    index = 0
    while True:
        try:
            if isinstance(pending, SendQuery) and index < len(script):
                pending = generator.send(script[index])
                index += 1
            else:
                pending = generator.send(None)
        except StopIteration:
            break
        trace.record(pending)
    diagram = trace.to_mermaid()
    assert "(dnssec)" in diagram  # the helper queries are marked as chain fetches
    assert "dnssec secure: zone.test." in diagram


# ------------------------------------------------------------------- positive answers
#
# RFC 4035 §3.2.3 makes AD speak for "all RRsets in the Answer and Authority
# sections", so the positive half of the walk needs the same judge-fetch-stamp
# loop the denials earned -- composite over the whole response, and with the
# same refusals: a forged or stripped answer is refused where CD is clear,
# delivered unasserted where it is not, and never cached unvalidated.

_HOST6 = ipaddress.IPv6Address("2001:db8::53")


def _aaaa_rrset(name, *, flip=False, signed=True):
    rdata = RData_AAAA(_HOST6)
    if signed:
        return _signed("zone.test.", name, DnsRType.AAAA, [rdata], "zone", flip=flip)
    return [_rec(name, DnsRType.AAAA, rdata)]


def positive(qname, records):
    return _resp(qname, DnsQType.AAAA, aa=True, answers=list(records))


def _positive_script(name="www.zone.test.", *, flip=False, signed=True, keys=True):
    """Root -> test. -> zone.test. -> a signed (or stripped/forged) AAAA answer."""
    script = [
        root_referral(name),
        tld_referral(name),
        positive(name, _aaaa_rrset(name, flip=flip, signed=signed)),
    ]
    if keys:
        script += [
            key_answer(".", root_keys()),
            key_answer("test.", tld_keys()),
            key_answer("zone.test.", zone_keys()),
        ]
    return script


def test_a_signed_answer_is_judged_traced_and_bears_ad():
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(cache, "www.zone.test.", responses=_positive_script(), anchors=(_anchor(),))
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "secure", verdict.reason
    assert str(verdict.zone) == "zone.test."
    response = _done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR
    assert response.AD is True  # RFC 4035 §3.2.3: every RRset it stands on, judged
    entry = cache.get("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is True
    assert len(_helpers(events)) == 3


def test_a_signed_answer_served_from_cache_answers_with_ad():
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "www.zone.test.", responses=_positive_script(), anchors=(_anchor(),))
    events = _walk(cache, "www.zone.test.", responses=[], anchors=(_anchor(),))
    assert not _queries(events)
    assert _done(events).AD is True
    assert _verdict(events) is None  # the stamp speaks; nothing is re-judged


def test_the_same_entry_asserts_nothing_to_a_resolver_without_anchors():
    """§3.1.6¶3 keeps its promise on positives exactly as on denials and cuts."""
    cache = MemoryDnsCache(time_fn=Clock())
    _walk(cache, "www.zone.test.", responses=_positive_script(), anchors=(_anchor(),))
    events = _walk(cache, "www.zone.test.", responses=[])
    assert not _queries(events)
    assert _done(events).AD is False


def test_a_forged_answer_signature_is_refused_and_caches_nothing():
    cache = MemoryDnsCache(time_fn=Clock())
    failures = FailureCache()
    events = _walk(
        cache,
        "www.zone.test.",
        responses=_positive_script(flip=True),
        anchors=(_anchor(),),
        failures=failures,
    )
    verdict = _verdict(events)
    assert verdict.status == "bogus"
    response = _done(events)
    assert response.RCODE == DnsResponseCode.SERVER_FAILURE
    assert response.dnssec_bogus is True
    assert not response.answers  # the forged data is not served to a validation client
    assert cache.get("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN)) is None
    note = failures.lookup_query("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert note is not None
    assert note.dnssec is True


def test_an_answer_stripped_of_its_signature_is_bogus_not_unsigned():
    """The strip-a-signature attack, met head on: a secure zone answering without
    its RRSIG is RFC 4033 §5's missing-signature bogus, not an unsigned answer --
    and a walk that judged only present RRSIGs would serve the stripped data as
    merely unauthenticated. The chain fetches settle who the zone is; the zone's
    own keys convict the bare RRset.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(
        cache,
        "www.zone.test.",
        responses=_positive_script(signed=False),
        anchors=(_anchor(),),
    )
    verdict = _verdict(events)
    assert verdict.status == "bogus", verdict.reason
    assert "unsigned" in verdict.reason
    assert _done(events).RCODE == DnsResponseCode.SERVER_FAILURE
    assert cache.get("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN)) is None


def test_a_cd_query_collects_the_forged_answer_claims_nothing_caches_nothing():
    cache = MemoryDnsCache(time_fn=Clock())
    failures = FailureCache()
    _walk(
        cache,
        "www.zone.test.",
        responses=_positive_script(flip=True),
        anchors=(_anchor(),),
        failures=failures,
    )
    events = _walk(
        cache,
        "www.zone.test.",
        responses=_positive_script(flip=True),
        anchors=(_anchor(),),
        failures=failures,
        client_cd=True,
    )
    response = _done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR  # §3.2.2¶3: pass it through
    assert len(response.answers) == 2  # the RRset and its bad signature, raw
    assert response.AD is False
    assert cache.get("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN)) is None
    note = failures.lookup_query("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert note.strikes == 1


def test_a_zone_that_stays_silent_on_its_keys_leaves_the_answer_unasserted():
    """§4.3¶5 on a positive: could not obtain, could not tell, could not claim."""
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(
        cache,
        "www.zone.test.",
        responses=_positive_script(keys=False),  # the three fetches get nothing
        anchors=(_anchor(),),
    )
    verdict = _verdict(events)
    assert verdict.status == "indeterminate"
    response = _done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR  # indeterminate still answers
    assert response.AD is False
    entry = cache.get("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False


def test_an_answer_below_a_proved_unsigned_delegation_is_insecure():
    """Insecure is a verdict, not a shrug -- and it takes the chain to reach.

    The walk descends through zone.test.'s proof that sub.zone.test. carries no DS
    (§5.2¶9), receives an unsigned answer from the child, and can call it Insecure
    only because the parent's NSEC verified under authenticated keys. The answer
    stands, served, stamped nothing, asserting nothing.
    """
    cache = MemoryDnsCache(time_fn=Clock())
    name = "host.sub.zone.test."
    script = [
        root_referral(name),
        tld_referral(name),
        zone_referral_sub(name),
        positive(name, [_rec(name, DnsRType.AAAA, RData_AAAA(_HOST6))]),
        key_answer(".", root_keys()),
        key_answer("test.", tld_keys()),
        key_answer("zone.test.", zone_keys()),
    ]
    events = _walk(cache, name, responses=script, anchors=(_anchor(),))
    verdict = _verdict(events)
    assert verdict.status == "insecure", verdict.reason
    response = _done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR
    assert response.AD is False
    entry = cache.get(name, int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False


def test_no_anchors_judges_no_answer_stamps_nothing():
    """The unvalidating default is untouched by the positive half, RRSIGs and all."""
    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(cache, "www.zone.test.", responses=_positive_script())
    assert _verdict(events) is None
    assert not _helpers(events)
    response = _done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR
    assert response.AD is False
    entry = cache.get("www.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False


def _soa_rrset(*, flip=False):
    return _signed(
        "zone.test.",
        "zone.test.",
        DnsRType.SOA,
        [
            RData_SOA(
                DomainName("ns1.zone.test."),
                DomainName("hostmaster.zone.test."),
                1,
                7200,
                3600,
                1209600,
                300,
            )
        ],
        "zone",
        flip=flip,
    )


def test_every_rrset_in_the_answer_judges_and_a_forged_one_poisons_them_all():
    """RFC 4035 §3.2.3 counts the Authority section, and one poisoned RRset is one
    forged response.

    The signed SOA riding along turns the verdict into a composite over two
    RRsets; flipping its signature -- leaving the queried AAAA perfectly valid --
    still refuses the whole response. An attacker who can forge one RRset in a
    response can pick the one nobody thought to re-check, and "all RRsets" is
    the rule's whole defence against exactly that.
    """
    name = "www.zone.test."

    def script(flip_soa):
        return [
            root_referral(name),
            tld_referral(name),
            _resp(
                name,
                DnsQType.AAAA,
                aa=True,
                answers=_aaaa_rrset(name),
                nameservers=_soa_rrset(flip=flip_soa),
            ),
            key_answer(".", root_keys()),
            key_answer("test.", tld_keys()),
            key_answer("zone.test.", zone_keys()),
        ]

    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(cache, name, responses=script(False), anchors=(_anchor(),))
    verdict = _verdict(events)
    assert verdict.status == "secure", verdict.reason
    assert "2 RRsets" in verdict.reason
    assert _done(events).AD is True
    assert cache.get(name, int(DnsQType.AAAA), int(DnsRClass.IN)).validated is True

    cache = MemoryDnsCache(time_fn=Clock())
    events = _walk(cache, name, responses=script(True), anchors=(_anchor(),))
    assert _verdict(events).status == "bogus"
    response = _done(events)
    assert response.RCODE == DnsResponseCode.SERVER_FAILURE
    assert response.dnssec_bogus is True
    assert cache.get(name, int(DnsQType.AAAA), int(DnsRClass.IN)) is None
