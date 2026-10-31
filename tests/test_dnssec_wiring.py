"""The walk that fetches its own chain -- the resolver-side DNSSEC wiring.

The validator of :mod:`namespy.validate` judges the records it is handed; these tests
drive the *handing*: a scripted descent from the root through two signed referrals
into a signed zone's NXDOMAIN, the chain-fetch loop the walk runs when the chain is
incomplete (RFC 4035 §5.2¶6: "A security-aware resolver MUST query the name servers
for the parent zone for the DS RRset"), the verdict stamped into the cached denial,
and :attr:`NxdomainPolicy.VALIDATED` finally consuming it (RFC 8020 §2¶3).

The keys, signatures, and trust anchor are the fixture tree of
:mod:`tests.test_dnssec_validate` -- imported rather than duplicated, following the
precedent of its live-root test -- restated as wire :class:`DnsRecord` so the walk
can carry them inside :class:`Response` packets exactly as a server sends them.
"""

import ipaddress

import pytest
import test_dnssec_validate as tree

from namespy.cache import MemoryDnsCache
from namespy.crypto import crypto_available
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.rdata import RData_A, RData_DS, RData_NS, RData_RRSIG, RData_SOA
from namespy.resolver import (
    DnssecVerdict,
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


def _walk(cache, name, *, responses=(), anchors=(), policy=None, qtype=DnsQType.AAAA):
    sname = Sname(DomainName(name), qtype)
    kwargs = {"dnssec_ok": True, "anchors": tuple(anchors), "now": NOW}
    if policy is not None:
        kwargs["nxdomain_cut"] = policy
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


def test_a_forged_proof_is_bogus_unstamped_and_never_cuts():
    cache = MemoryDnsCache(time_fn=Clock())
    script = _secure_script("aaa.zone.test.")
    script[2] = nxdomain("aaa.zone.test.", [soa(), *zone_denials(flip_apex=True)])
    events = _walk(
        cache,
        "aaa.zone.test.",
        responses=script,
        anchors=(_anchor(),),
        policy=NxdomainPolicy.VALIDATED,
    )
    verdict = _verdict(events)
    assert verdict is not None
    assert verdict.status == "bogus"
    entry = cache.get("aaa.zone.test.", int(DnsQType.AAAA), int(DnsRClass.IN))
    assert entry.validated is False
    # The descendant is re-asked rather than cut: unvalidated entries prove nothing.
    events2 = _walk(
        cache,
        "deeper.aaa.zone.test.",
        responses=_secure_script("deeper.aaa.zone.test."),
        anchors=(_anchor(),),
        policy=NxdomainPolicy.VALIDATED,
    )
    assert not any(isinstance(event, NxdomainCut) for event in events2)
    assert _queries(events2)  # the walk went back to the name servers


def test_a_second_walk_rejudges_rather_than_laundering_the_first():
    """Re-walking a forged denial yields bogus again -- repetition proves nothing."""
    cache = MemoryDnsCache(time_fn=Clock())
    script = _secure_script("deeper.aaa.zone.test.")
    script[2] = nxdomain("deeper.aaa.zone.test.", [soa(), *zone_denials(flip_apex=True)])
    events = _walk(cache, "deeper.aaa.zone.test.", responses=script, anchors=(_anchor(),))
    assert _verdict(events).status == "bogus"


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
