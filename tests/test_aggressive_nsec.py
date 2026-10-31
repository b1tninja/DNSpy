"""Aggressive NSEC caching: denials synthesised from validated cached proofs (RFC 8198).

The scenario is the document's own: a cached, validated NXDOMAIN for ``aaa``
covers the span its neighbours fall in, and 8198 says the validating resolver
SHOULD answer for those names without asking. Every refusal this feature makes
-- the unsigned entry, the name below a cut, the CD client, the expired
signature, the foreign zone -- is a gate its text states, and each gets its own
test here. The fixture tree of ``test_dnssec_wiring`` supplies the signed zones;
entries reach the cache the way they do in production, by a real validated walk.
"""

import pytest
import test_cli as cli_tests
import test_dnssec_wiring as wiring

from namespy.aggressive import _capped, synthesize_denial
from namespy.cache import DnsCache, MemoryDnsCache, NegativeEntry
from namespy.cache.sqlite import SqliteDnsCache
from namespy.crypto import crypto_available
from namespy.enums import DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.nsec import collect_proof_records
from namespy.resolver import AggressiveDenial, Sname, resolve_steps
from namespy.trace import Trace

IN = int(DnsRClass.IN)

#: The signed fixture tree is crypto; the three tests that never touch it -- the
#: base-class fallback and the two CLI polarities -- must still run on the
#: crypto-free CI matrix, which is the lesson of the earlier rounds' fixture
#: laziness written the other way round.
needs_tree = pytest.mark.skipif(
    not crypto_available(), reason="the signed fixture tree needs namespy[crypto]"
)


def _aggr_walk(
    cache,
    name,
    *,
    responses=(),
    anchors=(),
    aggressive=True,
    client_cd=False,
    qtype=DnsQType.AAAA,
):
    """The wiring file's _walk, plus the one knob this feature adds."""
    sname = Sname(DomainName(name), qtype)
    kwargs = {
        "dnssec_ok": True,
        "anchors": tuple(anchors),
        "now": wiring.NOW,
        "aggressive_nsec": aggressive,
    }
    if client_cd:
        kwargs["client_cd"] = True
    return wiring._drive(
        resolve_steps(sname, wiring._seed_slist(sname), cache, **kwargs), list(responses)
    )


def _aggressive(events):
    return next((event for event in events if isinstance(event, AggressiveDenial)), None)


def _done_response(events):
    end = next((event for event in events if isinstance(event, wiring.Done)), None)
    return None if end is None else end.response


def _secured_cache():
    """One real validated walk: the cache holds (aaa.zone.test., AAAA) stamped."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    events = wiring._walk(
        cache,
        "aaa.zone.test.",
        responses=wiring._secure_script("aaa.zone.test."),
        anchors=(wiring._anchor(),),
    )
    assert wiring._verdict(events).status == "secure"
    return cache


# ------------------------------------------------------------------- the licence in action


@needs_tree
def test_a_validated_denial_denies_its_neighbours_name_without_a_query():
    """8198 §5.1/Appendix A ¶1: the covering NSEC was cached and validated; that is the answer.

    ``dog.zone.test.`` sorts between the apex NSEC's endpoints -- the very record
    that arrived to deny ``aaa`` -- and its wildcard denial rode along with it,
    so §5.4's full Name Error proof exists in the cache for a name that was never
    queried. The zero queries are the point: Appendix A ¶1's "will not make
    queries for any name covered by a cached and validated NSEC record".
    """
    cache = _secured_cache()
    events = _aggr_walk(cache, "dog.zone.test.", responses=[], anchors=(wiring._anchor(),))

    event = _aggressive(events)
    assert event is not None
    assert str(event.name) == "dog.zone.test."
    assert str(event.proven_by).lower() == "aaa.zone.test."
    assert event.kind == "nxdomain"
    assert wiring._queries(events) == []  # not one query left the process
    response = _done_response(events)
    assert response.RCODE == DnsResponseCode.NAME_ERROR
    assert response.AD is True  # the stamp is this resolver's own verdict
    assert response.AA is False  # a synthesised answer never claims authority
    assert str(response.questions[0].name) == "dog.zone.test."
    types = [int(record.rtype) for record in response.nameservers]
    assert int(DnsRType.SOA) in types
    assert int(DnsRType.NSEC) in types  # DO asked, so the proof rides (8020 §2¶5's habit)

    # And the synthesis wrote nothing back: one proof, one entry, no second
    # generation of negative data to outlive the first. (The chain records the
    # first walk filed are counted in the baseline -- what must not grow is a
    # synthesised answer of the walk's own making.)
    before = len(cache)
    events_again = _aggr_walk(cache, "dog.zone.test.", responses=[], anchors=(wiring._anchor(),))
    assert _aggressive(events_again) is not None
    assert len(cache) == before


@needs_tree
def test_the_events_say_proof_before_inference():
    """AggressiveDenial, then the bare Nxdomain it caused, then Done -- the NxdomainCut order."""
    cache = _secured_cache()
    events = _aggr_walk(cache, "dog.zone.test.", responses=[], anchors=(wiring._anchor(),))
    kinds = [type(event).__name__ for event in events]
    assert kinds.index("AggressiveDenial") < kinds.index("Nxdomain") < kinds.index("Done")


@needs_tree
def test_a_cached_nodata_denies_another_type_at_the_same_name():
    """§5.4¶3 says nothing new to a server: the matching NSEC lists the types that exist.

    The denial cached for ``(www, AAAA)`` carries www's own NSEC, and its bitmap
    is a statement about every type the name lacks -- TXT included. The exact-key
    lookup cannot see this (the entry is keyed AAAA) and the 8020 cut cannot
    (NODATA is not a subtree denial), so only the aggressive path knows: the
    Appendix-A lookup that is nobody's ancestor and nobody's descendant.
    """
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    name = "www.zone.test."
    script = [
        wiring.root_referral(name),
        wiring.tld_referral(name),
        wiring.nodata(name, [wiring.soa(), *wiring.zone_denials()]),
        wiring.key_answer(".", wiring.root_keys()),
        wiring.key_answer("test.", wiring.tld_keys()),
        wiring.key_answer("zone.test.", wiring.zone_keys()),
    ]
    events = wiring._walk(cache, name, responses=script, anchors=(wiring._anchor(),))
    assert wiring._verdict(events).status == "secure"

    events = _aggr_walk(
        cache, name, responses=[], anchors=(wiring._anchor(),), qtype=int(DnsRType.TXT)
    )
    event = _aggressive(events)
    assert event is not None
    assert event.kind == "nodata"
    assert wiring._queries(events) == []
    response = _done_response(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR
    assert response.AD is True
    # NODATA's own shape: an authority section that says SOA, not referral.
    assert response.nameservers[0].rtype == DnsRType.SOA


@needs_tree
def test_an_unvalidated_entry_is_unusable_not_unbelievable():
    """Appendix B ¶2 discards; the walk then behaves as though 8198 did not exist."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    wiring._walk(cache, "aaa.zone.test.", responses=wiring._secure_script("aaa.zone.test."))
    entry = cache.get(DomainName("aaa.zone.test."), int(DnsQType.AAAA), IN)
    assert entry is not None
    assert entry.validated is False  # no anchors, no stamp

    events = _aggr_walk(cache, "dog.zone.test.", responses=[], anchors=())
    assert _aggressive(events) is None
    assert wiring._queries(events) != []  # the name went out to the network as usual


@needs_tree
def test_a_cd_client_is_served_the_wire_and_nothing_inferred():
    """Appendix A ¶1's exemption: "unless the CD bit was set on the incoming query".

    The same stance §3.2.2¶3 made the walk adopt for every other trick: a client
    that validates for itself asked this server not to interfere, and a denial
    written from this resolver's inference -- however well proven -- is a
    different answer from the one the authority chose to send.
    """
    cache = _secured_cache()
    events = _aggr_walk(
        cache,
        "dog.zone.test.",
        responses=[
            wiring.root_referral("dog.zone.test."),
            wiring.tld_referral("dog.zone.test."),
            wiring.nxdomain("dog.zone.test.", [wiring.soa(), *wiring.zone_denials()]),
        ],
        anchors=(wiring._anchor(),),
        client_cd=True,
    )
    assert _aggressive(events) is None
    assert wiring._queries(events) != []


@needs_tree
def test_the_feature_is_off_unless_it_is_asked_for():
    """Default off, and inert when not: §9¶4's widened blast radius is why a flag exists."""
    cache = _secured_cache()
    events = _aggr_walk(
        cache, "dog.zone.test.", responses=[], anchors=(wiring._anchor(),), aggressive=False
    )
    assert _aggressive(events) is None
    assert wiring._queries(events) != []


@needs_tree
def test_a_neighbour_in_another_zone_gets_no_inference():
    """A bundle proves names in the zone whose SOA signs it -- the guard no geometry has."""
    cache = _secured_cache()
    events = _aggr_walk(cache, "dog.other.example.", responses=[], anchors=(wiring._anchor(),))
    assert _aggressive(events) is None
    assert wiring._queries(events) != []


@needs_tree
def test_the_trace_names_the_proof_that_vouched():
    """The synthesised packet cannot show its own cause; the trace line has to."""
    cache = _secured_cache()
    sname = Sname(DomainName("dog.zone.test."), DnsQType.AAAA)
    trace = Trace(sname)
    generator = resolve_steps(
        sname,
        wiring._seed_slist(sname),
        cache,
        dnssec_ok=True,
        anchors=(wiring._anchor(),),
        now=wiring.NOW,
        aggressive_nsec=True,
    )
    pending = next(generator)
    trace.record(pending)
    while True:
        try:
            pending = generator.send(None)
        except StopIteration:
            break
        trace.record(pending)
    diagram = trace.to_mermaid()
    assert "aggressive nxdomain: dog.zone.test. proven by aaa.zone.test." in diagram


# ---------------------------------------------------------------------------- the unit gates


def _entry(*, validated=True, expires=None, soa_ttl=None):
    """A NegativeEntry in the exact shape the validated walk writes, built from fixture records."""
    from namespy.packet import DnsRecord

    response = wiring.nxdomain("aaa.zone.test.", [wiring.soa(), *wiring.zone_denials()])
    proofs = collect_proof_records(response.nameservers)
    soa = next(r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA))
    if soa_ttl is not None:
        soa = DnsRecord(soa.name, soa.rtype, soa.rclass, soa_ttl, rdata=soa.rdata)
    return NegativeEntry(
        DomainName("aaa.zone.test."),
        int(DnsQType.AAAA),
        IN,
        DnsResponseCode.NAME_ERROR,
        soa,
        wiring.NOW + 300 if expires is None else expires,
        proofs,
        validated=validated,
    )


def _sname(name, qtype=int(DnsQType.AAAA)):
    return Sname(DomainName(name), qtype)


@needs_tree
def test_the_stamp_is_the_entrys_only_test():
    denial = synthesize_denial(_entry(validated=False), _sname("dog.zone.test."), now=wiring.NOW)
    assert denial is None


@needs_tree
def test_an_expired_signature_ends_the_evidence_before_the_ttl_does():
    """§7's "until the effective TTLs or signatures ... expire", the half 2308 TTLs miss (§9¶4)."""
    far = wiring.NOW + 3 * 10**8  # past the tree's fixed signature epoch of 2_000_000_000
    entry = _entry(expires=far + 3600)
    assert synthesize_denial(entry, _sname("dog.zone.test."), now=far) is None
    # ...and the same bundle is usable again at a moment its signatures cover.
    assert synthesize_denial(_entry(), _sname("dog.zone.test."), now=wiring.NOW) is not None


@needs_tree
def test_a_name_below_a_delegation_is_not_this_zones_to_deny():
    """Appendix B ¶4 / §8.3¶12: an NS-without-SOA at the encloser means the walk must go on.

    ``deep.sub.zone.test.`` falls inside a parent-zone span -- the NSEC range
    reaches under the unsigned delegation with tidy geometry -- and that range
    proves only that the *parent* holds no such name. A signed or unsigned
    child's data lives beyond this zone's authority, and an aggressive answer
    from parent records would deny a name the child may well hold.
    """
    entry = _entry()
    assert synthesize_denial(entry, _sname("deep.sub.zone.test."), now=wiring.NOW) is None
    # The cut name itself: NODATA for an ordinary type is the referral's business.
    denied = synthesize_denial(entry, _sname("sub.zone.test.", int(DnsRType.TXT)), now=wiring.NOW)
    assert denied is None


@needs_tree
def test_the_ds_at_a_proven_unsigned_cut_is_synthensible():
    """§5.4¶5/§8.6's exception: DS is the one type the delegation point's owner answers for.

    The fixture's ``sub`` carries NS without DS -- the parent's signed statement
    of an unsigned delegation -- and synthesising that NODATA for a DS query is
    exactly what tells a validator to stop validating below. The one type the
    cut check must not bite on is the one whose absence is the answer.
    """
    response = synthesize_denial(
        _entry(), _sname("sub.zone.test.", int(DnsRType.DS)), now=wiring.NOW
    )
    assert response is not None
    assert response.RCODE == DnsResponseCode.NO_ERROR


@needs_tree
def test_a_type_the_bitmap_lists_is_never_denied():
    """§5.4¶3's own refusal rides along: ``www`` exists and lists A; A is not denied."""
    denial = synthesize_denial(_entry(), _sname("www.zone.test.", int(DnsRType.A)), now=wiring.NOW)
    assert denial is None


@needs_tree
def test_the_ttl_is_the_evidences_remaining_life_capped_at_three_hours():
    """9077 §3.4's replacement §5.4: "limit the maximum effective TTL" -- and never overstate."""
    response = synthesize_denial(_entry(), _sname("dog.zone.test."), now=wiring.NOW)
    assert all(int(record.ttl) <= 300 for record in response.nameservers)  # the entry's life
    long_lived = _entry(expires=wiring.NOW + 10**9, soa_ttl=99999)
    response = synthesize_denial(long_lived, _sname("dog.zone.test."), now=wiring.NOW)
    soa = response.nameservers[0]
    assert int(soa.ttl) == 10800  # the cap, not the 99999 the zone claimed
    assert _capped(wiring.soa(), 5).ttl == 5
    assert _capped(soa, 10800) is soa  # at the cap already: the same object, no churn


@needs_tree
def test_a_proof_without_dnssec_ok_carries_nothing_to_verify():
    """The instance knob, not the client's bit: a non-DNSSEC resolver answers bare; the
    server's strip withdraws the records for DO=0 clients (4035 §3.2.1) either way."""
    response = synthesize_denial(
        _entry(), _sname("dog.zone.test."), now=wiring.NOW, dnssec_ok=False
    )
    assert [int(record.rtype) for record in response.nameservers] == [int(DnsRType.SOA)]


# ------------------------------------------------------------------------- the caches' turn


@needs_tree
def test_the_memory_cache_offers_zone_containing_bundles_only():
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    cache.put(_entry())
    assert cache.denial_candidates(DomainName("dog.zone.test."), IN) != ()
    assert cache.denial_candidates(DomainName("dog.other.example."), IN) == ()
    assert cache.denial_candidates(DomainName("dog.zone.test."), IN + 3) == ()


@needs_tree
def test_the_memory_cache_forgets_expired_candidates_on_sight():
    """9077's whole reason for existing, applied to the scan: no reading past the TTL."""
    clock = wiring.Clock()
    cache = MemoryDnsCache(time_fn=clock)
    entry = _entry()
    entry.expires_at = clock.t + 300  # the entry lives on the cache clock; the proofs on UNIX time
    cache.put(entry)
    clock.t += 400  # the entry lived 300 seconds
    assert cache.denial_candidates(DomainName("dog.zone.test."), IN) == ()
    assert len(cache) == 0  # forgotten, not merely skipped


@needs_tree
def test_sqlite_offers_the_same_candidates_its_rows_re_serialise():
    cache = SqliteDnsCache(":memory:", time_fn=wiring.Clock())
    cache.put(_entry())
    # The row stores canonical text; the query arrives in any case it likes.
    candidates = cache.denial_candidates(DomainName("DOG.ZONE.TEST."), IN)
    assert len(candidates) == 1
    entry = candidates[0]
    assert entry.validated is True
    assert len(entry.proofs) == len(_entry().proofs)  # the bundle rides the trip intact


def test_a_backend_that_cannot_offer_leaves_the_walk_alone():
    """The base method's documented fallback: no candidates is the pre-8198 world, still correct."""

    class Bare(DnsCache):
        def get(self, name, qtype, qclass):
            return None

        def put(self, entry):
            pass

        def __len__(self):
            return 0

    assert Bare().denial_candidates(DomainName("dog.zone.test."), IN) == ()
    assert Bare().nxdomain_at(DomainName("zone.test."), IN) is None


# --------------------------------------------------------------------------------- the CLI


async def test_the_aggressive_flag_reaches_the_resolver(monkeypatch, capsys):
    made = cli_tests._stub_endpoints(monkeypatch, cli_tests._answered)
    args = cli_tests._args(["--aggressive-nsec", "example.com"])
    assert await cli_tests.cli.cli_query(args) == 0
    assert made[0][1].aggressive_nsec is True


async def test_aggressive_synthesis_is_off_unless_it_is_asked_for(monkeypatch, capsys):
    made = cli_tests._stub_endpoints(monkeypatch, cli_tests._answered)
    assert await cli_tests.cli.cli_query(cli_tests._args(["example.com"])) == 0
    assert made[0][1].aggressive_nsec is False
