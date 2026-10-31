"""Wildcard synthesis from the cache (RFC 8198 §5.3, RFC 4035 §4.5¶4, §5.3.4; RFC 4592 §3.3.1, §4.1-§4.2).

The positive half of aggressive caching: a validated wildcard answer's
template is stored, and the next nonexistent name under that wildcard is
answered from the cache without a query -- but only when a cached, signed
closer-match denial proves the name "would not exist without the wildcard
match" (§5.3's exact words). Both records are gates: template present and
denial present, or §5¶2's MUST to fall back to the wire holds. The fixture
zone's ``*.y.zone.test.`` owns a TXT; the chain's last edge runs y -> *.y ->
apex so the ``*.y`` NSEC spans every nonexistent name beneath it.
"""

import pytest
import test_dnssec_wiring as wiring

from namespy.cache import MemoryDnsCache, PositiveEntry
from namespy.enums import DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsRecord
from namespy.rdata import RData_RRSIG
from namespy.resolver import Sname, WildcardSynthesis, _cache_wildcard_template

IN = int(DnsRClass.IN)

needs_tree = pytest.mark.skipif(
    not wiring.crypto_available(), reason="the signed fixture tree needs namespy[crypto]"
)


def _seeded_cache():
    """A cache holding the wildcard template and a same-zone closer-match denial.

    walk1 files the ``*.y.zone.test.`` TXT template; walk2 files the NODATA
    denial at ``y.zone.test.`` whose authority section carries the whole zone
    chain, including the ``*.y`` NSEC that spans every name synthesised below
    it. Both are required before any sibling under the wildcard can be
    answered from the cache.
    """
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    events1 = wiring._txt_walk(
        cache,
        "deep.y.zone.test.",
        responses=wiring._wildcard_script(),
        anchors=(wiring._anchor(),),
    )
    assert wiring._verdict(events1).status == "secure"
    events2 = wiring._walk(
        cache,
        "y.zone.test.",
        responses=[
            wiring.root_referral("y.zone.test."),
            wiring.tld_referral("y.zone.test."),
            wiring.nodata("y.zone.test.", [wiring.soa(), *wiring.zone_denials()]),
            wiring.key_answer(".", wiring.root_keys()),
            wiring.key_answer("test.", wiring.tld_keys()),
            wiring.key_answer("zone.test.", wiring.zone_keys()),
        ],
        anchors=(wiring._anchor(),),
    )
    assert wiring._verdict(events2).status == "secure"
    return cache


def _synthesize(cache, name, *, aggressive=True, client_cd=False):
    return wiring._txt_walk(
        cache,
        name,
        responses=[],
        anchors=(wiring._anchor(),),
        aggressive=aggressive,
        client_cd=client_cd,
    )


# --------------------------------------------------------------------------- the template


@needs_tree
def test_a_wildcard_answer_is_judged_secure_and_files_its_template():
    """§5.3.4: the answer is only secure with its closer-match denial; §4.5¶4: it templates."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    events = wiring._txt_walk(
        cache,
        "deep.y.zone.test.",
        responses=wiring._wildcard_script(),
        anchors=(wiring._anchor(),),
    )
    verdict = wiring._verdict(events)
    assert verdict.status == "secure", verdict.reason
    assert "wildcard" in verdict.reason
    response = wiring._done(events)
    assert response.AD is True
    template = cache.get(DomainName("*.y.zone.test."), int(DnsRType.TXT), IN)
    assert template is not None
    assert template.validated is True
    assert template.authoritative is True
    types = sorted({int(r.rtype) for r in template.records})
    assert types == sorted({int(DnsRType.TXT), int(DnsRType.RRSIG)})


@needs_tree
def test_a_sibling_under_the_wildcard_is_answered_without_a_query():
    """§5.3: name absent (proved) + wildcard present (cached) => synthesize, do not query."""
    cache = _seeded_cache()
    events = _synthesize(cache, "other.y.zone.test.")
    assert wiring._queries(events) == []
    synthesis = next(e for e in events if isinstance(e, WildcardSynthesis))
    assert synthesis.name == "other.y.zone.test."
    assert synthesis.via == "*.y.zone.test."
    response = wiring._done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR
    assert response.AA is False  # a recursive server never asserts authority
    assert response.AD is True
    by_type = {}
    for record in response.answers:
        by_type.setdefault(int(record.rtype), []).append(record)
    assert str(by_type[int(DnsRType.TXT)][0].name) == "other.y.zone.test."
    # presented at the queried name, but the signature still remembers the wildcard
    assert int(next(r.rdata.labels for r in response.answers if int(r.rtype) == 46)) == 3


@needs_tree
def test_a_deeper_name_under_the_wildcard_is_answered_too():
    """The next-closer cover proves every intervening name absent, at any depth below it."""
    cache = _seeded_cache()
    events = _synthesize(cache, "x.deep.y.zone.test.")
    assert wiring._queries(events) == []
    assert any(isinstance(e, WildcardSynthesis) for e in events)
    assert wiring._done(events).RCODE == DnsResponseCode.NO_ERROR


@needs_tree
def test_the_synthesised_ttl_never_exceeds_the_templates_remaining_life():
    """§4.5¶1's atomic entry expires on the cache clock; the served TTL must not outlive it."""
    cache = _seeded_cache()
    template = cache.get(DomainName("*.y.zone.test."), int(DnsRType.TXT), IN)
    remaining = int(template.expires_at - cache.time_fn())
    events = _synthesize(cache, "other.y.zone.test.")
    for record in wiring._done(events).answers:
        assert int(record.ttl) <= remaining


# --------------------------------------------------------------------------- the refusals


@needs_tree
def test_without_a_template_the_name_falls_back_to_the_wire():
    """§5.3¶2's MUST: "If the corresponding wildcard record is not in the cache, it MUST fall back"."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    # only the closer-match denial, no wildcard answer walked first
    wiring._walk(
        cache,
        "y.zone.test.",
        responses=[
            wiring.root_referral("y.zone.test."),
            wiring.tld_referral("y.zone.test."),
            wiring.nodata("y.zone.test.", [wiring.soa(), *wiring.zone_denials()]),
            wiring.key_answer(".", wiring.root_keys()),
            wiring.key_answer("test.", wiring.tld_keys()),
            wiring.key_answer("zone.test.", wiring.zone_keys()),
        ],
        anchors=(wiring._anchor(),),
    )
    name = "other.y.zone.test."
    events = wiring._txt_walk(
        cache,
        name,
        responses=wiring._wildcard_script(name),
        anchors=(wiring._anchor(),),
        aggressive=True,
    )
    assert wiring._queries(events) != []  # it asked
    assert not any(isinstance(e, WildcardSynthesis) for e in events)


@needs_tree
def test_without_a_closer_match_denial_the_name_falls_back_to_the_wire():
    """§5.3 wants more than the wildcard: proof the name "would not exist without the match"."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    # only the wildcard template, no cached denial to prove absence
    wiring._txt_walk(
        cache,
        "deep.y.zone.test.",
        responses=wiring._wildcard_script(),
        anchors=(wiring._anchor(),),
    )
    name = "other.y.zone.test."
    events = wiring._txt_walk(
        cache,
        name,
        responses=wiring._wildcard_script(name),
        anchors=(wiring._anchor(),),
        aggressive=True,
    )
    assert wiring._queries(events) != []
    assert not any(isinstance(e, WildcardSynthesis) for e in events)


@needs_tree
def test_synthesis_is_off_unless_the_knob_is_turned():
    """Aggressive caching is new behaviour: default-off, like serve-stale before it."""
    cache = _seeded_cache()
    events = _synthesize(cache, "other.y.zone.test.", aggressive=False)
    assert wiring._queries(events) != []
    assert not any(isinstance(e, WildcardSynthesis) for e in events)


@needs_tree
def test_a_cd_client_asks_for_the_wire_not_the_inference():
    """RFC 8198 Appendix A: the synthesis is waived "unless the CD bit was set on the incoming query"."""
    cache = _seeded_cache()
    events = _synthesize(cache, "other.y.zone.test.", client_cd=True)
    assert wiring._queries(events) != []
    assert not any(isinstance(e, WildcardSynthesis) for e in events)


@needs_tree
def test_an_unvalidated_template_is_never_synthesized():
    """The stamp licenses the load: a template nobody verified is not chain evidence."""
    cache = _seeded_cache()
    template = cache.get(DomainName("*.y.zone.test."), int(DnsRType.TXT), IN)
    cache.put(
        PositiveEntry(
            DomainName("*.y.zone.test."),
            int(DnsRType.TXT),
            IN,
            list(template.records),
            cache.time_fn() + 300,
            authoritative=True,
            validated=False,
        )
    )
    name = "other.y.zone.test."
    events = wiring._txt_walk(
        cache,
        name,
        responses=wiring._wildcard_script(name),
        anchors=(wiring._anchor(),),
        aggressive=True,
    )
    assert not any(isinstance(e, WildcardSynthesis) for e in events)
    assert wiring._queries(events) != []


@needs_tree
def test_a_template_whose_signature_expired_is_refused_and_refetched():
    """The two clocks again: cache-clock life cannot outlive the signature's window (§9¶4)."""
    cache = _seeded_cache()
    template = cache.get(DomainName("*.y.zone.test."), int(DnsRType.TXT), IN)
    dead = []
    for record in template.records:
        if int(record.rtype) == int(DnsRType.RRSIG):
            sig = record.rdata
            sig = RData_RRSIG(
                sig.type_covered,
                sig.algorithm,
                sig.labels,
                sig.original_ttl,
                wiring.NOW - 1,  # window closed
                sig.inception,
                sig.key_tag,
                sig.signer_name,
                sig.signature,
            )
            record = DnsRecord(record.name, record.rtype, record.rclass, record.ttl, rdata=sig)
        dead.append(record)
    cache.put(
        PositiveEntry(
            DomainName("*.y.zone.test."),
            int(DnsRType.TXT),
            IN,
            dead,
            cache.time_fn() + 86400,  # alive on the cache clock, dead on the signature's
            authoritative=True,
            validated=True,
        )
    )
    name = "other.y.zone.test."
    events = wiring._txt_walk(
        cache,
        name,
        responses=wiring._wildcard_script(name),
        anchors=(wiring._anchor(),),
        aggressive=True,
    )
    assert not any(isinstance(e, WildcardSynthesis) for e in events)
    assert wiring._queries(events) != []


@needs_tree
def test_a_forged_wildcard_answer_files_no_template_and_caches_nothing():
    """§5.3.4's closer-match proof is verified like every proof: a bogus answer templates nothing."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    events = wiring._txt_walk(
        cache,
        "deep.y.zone.test.",
        responses=wiring._wildcard_script(flip=True),
        anchors=(wiring._anchor(),),
    )
    verdict = wiring._verdict(events)
    assert verdict.status == "bogus", verdict.reason
    done = wiring._done(events)
    assert done.RCODE == DnsResponseCode.SERVER_FAILURE
    assert cache.get(DomainName("*.y.zone.test."), int(DnsRType.TXT), IN) is None


# --------------------------------------------------------------------------- the boundaries


@needs_tree
def test_a_denied_name_still_synthesizes_the_denial_not_a_wildcard_answer():
    """`synthesize` tries denials first: a provably-absent name with no matching wildcard is denied."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    # an apex-span denial only; nothing templates, nothing under *.y
    wiring._walk(
        cache,
        "aaa.zone.test.",
        responses=wiring._secure_script("aaa.zone.test."),
        anchors=(wiring._anchor(),),
    )
    events = wiring._walk(
        cache, "dog.zone.test.", responses=[], anchors=(wiring._anchor(),), aggressive=True
    )
    from namespy.resolver import AggressiveDenial

    assert any(isinstance(e, AggressiveDenial) for e in events)
    assert not any(isinstance(e, WildcardSynthesis) for e in events)


@needs_tree
def test_the_inference_asserts_nothing_to_a_resolver_without_anchors():
    """§3.1.6: a synthesised answer to a non-validating reader carries no AD, though it still answers."""
    cache = _seeded_cache()
    events = wiring._txt_walk(cache, "other.y.zone.test.", responses=[], aggressive=True)
    assert wiring._queries(events) == []
    response = wiring._done(events)
    assert response.RCODE == DnsResponseCode.NO_ERROR
    assert (
        response.AD is False
    )  # no anchors, no assertion -- the template's stamp is not the reader's verdict


@needs_tree
def test_soa_and_wildcard_never_template():
    """RFC 4592 §4.1: a wildcard SOA "can never be a source of synthesis"; §4.2: NS is undefined."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    answer = wiring.wildcard_answer("deep.y.zone.test.")
    for qtype in (DnsRType.SOA, DnsRType.NS):
        sname = Sname(DomainName("deep.y.zone.test."), DnsQType(int(qtype)))
        _cache_wildcard_template(cache, sname, answer, cache.time_fn())
    assert cache.get(DomainName("*.y.zone.test."), int(DnsRType.TXT), IN) is None


@needs_tree
def test_an_explicit_answer_never_templates():
    """§5.4¶3: equal label counts mean the name signed itself -- nothing wider may be deduced."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    # a directly-owned, explicitly-signed AAAA answer at the name
    wiring._walk(
        cache,
        "www.zone.test.",
        responses=wiring._positive_script("www.zone.test."),
        anchors=(wiring._anchor(),),
    )
    assert cache.get(DomainName("*.zone.test."), int(DnsRType.AAAA), IN) is None


@needs_tree
def test_the_trace_names_the_template_the_answer_came_from():
    """A synthesised answer is byte-honest but query-free; the trace is where it says so."""
    from namespy.trace import Trace

    cache = _seeded_cache()
    sname = Sname(DomainName("other.y.zone.test."), DnsQType(int(DnsRType.TXT)))
    trace = Trace(sname)
    generator = wiring.resolve_steps(
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
    assert "wildcard answer: other.y.zone.test. via *.y.zone.test." in trace.to_mermaid()
