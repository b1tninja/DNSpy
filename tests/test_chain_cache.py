"""Chain records in the cache: DNSKEY and DS material a secure verdict verified (RFC 4035 §4.5, §5.2¶6).

RFC 4035 §4.5¶1's atomic entry -- the RRset with its signatures, discarded
whole when any part expires -- describes every response the walk receives,
helper queries included; §5.2¶6 then makes the chain fetches a MUST, which is
a promise of traffic the cache exists to keep. The gates here mirror the
denials' stamp doctrine: only a secure verdict writes (these exact bytes were
verified against this resolver's anchors a moment ago), only stamped and
signature-live material loads, and the validator re-verifies everything as
always -- the stamp licenses the load, never the verdict.
"""

import pytest
import test_dnssec_wiring as wiring

from namespy.cache import MemoryDnsCache, PositiveEntry
from namespy.enums import DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsRecord
from namespy.rdata import RData_RRSIG
from namespy.resolver import ChainFromCache, _cache_chain, _file_chain_record

IN = int(DnsRClass.IN)

needs_tree = pytest.mark.skipif(
    not wiring.crypto_available(), reason="the signed fixture tree needs namespy[crypto]"
)


def _entry(cache, name, rtype):
    return cache.get(DomainName(name), int(rtype), IN)


def _secured_walk_cache():
    """One real secure positive walk: the cache holds its terminal answer and its chain."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    events = wiring._walk(
        cache, "www.zone.test.", responses=wiring._positive_script(), anchors=(wiring._anchor(),)
    )
    assert wiring._verdict(events).status == "secure"
    return cache


def _mail_script():
    name = "mail.zone.test."
    return [
        wiring.root_referral(name),
        wiring.tld_referral(name),
        wiring.positive(name, wiring._aaaa_rrset(name)),
    ]


# ---------------------------------------------------------------------------- the writes


@needs_tree
def test_a_secure_walk_files_the_chain_it_verified():
    """§4.5¶1's atomic entries, for the chain: each RRset with its signatures, stamped.

    The three helper DNSKEY fetches §5.2¶6 demanded and the DS records the
    referrals carried were all verified end to end by the verdict that ended
    the lookup -- caching them is not a new trust decision, it is the trust
    decision the walk just made given somewhere to live.
    """
    cache = _secured_walk_cache()
    for zone in ("test.", "zone.test."):
        key = _entry(cache, zone, DnsRType.DNSKEY)
        assert key is not None
        assert key.validated is True
        assert key.authoritative is True
        types = sorted({int(r.rtype) for r in key.records})
        assert types == sorted({int(DnsRType.DNSKEY), int(DnsRType.RRSIG)})  # atomic: data + sigs
    ds = _entry(cache, "zone.test.", DnsRType.DS)
    assert ds is not None
    assert ds.validated is True
    root = _entry(cache, ".", DnsRType.DNSKEY)
    assert root is not None
    assert root.validated is True


@needs_tree
def test_the_next_lookup_climbs_the_chain_from_the_cache():
    """§5.2¶6's MUST is to obtain the record -- a cache the same validator filled is obtaining.

    Second name, same cache: the descent still speaks (referrals are not
    cacheable data), the terminal query still goes out, and not one chain
    question does: every helper fetch the verdict demands lands on a stamped,
    signature-live entry instead.
    """
    cache = _secured_walk_cache()
    events = wiring._walk(
        cache, "mail.zone.test.", responses=_mail_script(), anchors=(wiring._anchor(),)
    )
    assert wiring._verdict(events).status == "secure"
    assert wiring._helpers(events) == []
    assert len(wiring._queries(events)) == 3  # root, tld, terminal -- the chain rode the cache
    legs = {(event.name, event.qtype) for event in events if isinstance(event, ChainFromCache)}
    assert (".", "DNSKEY") in legs
    assert ("zone.test.", "DNSKEY") in legs


@needs_tree
def test_the_loaded_material_is_still_verified_not_assumed():
    """The stamp licenses the load; the validator still checks every byte.

    Unstamped material -- a DNSKEY answer some non-validating lookup happened
    to cache -- is not chain evidence no matter how plausible its contents:
    this resolver never verified it, and RFC 4035 §4.3's states are this
    validator's answers, not the cache's.
    """
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    cache.put(
        PositiveEntry(
            DomainName("zone.test."),
            int(DnsRType.DNSKEY),
            IN,
            list(wiring.zone_keys()),
            cache.time_fn() + 300,
            validated=False,
        )
    )
    events = wiring._walk(
        cache, "mail.zone.test.", responses=_mail_script(), anchors=(wiring._anchor(),)
    )
    assert not any(
        isinstance(event, ChainFromCache) and event.name == "zone.test." for event in events
    )
    assert wiring._helpers(events) != []  # the network asked, as if the cache were empty


@needs_tree
def test_a_signature_expired_beyond_a_living_ttl_does_not_enter_the_store():
    """The two clocks disagree by construction -- §4.5¶1 counts signatures in the entry.

    An entry alive on the cache clock can carry an RRSIG whose window closed:
    §9¶4's poisoned-long-TTL scenario in one row. The load filter reads the
    window and treats expiry as absence (the network asked again), never
    feeding a corpse to the validator -- whose own reading of an expired
    window is Bogus, and a cache that turned a live zone bogus on a stale
    signature would be the attack doing the resolver's work for it.
    """
    cache = _secured_walk_cache()
    key_entry = _entry(cache, "zone.test.", DnsRType.DNSKEY)
    stale = []
    for record in key_entry.records:
        if int(record.rtype) == int(DnsRType.RRSIG):
            sig = record.rdata
            sig = RData_RRSIG(
                sig.type_covered,
                sig.algorithm,
                sig.labels,
                sig.original_ttl,
                wiring.NOW - 1,  # the window closed yesterday
                sig.inception,
                sig.key_tag,
                sig.signer_name,
                sig.signature,
            )
            record = DnsRecord(record.name, record.rtype, record.rclass, record.ttl, rdata=sig)
        stale.append(record)
    cache.put(
        PositiveEntry(
            DomainName("zone.test."),
            int(DnsRType.DNSKEY),
            IN,
            stale,
            cache.time_fn() + 86400,  # the cache clock says it lives; the signature says no
            authoritative=True,
            validated=True,
        )
    )
    events = wiring._walk(
        cache, "mail.zone.test.", responses=_mail_script(), anchors=(wiring._anchor(),)
    )
    assert not any(
        isinstance(event, ChainFromCache) and event.name == "zone.test." for event in events
    )
    assert wiring._helpers(events) != []  # re-fetched, the ordinary walk


@needs_tree
def test_an_unvalidated_or_bogus_walk_files_nothing():
    """The write gate is the secure verdict: no anchors, no chain; bogus, no chain."""
    plain = MemoryDnsCache(time_fn=wiring.Clock())
    wiring._walk(plain, "www.zone.test.", responses=wiring._positive_script(keys=False))
    assert _entry(plain, "zone.test.", DnsRType.DNSKEY) is None

    forged = MemoryDnsCache(time_fn=wiring.Clock())
    wiring._walk(
        forged,
        "www.zone.test.",
        responses=wiring._positive_script(flip=True),
        anchors=(wiring._anchor(),),
    )
    assert _entry(forged, "zone.test.", DnsRType.DNSKEY) is None


@needs_tree
def test_the_writer_keeps_fresher_material_and_refuses_unsigned_groups():
    """The unit seam: min-TTL atomic expiry, the fresher-entry guard, the unsigned refusal."""
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    material: dict = {}
    for record in wiring.zone_keys():
        _file_chain_record(material, record)
    _cache_chain(cache, material, wiring.NOW)
    entry = _entry(cache, "zone.test.", DnsRType.DNSKEY)
    assert entry is not None
    assert entry.validated is True
    assert entry.expires_at <= cache.time_fn() + min(int(r.ttl) for r in wiring.zone_keys())

    fresher = MemoryDnsCache(time_fn=wiring.Clock())
    fresher.put(
        PositiveEntry(
            DomainName("zone.test."),
            int(DnsRType.DNSKEY),
            IN,
            list(wiring.zone_keys()),
            fresher.time_fn() + 10**6,
            authoritative=True,
            validated=True,
        )
    )
    _cache_chain(fresher, material, wiring.NOW)
    assert _entry(fresher, "zone.test.", DnsRType.DNSKEY).expires_at == fresher.time_fn() + 10**6

    unsigned: dict = {}
    _file_chain_record(
        unsigned, wiring._rec("plain.test.", DnsRType.DNSKEY, wiring.zone_keys()[0].rdata)
    )
    bare = MemoryDnsCache(time_fn=wiring.Clock())
    _cache_chain(bare, unsigned, wiring.NOW)
    assert _entry(bare, "plain.test.", DnsRType.DNSKEY) is None


@needs_tree
def test_the_trace_shows_which_leg_the_cache_carried():
    """An absent query is invisible; this line is the only place it is not."""
    from namespy.resolver import Sname, resolve_steps
    from namespy.trace import Trace

    cache = _secured_walk_cache()
    sname = Sname(DomainName("mail.zone.test."), wiring.DnsQType.AAAA)
    trace = Trace(sname)
    generator = resolve_steps(
        sname,
        wiring._seed_slist(sname),
        cache,
        dnssec_ok=True,
        anchors=(wiring._anchor(),),
        now=wiring.NOW,
        special_names="ignore",  # fixture tree is .test; see test_dnssec_wiring
    )
    responses = iter(_mail_script())
    pending = next(generator)
    trace.record(pending)
    while True:
        try:
            if isinstance(pending, wiring.SendQuery):
                pending = generator.send(next(responses, None))
            else:
                pending = generator.send(None)
        except StopIteration:
            break
        trace.record(pending)
    assert "chain from cache: DNSKEY zone.test." in trace.to_mermaid()
