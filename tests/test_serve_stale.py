"""Serving stale data when refreshing fails (RFC 8767; EDE 2 per RFC 8914 §4.2).

The resiliency feature in two layers: the cache keeps expired rows inside a
maximum-stale window (§5¶11) without ever letting :meth:`get` hand them out
as live, and the walk answers from that door only where refreshing has
failed (§7¶1) -- never instead of a reachable authority, never with the AD
bit, and never with an expired record's original TTL (§4¶4's MUST: greater
than zero, recommended 30, the rate-limiting reasoning in §6¶6).
"""

import pytest
import test_dnssec_wiring as wiring

from namespy.cache import MemoryDnsCache, NegativeEntry, PositiveEntry
from namespy.cache.sqlite import SqliteDnsCache
from namespy.enums import DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.resolver import ServeStale, Sname, resolve_steps
from namespy.trace import Trace

IN = int(DnsRClass.IN)


class Clock:
    """A hand-cranked cache clock: the stale window is all about *when*."""

    def __init__(self, t=100000.0):
        self.t = t

    def __call__(self):
        return self.t


def _stale_walk(cache, name, *, responses=(), serve_stale=3600.0, client_cd=False, failures=None):
    sname = Sname(DomainName(name), wiring.DnsQType.AAAA)
    kwargs = {"dnssec_ok": False, "now": wiring.NOW, "serve_stale": serve_stale}
    if client_cd:
        kwargs["client_cd"] = True
    if failures is not None:
        kwargs["failures"] = failures
    return wiring._drive(
        resolve_steps(sname, wiring._seed_slist(sname), cache, special_names="ignore", **kwargs),
        list(responses),
    )


def _seeded_cache(*, ttl_past=10.0, stale_ttl=3600.0, name="www.zone.test.", validated=False):
    """A cache whose one entry for *name* expired *ttl_past* seconds ago."""
    cache = MemoryDnsCache(time_fn=Clock(), stale_ttl=stale_ttl)
    cache.put(
        PositiveEntry(
            DomainName(name),
            int(DnsRType.AAAA),
            IN,
            list(wiring._aaaa_rrset(name, signed=False)),
            cache.time_fn() - ttl_past,
            authoritative=True,
            validated=validated,
        )
    )
    return cache


# ------------------------------------------------------------------- the cache's door


def test_expired_data_is_discarded_on_read_unless_a_window_wants_it():
    """The default cache keeps its old rule: expired is gone (stale_ttl = 0)."""
    cache = MemoryDnsCache(time_fn=Clock())
    cache.put(PositiveEntry(DomainName("a.test."), int(DnsRType.AAAA), IN, [], cache.time_fn() - 1))
    assert cache.get(DomainName("a.test."), int(DnsRType.AAAA), IN) is None
    assert len(cache) == 0
    assert cache.stale(DomainName("a.test."), int(DnsRType.AAAA), IN) is None


def test_a_window_keeps_the_row_expired_without_calling_it_live():
    """Retention is retention: ``get`` still misses, the row survives, ``stale`` finds it."""
    cache = _seeded_cache()
    assert cache.get(DomainName("www.zone.test."), int(DnsRType.AAAA), IN) is None
    assert len(cache) == 1  # the read did not discard what the window still owns
    hit = cache.stale(DomainName("www.zone.test."), int(DnsRType.AAAA), IN)
    assert hit is not None
    assert hit.expired(cache.time_fn())


def test_the_stale_door_never_touches_live_data():
    cache = MemoryDnsCache(time_fn=Clock(), stale_ttl=3600)
    cache.put(
        PositiveEntry(
            DomainName("fresh.test."),
            int(DnsRType.AAAA),
            IN,
            list(wiring._aaaa_rrset("fresh.test.", signed=False)),
            cache.time_fn() + 300,
        )
    )
    assert cache.stale(DomainName("fresh.test."), int(DnsRType.AAAA), IN) is None
    assert cache.get(DomainName("fresh.test."), int(DnsRType.AAAA), IN) is not None


def test_a_row_past_the_window_is_retired_by_whichever_door_reads_it_last():
    cache = MemoryDnsCache(time_fn=Clock(), stale_ttl=60)
    cache.put(
        PositiveEntry(DomainName("dead.test."), int(DnsRType.AAAA), IN, [], cache.time_fn() - 61)
    )
    assert cache.stale(DomainName("dead.test."), int(DnsRType.AAAA), IN) is None
    assert len(cache) == 0


def test_prune_sweeps_retirement_not_mere_expiry():
    """:meth:`prune` reclaims what even a failed refresh could not serve."""
    cache = MemoryDnsCache(time_fn=Clock(), stale_ttl=3600)
    cache.put(PositiveEntry(DomainName("kept.test."), 28, IN, [], cache.time_fn() - 10))
    cache.put(PositiveEntry(DomainName("gone.test."), 28, IN, [], cache.time_fn() - 3601))
    assert cache.prune() == 1
    assert cache.stale(DomainName("kept.test."), 28, IN) is not None


def test_sqlite_retains_and_retires_like_the_memory_backend():
    clock = Clock()
    cache = SqliteDnsCache(time_fn=clock, stale_ttl=3600)
    try:
        cache.put(
            PositiveEntry(
                DomainName("sql.zone.test."),
                int(DnsRType.AAAA),
                IN,
                list(wiring._aaaa_rrset("sql.zone.test.", signed=False)),
                clock.t - 5,
            )
        )
        assert cache.get(DomainName("sql.zone.test."), int(DnsRType.AAAA), IN) is None
        hit = cache.stale(DomainName("sql.zone.test."), int(DnsRType.AAAA), IN)
        assert hit is not None
        assert [int(r.rtype) for r in hit.records] == [int(DnsRType.AAAA)]
        cache.put(PositiveEntry(DomainName("old.zone.test."), 28, IN, [], clock.t - 3601))
        assert cache.stale(DomainName("old.zone.test."), 28, IN) is None
        assert cache.get(DomainName("sql.zone.test."), 28, IN) is None
        assert len(cache) == 1  # the retired row was deleted; the retained one survived
    finally:
        cache.close()


# ------------------------------------------------------------------- the walk's seams


def test_an_outage_answers_from_the_expired_entry_and_says_so():
    """§7¶1's placement and §4¶2's permission: unable to refresh, used as though unexpired.

    Every scripted reply is ``None`` -- the whole authority set is down -- so
    the walk ends at its out-of-servers seam and the expired entry answers.
    """
    cache = _seeded_cache()
    events = _stale_walk(cache, "www.zone.test.")
    stale = next((e for e in events if isinstance(e, ServeStale)), None)
    assert stale is not None
    assert stale.name == "www.zone.test."
    assert stale.age == 10
    done = wiring._done(events)
    assert done is not None
    assert done.RCODE == DnsResponseCode.NO_ERROR
    assert done.stale_answer is True
    assert done.AD is False  # §3.2.3's claim is present tense; this data's is past
    assert [str(r.name) for r in done.answers] == ["www.zone.test."]
    for record in done.answers:
        assert 0 < int(record.ttl) <= 30  # §4¶4's MUST: > 0; its recommendation: 30


def test_the_stale_serve_leaves_the_cached_original_whole():
    """The served TTLs are rebuilt, never edited into the entry the window still owns."""
    cache = _seeded_cache()
    _stale_walk(cache, "www.zone.test.")
    hit = cache.stale(DomainName("www.zone.test."), int(DnsRType.AAAA), IN)
    assert hit is not None
    assert all(int(r.ttl) > 30 for r in hit.records)  # untouched originals


def test_a_denial_can_be_stale_too():
    cache = MemoryDnsCache(time_fn=Clock(), stale_ttl=3600)
    cache.put(
        NegativeEntry(
            DomainName("gone.zone.test."),
            int(DnsRType.AAAA),
            IN,
            DnsResponseCode.NAME_ERROR,
            wiring.soa(),
            cache.time_fn() - 20,
        )
    )
    events = _stale_walk(cache, "gone.zone.test.")
    done = wiring._done(events)
    assert done is not None
    assert done.RCODE == DnsResponseCode.NAME_ERROR
    assert done.stale_answer is True
    assert done.nameservers  # the SOA rides along, TTL-refreshed
    assert all(int(r.ttl) <= 30 for r in done.nameservers)


def test_the_remembered_failure_asks_nothing_and_answers_stale():
    """§5¶7: inside the backoff window, "the cache may be immediately consulted for stale data"."""
    from namespy.cache import FailureCache

    failures = FailureCache()
    failures.note_query(DomainName("www.zone.test."), int(DnsRType.AAAA), IN, "authorities down")
    cache = _seeded_cache()
    events = _stale_walk(cache, "www.zone.test.", failures=failures)
    assert wiring._queries(events) == []  # no refresh attempted, none wasted
    done = wiring._done(events)
    assert done is not None
    assert done.RCODE == DnsResponseCode.NO_ERROR


def test_the_knob_off_discards_expired_and_fails_honestly():
    """Default: no window, no stale serve, the plain SERVFAIL the outage deserves."""
    cache = MemoryDnsCache(time_fn=Clock())
    cache.put(
        PositiveEntry(
            DomainName("www.zone.test."),
            int(DnsRType.AAAA),
            IN,
            list(wiring._aaaa_rrset("www.zone.test.", signed=False)),
            cache.time_fn() - 10,
        )
    )
    events = _stale_walk(cache, "www.zone.test.", serve_stale=0.0)
    assert wiring._done(events) is None
    assert not any(isinstance(e, ServeStale) for e in events)
    assert len(cache) == 0  # with no window, expiry still means eviction


def test_data_past_the_window_is_not_stale_it_is_gone():
    cache = _seeded_cache(ttl_past=7200.0, stale_ttl=3600.0)
    events = _stale_walk(cache, "www.zone.test.")
    assert wiring._done(events) is None
    assert not any(isinstance(e, ServeStale) for e in events)


def test_a_cd_client_may_have_the_stale_answer():
    """Serve-stale is a cache read, not an inference: §9¶2's "for all clients" reaches CD.

    CD means the client validates for itself and asked us not to enforce --
    it does not mean "withhold your cache". The answer carries no AD, so the
    CD client's own validator judges these bytes (an expired signature, if
    there is one, is its call to make, §10¶1's accepted risk).
    """
    cache = _seeded_cache()
    events = _stale_walk(cache, "www.zone.test.", client_cd=True)
    assert any(isinstance(e, ServeStale) for e in events)
    done = wiring._done(events)
    assert done is not None
    assert done.RCODE == DnsResponseCode.NO_ERROR
    assert done.AD is False


@pytest.mark.skipif(
    not wiring.crypto_available(), reason="the signed fixture tree needs namespy[crypto]"
)
def test_a_validators_own_expired_entry_still_asserts_nothing():
    """The stamp says the entry was verified then; stale serving refuses to stretch it to now."""
    cache = _seeded_cache(validated=True)
    events = _stale_walk(cache, "www.zone.test.")
    assert any(isinstance(e, ServeStale) for e in events)
    done = wiring._done(events)
    assert done.AD is False


def test_the_trace_says_the_answer_was_expired():
    cache = _seeded_cache()
    sname = Sname(DomainName("www.zone.test."), wiring.DnsQType.AAAA)
    trace = Trace(sname)
    generator = resolve_steps(
        sname,
        wiring._seed_slist(sname),
        cache,
        dnssec_ok=False,
        now=wiring.NOW,
        serve_stale=3600.0,
        special_names="ignore",  # fixture tree is .test; see test_dnssec_wiring
    )
    pending = next(generator)
    trace.record(pending)
    while True:
        try:
            pending = generator.send(None)
        except StopIteration:
            break
        trace.record(pending)
    assert "serve stale: www.zone.test. (expired 10s ago)" in trace.to_mermaid()


def test_the_stale_response_carries_the_marker_the_ede_door_reads():
    """`stale_answer` is to EDE 2 what `dnssec_bogus` is to EDE 6 -- and 2 is 8914 §4.2's."""
    from namespy.resolver import _synthesize_stale
    from namespy.server import EDE_STALE_ANSWER

    assert EDE_STALE_ANSWER == 2
    cache = _seeded_cache()
    hit = cache.stale(DomainName("www.zone.test."), int(DnsRType.AAAA), IN)
    sname = Sname(DomainName("www.zone.test."), wiring.DnsQType.AAAA)
    response = _synthesize_stale(sname, hit)
    assert response.stale_answer is True
    assert response.AD is False


def test_a_resolver_with_the_knob_opens_its_cache_window():
    """The instance knob sets retention on the cache it runs -- and only widens."""
    from namespy.resolver import RecursiveResolver

    resolver = RecursiveResolver(serve_stale=3600)
    assert resolver.serve_stale == 3600
    assert resolver.cache.stale_ttl == 3600

    wide = MemoryDnsCache(time_fn=Clock(), stale_ttl=9999)
    RecursiveResolver(cache=wide, serve_stale=60)
    assert wide.stale_ttl == 9999  # a window already wider is the operator's, not ours

    off = MemoryDnsCache(time_fn=Clock())
    RecursiveResolver(cache=off)
    assert off.stale_ttl == 0
