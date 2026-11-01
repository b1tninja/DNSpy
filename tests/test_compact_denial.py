"""RFC 9824 -- Compact Denial of Existence, end to end.

The mechanism is small enough to state in one breath: an online-signing zone
answers a nonexistent name with a NODATA-shaped response whose proof record
*matches* that name and carries the NXNAME (128) Meta-TYPE in its type bitmap,
because "not even the name" is a claim the ordinary shapes cannot make without
an NXDOMAIN RCODE the signer refuses to lie with (sections 2, 3.1). The rest of
the document is what everyone downstream has to unlearn: that a matching record
means existence (section 7.2's amendment), that a proven denial can deny for
its neighbours (section 6 para 3 forbids exactly this for compact data), and
that the RCODE the tools read may need restoring from the signed body (section
5, section 5.1's CO flag).

The fixtures are the signed tree of :mod:`tests.test_dnssec_validate`,
restated in wire form through :mod:`tests.test_dnssec_wiring` -- the same
import-not-duplicate precedent that file itself follows -- plus one
known-answer from RFC 9824 section 4 para 8, which pins the hash arithmetic
the compact NSEC3 owner names are made of.
"""

import asyncio
import base64

import pytest
import test_dnssec_validate as tree
import test_dnssec_wiring as wiring
import test_server as server_tests

from namespy.aggressive import synthesize_denial
from namespy.cache import MemoryDnsCache, NegativeEntry
from namespy.crypto import crypto_available
from namespy.dnssec import nsec3_hash
from namespy.edns import extended_error_name, extended_errors_of
from namespy.enums import DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.nsec import (
    collect_proof_records,
    name_between,
    nsec_proves_nxdomain,
    record_asserts_nonexistent,
    record_is_compact_denial,
)
from namespy.packet import EDNS_CO_BIT, EDNS_DO_BIT, DnsPacket, DnsQuestion, Query
from namespy.rdata import RData_DS, RData_NSEC, RData_NSEC3, type_name_of
from namespy.resolver import (
    CompactDenial,
    DnssecVerdict,
    Nodata,
    Nxdomain,
    NxdomainCut,
    RecursiveResolver,
    SendQuery,
    Slist,
    Sname,
    resolve_steps,
)
from namespy.stub import StubResolver, Upstream
from namespy.validate import DnssecStore, SecurityStatus, Validator

IN = int(DnsRClass.IN)
TTL = tree.TTL
NOW = tree.NOW
NXNAME = int(DnsRType.NXNAME)

needs_tree = pytest.mark.skipif(not crypto_available(), reason="namespy[crypto] is not installed")


# --------------------------------------------------------------------------- registry


def test_nxname_is_registered_at_128_as_a_meta_type() -> None:
    """RFC 9824 section 9 Table 1: Type NXNAME, value 128, the meta-TYPE range."""
    assert DnsRType(128).name == "NXNAME"
    assert DnsQType(128).name == "NXNAME"
    assert type_name_of(128) == "NXNAME"


def test_type128_round_trips_through_an_nsec_bitmap() -> None:
    """Type 128 fits window 0 (128 < 256) and reads back by its registered name."""
    record = RData_NSEC(DomainName(r"\000.gone.zone.test."), [46, 47, NXNAME])
    wire = record.to_wire()
    parsed = RData_NSEC.parse_from(wire, 0, len(wire))
    assert parsed.has_type(NXNAME)
    assert type_name_of(NXNAME) == "NXNAME"


def test_a_code_30_prints_with_its_registry_name() -> None:
    """Section 9 Table 3: 30, "Invalid Query Type" -- registered by this document."""
    assert extended_error_name(30) == "Invalid Query Type"


def test_co_is_opt_flags_bit_14_alongside_do() -> None:
    """Section 5.1's drawing and the live registry's "Bit 1" are the same 0x4000.

    The registry numbers EDNS flags from the top -- its Bit 0 is DO -- so CO's
    "Bit 1" is the physical second-most-significant bit; this package reads the
    OPT TTL's low half, where DO is 1 << 15 and CO 1 << 14.
    """
    query = Query(questions=[DnsQuestion("x.test.", DnsQType.A)])
    query.add_edns(1232, flags=EDNS_DO_BIT | EDNS_CO_BIT)
    parsed, _tail = DnsPacket.parse(bytes(query))
    assert parsed.dnssec_ok
    assert parsed.compact_answers_ok
    bare = Query(questions=[DnsQuestion("x.test.", DnsQType.A)])
    bare.add_edns(1232, flags=EDNS_DO_BIT)
    parsed_bare, _ = DnsPacket.parse(bytes(bare))
    assert parsed_bare.dnssec_ok
    assert not parsed_bare.compact_answers_ok


# --------------------------------------------------------------------------- geometry


def _nsec_pair(owner: str, next_domain: str, types):
    return (DomainName(owner), RData_NSEC(DomainName(next_domain), types))


def test_the_compact_record_spans_nothing_and_denies_no_neighbour() -> None:
    """Section 3.1 para 2's successor -- the name with a null label prefixed -- is

    immediately after the owner in canonical order: a name's empty rest sorts
    before any label (RFC 4034 section 6.1), so between X and \\0.X there is
    nothing, and below-X names sort after \\0.X. The covering predicates
    therefore refuse the compact record for neighbours and for descendants
    alike -- the structural half of section 6 para 3's ban, provable without
    a single signature.
    """
    entry = _nsec_pair("gone.zone.test.", r"\000.gone.zone.test.", [46, 47, NXNAME])
    # It matches its own name -- that is the point of it -- and covers nothing:
    assert not nsec_proves_nxdomain(entry, "gone.zone.test.")
    assert not nsec_proves_nxdomain(entry, "x.gone.zone.test.")
    owner, record = entry
    assert not name_between("x.gone.zone.test.", owner, record.next_domain)
    assert not name_between("aaa.zone.test.", owner, record.next_domain)


def test_the_bitmap_shapes_the_two_record_classes_allow() -> None:
    """NSEC may carry RRSIG and NSEC beside NXNAME; NSEC3's sole entry is NXNAME."""
    good_nsec = _nsec_pair("gone.zone.test.", r"\000.gone.zone.test.", [46, 47, NXNAME])[1]
    assert record_is_compact_denial((DomainName("gone.zone.test."), good_nsec))
    bare_nsec3 = RData_NSEC3(1, 0, 0, b"", b"\x01" * 20, [NXNAME])
    assert record_is_compact_denial((DomainName("AAAA.zone.test."), bare_nsec3))
    # A real type beside the signal contradicts it (refused, section 3.1 para 2):
    fat = _nsec_pair("bad.zone.test.", r"\000.bad.zone.test.", [1, 46, 47, NXNAME])[1]
    assert record_asserts_nonexistent((DomainName("bad.zone.test."), fat))
    assert not record_is_compact_denial((DomainName("bad.zone.test."), fat))
    # ...and so does a CNAME bit, which would owe the client an answer.
    cname = RData_NSEC3(1, 0, 0, b"", b"\x01" * 20, [NXNAME, int(DnsRType.CNAME)])
    assert not record_is_compact_denial((DomainName("X.zone.test."), cname))
    # No signal at all is simply not a compact answer.
    plain = _nsec_pair("www.zone.test.", "y.zone.test.", [1])[1]
    assert not record_asserts_nonexistent((DomainName("www.zone.test."), plain))


def test_section_4_paragraph_8_hashes_to_its_published_digest() -> None:
    """The document's one worked NSEC3 example: a.example.com with "1 0 0 -".

    Owner H64KFA4P1ACER2EBPS9QSDK6DNP8B3JQ, next hashed owner that value plus
    one -- the increment section 4 para 5 states as "adding one to the binary
    hash value", and the empty span this file keeps coming back to.
    """
    digest = nsec3_hash("a.example.com.", iterations=0, salt=b"")
    assert base64.b32hexencode(digest).decode("ascii").rstrip("=") == (
        "H64KFA4P1ACER2EBPS9QSDK6DNP8B3JQ"
    )
    successor = (int.from_bytes(digest, "big") + 1).to_bytes(len(digest), "big")
    assert base64.b32hexencode(successor).decode("ascii").rstrip("=") == (
        "H64KFA4P1ACER2EBPS9QSDK6DNP8B3JR"
    )


# --------------------------------------------------------------------------- validator


def _validator(*zone_records) -> Validator:
    """The signed zone.test. with exactly the proof records a scenario needs."""
    store = DnssecStore()
    store.add(wiring._signed(".", ".", DnsRType.DNSKEY, [tree._pub("root")], "root"), zone=".")
    store.add(
        wiring._signed(
            ".", "test.", DnsRType.DS, [RData_DS.for_dnskey("test.", tree._pub("test"))], "root"
        ),
        zone=".",
    )
    store.add(
        wiring._signed("test.", "test.", DnsRType.DNSKEY, [tree._pub("test")], "test"),
        zone="test.",
    )
    store.add(
        wiring._signed(
            "test.",
            "zone.test.",
            DnsRType.DS,
            [RData_DS.for_dnskey("zone.test.", tree._pub("zone"))],
            "test",
        ),
        zone="test.",
    )
    store.add(
        wiring._signed("zone.test.", "zone.test.", DnsRType.DNSKEY, [tree._pub("zone")], "zone"),
        zone="zone.test.",
    )
    if zone_records:
        store.add(list(zone_records), zone="zone.test.")
    return Validator(anchors=[tree._anchor()], store=store, now=NOW)


def _compact_nsec_rrsig(owner: str, types=(46, 47, NXNAME)):
    """The section 3.1 record: QNAME's own name, its null-labeled successor."""
    successor = r"\000." + owner
    return wiring._signed(
        "zone.test.", owner, DnsRType.NSEC, [wiring._nsec(successor, list(types))], "zone"
    )


def _compact_nsec3_rrsig(owner: str, types=(NXNAME,)):
    """The section 4 shape: hash(owner) -> hash+1, parameters "1 0 0 -"."""
    digest = nsec3_hash(owner, iterations=0, salt=b"")
    successor = (int.from_bytes(digest, "big") + 1).to_bytes(len(digest), "big")
    label = base64.b32hexencode(digest).decode("ascii").rstrip("=")
    return wiring._signed(
        "zone.test.",
        f"{label}.zone.test.",
        DnsRType.NSEC3,
        [RData_NSEC3(1, 0, 0, b"", successor, list(types))],
        "zone",
    )


@needs_tree
def test_a_signed_nsec_asserting_nxname_proves_nodata_and_says_its_name() -> None:
    """Sections 2 para 3-4: the NOERROR branch changes nothing mechanically...

    ...because the matching record already proves QTYPE absent -- and the
    verdict now also says *why the name itself* is denied: via_compact, with
    the Compact Answer in the reason an operator will read.
    """
    verdict = _validator(*_compact_nsec_rrsig("gone.zone.test.")).validate_denial(
        "gone.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure
    assert verdict.via_compact
    assert "Compact Answer" in verdict.reason
    assert verdict.ad_worthy  # compact is not Opt-Out; nothing subtracts from the stamp


@needs_tree
def test_a_signed_compact_nsec3_denies_the_same_way() -> None:
    """Section 4: hashed owner, parameters "1 0 0 -", NXNAME as the sole entry.

    The digest is computed with the record's own parameters -- which is why a
    compact NSEC3 matches its name whether or not the zone advertises those
    parameters in an NSEC3PARAM RR of its own.
    """
    verdict = _validator(*_compact_nsec3_rrsig("gone.zone.test.")).validate_denial(
        "gone.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure
    assert verdict.via_compact


@needs_tree
def test_co_restores_nxdomain_over_the_compact_shape() -> None:
    """Section 5.1 para 3: CO licenses a NODATA-shaped proof wearing RCODE 3."""
    verdict = _validator(*_compact_nsec_rrsig("gone.zone.test.")).validate_denial(
        "gone.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
        co_signaled=True,
    )
    assert verdict.secure
    assert verdict.via_compact
    assert "5.1" in verdict.reason


@needs_tree
def test_nxdomain_over_a_matching_record_without_the_signal_is_no_verdict() -> None:
    """A matching record proves a name *exists* -- NXDOMAIN needs the bit.

    CO promised section 5.1 para 3's shape and the zone delivered the wrong
    claim: incomplete, ask again, never believe the RCODE that the signed body
    contradicts.
    """
    verdict = _validator(*wiring.zone_denials()).validate_denial(
        "www.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
        co_signaled=True,
    )
    assert verdict.status is SecurityStatus.INDETERMINATE
    assert "no NXNAME assertion" in verdict.reason


@needs_tree
def test_a_compact_answer_beside_a_type_it_denies_is_bogus_not_looked_past() -> None:
    """NXNAME + an A bit in one bitmap: the signature is fine and the record is not."""
    verdict = _validator(
        *_compact_nsec_rrsig("bad.zone.test.", types=(1, 46, 47, NXNAME))
    ).validate_denial(
        "bad.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
        co_signaled=True,
    )
    assert verdict.status is SecurityStatus.BOGUS
    assert "Compact" in verdict.reason


@needs_tree
def test_co_is_inert_against_the_conventional_covering_proof() -> None:
    """Section 5.1 adds a shape; it does not demote the one RFC 4035 section 5.3.1 knows."""
    verdict = _validator(*wiring.zone_denials()).validate_denial(
        "aaa.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NAME_ERROR,
        zone="zone.test.",
        co_signaled=True,
    )
    assert verdict.secure
    assert not verdict.via_compact
    assert "Compact" not in verdict.reason


@needs_tree
def test_a_malformed_signal_degrades_to_an_ordinary_nodata_not_a_lie() -> None:
    """NOERROR + a matching bitmap carrying NXNAME beside real types.

    The NODATA proof stands on QTYPE being absent and it is absent; the bits
    that spoil section 3.1 para 2's shape are pseudo-type noise RFC 4034
    section 4.1.2 already tells a reader to ignore. What gets withheld is the
    *signal* -- this resolver will not restore on the strength of a bitmap
    that contradicts itself -- while the answer stands.
    """
    verdict = _validator(
        *_compact_nsec_rrsig("bad.zone.test.", types=(1, 46, 47, NXNAME))
    ).validate_denial(
        "bad.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure
    assert not verdict.via_compact


@needs_tree
def test_an_ordinary_nodata_earns_no_compact_marking() -> None:
    """The regression guard: fixture-shape proofs keep their old verdicts."""
    verdict = _validator(*wiring.zone_denials()).validate_denial(
        "www.zone.test.",
        int(DnsQType.AAAA),
        rcode=DnsResponseCode.NO_ERROR,
        zone="zone.test.",
    )
    assert verdict.secure
    assert not verdict.via_compact


# --------------------------------------------------------------------------- the walk


def _descent(name, final):
    """Root -> test. -> zone.test. -> *final*, then the three key fetches."""
    return [
        wiring.root_referral(name),
        wiring.tld_referral(name),
        final,
        wiring.key_answer(".", wiring.root_keys()),
        wiring.key_answer("test.", wiring.tld_keys()),
        wiring.key_answer("zone.test.", wiring.zone_keys()),
    ]


def _anchor():
    return wiring._anchor()


@needs_tree
def test_the_walk_records_a_compact_denial_and_keeps_its_rcode_honest() -> None:
    """NOERROR + NXNAME: the event says so, the cache entry stays a Nodata.

    Nothing rewrites this packet's RCODE on the way out -- section 5.1's
    restoration is a server product's act toward its downstream, and namespy
    serves nobody -- but the walk's own vocabulary distinguishes it: a
    CompactDenial between the verdict and the Nodata, and a cache entry that
    describes a single name.
    """
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    name = "gone.zone.test."
    final = wiring.nodata(name, [wiring.soa(), *_compact_nsec_rrsig(name)])
    events = wiring._walk(cache, name, responses=_descent(name, final), anchors=(_anchor(),))
    verdict = wiring._verdict(events)
    assert isinstance(verdict, DnssecVerdict)
    assert verdict.status == SecurityStatus.SECURE.value
    marks = [event for event in events if isinstance(event, CompactDenial)]
    assert [(m.name, m.restored) for m in marks] == [(name, False)]
    assert any(isinstance(event, Nodata) for event in events)
    assert not any(isinstance(event, (Nxdomain, NxdomainCut)) for event in events)
    entry = cache.get(DomainName(name), int(DnsQType.AAAA), IN)
    assert isinstance(entry, NegativeEntry)
    assert entry.rcode is DnsResponseCode.NO_ERROR
    assert entry.validated  # AD-worthy: compact is a full proof of this one name


@needs_tree
def test_a_restored_nxdomain_is_cached_as_the_name_level_denial_it_proved() -> None:
    """The swap section 6 para 3 demands, seen from the walk's exit.

    A zone that implements section 5.1 hands back RCODE 3 over the compact
    shape; the client's packet keeps it (the zone itself restored it -- the
    honest source) and the AD bit rides on the verdict. The cache does not:
    a Nxdomain entry is the shape that cuts descendants, and no NXDOMAIN
    synthesis "in the style of [RFC8020]" is licensable from compact
    evidence, so the entry is filed as a NODATA-format denial.
    """
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    name = "gone.zone.test."
    final = wiring.nxdomain(name, [wiring.soa(), *_compact_nsec_rrsig(name)])
    final.add_edns(1232, flags=EDNS_DO_BIT | EDNS_CO_BIT)
    events = wiring._walk(cache, name, responses=_descent(name, final), anchors=(_anchor(),))
    marks = [event for event in events if isinstance(event, CompactDenial)]
    assert [(m.name, m.restored) for m in marks] == [(name, True)]
    done = wiring._done(events)
    assert done is not None
    assert done.RCODE is DnsResponseCode.NAME_ERROR  # the zone's own restoration
    assert done.AD is True  # section 3.2.3 on a fully verified compact proof
    entry = cache.get(DomainName(name), int(DnsQType.AAAA), IN)
    assert isinstance(entry, NegativeEntry)
    assert entry.rcode is DnsResponseCode.NO_ERROR  # not the cut-capable shape
    # And the descendant that a Nxdomain entry *would* have cut gets asked:
    deeper = "x.gone.zone.test."
    second = wiring.nodata(deeper, [wiring.soa(), *_compact_nsec_rrsig(deeper)])
    events2 = wiring._walk(cache, deeper, responses=_descent(deeper, second), anchors=(_anchor(),))
    assert not any(isinstance(event, NxdomainCut) for event in events2)
    assert any(isinstance(event, SendQuery) for event in events2)


# --------------------------------------------------------------------------- synthesis ban


@needs_tree
def test_a_compact_bundle_is_never_the_evidence_aggressive_caching_fabricates_from() -> None:
    """Section 6 para 3 by differential: one bit changes the answer to None.

    Both entries hold a signed record *matching* www.zone.test. whose bitmap
    leaves TXT unlisted -- geometry that would synthesise `www TXT` NODATA
    from the first. The second entry's bitmap also carries NXNAME, which says
    the name is gone, and a synthesised NODATA is the shape of "exists, no
    such type": the same record cannot license both, so the gate discards the
    bundle before the geometry ever sees it.
    """
    plain = wiring._signed(
        "zone.test.", "www.zone.test.", DnsRType.NSEC, [wiring._nsec("y.zone.test.", [1])], "zone"
    )
    compact = wiring._signed(
        "zone.test.",
        "www.zone.test.",
        DnsRType.NSEC,
        [wiring._nsec(r"\000.www.zone.test.", [46, 47, NXNAME])],
        "zone",
    )

    def entry(records):
        return NegativeEntry(
            DomainName("www.zone.test."),
            int(DnsQType.TXT),
            IN,
            DnsResponseCode.NO_ERROR,
            wiring.soa(),
            wiring.NOW + 300,
            collect_proof_records(records),
            validated=True,
        )

    sname = Sname(DomainName("www.zone.test."), int(DnsQType.TXT))
    assert synthesize_denial(entry(plain), sname, now=wiring.NOW) is not None
    assert synthesize_denial(entry(compact), sname, now=wiring.NOW) is None


# --------------------------------------------------------------------------- the refusal to ask


def test_the_walk_refuses_to_attempt_an_nxname_question() -> None:
    """Section 3.5 para 2: "MUST NOT ... attempt iterative resolution"."""
    steps = resolve_steps(Sname(DomainName("x.test."), NXNAME), Slist(Sname(DomainName("."))))
    with pytest.raises(ValueError, match="Meta-TYPE"):
        next(steps)


def test_the_stub_refuses_to_forward_an_nxname_question() -> None:
    """The forwarding half of the same sentence, at the forwarder's door."""
    stub = StubResolver([Upstream.parse("10.0.0.1")])

    async def ask():
        return await stub.forward([DnsQuestion(DomainName("x.test."), NXNAME)])

    with pytest.raises(ValueError, match="must not be forwarded"):
        asyncio.run(ask())


def test_co_rides_with_do_and_never_alone() -> None:
    """Section 5.1's flag is a promise under DNSSEC; without DO, no OPT flags."""
    resolver = RecursiveResolver()
    resolver.dnssec_ok = False
    resolver.compact_answers = True
    assert resolver._edns_flags == 0  # CO without DO asks for nothing
    resolver.compact_answers = False
    resolver.dnssec_ok = True
    assert resolver._edns_flags == EDNS_DO_BIT
    resolver.compact_answers = True
    assert resolver._edns_flags == (EDNS_DO_BIT | EDNS_CO_BIT)


def test_the_cli_refuses_nxname_by_name_and_by_number() -> None:
    """DnsQType spells 128 so the refusal can name it -- then exits with a sentence."""
    from namespy.__main__ import build_parser

    parser = build_parser()
    for spelling in ("NXNAME", "TYPE128"):
        with pytest.raises(SystemExit):
            parser.parse_args(["gone.zone.test.", spelling])


@needs_tree
def test_a_served_nxname_query_bounces_formerr_with_ede_30() -> None:
    """Section 3.5 para 2's MUST and para 3's MAY, on one wire."""

    async def exchange():
        server, _resolver, transport = server_tests.make_server()
        query = server_tests.query_packet("gone.zone.test.", qtype=DnsQType(NXNAME))
        query.add_edns(1232)  # EDE needs an OPT to ride in (RFC 6891 section 7)
        server.datagram_received(bytes(query), ("10.9.9.9", 5353))
        await server_tests.drain(server)
        return transport.replies

    replies = asyncio.run(exchange())
    assert len(replies) == 1
    reply = replies[0]
    assert reply.RCODE is DnsResponseCode.FORMAT_ERROR
    codes = [error.info_code for error in extended_errors_of(reply.edns_options())]
    assert 30 in codes  # "Invalid Query Type" -- registry name, section 9 Table 3
