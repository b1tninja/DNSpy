"""edns-key-tag: signaling trust-anchor knowledge (RFC 8145 section 4).

The option is telemetry, not a fetch directive -- section 4.3 asks a responder for
nothing beyond a MUST NOT on putting it in responses -- and this file tests the
three roles this package plays: encoder (the validator's own DNSKEY queries,
section 4.2.2.1 paragraph 1), copier (a client's list forwarded upstream, sections
4.2.2.1 paragraph 2 and 4.2.2.2), and silent responder (section 4.3 paragraph 2).
The fixture tree of ``test_dnssec_wiring`` supplies the signed zones; the codec
tests need no crypto and run anywhere.
"""

import asyncio
import struct

import pytest
import test_dnssec_wiring as wiring

from namespy.anchors import TrustAnchor
from namespy.cache import MemoryDnsCache
from namespy.crypto import crypto_available
from namespy.edns import (
    KEY_TAG_OCTETS,
    KEY_TAG_OPTION_CODE,
    MAX_KEY_TAGS,
    EdnsOption,
    key_tag_lists,
    key_tag_option,
    key_tags_of,
    option_name,
    parse_options,
    serialize_options,
)
from namespy.enums import DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import EDNS_DO_BIT, DnsQuestion, Query
from namespy.resolver import RecursiveResolver, Sname, resolve_steps
from namespy.server import DnsServer
from namespy.validate import DnssecStore, Validator

DS = int(DnsRType.DS)
DNSKEY = int(DnsRType.DNSKEY)
IN = int(DnsRClass.IN)

needs_tree = pytest.mark.skipif(
    not crypto_available(), reason="the signed fixture tree needs namespy[crypto]"
)


def _wire_tags(option):
    """The KEY-TAG values one encoded option carries, straight off the figure."""
    return struct.unpack(f"!{len(option.data) // KEY_TAG_OCTETS}H", option.data)


# --------------------------------------------------------------------- the option itself


def test_the_option_is_code_fourteen_and_round_trips():
    """§4.1: OPTION-CODE 14, OPTION-LENGTH 2 x count, one or more 16-bit tags."""
    assert option_name(KEY_TAG_OPTION_CODE) == "edns-key-tag"  # §6's registration
    option = key_tag_option([19036, 12345])
    assert option.code == 14
    assert len(option.data) == 2 * 2  # §4.1¶4: OPTION-LENGTH is 2 x count
    again = parse_options(serialize_options([option]))
    assert key_tag_lists(again) == ((19036, 12345),)


def test_duplicates_fold_and_order_survives():
    option = key_tag_option([5, 3, 5, 1])
    assert option.data == struct.pack("!HHH", 5, 3, 1)


def test_the_cap_holds_a_malicious_list_down():
    """§4.2.2.1¶3 recommends a limit; §7¶3 names the motive: tags "made up" to stall a rollover.

    The cap is the sender's obligation read as ours: forty invented tags leave as
    the thirty-two the implementation is willing to have a responder collect.
    """
    option = key_tag_option(range(1000, 1040))
    assert len(option.data) == KEY_TAG_OCTETS * MAX_KEY_TAGS
    assert _wire_tags(option) == tuple(range(1000, 1000 + MAX_KEY_TAGS))


def test_an_empty_list_is_not_a_signal():
    """§4.1¶5 says "one or more"; §4.2¶2-¶6 make the zero-tag case *no option*."""
    with pytest.raises(ValueError, match="one or more"):
        key_tag_option([])
    with pytest.raises(ValueError, match="16-bit"):
        key_tag_option([0x10000])  # Appendix B arithmetic cannot produce 65536


def test_two_instances_stay_two_lists_and_flatten_on_copy():
    """§4.2.2.1¶2 transmits own and client lists separately; §4.2.2.2 copies one list."""
    options = [key_tag_option([19036, 12345]), key_tag_option([19036, 34567])]
    again = parse_options(serialize_options(options))
    assert key_tag_lists(again) == ((19036, 12345), (19036, 34567))
    assert key_tags_of(again) == (19036, 12345, 34567)


def test_malformed_instances_carry_no_list():
    """Odd, empty, or wrong-direction: read as nothing, never as an error.

    §4.1¶4 defines OPTION-LENGTH as "2 x number of key-tag values present", so a
    trailing half-tag is arithmetic nobody meant -- and §4.2¶7's remedy for seeing
    this option wrongly is "no action needs to be taken"; the same leniency reads
    a zero-length instance (which says nothing per §4.1¶5) and one arriving in a
    response (where §4.3¶2 says it should not have been sent at all).
    """
    odd = EdnsOption(KEY_TAG_OPTION_CODE, b"\x01\x02\x03")
    empty = EdnsOption(KEY_TAG_OPTION_CODE, b"")
    other = EdnsOption(65001, b"\x41\x42")
    good = key_tag_option([42])
    assert key_tag_lists([odd, empty, other, good]) == ((42,),)
    assert key_tags_of([odd, empty]) == ()


# ------------------------------------------------------------- who may claim a key tag


@needs_tree
def test_a_ds_shaped_anchor_lends_its_own_tag():
    """§4.2¶3: tags "learned ... from a trust anchor"; §4.2¶4 SHOULDs exactly this query."""
    anchor = wiring._anchor()
    validator = Validator(anchors=(anchor,))
    assert validator.key_tags_for(".") == (anchor.key_tag,)


@needs_tree
def test_a_key_shaped_anchor_lends_the_keys_own_tag():
    """RFC 4033 §2 lets an anchor be a DNSKEY; its tag is the same Appendix B arithmetic."""
    key = wiring.root_keys()[0].rdata
    anchor = TrustAnchor(
        zone="zone.test.",
        key_tag=4242,  # the DS-shape fields are this anchor's own; the tag rides too
        algorithm=key.algorithm,
        digest_type=2,
        digest=b"\x00" * 32,
        flags=key.flags,
        public_key=key.public_key,
    )
    validator = Validator(anchors=(anchor,))
    assert validator.key_tags_for("zone.test.") == (4242, key.key_tag)


@needs_tree
def test_the_ds_a_descent_collected_counts_and_an_answer_dnskey_does_not():
    """§4.2¶3's two sources against §4.2¶6's MUST NOT: a key nobody pinned lends no tag."""
    store = DnssecStore()
    store.add(wiring.ds_zone(), zone="test.")  # the parent's DS for zone.test.
    validator = Validator(anchors=(), store=store)
    expected = tuple(record.rdata.key_tag for record in wiring.ds_zone() if int(record.rtype) == DS)
    assert expected
    assert validator.key_tags_for("zone.test.") == expected

    # The zone's own DNSKEY answer -- even a *different* key's -- is an answer, not
    # a learned pin: its tag would be the data making its own telemetry claim.
    stray = wiring.zone_keys()[0]
    other = type(stray.rdata)(
        stray.rdata.flags,
        stray.rdata.protocol,
        stray.rdata.algorithm,
        b"\x99" + bytes(stray.rdata.public_key),
    )
    assert other.key_tag not in expected
    store.add([wiring._rec("zone.test.", DnsRType.DNSKEY, other)], zone="zone.test.")
    store.add(wiring.zone_keys(), zone="zone.test.")
    assert validator.key_tags_for("zone.test.") == expected


@needs_tree
def test_a_tag_learned_twice_is_claimed_once():
    """An anchor and the parent's DS pinning the same KSK produce one entry, no stammer."""
    ds_tag = next(r.rdata.key_tag for r in wiring.ds_zone() if int(r.rtype) == DS)
    anchor = TrustAnchor(
        zone="zone.test.",
        key_tag=ds_tag,
        algorithm=8,
        digest_type=2,
        digest=b"\x00" * 32,
    )
    store = DnssecStore()
    store.add(wiring.ds_zone(), zone="test.")
    validator = Validator(anchors=(anchor,), store=store)
    assert validator.key_tags_for("zone.test.") == (ds_tag,)


@needs_tree
def test_nothing_learned_nothing_claimed():
    """§4.2.2.1¶4's honest output for a validator that knows this zone's keys not: empty."""
    assert Validator(anchors=()).key_tags_for("zone.test.") == ()


# ------------------------------------------------------------------------ the walk's turn


def _keytag_walk(name, qtype, *, responses, anchors=(), client_key_tags=()):
    sname = Sname(DomainName(name), qtype)
    kwargs = {"dnssec_ok": True, "now": wiring.NOW}
    if anchors:
        kwargs["anchors"] = tuple(anchors)
    if client_key_tags:
        kwargs["client_key_tags"] = tuple(client_key_tags)
    cache = MemoryDnsCache(time_fn=wiring.Clock())
    return wiring._drive(
        resolve_steps(sname, wiring._seed_slist(sname), cache, **kwargs), list(responses)
    )


def _dnskey_script():
    """Root -> test. -> zone.test. (AA), each hop asked the same DNSKEY question."""
    name = "zone.test."
    return [
        wiring.root_referral(name),
        wiring.tld_referral(name),
        wiring.key_answer(name, wiring.zone_keys()),
    ]


@needs_tree
def test_the_zones_own_hop_carries_the_clients_list_copied_forward():
    """§4.2.2.2: a non-validating recursive resolver copies the downstream validator's list.

    §4.2¶3's "the zone for which the server is authoritative" says the copy belongs
    at the zone's own server and nowhere earlier: the root that merely routes a
    DNSKEY question has no use for zone.test.'s KSK numbers, and §7¶2 warns what a
    listener can infer from a list. So the referral hops carry nothing and the
    authoritative hop carries the client's.
    """
    events = _keytag_walk(
        "zone.test.", DNSKEY, responses=_dnskey_script(), client_key_tags=(111, 222)
    )
    queries = wiring._queries(events)
    assert [str(q.entry.zone) for q in queries] == [".", "test.", "zone.test."]
    assert queries[0].extra_edns_options == ()
    assert queries[1].extra_edns_options == ()
    assert key_tag_lists(queries[2].extra_edns_options) == ((111, 222),)


@needs_tree
def test_a_validating_server_sends_two_lists_own_first_when_they_differ():
    """§4.2.2.1¶2, transmitted shape and all: the RFC's own example is (own, client)."""
    own = tuple(r.rdata.key_tag for r in wiring.ds_zone() if int(r.rtype) == DS)
    events = _keytag_walk(
        "zone.test.",
        DNSKEY,
        responses=_dnskey_script(),
        anchors=(wiring._anchor(),),
        client_key_tags=(19036, 34567),
    )
    zone_hop = next(q for q in wiring._queries(events) if str(q.entry.zone) == "zone.test.")
    lists = key_tag_lists(zone_hop.extra_edns_options)
    assert lists == (own, (19036, 34567))


@needs_tree
def test_identical_lists_travel_once():
    """§4.2.2.1¶2 forwards both only when the client's "differs from its own"."""
    own = tuple(r.rdata.key_tag for r in wiring.ds_zone() if int(r.rtype) == DS)
    events = _keytag_walk(
        "zone.test.",
        DNSKEY,
        responses=_dnskey_script(),
        anchors=(wiring._anchor(),),
        client_key_tags=own,
    )
    zone_hop = next(q for q in wiring._queries(events) if str(q.entry.zone) == "zone.test.")
    assert key_tag_lists(zone_hop.extra_edns_options) == (own,)


@needs_tree
def test_the_validator_asks_its_chain_questions_with_its_own_list():
    """§4.2.2.1¶1 "its DNSKEY queries", §4.2¶3's sources per zone, §4.2¶2's gate for the DS.

    The secure descent fetches three DNSKEYs: the root's earns the anchor's tag,
    and the two below earn the DS each referral carried -- tags learned from
    exactly the two places §4.2¶3 admits. The one DS query of the §5.2¶6-shaped
    script carries nothing: it is not a DNSKEY query, and §4.2¶2's MUST NOT is the
    option's only truly universal rule.
    """
    name = "bob.sub.zone.test."
    proof = wiring._signed(
        "zone.test.",
        "sub.zone.test.",
        DnsRType.NSEC,
        [wiring._nsec("www.zone.test.", [int(DnsRType.NS)])],
        "zone",
    )
    script = [
        wiring.root_referral(name),
        wiring.tld_referral(name),
        wiring.zone_referral_sub(name, with_proof=False),
        wiring.nxdomain(name, [wiring.soa("sub.zone.test.")]),
        wiring.key_answer(".", wiring.root_keys()),
        wiring.key_answer("test.", wiring.tld_keys()),
        wiring.key_answer("zone.test.", wiring.zone_keys()),
        wiring.ds_nodata("zone.test.", proof),
    ]
    events = _keytag_walk(name, int(DnsQType.AAAA), responses=script, anchors=(wiring._anchor(),))
    helpers = wiring._helpers(events)
    by_question = {str(q.questions[0].name): q for q in helpers}
    assert set(by_question) >= {".", "test.", "zone.test.", "sub.zone.test."}
    root_tag = (wiring._anchor().key_tag,)
    test_tags = tuple(r.rdata.key_tag for r in wiring.ds_test() if int(r.rtype) == DS)
    zone_tags = tuple(r.rdata.key_tag for r in wiring.ds_zone() if int(r.rtype) == DS)
    assert key_tag_lists(by_question["."].extra_edns_options) == (root_tag,)
    assert key_tag_lists(by_question["test."].extra_edns_options) == (test_tags,)
    assert key_tag_lists(by_question["zone.test."].extra_edns_options) == (zone_tags,)
    assert by_question["sub.zone.test."].extra_edns_options == ()


def test_the_walk_reads_the_initiating_packets_instances_into_one_copy():
    """resolve() lifts the client packet's edns-key-tag option(s), §4.2.2.2's quarry.

    The walk starts from the initiating packet exactly as it lifts the CD bit, and
    a client that sent two instances (two validators' lists, or one client being
    pedantic about §4.2.2.1¶2's shape on its *own* DNSKEY query) arrives flattened:
    upstream of a recursive server that validates nothing, whose copy says only
    "these are the tags the one below me knows".
    """
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    seen = []

    async def fake_network(entry, questions, extra_qtypes=(), edns_options=()):
        seen.append((str(entry.zone), tuple(edns_options)))
        zone = str(entry.zone)
        if zone == ".":
            return wiring.root_referral("zone.test.")
        if zone == "test.":
            return wiring.tld_referral("zone.test.")
        return wiring.key_answer("zone.test.", wiring.zone_keys())

    resolver._send_for_entry = fake_network
    query = Query(questions=[DnsQuestion(DomainName("zone.test."), DNSKEY, IN)])
    query.add_edns(
        1232,
        options=[key_tag_option([111, 222]), key_tag_option([111, 333])],
        flags=EDNS_DO_BIT,
    )
    asyncio.run(resolver.resolve(query))

    assert [hop for hop, _ in seen] == [".", "test.", "zone.test."]
    assert seen[0][1] == ()
    assert seen[1][1] == ()
    assert key_tag_lists(seen[2][1]) == ((111, 222, 333),)


def test_the_server_never_answers_with_the_option():
    """§4.3¶2: "A responder MUST NOT include the edns-key-tag option in any DNS response."

    The clause reaches both of this server's mouths: the one above is a MUST NOT on
    any responder, and §4.2.2.1¶5 says the same to a validating recursive server
    about its final response. The reply OPT is built from the response's own news
    (NSID asked, MQTYPE answered, EDE owed), so the received list is read for the
    upstream leg and dropped here -- and dropped without FORMERR, which is the
    choice `_edns_options_or_error`'s docstring records for a malformed instance.
    """
    request = Query(questions=[DnsQuestion(DomainName("zone.test."), DNSKEY, IN)])
    request.add_edns(1232, options=[key_tag_option([1, 2])], flags=EDNS_DO_BIT)
    server = DnsServer.__new__(DnsServer)
    server.nsid = None
    assert all(option.code != KEY_TAG_OPTION_CODE for option in server._reply_options(request))
