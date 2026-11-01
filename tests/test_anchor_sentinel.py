"""RFC 8509: the sentinel's two questions, answered at the serving edge.

The document is a questionnaire for a validating resolver's own trust-anchor
store. An operator (or, during a KSK ceremony, §4.3's test harness) queries
``root-key-sentinel-is-ta-20326.`` and ``root-key-sentinel-not-ta-20326.``
and reads the answers as yes/no about whether key tag 20326 is in the store
right now: §2.2¶4's table returns the original answer when the label's claim
matches reality and §2.2¶5's SERVFAIL with an empty Answer Section when it
does not. The mechanism exists because a ceremony is exactly when a resolver
that cannot see its own store becomes dangerous -- roadmap row 157's
"the root is 8509's own sentinel; a validator that cannot roll fails at the
next KSK ceremony".

Everything the document makes exact, these tests make exact: the five-digit
zero-padded tag (§2.1¶9 -- a label that misses the precise shape is an
ordinary name, including the real ceremonies' ten-digit key-identifier
labels, which §2 as written does not special-process and this package does
not silently widen); the six preconditions (§2.1¶2-¶7, each with its own
inertia test); the AddPend/Revoked exclusion (§2.2¶2, read through RFC 9718
§2.2¶7's windows, the shape this package's store keeps); the root-zone
scoping (§2.2¶2's "root zone KSK"); and the empty-Answer shape of a refusal
(§2.2¶5) beside the echoed question the client matches on (RFC 5452 §9.1).

``namespy/anchors.py`` holds the parsing and the store question; the table
is enforced at :meth:`namespy.server.DnsServer._sentinel_gate`, and the
integration cases below drive it through the same harness the rest of the
server's rules use.
"""

import datetime

import test_server as srv

from namespy.anchors import (
    SENTINEL_IS_TA_LABEL,
    SENTINEL_NOT_TA_LABEL,
    TrustAnchor,
    sentinel_expectation,
    trusted_anchor_tags,
)
from namespy.cache import MemoryDnsCache
from namespy.enums import DnsQClass, DnsQR, DnsQType, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import EDNS_DO_BIT, DnsQuestion, DnsRecord, Query, Response
from namespy.resolver import RecursiveResolver

TRUSTED_TAG = 20326  # the current root KSK's tag, as RFC 9718's document gives it
ABSENT_TAG = 42  # 8509 §2.1¶9's own example number, zero-padded by its rule


def anchor(tag: int = TRUSTED_TAG, *, zone: str = ".", **window) -> TrustAnchor:
    fields = {"digest_type": 2, "digest": bytes(32), "algorithm": 8}
    fields.update(window)
    return TrustAnchor(zone=zone, key_tag=tag, **fields)


# ------------------------------------------------------------------ §2 labels


def test_the_two_labels_parse_to_the_question_they_ask():
    assert sentinel_expectation(DomainName(f"{SENTINEL_IS_TA_LABEL}-20326.")) == (True, 20326)
    assert sentinel_expectation(DomainName(f"{SENTINEL_NOT_TA_LABEL}-00042.")) == (False, 42)


def test_the_query_is_case_insensitive_like_every_other_dns_name():
    assert sentinel_expectation(DomainName("ROOT-KEY-SENTINEL-IS-TA-20326.")) == (True, 20326)


def test_five_digit_padding_is_the_precise_specification_and_the_only_one():
    """§2.1¶9, quoted in full force: a label missing the exact shape "should be
    handled as any other label and not according to Section 2.2". The
    ten-digit case is not hypothetical -- the real ceremony names encoded a
    32-bit key identifier, which is not this document's 16-bit key tag, and
    a generous parser would be processing a different protocol than the one
    this document specifies."""
    assert sentinel_expectation(DomainName(f"{SENTINEL_IS_TA_LABEL}-42.")) is None
    assert sentinel_expectation(DomainName(f"{SENTINEL_IS_TA_LABEL}-000420.")) is None
    assert sentinel_expectation(DomainName("root-key-sentinel-is-ta-0208502326.")) is None
    assert sentinel_expectation(DomainName(f"{SENTINEL_IS_TA_LABEL}-abcde.")) is None
    assert sentinel_expectation(DomainName("root-key-sentinel-is-ta.")) is None  # no hyphen/tag
    assert sentinel_expectation(DomainName("root-key-sentinel-is-ta-65536.")) == (True, 65536)
    # ...and 65536 is legal to ASK (five digits, decimal) and impossible to
    # trust (no key tag reaches it), which is the table's not-trusted column
    # rather than a parse failure -- exercised by the gate tests below.


def test_only_the_leftmost_label_asks():
    """§2.1¶7: the pattern is about the leftmost label of the original QNAME."""
    inner = f"{SENTINEL_IS_TA_LABEL}-20326"
    assert sentinel_expectation(DomainName(f"www.{inner}.")) is None
    # The sentinel may live anywhere in the tree -- under the root or inside
    # a zone -- as long as the leftmost label is the question.
    assert sentinel_expectation(DomainName(f"{inner}.t.example.")) == (True, TRUSTED_TAG)


def test_the_root_itself_and_a_trailing_hyphen_are_ordinary():
    assert sentinel_expectation(DomainName(".")) is None
    assert sentinel_expectation(DomainName(f"{SENTINEL_IS_TA_LABEL}-")) is None


# ------------------------------------------------------- §2.2¶2: the store, live now


def test_the_store_answers_for_the_root_zone_and_for_the_live_window():
    past = datetime.datetime(2019, 1, 12, tzinfo=datetime.UTC)
    future = datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC)
    anchors = (
        anchor(),  # open window: trusted now
        anchor(19036, valid_until=past),  # expired: §2.2¶2's Revoked equivalent
        anchor(30000, valid_from=future),  # pre-published: the AddPend equivalent
        anchor(TRUSTED_TAG, zone="example."),  # right tag, wrong zone: §2.2¶2 is root's
    )
    assert trusted_anchor_tags(anchors) == frozenset({TRUSTED_TAG})
    # The window is a moment's property: the expired anchor was live once.
    then = datetime.datetime(2018, 1, 1, tzinfo=datetime.UTC)
    assert TRUSTED_TAG in trusted_anchor_tags(anchors, moment=then)
    assert 19036 in trusted_anchor_tags(anchors, moment=then)


# ------------------------------------------------------------ §2.2: the table at the edge


def secure_answer(packet, *, ad=True, bogus=False, rdata=bytes([203, 0, 2, 70])):
    """A resolver-shaped verdict: the answer plus the AD bit validation stamps.

    ``bogus`` sets the marker the walk carries on refused answers; the gate
    reads both before RFC 6840 §5.8's courtesy strip has had its say.
    """
    name = packet.questions[0].name
    response = Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        AD=ad,
        RD=packet.RD,
        questions=list(packet.questions),
        answers=[DnsRecord(name, DnsRType.A, DnsQClass.IN, 300, rdata=rdata)],
    )
    if bogus:
        response.dnssec_bogus = True
    return response


async def ask(name, *, qtype=DnsQType.A, cd=False, anchors=(), reply=None):
    """Serve one query past a hand-stamped anchor store; return the reply."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    resolver.trust_anchors = tuple(anchors)
    server, _resolver, transport = srv.make_server(resolver)
    await srv.answer_with(_resolver, reply if reply is not None else secure_answer)
    query = Query(
        ID=0xABCD,
        CD=cd,
        questions=[DnsQuestion(name, qtype, DnsQClass.IN)],
    ).add_edns(1232, flags=EDNS_DO_BIT)
    server.datagram_received(bytes(query), srv.ADDR)
    await srv.drain(server)
    return transport.replies[0]


IS_TA = f"{SENTINEL_IS_TA_LABEL}-{TRUSTED_TAG}."
IS_TA_ABSENT = f"{SENTINEL_IS_TA_LABEL}-{ABSENT_TAG:05d}."
NOT_TA = f"{SENTINEL_NOT_TA_LABEL}-{ABSENT_TAG:05d}."
NOT_TA_TRUSTED = f"{SENTINEL_NOT_TA_LABEL}-{TRUSTED_TAG}."


# §2.2¶4's table, four cells, each asked of a store that knows one tag.
#
#   Label      | Key is trusted          | Key is not trusted
#   ------------------------------------------------------------------
#   is-ta      | return original answer  | return SERVFAIL
#   not-ta     | return SERVFAIL         | return original answer


async def test_is_ta_of_a_trusted_tag_gets_the_original_answer():
    reply = await ask(DomainName(IS_TA), anchors=(anchor(),))
    assert reply.RCODE == DnsResponseCode.NO_ERROR
    assert len(reply.answers) == 1
    assert reply.AD, "the diagonal cell returns the answer as the walk settled it"


async def test_is_ta_of_an_untrusted_tag_is_the_first_off_diagonal():
    reply = await ask(DomainName(IS_TA_ABSENT), anchors=(anchor(),))
    assert reply.RCODE == DnsResponseCode.SERVER_FAILURE
    assert reply.answers == []
    assert reply.ANCOUNT == 0


async def test_not_ta_of_a_trusted_tag_is_the_second_off_diagonal():
    reply = await ask(DomainName(NOT_TA_TRUSTED), anchors=(anchor(),))
    assert reply.RCODE == DnsResponseCode.SERVER_FAILURE
    assert reply.answers == []


async def test_not_ta_of_an_untrusted_tag_gets_the_original_answer():
    reply = await ask(DomainName(NOT_TA), anchors=(anchor(),))
    assert reply.RCODE == DnsResponseCode.NO_ERROR
    assert len(reply.answers) == 1


async def test_a_refusal_keeps_the_shape_a_client_matches_on():
    """§2.2¶5 empties the Answer Section; RFC 5452 §9.1 keeps the question --
    a refusal whose question is gone is a packet no client can attribute.
    And no refusal asserts: the AD bit went with the answer it described."""
    reply = await ask(DomainName(IS_TA_ABSENT), anchors=(anchor(),))
    assert [str(q.name) for q in reply.questions] == [str(DomainName(IS_TA_ABSENT))]
    assert reply.RCODE == DnsResponseCode.SERVER_FAILURE
    assert not reply.AD


# ----------------------------------------------------- §2.1: the inertia of preconditions


async def test_a_cd_query_asks_for_the_data_not_the_diagnosis():
    """§2.1¶4: with CD set the client validates for itself, and §2.1¶8's
    MUST NOT alter is absolute -- even an off-diagonal label passes through."""
    reply = await ask(DomainName(IS_TA_ABSENT), cd=True, anchors=(anchor(),))
    assert reply.RCODE == DnsResponseCode.NO_ERROR
    assert len(reply.answers) == 1


async def test_the_mechanism_speaks_only_a_and_aaaa():
    """§2.1¶5. A TXT under a mismatching sentinel label is just a TXT query."""
    reply = await ask(
        DomainName(IS_TA_ABSENT),
        qtype=DnsQType.TXT,
        anchors=(anchor(),),
        reply=lambda p: secure_answer(p, rdata=b"\x03abc"),
    )
    assert reply.RCODE == DnsResponseCode.NO_ERROR


async def test_an_unvalidated_answer_gives_the_mechanism_nothing_to_answer():
    """§2.1¶2-¶3: the questionnaire is about a validating resolver's store,
    and an answer that never passed through validation (no AD stamped, or
    stamped bogus) is not a Secure result. The gate stays shut; the ordinary
    answer goes out."""

    def unvalidated(packet):
        return secure_answer(packet, ad=False)

    def refused(packet):
        return secure_answer(packet, bogus=True)

    plain = await ask(DomainName(IS_TA_ABSENT), anchors=(anchor(),), reply=unvalidated)
    assert plain.RCODE == DnsResponseCode.NO_ERROR
    bogus = await ask(DomainName(IS_TA), anchors=(anchor(),), reply=refused)
    assert bogus.RCODE == DnsResponseCode.NO_ERROR


async def test_an_empty_store_answers_the_questionnaire_with_refusals():
    """A store that trusts no tags still answers §2.2's questions -- with the
    not-trusted column, everywhere. ``is-ta`` of any tag refuses because the
    store holds nothing to match; the true inertness (§2.1¶2's precondition
    failing before the table speaks) belongs to validation, not to the
    store's size, and is pinned by the unvalidated-answer test above."""
    reply = await ask(DomainName(IS_TA), anchors=())
    assert reply.RCODE == DnsResponseCode.SERVER_FAILURE
    calm = await ask(DomainName(NOT_TA), anchors=())
    assert calm.RCODE == DnsResponseCode.NO_ERROR


async def test_the_store_is_read_now_not_forever():
    """§2.2¶2's "could currently be used": an anchor whose window closed is
    as untrusted as one never acquired -- an is-ta asking for it refuses,
    and the ceremony's other question about the same tag answers normally."""
    expired = anchor(valid_until=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
    refuse = await ask(DomainName(IS_TA), anchors=(expired,))
    assert refuse.RCODE == DnsResponseCode.SERVER_FAILURE
    calm = await ask(DomainName(NOT_TA_TRUSTED), anchors=(expired,))
    assert calm.RCODE == DnsResponseCode.NO_ERROR


async def test_a_ten_digit_ceremony_name_is_an_ordinary_query_as_written():
    """The precise-specification rule, end to end: the label shape the real
    ceremonies used carries a key identifier, not §2's key tag, and §2.1¶9
    sends it to ordinary processing whatever a generous parser might sniff."""
    reply = await ask(DomainName("root-key-sentinel-is-ta-0208502326."), anchors=(anchor(),))
    assert reply.RCODE == DnsResponseCode.NO_ERROR
    assert len(reply.answers) == 1


async def test_an_above_range_tag_is_askable_and_untrustable():
    """65536 has no key tag to match (16 bits), so is-ta-65536 always refuses
    and not-ta-65536 always answers -- the table, arithmetic, and no parse
    drama in between."""
    refuse = await ask(DomainName(f"{SENTINEL_IS_TA_LABEL}-65536."), anchors=(anchor(),))
    assert refuse.RCODE == DnsResponseCode.SERVER_FAILURE
    calm = await ask(DomainName(f"{SENTINEL_NOT_TA_LABEL}-65536."), anchors=(anchor(),))
    assert calm.RCODE == DnsResponseCode.NO_ERROR
