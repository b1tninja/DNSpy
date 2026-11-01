"""RFC 8145 §5: the Key Tag query -- a NULL question that says who validates.

The mechanism is telemetry with a question-name: a validating resolver that
fetches a trust-anchor zone's DNSKEY also asks, of the same authority, a
NULL/IN query whose first label spells the anchor key tags -- ``_ta-4444.``
for tag 17476 (§5.1¶3), four-digit lowercase hex (§5.1¶4), sorted smallest
to largest when several (§5.1¶5, restated §5.3.1¶4). The answer means
nothing to the asker; §5.3¶1 is what it is for -- the zone operator "MAY log
or otherwise collect the Key Tag values", which is how an operator learns
whether anyone out there still trusts the old KSK before withdrawing it.

§4 (the edns-key-tag option on DNSKEY queries, both lists of §4.2.2.1
riding side by side) shipped long before this file -- ``test_edns_keytag.py``
holds it; what was missing was §5, the query the DNSKEY fetch triggers. The
trigger lives at ``RecursiveResolver._maybe_key_tag_signal``, fires as a
background ``resolve`` (the full path, because §5.2¶5 asks the response be
cached "just as it would any other response"), and keeps §5.2's three doors:
non-validating resolvers MUST NOT (§5.2¶4), non-anchor zones SHOULD NOT
(§5.2¶3), and warm caches should not re-ask at all (¶5).

The server side is §5.3¶2's quiet sentence -- "An authoritative name server
MUST generate an appropriate response" -- which this fixture already does by
*not* refusing: NULL is a queryable Meta-TYPE (RFC 2231 §2.4's own rule the
server's NXNAME gate of RFC 9824 §3.5 deliberately does not extend to), so
the ``_ta-`` name resolves or not exactly as the zone says. And §4.3¶2's
MUST NOT -- no edns-key-tag ever rides a response -- gets pinned against
the one server that might have been tempted to echo it.
"""

import asyncio
import datetime

import pytest
import test_server as srv

from namespy.anchors import TrustAnchor, key_tag_query_name
from namespy.cache import MemoryDnsCache
from namespy.edns import KEY_TAG_OPTION_CODE, key_tag_option
from namespy.enums import DnsQClass, DnsQR, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, Query, Response
from namespy.resolver import RecursiveResolver


def anchor(tag: int = 20326, *, zone: str = ".", **window) -> TrustAnchor:
    fields = {"digest_type": 2, "digest": bytes(32), "algorithm": 8}
    fields.update(window)
    return TrustAnchor(zone=zone, key_tag=tag, **fields)


# ------------------------------------------------------------- §5.1: the QNAME


def test_the_documents_own_examples_are_the_arithmetic():
    assert str(key_tag_query_name(".", [17476])) == "_ta-4444."  # §5.1¶3
    assert str(key_tag_query_name(".", [999])) == "_ta-03e7."  # §5.1¶4
    # §5.1¶5's three-anchor example, fed unsorted to prove ¶5's sort:
    name = key_tag_query_name("example.com.", [43547, 1589, 31406])
    assert str(name) == "_ta-0635-7aae-aa1b.example.com."


def test_duplicates_collapse_and_the_zone_may_arrive_as_a_name():
    assert str(key_tag_query_name(".", [17476, 17476])) == "_ta-4444."
    assert str(key_tag_query_name(DomainName("com."), [1])) == "_ta-0001.com."


def test_no_encoding_for_no_tags_and_none_for_tags_that_are_not_16_bits():
    """A key tag is Appendix B's 16-bit arithmetic; §5.1's label only
    encodes numbers that fit, and an empty list has no question to ask."""
    with pytest.raises(ValueError, match="empty tag list"):
        key_tag_query_name(".", [])
    with pytest.raises(ValueError, match="16-bit"):
        key_tag_query_name(".", [70000])


# --------------------------------------------------- §5.2: the trigger and its doors


class CapturedResolve:
    """Swaps the resolver's recursive door for a list of what rode through it.

    The returned future never completes until the test says so, keeping the
    signal "in flight" for the dedup case; ``release`` lets it settle.
    """

    def __init__(self, resolver):
        self.queries = []
        self.gate = asyncio.Event()
        resolver.resolve = self  # the background task reads the instance attr

    async def __call__(self, dns_packet):
        self.queries.append(dns_packet)
        await self.gate.wait()
        return

    def release(self):
        self.gate.set()


def make_validator(*anchors):
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    resolver.trust_anchors = tuple(anchors)
    return resolver


DNSKEY_DOT = [DnsQuestion(DomainName("."), DnsRType.DNSKEY, DnsQClass.IN)]


async def test_a_dnskey_query_for_an_anchor_zone_asks_the_stores_question():
    resolver = make_validator(anchor(20326))
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal(DNSKEY_DOT)
    await asyncio.sleep(0)
    assert len(capture.queries) == 1
    question = capture.queries[0].questions[0]
    assert str(question.name) == "_ta-4f66."  # 20326 == 0x4f66, four hex digits
    assert int(question.qtype) == int(DnsRType.NULL)  # §5.1¶1: NULL...
    assert int(question.qclass) == int(DnsQClass.IN)  # ...and IN
    capture.release()


async def test_a_validating_resolver_without_anchors_is_the_must_not():
    resolver = make_validator()
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal(DNSKEY_DOT)
    await asyncio.sleep(0)
    assert capture.queries == []  # §5.2¶4
    capture.release()


async def test_a_ds_learned_zone_gets_the_option_not_a_query():
    """§5.2¶3's SHOULD NOT, in the shape §4.2 already honors: the anchor
    covers "." -- a DNSKEY fetch for some other zone carries whatever tags
    §4.2.2.1 admits but originates no Key Tag query of its own."""
    resolver = make_validator(anchor(20326, zone="."))
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal(
        [DnsQuestion(DomainName("example."), DnsRType.DNSKEY, DnsQClass.IN)]
    )
    await asyncio.sleep(0)
    assert capture.queries == []
    capture.release()


async def test_not_every_question_is_a_trigger():
    resolver = make_validator(anchor(20326))
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal([DnsQuestion(DomainName("."), DnsRType.A, DnsQClass.IN)])
    resolver._maybe_key_tag_signal(
        [
            DnsQuestion(DomainName("."), DnsRType.DNSKEY, DnsQClass.IN),
            DnsQuestion(DomainName("."), DnsRType.DNSKEY, DnsQClass.IN),
        ]
    )
    await asyncio.sleep(0)
    assert capture.queries == []  # §5.1¶1's one-question form, §5.2¶1's qtype
    capture.release()


async def test_an_expired_anchor_is_not_the_trust_that_asks():
    """§5.2¶2: the tags are "of the trust anchor that will be used to
    validate" -- a window that closed validates with nothing."""
    resolver = make_validator(
        anchor(20326, valid_until=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
    )
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal(DNSKEY_DOT)
    await asyncio.sleep(0)
    assert capture.queries == []
    capture.release()


async def test_one_descent_signals_once_not_once_per_helper():
    """The in-flight set: the first signal's answer belongs to nobody, and
    telemetry counted twice says less than once."""
    resolver = make_validator(anchor(20326))
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal(DNSKEY_DOT)
    resolver._maybe_key_tag_signal(DNSKEY_DOT)
    await asyncio.sleep(0)
    assert len(capture.queries) == 1
    capture.release()


async def test_a_warm_cache_is_the_reuse_that_does_not_ask_again():
    """§5.2¶5, read as the instruction not to send: the response for the
    signal name is already held, so the descent stays silent on the wire."""
    resolver = make_validator(anchor(20326))

    class WarmCache:
        def get(self, name, qtype, qclass):
            return object()  # any entry is an entry for this purpose

    resolver.cache = WarmCache()
    capture = CapturedResolve(resolver)
    resolver._maybe_key_tag_signal(DNSKEY_DOT)
    await asyncio.sleep(0)
    assert capture.queries == []
    capture.release()


# ------------------------------------------------- §5.3¶2 + §4.3¶2: the other side


def _ta_nodata(packet):
    """The ordinary answer an authority gives a name it does not hold:
    NOERROR, no answers -- or NXDOMAIN; the server's part is not to invent
    a third thing for a Meta-TYPE question."""
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RD=packet.RD,
        questions=list(packet.questions),
    )


async def test_a_key_tag_query_gets_an_appropriate_response_not_a_refusal():
    """§5.3¶2: "An authoritative name server MUST generate an appropriate
    response to the Key Tag query... the response code is determined by
    whether the data is in the zone file or covered by wildcards." The
    fixture's walk says whatever the zone says -- what the server MUST NOT
    do is treat the question as unanswerable-in-principle the way RFC 9824
    §3.5¶2 makes NXNAME; NULL is queryable (RFC 2231 §2.4), and this gate
    guards the walk's verdict, not the type's name."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, _ta_nodata)
    query = Query(
        ID=0xABCD,
        questions=[DnsQuestion(DomainName("_ta-4444."), DnsRType.NULL, DnsQClass.IN)],
    )
    server.datagram_received(bytes(query), srv.ADDR)
    await srv.drain(server)

    reply = transport.replies[0]
    assert reply.RCODE != DnsResponseCode.FORMAT_ERROR
    assert reply.RCODE != DnsResponseCode.NOT_IMPLEMENTED
    assert reply.RCODE == DnsResponseCode.NO_ERROR  # whatever the zone said
    assert [str(q.name) for q in reply.questions] == ["_ta-4444."]
    assert reply.answers == []


async def test_the_nxname_door_stays_shut_on_its_own_type_alone():
    """The pair to the above: §5.3¶2's ordinary-ness is NULL's, not a general
    Meta-TYPE amnesty -- NXNAME still earns the FORMERR RFC 9824 demands,
    which is the boundary the two documents draw between them."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, _ta_nodata)
    query = Query(
        ID=0xABCD,
        questions=[DnsQuestion(DomainName("_ta-4444."), DnsRType.NXNAME, DnsQClass.IN)],
    )
    server.datagram_received(bytes(query), srv.ADDR)
    await srv.drain(server)
    assert transport.replies[0].RCODE == DnsResponseCode.FORMAT_ERROR


async def test_the_server_never_answers_with_a_key_tag_option():
    """§4.3¶2, the responder's one MUST NOT: "A responder MUST NOT include
    the edns-key-tag option in any DNS response." A server that echoed the
    client's list would answer a question the client asked the *authority*,
    and the walk reading it back would have one more number than §4.2¶3's
    two admitted sources can account for."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, _ta_nodata)
    query = Query(
        ID=0xABCD,
        questions=[DnsQuestion(DomainName("."), DnsRType.DNSKEY, DnsQClass.IN)],
    ).add_edns(1232, options=(key_tag_option([20326]),))
    server.datagram_received(bytes(query), srv.ADDR)
    await srv.drain(server)

    reply = transport.replies[0]
    assert KEY_TAG_OPTION_CODE not in {int(o.code) for o in reply.edns_options()}
