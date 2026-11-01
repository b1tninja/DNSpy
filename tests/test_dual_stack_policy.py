"""RFC 10001 §4.2: the recursive resolver that keeps both families in play.

BCP 91 is the successor to RFC 3901, and its §3 is a long catalogue of ways a
resolver can lose half the name space by betting on one address family --
§3.2's network conditions (a black-holed v6 route, a v4-degraded path) being
the ones a running resolver discovers the hard way. §4.2 translates that into
guidance for the recursive resolver, and two sentences of it reach into this
codebase:

*  ¶1: "every recursive DNS resolver SHOULD be dual-stack" -- which the walk
   answers with two sockets, and, since this increment, with a *policy*: the
   addresses of one SLIST entry are tried family-alternately, so a black-holed
   family costs one timeout rather than every timeout its addresses own
   (:func:`namespy.resolver._interleave_families`).
*  ¶4: a resolver answering recursive queries follows §4.1 ¶4's
   fragmentation-avoidance guidance analogously -- §4.1 ¶4: "IP fragmentation
   SHOULD be avoided" and "DNS-over-TCP MUST be available as a fallback
   option, instead of relying on fragmented UDP packets". For this server that
   lands as :meth:`namespy.server.DnsServer._fit_datagram`: a UDP answer is
   capped at what the client advertised (RFC 6891 §6.2.3), truncated back from
   the end of the datagram with TC set (RFC 1035 §6.2 ¶4, §4.2.1), never
   falling below the header, question, and OPT of RFC 6891 §7 ¶6 -- and the
   stream is never touched, because the stream *is* the fallback the TC bit
   promises.

What is deliberately not here: §4.2 ¶2-¶3's single-stack escape hatches
(PREF64 synthesis, forwarding to a dual-stack resolver) are deployment
configurations this library cannot observe, and RFC 6724's family *ranking*
arrives in §4.3 as guidance for *stub* resolvers, not for this walk. §5 ¶5's
forwarding-loop MUST is a rule about configurations, not about packets.

The server half drives the harness of :mod:`tests.test_server`; the resolver
half stubs :meth:`RecursiveResolver.query`, the seam beneath every send the
walk performs.
"""

import ipaddress

import test_server as srv

from namespy.cache import MemoryDnsCache
from namespy.edns import extended_errors_of
from namespy.enums import DnsQClass, DnsQR, DnsQType, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Response
from namespy.rdata import RData_TXT
from namespy.resolver import RecursiveResolver, SlistEntry, _interleave_families

V6A = ipaddress.IPv6Address("2001:db8::61")
V6B = ipaddress.IPv6Address("2001:db8::62")
V4A = ipaddress.IPv4Address("192.0.2.51")
V4B = ipaddress.IPv4Address("192.0.2.52")

ADDR = srv.ADDR


# ------------------------------------------------------- ¶1: both families in play


def test_a_blacked_out_family_costs_the_next_turn_not_the_whole_entry():
    """Glue order decides who leads; alternation decides no one is starved."""
    assert _interleave_families([V6A, V6B, V4A]) == [V6A, V4A, V6B]
    assert _interleave_families([V4A, V4B, V6A]) == [V4A, V6A, V4B]


def test_a_single_family_list_comes_out_as_it_went_in():
    """One family is not a partition -- an IPv4-only delegation is §4.1 ¶2's
    zone problem, and no reshuffling by the resolver can invent the family."""
    assert _interleave_families([V4A, V4B]) == [V4A, V4B]
    assert _interleave_families([V6A]) == [V6A]
    assert _interleave_families([]) == []


def test_raw_packed_octets_and_nonsense_sort_like_objects():
    """A belt seeded by hand may hold anything; the helper classifies, never edits.

    The two-octet entry is not dropped -- dropping is the send loop's call to
    make, in front of the log line that can say why; this function only owes a
    sensible order, and nonsense waits at the tail for exactly that.
    """
    v4_raw, v6_raw = V4A.packed, V6A.packed
    assert _interleave_families([v4_raw, v6_raw, V4B]) == [v4_raw, v6_raw, V4B]
    junk = b"\x01\x02"
    assert _interleave_families([junk, V4A, V6A]) == [V4A, V6A, junk]


async def test_the_send_loop_reaches_the_living_family_after_one_timeout():
    """The end-to-end shape of §3.2's fault: v6 black-holed, v4 up.

    With three addresses on one entry and the IPv6 transport answering nothing,
    sequential order spends two timeouts before the working family is asked;
    alternation spends one. The assertion is the timeout count, which is the
    only thing a partitioned network teaches the client, and it is one.
    """
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    seen: list = []
    sentinel = Response(ID=7, QR=DnsQR.RESPONSE)

    async def fake_query(questions, ns_record, addr_record, **kwargs):
        ip = ipaddress.ip_address(addr_record.rdata)
        seen.append(ip)
        return None if ip.version == 6 else sentinel

    resolver.query = fake_query
    entry = SlistEntry(DomainName("."), DomainName("ns.example."), [V6A, V6B, V4A])
    result = await resolver._send_for_entry(entry, [DnsQuestion(srv.HOST, DnsQType.A)])
    assert result is sentinel
    assert seen == [V6A, V4A]  # 2001:db8::62 never got asked; the answer arrived first


# ---------------------------------------------------- ¶4: no fragmented UDP answers


def big_txt_answer(packet, *, count=4, size=400, authority=0):
    """A resolver-shaped reply this server would be tempted to fragment.

    TXT records of 400-odd octets each: four of them clear RFC 1035 §4.2.1's
    512 for a legacy client and three clear the 1232 this build advertises,
    so every test below truncates for a reason it can name.
    """
    name = packet.questions[0].name

    def fat_blob(char: bytes) -> RData_TXT:
        # §3.3.14 caps one character-string at 255 octets (this codec says so),
        # and it should: the size tests want fat records, not illegal ones.
        blob = char * size
        return RData_TXT([blob[i : i + 200] for i in range(0, len(blob), 200)])

    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        questions=list(packet.questions),
        answers=[
            DnsRecord(name, DnsRType.TXT, DnsQClass.IN, 300, rdata=fat_blob(b"x"))
            for _ in range(count)
        ],
        nameservers=[
            DnsRecord(name, DnsRType.TXT, DnsQClass.IN, 300, rdata=fat_blob(b"n"))
            for _ in range(authority)
        ],
    )


async def test_a_legacy_client_gets_512_octets_and_a_tc_bit_not_a_fragment():
    """RFC 1035 §4.2.1's ceiling still rules the client that sent no OPT.

    Pre-increment this datagram left the socket at 1.6 kilobytes: fragmented
    or lost, and the TC bit nowhere -- the client's only clue that TCP holds
    more was a timeout. Now: inside 512, TC set, the question echoed, and at
    least one record of the answer section actually delivered.
    """
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: big_txt_answer(p, count=4))
    server.datagram_received(bytes(srv.query_packet()), ADDR)
    await srv.drain(server)

    data, _addr = transport.sent[0]
    assert len(data) <= 512
    reply = DnsPacket.parse(data)[0]
    assert reply.TC
    assert reply.questions[0].name == srv.HOST
    assert 0 < len(reply.answers) < 4
    assert reply.ANCOUNT == len(reply.answers)
    assert reply.opt() is None  # §7 ¶2: truncation does not smuggle EDNS past §7's rule


async def test_an_extended_client_gets_what_it_advertised_and_keeps_its_opt():
    """§6.2.3 ¶1's advertised size is the cap; §7 ¶6 keeps the OPT on the floor."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: big_txt_answer(p, count=4))
    server.datagram_received(bytes(srv.query_packet().add_edns(1232)), ADDR)
    await srv.drain(server)

    data, _addr = transport.sent[0]
    assert len(data) <= 1232
    reply = DnsPacket.parse(data)[0]
    assert reply.TC
    assert reply.opt() is not None
    assert 0 < len(reply.answers) < 4


async def test_the_advertised_number_under_512_is_measured_at_512():
    """§6.2.3 ¶2: "Values lower than 512 MUST be treated as equal to 512"."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: big_txt_answer(p, count=1))  # ~450 octets
    server.datagram_received(bytes(srv.query_packet().add_edns(128)), ADDR)
    await srv.drain(server)

    reply = transport.replies[0]
    assert not reply.TC  # the answer fit the floor; the stingy number changes nothing
    assert len(reply.answers) == 1


async def test_the_authority_section_gives_way_before_the_answer_does():
    """§6.2 ¶4's direction, and the guarantee its second sentence buys.

    "Truncation should start at the end of the response and work forward in
    the datagram. Thus if there is any data for the authority section, the
    answer section is guaranteed to be unique." Three fat records in each
    section and a 1232-octet client: the authority empties entirely and the
    answer never opens its mouth -- the client that retries over TCP at least
    knows exactly which section was whole.
    """
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: big_txt_answer(p, count=2, authority=3))
    server.datagram_received(bytes(srv.query_packet().add_edns(1232)), ADDR)
    await srv.drain(server)

    data, _addr = transport.sent[0]
    reply = DnsPacket.parse(data)[0]
    assert len(data) <= 1232
    assert reply.TC
    assert len(reply.answers) == 2
    assert len(reply.nameservers) == 0
    assert reply.NSCOUNT == len(reply.nameservers)


async def test_the_floor_of_a_truncated_response_is_header_question_and_opt():
    """§7 ¶6: "The minimal response MUST be the DNS header, question section,
    and an OPT record. This MUST also occur when a truncated response ... is
    returned." One 600-octet record clears every cap there is; what survives
    is the floor, TC lit, ANCOUNT honestly zero. The advertised 128 doubles
    as §6.2.3 ¶2's floor case: even a client begging for 128 is owed the 512
    and the OPT it asked EDNS for.
    """
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: big_txt_answer(p, count=1, size=600))
    server.datagram_received(bytes(srv.query_packet().add_edns(128)), ADDR)
    await srv.drain(server)

    data, _addr = transport.sent[0]
    reply = DnsPacket.parse(data)[0]
    assert reply.TC
    assert len(reply.answers) == 0
    assert reply.ANCOUNT == 0
    assert reply.questions[0].name == srv.HOST
    assert reply.opt() is not None
    assert len(data) <= 512


async def test_the_explanation_goes_before_any_record_does():
    """RFC 8914 §3's order kept across the two mechanisms: EDE first, data second.

    The answer is Bogus (so an EDE rides) and oversized together with its
    records: :meth:`_keep_explanation_inside_advertised_size` drops the
    explanation -- "before dropping other data from packets" -- and only then
    does :meth:`_fit_datagram` eat records. Both halves run on the same
    advertised number; the test pins that the cheap thing goes first.
    """
    server, resolver, transport = srv.make_server()

    def bogus_big(p):
        reply = big_txt_answer(p, count=3)
        reply.RCODE = 2  # answer gone wrong; the EDE below explains
        reply.dnssec_bogus = True
        return reply

    await srv.answer_with(resolver, bogus_big)
    server.datagram_received(bytes(srv.query_packet().add_edns(1232)), ADDR)
    await srv.drain(server)

    data, _addr = transport.sent[0]
    reply = DnsPacket.parse(data)[0]
    assert len(data) <= 1232
    assert reply.TC
    assert extended_errors_of(reply.edns_options()) == ()  # the first thing given up
    assert 0 < len(reply.answers) < 3


class FakeChannel:
    """The stream side of :meth:`DnsServer._reply`: records, never sizes."""

    keepalive = None

    def __init__(self):
        self.sent: list = []

    def send(self, data):
        self.sent.append(bytes(data))


async def test_the_stream_never_truncates_because_the_stream_is_the_promise():
    """TC is a promise that the rest lives on TCP (§4.1 ¶4's fallback); a server
    that truncated the *stream* would break the promise it just made. The
    advertised size is "the largest UDP payload" (RFC 6891 §6.2.3 ¶1) -- a
    2-octet-framed conversation answers to no such number, so a 128-octet
    advertisement arrives on a stream, and all four records leave on it."""
    server, _resolver, _transport = srv.make_server()
    request = srv.query_packet().add_edns(128)
    channel = FakeChannel()
    server._reply(big_txt_answer(request, count=4), ADDR, request=request, channel=channel)

    data = channel.sent[0]
    assert len(data) > 128
    reply = DnsPacket.parse(data)[0]
    assert not reply.TC
    assert len(reply.answers) == 4
