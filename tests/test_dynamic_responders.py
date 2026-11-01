"""Dynamic responders and the reflexive zone (increments U1 + U2).

The hook's contract is that bound answers leave through the same egress door
as resolved ones, so most of these tests assert inheritance rather than
behavior: the OPT the client asked for, the CD echo of RFC 4035 3.2.2, the
empty MQTYPE-Response that says "supported, not combined", the truncation a
fat answer cannot escape. The reflex responder gets its own class because its
promises are the interesting ones: it answers only what the socket saw, and
says NODATA rather than invent the rest.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_server as srv

from namespy.enums import (
    DnsQType,
    DnsResponseCode,
)
from namespy.mqtype import (
    mqtype_answered_qtypes,
    mqtype_query_option,
    mqtype_supported,
)
from namespy.names import DomainName
from namespy.packet import EDNS_DO_BIT, DnsPacket, DnsRecord
from namespy.rdata import RData_TXT
from namespy.server import (
    REFLEXIVE_NAME,
    DynamicResponse,
    whoami_responder,
)

WHOAMI = DomainName("whoami.")
PEER4 = ("203.0.113.7", 51111)
PEER6 = ("fe80::1", 60000)


class FakeChannel:
    """The stream side of the egress door: one send, a keepalive, no socket."""

    def __init__(self):
        self.sent = []
        self.keepalive = None

    def send(self, wire):
        self.sent.append(bytes(wire))


def _never():
    """A resolver stub that fails the test if the network door is opened."""

    async def no_network(_packet):
        raise AssertionError("a bound name must not reach the network")

    return no_network


def _txt(name, sentence):
    return DnsRecord(name, DnsQType.TXT, ttl=0, rdata=RData_TXT([sentence]))


def _bound_server(**kwargs):
    """A server with whoami bound and the network door welded shut."""
    server, resolver, transport = srv.make_server(**kwargs)
    resolver.resolve = _never()
    server.bind(REFLEXIVE_NAME, whoami_responder)
    return server, resolver, transport


class TestHookContract:
    async def test_bound_answer_echoes_id_question_and_sets_aa(self):
        server, _resolver, transport = _bound_server()
        query = srv.query_packet(name=WHOAMI, qtype=DnsQType.A, packet_id=0x4242)
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        reply = transport.replies[0]
        assert reply.ID == 0x4242
        assert reply.questions[0].name == WHOAMI
        assert reply.AA is True, "this server is the authority it claims to be"
        assert int(reply.RCODE) == int(DnsResponseCode.NO_ERROR)

    async def test_declining_handler_falls_through_to_the_resolver(self):
        server, resolver, transport = srv.make_server()
        reached = []

        def sentinel(packet):  # sync: answer_with's reply_factory contract
            reached.append(packet)
            return srv.stub_reply(packet)

        await srv.answer_with(resolver, sentinel)
        server.bind(WHOAMI, lambda _request: None)
        server.datagram_received(bytes(srv.query_packet(name=WHOAMI)), PEER4)
        await srv.drain(server)
        assert reached, "None means 'not mine': the network must be asked"
        assert transport.replies, "and the client still gets the resolver's answer"

    async def test_raising_handler_answers_servfail_without_recursing(self):
        # The operator bound this name precisely so the network would never
        # be asked; the substitute breaking is not a licence to consult the
        # original.
        server, _resolver, transport = _bound_server()
        server.bind(DomainName("boom."), lambda _request: 1 / 0)
        query = srv.query_packet(name=DomainName("boom."))
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        reply = transport.replies[0]
        assert int(reply.RCODE) == int(DnsResponseCode.SERVER_FAILURE)
        assert reply.questions, "even a failure echoes the question"

    async def test_dynamic_response_carries_its_own_rcode(self):
        server, _resolver, transport = srv.make_server()
        server.resolver.resolve = _never()
        server.bind(
            DomainName("gone."),
            lambda _request: DynamicResponse(rcode=DnsResponseCode.NAME_ERROR),
        )
        server.datagram_received(bytes(srv.query_packet(name=DomainName("gone."))), PEER4)
        await srv.drain(server)
        assert int(transport.replies[0].RCODE) == int(DnsResponseCode.NAME_ERROR)

    async def test_first_non_declining_binding_wins(self):
        server, _resolver, transport = srv.make_server()
        server.bind(WHOAMI, lambda _request: None)  # declines
        server.bind(WHOAMI, lambda _request: [])  # answers NODATA
        server.bind(WHOAMI, whoami_responder)  # never consulted
        server.resolver.resolve = _never()
        server.datagram_received(bytes(srv.query_packet(name=WHOAMI)), PEER4)
        await srv.drain(server)
        reply = transport.replies[0]
        assert int(reply.RCODE) == int(DnsResponseCode.NO_ERROR)
        assert reply.AA is True
        assert reply.answers == [], "the second binding answered nothing, deliberately"

    async def test_exact_binding_ignores_subdomains_suffix_binding_catches_them(self):
        server, _resolver, transport = srv.make_server()
        fell = []

        async def fallthrough(packet):
            fell.append(str(packet.questions[0].name))
            return srv.stub_reply(packet)

        server.resolver.resolve = fallthrough
        server.bind(DomainName("time."), lambda request: [_txt(request.name, "now")])
        server.bind(
            DomainName("sub."),
            lambda request: [_txt(request.name, "below")],
            include_subdomains=True,
        )
        for name in (DomainName("sub."), DomainName("deep.sub."), DomainName("deep.time.")):
            server.datagram_received(bytes(srv.query_packet(name=name)), PEER4)
            await srv.drain(server)
        by_name = {str(r.questions[0].name): r for r in transport.replies}
        assert [str(r.rdata) for r in by_name["sub."].answers] == ['"below"']
        assert [str(r.rdata) for r in by_name["deep.sub."].answers] == ['"below"']
        assert fell == ["deep.time."], "exact binding: deeper names still belong to the net"

    async def test_binding_rejects_a_non_handler(self):
        server, _resolver, _transport = srv.make_server()
        with pytest.raises(TypeError, match="callable"):
            server.bind(WHOAMI, "not callable")

    async def test_bound_answers_do_not_spend_the_recursion_semaphore(self):
        # A flood aimed at a bound name cannot starve the recursion budget:
        # the reflex answers while every lookup slot is held.
        server, _resolver, transport = _bound_server(max_concurrent_lookups=1)
        await server._slots.acquire()
        server.datagram_received(bytes(srv.query_packet(name=WHOAMI)), PEER4)
        await srv.drain(server)
        assert transport.replies, "the bound answer did not queue behind the slots"


class TestInheritance:
    """The point of the hook: obligations are structural, not per-caller."""

    async def test_an_extended_request_still_buys_an_opt(self):
        server, _resolver, transport = _bound_server()
        query = srv.query_packet(name=WHOAMI).add_edns(1232)
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        assert transport.replies[0].opt() is not None

    async def test_the_cd_bit_echoes_onto_a_bound_answer(self):
        server, _resolver, transport = _bound_server()
        query = srv.query_packet(name=WHOAMI)
        query.CD = True
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        assert transport.replies[0].CD is True

    async def test_a_fat_answer_truncates_like_any_other(self):
        server, _resolver, transport = srv.make_server()
        server.resolver.resolve = _never()

        def fat(request):
            # Three character-strings, each inside 1035 §3.3.14's 255-octet
            # limit, together past any client's advertised payload: RData_TXT
            # refuses one oversized string on the wire's behalf, so a handler
            # that means "fat TXT" splits the way a zone file would.
            strings = ["y" * 250, "z" * 250, "w" * 250]
            return [DnsRecord(request.name, DnsQType.TXT, ttl=0, rdata=RData_TXT(strings))]

        server.bind(DomainName("fat."), fat)
        query = srv.query_packet(name=DomainName("fat."), qtype=DnsQType.TXT).add_edns(512)
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        reply = transport.replies[0]
        assert reply.TC is True, "the 512 ceiling is a datagram rule, not a resolver rule"

    async def test_a_bundled_query_gets_support_claimed_but_nothing_combined(self):
        # RFC 10029 section 3: the presence of the MQTYPE-Response option is
        # the support claim, the empty list inside it is "nothing combined" --
        # and a bound name is exactly that: answered, not combined. Silence
        # would be a lie about the server's capabilities.
        server, _resolver, transport = _bound_server()
        query = srv.query_packet(name=WHOAMI)
        query.add_edns(1232, options=[mqtype_query_option((int(DnsQType.TXT),))])
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        reply = transport.replies[0]
        options = list(reply.edns_options())
        assert mqtype_supported(options)
        assert mqtype_answered_qtypes(options, primary_qtype=int(DnsQType.A)) == ()


class TestReflexiveZone:
    async def _ask(self, qtype, addr=PEER4, dnssec=False, channel=None):
        server, _resolver, transport = _bound_server()
        query = srv.query_packet(name=WHOAMI, qtype=qtype)
        if dnssec:
            query.add_edns(1232, flags=EDNS_DO_BIT)
        if channel is None:
            server.datagram_received(bytes(query), addr)
            await srv.drain(server)
            return transport.replies[0]
        await server.respond_to_packet(query, addr, channel=channel)
        return DnsPacket.parse(channel.sent[0])[0]

    async def test_a_query_from_a_v4_peer_answers_its_own_address(self):
        reply = await self._ask(DnsQType.A)
        assert [str(r.rdata) for r in reply.answers] == ["203.0.113.7"]
        assert reply.answers[0].ttl == 0, "a snapshot of your packet is not cacheable"

    async def test_txt_names_the_address_the_port_and_the_transport(self):
        reply = await self._ask(DnsQType.TXT)
        sentence = str(reply.answers[0].rdata)
        assert "203.0.113.7:51111" in sentence
        assert "udp" in sentence

    async def test_do_rides_into_the_sentence(self):
        reply = await self._ask(DnsQType.TXT, dnssec=True)
        assert "DO set" in str(reply.answers[0].rdata)

    async def test_a_family_the_socket_cannot_see_answers_nodata_not_a_lie(self):
        reply = await self._ask(DnsQType.AAAA)  # v4 peer asking for AAAA
        assert reply.answers == []
        assert reply.AA is True, "the nothing is this server's own honest nothing"

    async def test_v6_peer_gets_its_own_v6_and_no_invented_v4(self):
        reply = await self._ask(DnsQType.AAAA, addr=PEER6)
        assert [str(r.rdata) for r in reply.answers] == ["fe80::1"]
        reply = await self._ask(DnsQType.A, addr=PEER6)
        assert reply.answers == []

    async def test_tcp_answers_say_tcp_because_that_is_the_truth(self):
        channel = FakeChannel()
        reply = await self._ask(DnsQType.TXT, channel=channel)
        assert "over tcp" in str(reply.answers[0].rdata)

    async def test_any_bundles_the_visible_family_with_the_sentence(self):
        reply = await self._ask(DnsQType.ANY)
        types = sorted(int(r.rtype) for r in reply.answers)
        assert types == sorted([int(DnsQType.A), int(DnsQType.TXT)])

    async def test_other_types_answer_nodata(self):
        reply = await self._ask(DnsQType.MX)
        assert reply.answers == []

    async def test_the_name_folds_case_like_any_dns_name(self):
        server, _resolver, transport = _bound_server()
        query = srv.query_packet(name=DomainName("WHOAMI."), qtype=DnsQType.A)
        server.datagram_received(bytes(query), PEER4)
        await srv.drain(server)
        assert transport.replies[0].answers


class TestCliFlag:
    def test_serve_reflexive_parses(self):
        from namespy import __main__ as cli

        args = cli.build_parser().parse_args(["--serve", "--serve-reflexive"])
        assert args.serve_reflexive is True
        plain = cli.build_parser().parse_args(["--serve"])
        assert plain.serve_reflexive is False
