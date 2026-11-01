"""RFC 8467 padding policy: the arithmetic, the position, the transport gate.

Three documents meet on this one option and the tests are cut along their
seams. RFC 8467 §4.1¶2 ("Clients SHOULD pad queries to the closest multiple
of 128 octets") is the strategy and the number -- with §4.1¶5's footnote that
even the zero-length option costs its 4-octet header, and §3¶3's Transport
Protocol Independence, which makes the measurement the DNS message and never
the TCP frame around it. RFC 8467 §3¶1 fixes the position: padding is the
last option applied before sending. RFC 7830 contributes the two limits: the
padded message MUST NOT exceed the Requestor's Payload Size (§4¶1 -- here the
sender's *own* advertisement), and the option MUST NOT ride an unencrypted
transport at all (§6). RFC 9539 §4.6.8.1 is the sentence that points a DoT
client at authoritative servers back at this document.

The 468-octet response block of §4.1¶3 is a server's duty toward padded
queries, and :mod:`namespy.server` has no encrypted front on which to owe
it -- its silence is documented there, not here. The DoH leg shares its
egress with DoT inside ``StubResolver._stream_query``, so the live-TLS
cases prove the placement for both; the arithmetic itself is transport-blind
by §3¶3 construction.
"""

import ipaddress

import pytest
import test_cli as tcli
import test_stub_dot as sd
import test_stub_resolver as tsr

from namespy.cache import MemoryDnsCache
from namespy.edns import (
    EDNS_OPTION_HEADER_OCTETS,
    KEEPALIVE_OPTION_CODE,
    PADDING_OPTION_CODE,
    QUERY_PAD_BLOCK_OCTETS,
    find_option,
    keepalive_option,
    query_pad_octets,
)
from namespy.enums import DnsQType
from namespy.names import DomainName
from namespy.packet import EDNS_DO_BIT, DnsPacket, DnsQuestion, Query
from namespy.resolver import RecursiveResolver
from namespy.stub import Upstream

# ---------------------------------------------------------------- §4.1 arithmetic


def test_the_block_arithmetic_counts_the_option_header_and_the_dns_message():
    """§4.1¶5's zero-length option and §3¶3's worked example, as numbers."""
    # Four octets short of a boundary: the header alone lands it on 128 and
    # the payload is nothing at all.
    assert query_pad_octets(124) == 0
    # §3¶3's example with the document's own block: a 59-octet message pads
    # to 64 over UDP. Count the TCP length prefix (61) and the same rule
    # would overshoot to 96; this function never sees the prefix.
    assert query_pad_octets(59, block=32) == 1
    assert 59 + EDNS_OPTION_HEADER_OCTETS + 1 == 64
    assert query_pad_octets(100) == 24  # 100 + 4 + 24 = 128
    assert query_pad_octets(128) == 124  # a full block is already past one


def _query(name="block.example.", payload=1232, options=(), flags=EDNS_DO_BIT) -> Query:
    packet = Query(questions=[DnsQuestion(DomainName(name), DnsQType.A)])
    packet.add_edns(payload, options=options, flags=flags)
    return packet


def test_the_padded_clone_lands_on_the_block_and_leaves_the_original_alone():
    q = _query()
    before = bytes(q)
    wire = bytes(q.padded_clone(QUERY_PAD_BLOCK_OCTETS))
    assert len(wire) % QUERY_PAD_BLOCK_OCTETS == 0
    assert len(wire) >= len(before) + EDNS_OPTION_HEADER_OCTETS
    padded = DnsPacket.parse(wire)[0]
    codes = [int(o.code) for o in padded.edns_options()]
    assert codes[-1] == PADDING_OPTION_CODE  # §3¶1: the last option applied
    pad = find_option(padded.edns_options(), PADDING_OPTION_CODE)
    assert pad.data == bytes(len(pad.data))  # RFC 7830 §3's SHOULD: all zero
    assert padded.dnssec_ok  # the rebuilt OPT keeps the flags it had

    untouched = DnsPacket.parse(bytes(q))[0]  # the original never felt a thing
    assert find_option(untouched.edns_options(), PADDING_OPTION_CODE) is None
    assert bytes(q) == before


def test_every_option_a_caller_asked_for_stays_ahead_of_the_pad():
    """§3¶1 is about order among peers, not about being the only one."""
    q = _query(options=(keepalive_option(),))
    clone = q.padded_clone(QUERY_PAD_BLOCK_OCTETS)
    codes = [int(o.code) for o in clone.edns_options()]
    assert codes == [KEEPALIVE_OPTION_CODE, PADDING_OPTION_CODE]


def test_an_unextended_message_has_nowhere_to_put_padding():
    """No OPT (RFC 6891 §7's unextended exchange) means no option to carry."""
    q = Query(questions=[DnsQuestion(DomainName("plain.example."), DnsQType.A)])
    assert q.padded_clone(QUERY_PAD_BLOCK_OCTETS) is q


def test_a_second_padding_call_adds_no_second_pad():
    once = _query().padded_clone(QUERY_PAD_BLOCK_OCTETS)
    assert once.padded_clone(QUERY_PAD_BLOCK_OCTETS) is once


def _multi_query(count: int, payload: int = 1232) -> Query:
    """A multi-question message: the codec's parser notes QDCOUNT is not
    capped at one, and the budget arithmetic wants a fat *message*, which the
    255-octet name limit (RFC 1035 §2.3.4, enforced by DomainName) makes
    impossible from a single name."""
    names = [DomainName(".".join(["x" * 50] * 4) + f".q{n}.example.") for n in range(count)]
    packet = Query(questions=[DnsQuestion(name, DnsQType.A) for name in names])
    packet.add_edns(payload, flags=EDNS_DO_BIT)
    return packet


def test_the_advertised_size_outranks_the_block():
    """RFC 7830 §4¶1: padded messages MUST NOT exceed the advertised payload.

    A message sized so its next boundary clears the budget is refused padding
    entirely -- not clipped to it, because §4.1's promise is a *multiple*,
    and half a block anonymizes nothing -- while the same message under a
    generous budget pads. The advertisement belongs to the sender, so the
    budget here is the client's own OPT number.
    """
    count = 1
    probe = _multi_query(count)
    while len(bytes(probe)) + EDNS_OPTION_HEADER_OCTETS <= 640:
        count += 1
        probe = _multi_query(count)
    wire_len = len(bytes(probe))
    boundary = wire_len + EDNS_OPTION_HEADER_OCTETS + query_pad_octets(wire_len)
    assert boundary > 640  # by construction: the next block clears the budget
    assert probe.padded_clone(QUERY_PAD_BLOCK_OCTETS, budget=640) is probe
    padded = probe.padded_clone(QUERY_PAD_BLOCK_OCTETS, budget=1232)
    assert padded is not probe
    assert len(bytes(padded)) % QUERY_PAD_BLOCK_OCTETS == 0


# ------------------------------------------------------- the encrypted legs


class SilentProbe:
    """A Table-2 entry that says only the encrypted half may speak.

    ``send_over_do53`` False forces ``_query_authority`` down its single-leg
    branch -- the one path where the encrypted wire is computed without a
    cleartext race beside it -- and the stubbed ``_dot_query`` below stands
    in for the handshake so the test reads the wire, not a socket.
    """

    session = object()

    def consider(self, now, params):
        return None

    def send_over_do53(self, now, params):
        return False

    def ride(self):
        return False

    def may_initiate(self, now, params):
        return False


async def _authority_wire(resolver, packet):
    captured: dict = {}

    async def fake_dot(host, wire, query_packet, ns_record=None):
        captured["wire"] = wire
        return "answered"

    resolver._dot_probe = lambda _host: SilentProbe()
    resolver._dot_query = fake_dot
    result = await resolver._query_authority(ipaddress.IPv4Address("192.0.2.9"), packet)
    assert result == "answered"
    return captured["wire"]


async def test_the_encrypted_authority_leg_pads_and_its_cleartext_twin_does_not():
    """RFC 9539 §4.6.8.1's SHOULD, sized by §4.1¶2, paid at the leg that earned it.

    The wire is the clone's; the *packet* is the race's shared property, and
    RFC 7830 §6 governs the cleartext half of every concurrent attempt --
    which is the whole reason the padding is a clone and not a mutation.
    """
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    q = _query(name="padded.example.")
    wire = await _authority_wire(resolver, q)
    assert len(wire) % QUERY_PAD_BLOCK_OCTETS == 0
    assert find_option(DnsPacket.parse(wire)[0].edns_options(), PADDING_OPTION_CODE) is not None
    untouched = DnsPacket.parse(bytes(q))[0]
    assert find_option(untouched.edns_options(), PADDING_OPTION_CODE) is None


async def test_the_walks_off_switch_sends_the_plain_wire_encryption_and_all():
    resolver = RecursiveResolver(cache=MemoryDnsCache(), query_padding=False)
    wire = await _authority_wire(resolver, _query(name="bare.example."))
    assert find_option(DnsPacket.parse(wire)[0].edns_options(), PADDING_OPTION_CODE) is None


# ------------------------------------------------------------------ the stub


@pytest.fixture
async def dot():
    """The live-TLS harness of test_stub_dot, re-pointed at padding questions."""
    cert, key = sd._cert_paths()
    server = sd.DotServer(cert, key)
    await server.start()

    def stub(upstreams=None, **kwargs):
        return sd.TrustingStub(
            upstreams
            if upstreams is not None
            else [
                Upstream(
                    "127.0.0.1",
                    port=server.port,
                    transport="dot",
                    server_name=sd.CERT_NAME,
                )
            ],
            cafile=cert,
            **kwargs,
        )

    yield server, stub
    await server.stop()


async def test_a_stub_query_reaches_the_dot_upstream_padded_and_padding_last(dot):
    server, stub = dot
    resolver = stub()
    try:
        await resolver.forward([DnsQuestion(DomainName("stub-padded.example."), DnsQType.A)])
    finally:
        await resolver.aclose()
    codes = [int(o.code) for o in server.queries[0].edns_options()]
    assert codes == [KEEPALIVE_OPTION_CODE, PADDING_OPTION_CODE]  # §3¶1 over TLS


async def test_the_stubs_off_switch_sends_the_plain_size(dot):
    server, stub = dot
    resolver = stub(query_padding=False)
    try:
        await resolver.forward([DnsQuestion(DomainName("stub-plain.example."), DnsQType.A)])
    finally:
        await resolver.aclose()
    assert find_option(server.queries[0].edns_options(), PADDING_OPTION_CODE) is None


async def test_cleartext_udp_never_carries_the_option_with_padding_on():
    """§6 outranks every policy knob: the gate is the transport, not the taste.

    The queue entry holds the packet as handed to the transport -- the same
    object the encrypted legs would have cloned -- so this reads the wire's
    substance at the moment of the send.
    """
    stub = tsr.make_stub([Upstream(tsr.UP_IP)])
    task, sent_query, future = await tsr.start(stub)
    assert find_option(sent_query.edns_options(), PADDING_OPTION_CODE) is None
    future.set_result(tsr.answer_for(sent_query))
    await task


async def test_the_cli_flag_reaches_the_endpoint_it_belongs_to(monkeypatch):
    """The off-switch is the RFC 8467 §3¶2 resource exit, and the CLI is its door."""
    made = tcli._stub_endpoints(monkeypatch, tcli._answered)
    assert await tcli.cli.cli_query(tcli._args(["example.com"])) == 0
    assert made[0][1].query_padding is True  # the SHOULD, by default
    made2 = tcli._stub_endpoints(monkeypatch, tcli._answered)
    assert await tcli.cli.cli_query(tcli._args(["--no-query-padding", "example.com"])) == 0
    assert made2[0][1].query_padding is False
