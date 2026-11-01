"""The TCP front (RFC 7766 framing, RFC 7828 section 3.3, BCP 235).

Every test here is a real socket conversation: a ``DnsStreamServer``
listening on loopback in front of a ``DnsServer`` whose walk is stubbed,
and a client that speaks the 2-octet prefix and reads what comes back.
The claims are the ones the
server half owes -- the keepalive answer advertises the timeout this
connection enforces and nothing else (section 3.3.2 paragraph 1's MUST);
silence is a configuration, not a lie (section 3.2.2 paragraph 4's client
fallback says what a client does with it); 0 refuses and closes; the
datagram path ignores the option the way section 3.3.1 paragraph 1
demands; framing errors close the line and parse errors do not; idle
connections get the configurable goodbye BCP 235 section 4.2 paragraph 4
asks servers to provide; and pipelined queries are processed together and
answered in order.
"""

import asyncio
import struct
import time

from test_server import ADDR, answered_response, make_server, query_packet

from namespy.edns import (
    KEEPALIVE_OPTION_CODE,
    find_option,
    keepalive_of,
    keepalive_option,
)
from namespy.enums import DnsQClass, DnsQType
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsQuestion
from namespy.server import DEFAULT_TCP_IDLE_S, DnsStreamServer
from namespy.stub import StubResolver, Upstream


def frame(wire):
    return struct.pack("!H", len(wire)) + wire


async def read_response(reader):
    head = await reader.readexactly(2)
    (n,) = struct.unpack("!H", head)
    packet, _off = DnsPacket.parse(await reader.readexactly(n))
    return packet


def build_server(**kwargs):
    """A DnsServer whose resolver answers instantly, fronted for streams."""
    server, resolver, transport = make_server(**kwargs)

    async def resolve(dns_packet):
        return answered_response(dns_packet)

    resolver.resolve = resolve
    return server, transport


async def stream_front(server):
    listener = await asyncio.get_running_loop().create_server(
        lambda: DnsStreamServer(server), host="127.0.0.1", port=0
    )
    return listener, listener.sockets[0].getsockname()[1]


async def connect(port):
    return await asyncio.open_connection("127.0.0.1", port)


def extended_query(packet_id=0xABCD):
    packet = query_packet(packet_id=packet_id)
    packet.add_edns(1232, options=(keepalive_option(),))
    return packet


# ------------------------------------------------------------- the conversation


async def test_a_framed_query_is_answered_and_the_line_held():
    server, _transport = build_server()
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            writer.write(frame(bytes(extended_query())))
            await writer.drain()
            reply = await read_response(reader)
            assert reply.ID == 0xABCD
            assert reply.RA is True
            # The default policy advertised: the number this connection enforces.
            assert keepalive_of(reply.edns_options()) == DEFAULT_TCP_IDLE_S
            # And the connection is still there for the next question.
            writer.write(frame(bytes(extended_query(packet_id=0x1234))))
            await writer.drain()
            second = await read_response(reader)
            assert second.ID == 0x1234
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def test_the_advertised_timeout_is_the_configured_one():
    server, _transport = build_server(tcp_idle=17)
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            writer.write(frame(bytes(extended_query())))
            await writer.drain()
            reply = await read_response(reader)
            assert keepalive_of(reply.edns_options()) == 17  # what we hold is what we say
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def test_silence_is_a_configuration():
    server, _transport = build_server(tcp_idle=None)
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            writer.write(frame(bytes(extended_query())))
            await writer.drain()
            reply = await read_response(reader)
            options = reply.edns_options()
            assert reply.opt() is not None  # the query carried OPT, so the answer must too
            assert find_option(options, KEEPALIVE_OPTION_CODE) is None  # said nothing
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def test_a_query_with_no_opt_gets_no_opt_and_nothing_about_keepalive():
    """RFC 6891 section 7 and RFC 7828 section 3.4 paragraph 6, on a held line."""
    server, _transport = build_server()
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            writer.write(frame(bytes(query_packet())))  # unextended
            await writer.drain()
            reply = await read_response(reader)
            assert reply.opt() is None
            assert reply.RA is True  # answered -- just not extended
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


# ------------------------------------------------------------- the refusals


async def test_zero_idle_advertises_zero_and_ends_the_line():
    """Section 3.3.2 paragraph 1's SHOULD-0, honoured by both sides of it."""
    server, _transport = build_server(tcp_idle=0)
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            writer.write(frame(bytes(extended_query())))
            await writer.drain()
            reply = await read_response(reader)
            assert keepalive_of(reply.edns_options()) == 0  # the refusal, said
            assert await reader.read(1) == b""  # and meant: the line ends here
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def test_a_clients_zero_hint_ends_the_line_from_the_servers_side():
    """A TIMEOUT of 0 in a query's option can only mean close-as-apart."""
    server, _transport = build_server()  # ordinary 30-second policy...
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            hint = query_packet()
            hint.add_edns(1232, options=(keepalive_option(0),))  # ...but the client declines
            writer.write(frame(bytes(hint)))
            await writer.drain()
            reply = await read_response(reader)
            assert reply.RA is True  # the question was still worth answering
            assert keepalive_of(reply.edns_options()) == 0  # the session holds nothing now
            assert await reader.read(1) == b""
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


# ------------------------------------------------------------- the bad paths


async def test_an_unparseable_message_answers_formerr_and_spares_the_stream():
    server, _transport = build_server()
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            garbage = b"\x00\x01\x02\x03"  # well-framed, not a DNS message
            writer.write(frame(garbage))
            await writer.drain()
            reply = await read_response(reader)
            assert int(reply.RCODE) == 1  # FORMERR
            assert reply.opt() is None  # nothing parseable earned no OPT
            writer.write(frame(bytes(extended_query(packet_id=0x0101))))
            await writer.drain()
            second = await read_response(reader)  # the stream survived its passenger
            assert second.ID == 0x0101
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def test_a_zero_length_frame_ends_the_stream():
    """A prefix naming no message leaves no reading position to recover."""
    server, _transport = build_server()
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            writer.write(struct.pack("!H", 0))
            await writer.drain()
            assert await reader.read(1) == b""
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def test_an_idle_connection_gets_the_configurable_goodbye():
    """BCP 235 section 4.2 paragraph 4: software provides the timeout; this runs it."""
    server, _transport = build_server(tcp_idle=1)
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            # The clock resets on a complete message (RFC 7766 section 6.2.3
            # paragraph 3), so the close below is measured from this
            # question -- not from the handshake.
            reply = await ask_and_read(reader, writer, extended_query())
            assert reply.RA is True
            started = time.monotonic()
            assert await asyncio.wait_for(reader.read(1), timeout=3.0) == b""
            elapsed = time.monotonic() - started
            assert 0.7 <= elapsed <= 2.5  # the one-second timer spoke, at one second
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


async def ask_and_read(reader, writer, packet):
    writer.write(frame(bytes(packet)))
    await writer.drain()
    return await read_response(reader)


# ------------------------------------------------------------- pipelining


async def test_pipelined_queries_are_processed_together_and_answered_in_order():
    """RFC 7766 section 6.2.1.1 paragraph 4: expect them, process them, answer all."""

    async def slow_resolve(dns_packet):
        await asyncio.sleep(0.08)  # serial processing of two would cost 0.16+
        return answered_response(dns_packet)

    server, resolver, _transport = make_server()
    resolver.resolve = slow_resolve
    listener, port = await stream_front(server)
    try:
        reader, writer = await connect(port)
        try:
            started = time.monotonic()
            writer.write(
                frame(bytes(extended_query(packet_id=1)))
                + frame(bytes(extended_query(packet_id=2)))
            )
            await writer.drain()  # both, back to back, no waiting for the first answer
            first = await read_response(reader)
            second = await read_response(reader)
            elapsed = time.monotonic() - started
            assert (first.ID, second.ID) == (1, 2)  # answers leave in arrival order
            assert elapsed < 0.14  # both walked at once; serial would have cost 0.16+
        finally:
            writer.close()
    finally:
        listener.close()
        await listener.wait_closed()


# ------------------------------------------------------------- the datagram half


async def test_a_udp_query_carrying_keepalive_is_ignored_as_section_3_3_1_demands():
    """RFC 7828 section 3.3.1 paragraph 1: MUST ignore the option on UDP."""
    server, resolver, transport = make_server()

    async def resolve(dns_packet):
        return answered_response(dns_packet)

    resolver.resolve = resolve
    await server.respond_to_packet(extended_query(), ADDR)
    reply = transport.replies[-1]
    assert reply.RA is True  # the query is answered like any other
    assert reply.opt() is not None  # it carried OPT, so the answer owes one
    assert find_option(reply.edns_options(), KEEPALIVE_OPTION_CODE) is None  # ignored


# ------------------------------------------------------------- both halves


async def test_the_stub_and_the_front_complete_a_keepalive_conversation():
    """The package's client and server halves, agreeing on a number."""
    server, _transport = build_server(tcp_idle=11)
    accepted = []

    def factory():
        accepted.append(1)
        return DnsStreamServer(server)

    listener = await asyncio.get_running_loop().create_server(factory, host="127.0.0.1", port=0)
    port = listener.sockets[0].getsockname()[1]
    stub = StubResolver([Upstream("127.0.0.1", port=port, transport="tcp")])
    try:
        questions = [DnsQuestion(DomainName("held.example."), DnsQType.A, DnsQClass.IN)]
        first = await stub.forward(questions)
        second = await stub.forward(questions)
        assert first is not None
        assert first.RA is True
        assert second is not None
        assert second.RA is True
        assert len(accepted) == 1  # one line for two forwards: the pool, server-side
        session = next(iter(stub._tcp_sessions.values()))
        assert session.timer is not None  # and the client armed on the server's 11
    finally:
        await stub.aclose()
        listener.close()
        await listener.wait_closed()
