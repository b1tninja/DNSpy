"""The walk's pooled TCP fallbacks (RFC 7766 6.2.1/6.2.2/6.2.4, RFC 7828 3.2.2).

``Resolver._query_tcp`` used to open a connection the way a turnstile opens
-- once, for one body, immediately. These tests hold it to the reuse it now
promises: one connection per ``(host, port)`` (6.2.2 paragraph 1), the
keepalive conversation honoured from the answer (3.2.2), a death between
queries answered by a silent retry (6.2.4 paragraph 2), and zone transfers
kept on their own line, as 6.2.2 again asks. The server is a real
length-framed TCP server on loopback: every claim here is an observation of
bytes, not of internals.
"""

import asyncio
import struct

from namespy.edns import keepalive_option
from namespy.enums import DnsQClass, DnsQR, DnsQType, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.resolver import Resolver  # the pool lives on the base transport

QNAME = DomainName("held.example.")


def make_query(qtype=DnsQType.A, packet_id=0x3322):
    packet = Query(ID=packet_id, questions=[DnsQuestion(QNAME, qtype, DnsQClass.IN)])
    packet.add_edns(1232)
    return packet


class TcpDnsServer:
    """A length-framed DNS server that answers every query and remembers all of them.

    *keepalive* controls the server's half of RFC 7828: ``None`` answers with
    a plain OPT (no option, the RFC 7766 world), an ``int`` attaches an
    edns-tcp-keepalive with that TIMEOUT -- 0 included, which is section
    3.3.2 paragraph 1's refusal. *die_after* closes the connection after that
    many answers, impersonating the server-side idle close that RFC 7766
    section 6.2.4 paragraph 2 tells the client to expect and recover from.
    """

    def __init__(self, *, keepalive=None, die_after=None):
        self.keepalive = keepalive
        self.die_after = die_after
        self.connections = 0
        self.active = 0
        self.queries = []
        self.server = None

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        self.connections += 1
        self.active += 1
        try:
            while True:
                head = await reader.readexactly(2)
                (n,) = struct.unpack("!H", head)
                data = await reader.readexactly(n)
                query, _off = DnsPacket.parse(data)
                self.queries.append(query)
                answer = self._answer_for(query)
                wire = bytes(answer)
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
                if self.die_after is not None and len(self.queries) >= self.die_after:
                    return
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self.active -= 1
            writer.close()

    def _answer_for(self, query):
        answer = Response(
            ID=query.ID,
            QR=DnsQR.RESPONSE,
            RA=True,
            questions=list(query.questions),
            answers=[DnsRecord(QNAME, DnsRType.A, DnsQClass.IN, 60, rdata=bytes([203, 0, 113, 1]))],
        )
        options = () if self.keepalive is None else (keepalive_option(self.keepalive),)
        answer.add_edns(1232, options=options)
        return answer


def _resolver():
    return Resolver()  # the bare base: the pool creates its dict on demand


async def _ask(resolver, server, packet=None):
    packet = packet if packet is not None else make_query()
    return await resolver._query_tcp("127.0.0.1", bytes(packet), packet, port=server.port)


async def _wait_until(predicate, tries=100):
    for _ in range(tries):
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


# ---------------------------------------------------------------- the pool


async def test_the_second_query_rides_the_first_connection():
    server = TcpDnsServer()
    await server.start()
    resolver = _resolver()
    try:
        first = await _ask(resolver, server)
        second = await _ask(resolver, server)
        assert first is not None
        assert first.RA is True
        assert second is not None
        assert second.RA is True
        assert server.connections == 1  # section 6.2.1 para 1, observed
        assert len(server.queries) == 2
        assert len(resolver._tcp_sessions) == 1
        session = next(iter(resolver._tcp_sessions.values()))
        assert session.timer is not None  # no option spoken: the conservative 30 s hold
    finally:
        resolver._close_tcp_sessions()
        await server.stop()


async def test_close_releases_the_pooled_stream():
    server = TcpDnsServer()
    await server.start()
    resolver = _resolver()
    try:
        await _ask(resolver, server)
        assert server.active == 1
    finally:
        resolver._close_tcp_sessions()
    assert await _wait_until(lambda: server.active == 0)
    await server.stop()  # the socket is really gone, not merely unlinked


async def test_concurrent_queries_wait_on_the_lock_not_a_rival_handshake():
    server = TcpDnsServer()
    await server.start()
    resolver = _resolver()
    try:
        await _ask(resolver, server)  # establish the shared stream first
        answers = await asyncio.gather(*[_ask(resolver, server) for _ in range(3)])
        assert all(a is not None and a.RA for a in answers)
        assert server.connections == 1  # section 6.2.2 para 1, the one-connection rule
        assert len(server.queries) == 4
    finally:
        resolver._close_tcp_sessions()
        await server.stop()


# ---------------------------------------------------------------- keepalive


async def test_an_offered_timeout_keeps_the_session_held():
    server = TcpDnsServer(keepalive=120)
    await server.start()
    resolver = _resolver()
    try:
        await _ask(resolver, server)
        session = next(iter(resolver._tcp_sessions.values()))
        assert session.timer is not None  # section 3.2.2 para 2 acted on
        assert session.closed is False
    finally:
        resolver._close_tcp_sessions()
        await server.stop()


async def test_a_zero_timeout_drops_the_session_on_the_spot():
    """Section 3.2.2 para 3: send nothing more here -- so the session ends here."""
    server = TcpDnsServer(keepalive=0)
    await server.start()
    resolver = _resolver()
    try:
        answer = await _ask(resolver, server)
        assert answer is not None  # the answer arrived; only the future did not
        assert resolver._tcp_sessions == {}
        second = await _ask(resolver, server)
        assert second is not None
        assert server.connections == 2  # the refusal stood: the next ask needed a new line
    finally:
        resolver._close_tcp_sessions()
        await server.stop()


# ---------------------------------------------------------------- non-clean paths


async def test_a_stream_that_died_between_queries_is_reopened_silently():
    """RFC 7766 section 6.2.4 para 2: retry the unanswered query when it closed."""
    server = TcpDnsServer(die_after=1)
    await server.start()
    resolver = _resolver()
    try:
        first = await _ask(resolver, server)
        assert first is not None
        assert await _wait_until(lambda: server.active == 0)  # the FIN has landed
        second = await _ask(resolver, server)
        assert second is not None
        assert second.RA is True  # retried, not failed
        assert server.connections == 2  # one death, one reopening, no error surfaced
        assert len(resolver._tcp_sessions) == 1  # and the fresh stream is held again
    finally:
        resolver._close_tcp_sessions()
        await server.stop()


async def test_a_mismatched_answer_discredits_the_stream_it_came_on():
    """An answer to some other question means the reading position drifted."""

    class WrongIdServer(TcpDnsServer):
        def _answer_for(self, query):
            answer = super()._answer_for(query)
            answer.ID = (query.ID + 1) & 0xFFFF  # an answer to nobody's question
            return answer

    server = WrongIdServer()
    await server.start()
    resolver = _resolver()
    try:
        assert await _ask(resolver, server) is None
        assert resolver._tcp_sessions == {}  # the mismatch retired the session
        assert server.connections == 1  # a first-ride mismatch is not retried blind
    finally:
        resolver._close_tcp_sessions()
        await server.stop()


# ---------------------------------------------------------------- AXFR


async def test_a_zone_transfer_gets_its_own_line_and_holds_nothing():
    """Section 6.2.2 para 1 counts transfers as a connection of their own."""
    server = TcpDnsServer()
    await server.start()
    resolver = _resolver()
    try:
        axfr = make_query(qtype=DnsQType.AXFR)
        await _ask(resolver, server, axfr)
        assert resolver._tcp_sessions == {}  # never pooled
        await _ask(resolver, server, axfr)
        assert server.connections == 2  # each transfer opens its own stream, as asked
    finally:
        resolver._close_tcp_sessions()
        await server.stop()
