"""Opportunistic encryption of the authority leg (RFC 9539 section 4).

Two halves, mirroring the split in :mod:`namespy.opportunistic`. The first
drives the Table 2 policy with no sockets at all: the §4.6 formulas are
pure functions of (state, now, per-protocol parameters), and the two
verified errata -- 7831 and 7832, which turn the published ``persistence``
and ``damping`` into *E-persistence* and *E-damping* -- are only visible
in a test that hands two transports two different numbers.

The second half races the real thing against loopback: the DoT fixture
from :mod:`test_stub_dot` (a self-signed certificate that no verifying
client would accept -- which is the point: section 4.6.3.4's MUST means
this client completes the handshake anyway), and a recording stand-in for
the cleartext half of the walk, so every assertion is about *which legs
spoke* and *what the table remembered*. The one thing a stand-in cannot
prove -- that a late cleartext answer to an already-answered query dies
unmatched -- is a property of the pending table that predates this RFC
and is tested where that machinery lives.
"""

import asyncio
import ipaddress
import logging
import ssl
import struct

import pytest
from test_stub_dot import DotServer, _cert_paths

from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.opportunistic import AuthorityProbe, ProbeParams, ProbeStatus
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.rdata import RData_A
from namespy.resolver import Resolver

QNAME = DomainName("ninefivesixthree.example.")

#: Table 1 scaled to test speed: persistence and damping shrink to seconds
#: so a test can watch one expire. The handshake timeout is NOT shrunk much
#: -- 2 s is already a tenth of the documented default -- because a loaded
#: CI runner's loopback TLS is slower than an idle laptop's, and a
#: correctness assert must never race a timeout that is only there to bound
#: the wait. Tests assert the damping that follows a timeout, not the
#: timeout's speed.
FAST = ProbeParams(persistence=30.0, damping=30.0, timeout=2.0)

#: The cleartext half's deliberate slowness in tests that expect the
#: encrypted leg to win the race: the handshake measures in milliseconds,
#: and this measures in multiples of them, so the winner is the policy's
#: doing and not the runner's load.
E_WINS_DELAY = 0.3


def make_query(packet_id=0x9539):
    return Query(ID=packet_id, questions=[DnsQuestion(QNAME, DnsQType.A)])


def localhost_glue():
    """An A record for 127.0.0.1 shaped like the glue the walk carries."""
    return DnsRecord(
        QNAME,
        DnsRType.A,
        DnsRClass.IN,
        60,
        rdata=RData_A(ipaddress.IPv4Address("127.0.0.1")),
    )


def _answer_for(query):
    answer = Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RD=query.RD,
        questions=list(query.questions),
    )
    answer.add_edns(1232)
    return answer


# ------------------------------------------------- the policy, sans sockets


def test_a_fresh_address_offers_both_transports():
    probe, params = AuthorityProbe(), ProbeParams()
    assert probe.send_over_do53(0.0, params)  # §4.6.1: nothing says not to
    assert probe.may_initiate(0.0, params)  # §4.6.3¶6 third bullet: never tried
    assert not probe.ride()


def test_established_session_rides_and_silences_cleartext():
    probe, params = AuthorityProbe(), ProbeParams()
    probe.note_initiating(1.0, object())
    probe.note_established(2.0)
    assert probe.ride()  # §4.6.3¶1
    assert not probe.send_over_do53(2.0, params)  # §4.6.1¶2 first bullet
    assert not probe.may_initiate(2.0, params)  # not while a session exists


def test_success_silences_cleartext_for_the_persistence_period():
    probe = AuthorityProbe()
    probe.note_initiating(1.0, object())
    probe.note_established(2.0)
    probe.note_closed()  # cleanly gone; §4.6.1¶3: the next query still prefers E
    assert not probe.send_over_do53(2.5, ProbeParams(persistence=10.0))
    assert probe.may_initiate(2.5, ProbeParams())  # §4.6.3¶6 first bullet
    assert probe.send_over_do53(12.5, ProbeParams(persistence=10.0))  # expired


def test_erratum_7831_reads_the_protocols_own_persistence():
    """Each transport consults *its* number -- the published formula said the
    parameter generically; the corrected text says E-persistence."""
    probe = AuthorityProbe()
    probe.note_initiating(0.0, object())
    probe.note_established(100.0)  # last_response := 100
    probe.note_closed()
    dot = ProbeParams(persistence=1000.0)  # DoT remembers for a long time
    other = ProbeParams(persistence=50.0)  # a hypothetical E that forgets sooner
    assert not probe.send_over_do53(200.0, dot)
    assert probe.send_over_do53(200.0, other)


def test_erratum_7832_reads_the_protocols_own_damping():
    probe = AuthorityProbe()
    probe.note_initiating(0.0, object())
    probe.note_failed(10.0)
    dot = ProbeParams(damping=1000.0)
    other = ProbeParams(damping=50.0)
    assert not probe.may_initiate(60.0, dot)
    assert probe.may_initiate(61.0, other)  # 51 s > 50 s: the gate opens on the far side


def test_failure_falls_to_cleartext_at_once_and_damps_the_retry():
    probe, params = AuthorityProbe(), ProbeParams(damping=100.0)
    probe.note_initiating(0.0, object())
    probe.note_failed(10.0)
    assert probe.send_over_do53(10.0, params)  # §4.6.5: cleartext carries every query
    assert not probe.may_initiate(10.5, params)  # inside damping
    assert probe.may_initiate(110.5, params)  # §4.6.3¶6 second bullet, elapsed


def test_pending_initiation_ages_into_timeout(  # §4.6.3¶4
):
    probe, params = AuthorityProbe(), ProbeParams(timeout=4.0)
    probe.note_initiating(0.0, object())
    probe.consider(3.9, params)
    assert probe.session is not None  # still just slow, not dead
    assert probe.status is None
    probe.consider(4.1, params)
    assert probe.session is None
    assert probe.status is ProbeStatus.TIMEOUT


def test_clean_close_keeps_status_so_the_retry_is_prompt():  # §4.6.7¶4
    probe = AuthorityProbe()
    probe.note_initiating(0.0, object())
    probe.note_established(1.0)
    probe.note_closed()
    assert probe.status is ProbeStatus.SUCCESS
    assert probe.may_initiate(1.5, ProbeParams(damping=1000.0))  # no damping applies
    assert probe.last_response == 1.0  # response clock untouched by a close


# ------------------------------------------------ the race, on live sockets


class RacingResolver(Resolver):
    """The walker with a recording cleartext half.

    ``_query_do53`` -- the leg the policy races against -- stands in as a
    counter and an optional delay: which side the policy *asked* is exactly
    what these tests assert, and the cleartext leg's own machinery has its
    own suite. The encrypted half is deliberately not stood in for: the
    handshake, the framing, the certificate posture and the session table
    are the point.
    """

    opportunistic_dot = True

    def __init__(self, *, dot_port, params=FAST, do53_answer=True, do53_delay=0.0):
        self.log = logging.getLogger("namespy.test.opportunistic")
        self.opportunistic_dot_port = dot_port
        self.opportunistic_params = params
        self.do53_calls = 0
        self.do53_answer = do53_answer
        self.do53_delay = do53_delay
        self.tcp_calls = 0

    async def _query_do53(self, ip, dns_packet, port=53):
        self.do53_calls += 1
        if self.do53_delay:
            await asyncio.sleep(self.do53_delay)
        return _answer_for(dns_packet) if self.do53_answer else None

    async def _query_tcp(self, host, wire, query_packet, port=53):
        self.tcp_calls += 1
        return _answer_for(query_packet)

    async def ask(self):
        # The transaction id named so the race's winner is recognisable in
        # an assertion; the real walk lets the packet randomise it.
        return await self.query([DnsQuestion(QNAME, DnsQType.A)], None, localhost_glue(), ID=0x9539)

    async def settle(self):
        """Let any background learner (§4.6¶5) finish and record its verdict."""
        learners = list(getattr(self, "_probes_learning", ()))
        if learners:
            await asyncio.gather(*learners, return_exceptions=True)

    async def dispose(self):
        """Retire the learners, then close every stream this resolver holds.

        Fixture teardown depends on it: a DoT fixture ``stop()`` waits for
        its connection handlers, and those handlers wait for the client to
        hang up -- a deadlock inside one event loop if the client never
        puts its streams down.

        The learners go *first*: cancelling is honest here -- a §4.6¶5
        background initiation exists to inform future queries, and a
        disposing resolver has no future to inform -- but the cancellation
        must be awaited. A still-pending ``open_connection`` cancelled
        without a wait leaves the kernel-side connect half-open: the server
        accepts it, counts it, and a test that counts connections wakes up
        to a number that grew after it stopped looking.
        """
        while getattr(self, "_probes_learning", None):
            learners = list(self._probes_learning)
            for task in learners:
                task.cancel()
            await asyncio.gather(*learners, return_exceptions=True)
        self._close_tcp_sessions()


class SnoopingDotServer(DotServer):
    """Records what TLS each connection actually carried.

    The server-side view is the only place "SHOULD NOT send an SNI" and
    "MUST target ... an ALPN of 'dot'" can be checked: the client's own
    opinion about what it sent proves nothing.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._context.set_alpn_protocols(["dot"])
        self.hello: list[tuple] = []

    async def _handle(self, reader, writer):
        tls = writer.get_extra_info("ssl_object")
        self.hello.append(
            (
                tls.server_hostname if tls is not None else None,
                tls.selected_alpn_protocol() if tls is not None else None,
            )
        )
        await super()._handle(reader, writer)


class SessionKiller(DotServer):
    """Drops live connections while keeping the listener up: §4.6.7's server."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.live: list = []

    async def _handle(self, reader, writer):
        self.live.append(writer)
        try:
            await super()._handle(reader, writer)
        except (ssl.SSLError, OSError):
            pass  # APPLICATION_DATA_AFTER_CLOSE_NOTIFY and friends: killing a
            # TLS connection mid-keepalive is a race, and losing it is the point
        finally:
            if writer in self.live:
                self.live.remove(writer)

    def kill_sessions(self):
        for writer in list(self.live):
            writer.close()


class WrongIdDotServer(DotServer):
    """Answers every query with the wrong transaction id: a desynced stream."""

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            while True:
                (n,) = struct.unpack("!H", await reader.readexactly(2))
                query, _off = DnsPacket.parse(await reader.readexactly(n))
                self.queries.append(query)
                answer = _answer_for(query)
                answer.ID = (answer.ID + 1) & 0xFFFF
                wire = bytes(answer)
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass


class SinkServer:
    """Accepts connections and never finishes the handshake: a stalled port.

    (A *filtered* port would answer nothing at all, SYN dropped into a
    black hole; this fixture holds the connection open instead, which is
    the stall shape. The §4.6.3¶4 timeout verdict arrives for either, and
    the damping that follows does not ask which.)
    """

    def __init__(self):
        self.connections = 0
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
        try:
            await reader.read(4096)  # swallow the ClientHello...
            # ...wait for the rest of a handshake that never comes, and wake
            # on EOF when the client's E-timeout finally hangs up -- a held
            # Event would strand this handler, and the server's
            # wait_closed() with it.
            await reader.read(4096)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass  # never answering is the filter's whole trick
        finally:
            writer.close()


@pytest.fixture
async def dot():
    cert, key = _cert_paths()
    server = DotServer(cert, key)
    await server.start()
    yield server
    server.server.close()
    try:
        # Bounded even if a test failed before its dispose(): the handlers
        # this waits on are waiting on clients, and a client abandoned
        # mid-test has not hung up yet. wait_closed() unbound would turn a
        # visible failure into an invisible wall.
        await asyncio.wait_for(server.server.wait_closed(), 3.0)
    except TimeoutError:
        pass


class OnceDotServer(DotServer):
    """Answers the first query on each connection, then forgets how."""

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            (n,) = struct.unpack("!H", await reader.readexactly(2))
            query, _off = DnsPacket.parse(await reader.readexactly(n))
            self.queries.append(query)
            wire = bytes(_answer_for(query))
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            await reader.read()  # the second query falls into this void
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()


class GarbageDotServer(DotServer):
    """Answers every query with a well-framed lie: bytes no parser owes."""

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            while True:
                (n,) = struct.unpack("!H", await reader.readexactly(2))
                await reader.readexactly(n)
                blob = bytes(range(24))  # a legal frame length, an illegal DNS message
                writer.write(struct.pack("!H", len(blob)) + blob)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()


async def _dead_port():
    """A port just confirmed closed: bind it, then let go."""
    srv = await asyncio.start_server(lambda *_: None, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()
    return port


async def test_first_query_races_both_and_encryption_wins(dot):
    resolver = RacingResolver(dot_port=dot.port, do53_delay=E_WINS_DELAY)
    try:
        answer = await resolver.ask()
        assert answer is not None
        assert answer.ID == 0x9539
        assert resolver.do53_calls == 1  # the cleartext leg did go out (§4.6¶5)
        assert len(dot.queries) == 1
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.SUCCESS
        assert probe.ride()
    finally:
        await resolver.dispose()


async def test_success_silences_cleartext_for_the_next_query(dot):
    resolver = RacingResolver(dot_port=dot.port, do53_delay=E_WINS_DELAY)
    try:
        await resolver.ask()
        await resolver.ask()
        assert resolver.do53_calls == 1  # the second query never knew cleartext
        assert len(dot.queries) == 2  # and rode the one established session
        assert dot.connections == 1
    finally:
        await resolver.dispose()


async def test_the_handshake_carries_no_sni_and_offers_alpn_dot():
    cert, key = _cert_paths()
    server = SnoopingDotServer(cert, key)
    await server.start()
    resolver = RacingResolver(dot_port=server.port, do53_delay=E_WINS_DELAY)
    try:
        await resolver.ask()
        # §4.6.3.3¶4: nothing on the wire to correlate to a name; §4.4¶2:
        # the offer, accepted by a server that knows the protocol.
        assert server.hello == [(None, "dot")]
    finally:
        await resolver.dispose()
        await server.stop()


async def test_a_self_signed_authority_certificate_is_accepted(dot):
    """§4.6.3.4's MUST, demonstrated by construction: this fixture's
    certificate is trusted by nothing, and a verifying handshake would have
    raised instead of resolving."""
    resolver = RacingResolver(dot_port=dot.port, do53_delay=E_WINS_DELAY)
    try:
        await resolver.ask()
        assert resolver._dot_probe("127.0.0.1").status is ProbeStatus.SUCCESS
    finally:
        await resolver.dispose()


async def test_a_refused_853_answers_from_cleartext_and_damps():
    """The §4.1¶3 common case: a legacy authority behind a closed port."""
    port = await _dead_port()
    resolver = RacingResolver(dot_port=port)
    try:
        answer = await resolver.ask()
        assert answer is not None
        await resolver.settle()
        probe = resolver._dot_probe("127.0.0.1")
        # Which of the two closing verdicts arrives is the platform's: a
        # POSIX loopback answers the SYN with RST (fail, §4.6.5), Windows
        # black-holes it and the E-timeout clock closes it (timeout,
        # §4.6.3¶4). §4.6.3¶6 gates the retry identically for either.
        assert probe.status in (ProbeStatus.FAIL, ProbeStatus.TIMEOUT)
        before = resolver.do53_calls
        await resolver.ask()
        assert resolver.do53_calls == before + 1  # cleartext alone (§4.6.3¶6)
    finally:
        await resolver.dispose()


async def test_a_stalled_handshake_loses_the_race_but_keeps_learning():
    """The §4.6¶5 loser keeps running: the answer comes from cleartext now,
    and the encryption verdict -- timeout, damped -- arrives for the next
    query to honour."""
    sink = SinkServer()
    await sink.start()
    resolver = RacingResolver(dot_port=sink.port)
    try:
        answer = await resolver.ask()
        assert answer is not None  # cleartext, while the handshake goes nowhere
        await resolver.settle()  # E-timeout (2 s under FAST) lands in the table
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.TIMEOUT
        # Counted only once the learner has finished: the accept is the
        # loop's own work, and the race does not wait for it to answer.
        assert sink.connections == 1
        await resolver.ask()
        await resolver.settle()
        assert sink.connections == 1  # damped: no second SYN to a filtering host
    finally:
        await resolver.dispose()
        await sink.stop()


async def test_a_server_that_drops_the_stream_falls_back_and_retries_promptly():
    """§4.6.7 end to end: clean shutdown mid-session must cost the caller
    nothing, damp nothing, and take the next query back to the encrypted
    transport at once."""
    cert, key = _cert_paths()
    server = SessionKiller(cert, key)
    await server.start()
    resolver = RacingResolver(dot_port=server.port, do53_delay=E_WINS_DELAY)
    try:
        await resolver.ask()  # establishes
        server.kill_sessions()  # the authority gets tired of us
        answer = await resolver.ask()  # the ride finds an EOF; §4.6.5's fallback
        assert answer is not None
        assert resolver.do53_calls == 2  # cleartext carried exactly that one query
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.SUCCESS  # §4.6.7: not a failure
        await resolver.ask()  # and the retry is prompt (§4.6.7¶4's note)
        # Two connections, not three: the second query rode the dying
        # stream rather than opening a one of its own, and the third paid
        # for the fresh one §4.6.7¶4 promises.
        assert server.connections == 2
        assert resolver.do53_calls == 2  # ...over encryption, again silently
    finally:
        await resolver.dispose()
        await server.stop()


async def test_a_mismatched_answer_discredits_the_session():
    """A stream that answers someone else's question is desynced, not
    merely unlucky (§4.6.9¶12's "malformed or a failure"): retire it, damp
    it, and let the cleartext half that was racing carry this query."""
    cert, key = _cert_paths()
    server = WrongIdDotServer(cert, key)
    await server.start()
    resolver = RacingResolver(dot_port=server.port)
    try:
        answer = await resolver.ask()
        assert answer is not None  # cleartext's, the encrypted half having failed
        await resolver.settle()
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.FAIL
        assert not probe.ride()
    finally:
        await resolver.dispose()
        await server.stop()


async def test_keepalive_zero_retires_the_session_without_blame():
    """An authority that answers with keepalive 0 (§7828 §3.2.2¶3) is
    closed after the answer and carries no failure: the next query
    initiates fresh while success is still remembered."""
    cert, key = _cert_paths()
    server = DotServer(cert, key, keepalive=0)
    await server.start()
    resolver = RacingResolver(dot_port=server.port, do53_delay=E_WINS_DELAY)
    try:
        await resolver.ask()
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.SUCCESS
        assert not probe.ride()  # the session is gone, honestly
        await resolver.ask()
        assert server.connections == 2  # fresh initiation, promptly (§4.6.3¶6)
        assert resolver.do53_calls == 1  # still no cleartext: persistence holds
    finally:
        await resolver.dispose()
        await server.stop()


async def test_force_tcp_outranks_the_policy(dot):
    """A caller that named its transport gets it named: the policy is the
    resolver's default choice, not an override of the walk's own."""
    resolver = RacingResolver(dot_port=dot.port)
    try:
        await resolver.query(
            [DnsQuestion(QNAME, DnsQType.A)], None, localhost_glue(), force_tcp=True
        )
        assert resolver.tcp_calls == 1
        assert resolver.do53_calls == 0
        # The policy never consulted a table: the flag is the resolver's
        # default choice, and a caller that named its transport outranks it.
        assert not getattr(resolver, "_dot_probes", {})
    finally:
        await resolver.dispose()


async def test_aclose_retires_the_encrypted_sessions(dot):
    resolver = RacingResolver(dot_port=dot.port, do53_delay=E_WINS_DELAY)
    await resolver.ask()
    session = resolver._dot_sessions["127.0.0.1"]
    assert not session.closed
    resolver._close_tcp_sessions()
    assert session.closed
    assert resolver._dot_sessions == {}


async def test_a_session_that_stops_answering_is_treated_as_failure():
    """§4.6.6's established-then-broken, in the form §4.2¶4 warns of: the
    TLS channel lives, the server does not respond. That is a transport
    failure to be damped, not a per-query shrug -- and the query in flight
    when the silence is noticed still reaches cleartext."""
    cert, key = _cert_paths()
    server = OnceDotServer(cert, key)
    await server.start()
    resolver = RacingResolver(dot_port=server.port, do53_delay=E_WINS_DELAY)
    resolver.query_timeout = 0.3  # the exchange's own clock, shortened to test speed
    try:
        await resolver.ask()  # establishes; the server's one answer is spent
        answer = await resolver.ask()  # the ride goes silent: stall, §4.6.6
        assert answer is not None  # cleartext's, via the §4.6.5 fallback
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.TIMEOUT  # damped, not merely retired
        before = resolver.do53_calls
        await resolver.ask()
        assert resolver.do53_calls == before + 1  # and the retry waits for damping
    finally:
        await resolver.dispose()
        await server.stop()


async def test_a_malformed_answer_retires_and_damps_the_session():
    """A stream that returns undecidable bytes is desynced by definition
    (§4.6.9¶12's malformed branch): the session goes, the address is
    damped, and the racing cleartext half carries the query."""
    cert, key = _cert_paths()
    server = GarbageDotServer(cert, key)
    await server.start()
    resolver = RacingResolver(dot_port=server.port)
    try:
        answer = await resolver.ask()
        assert answer is not None  # cleartext's again
        await resolver.settle()
        probe = resolver._dot_probe("127.0.0.1")
        assert probe.status is ProbeStatus.FAIL
        assert probe.ride() is False
        assert not getattr(resolver, "_dot_sessions", {})  # the stream was closed, not kept
    finally:
        await resolver.dispose()
        await server.stop()
