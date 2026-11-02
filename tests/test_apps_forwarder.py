"""The forwarder: the composition handle as executable claims (roadmap W4).

``namespy/apps/forwarder.py`` adds no protocol logic -- it assembles the pieces
``serve()`` already wires -- so every test here is a claim about the *assembly*:
which objects get built, that the relay routes through the forwarder rung and never
the recursive one, that the composed server forwards to the transports configured
(not the ``dot`` the parameter name hints), and that lifecycle frees what it opened.
No real port is bound and no datagram leaves a socket: the engine loop's endpoint and
server factories are patched the way ``test_cli.py`` patches them, and the composed
``DnsServer`` is driven through ``respond_to_packet`` directly. Conventions from
``test_apps_lookup.py`` and ``test_engine.py``.
"""

import types

import pytest

from namespy.apps.forwarder import Forwarder
from namespy.engine import Engine
from namespy.enums import DnsQType, DnsResponseCode
from namespy.names import DomainName
from namespy.packet import DnsQuestion, Query
from namespy.resolver import RecursiveResolver
from namespy.server import DnsServer
from namespy.stub import StubResolver

ADDR = ("127.0.0.1", 5053)


class _FakeTransport:
    def __init__(self):
        self.closed = False
        self.sent = []

    def sendto(self, data, addr=None):
        self.sent.append(bytes(data))

    def get_extra_info(self, key, default=None):
        return default

    def close(self):
        self.closed = True


class _FakeStreamServer:
    def __init__(self):
        self.closed = False
        self.sockets = [types.SimpleNamespace(getsockname=lambda: ("127.0.0.1", 53))]

    def close(self):
        self.closed = True


def _patch_loop(eng):
    """Bind real DnsServer/RecursiveResolver protocols onto fake transports."""
    seen = {"endpoints": [], "servers": []}

    async def fake_endpoint(factory, **_kwargs):
        protocol = factory()
        transport = _FakeTransport()
        if isinstance(protocol, (DnsServer, RecursiveResolver)):
            protocol.connection_made(transport)
            seen["endpoints"].append((type(protocol).__name__, protocol, transport))
            return transport, protocol
        return _FakeTransport(), protocol  # the backstop's private IPv6 bring-up sink

    async def fake_create_server(factory, **_kwargs):
        factory()  # constructs the DnsStreamServer(front) offline
        stream = _FakeStreamServer()
        seen["servers"].append(stream)
        return stream

    eng._ensure_loop()
    eng._loop.create_datagram_endpoint = fake_endpoint
    eng._loop.create_server = fake_create_server
    return seen


def _query(name="example.com.", qtype=DnsQType.A, *, packet_id=4242):
    packet = Query(questions=[DnsQuestion(DomainName(name), qtype)])
    packet.ID = packet_id
    return packet


def _drive(eng, server, packet):
    async def go():
        await server.respond_to_packet(packet, ADDR)

    eng.run(go())


@pytest.fixture
def eng():
    engine = Engine("namespy-engine-forwarder-test")
    try:
        yield engine
    finally:
        if not engine._closed:
            engine.close()


def _served_forwarder(eng, *, upstreams=("10.1.1.1",)):
    forwarder = Forwarder(list(upstreams), engine=eng, name="namespy-forwarder-test")
    forwarder.serve()
    return forwarder


def test_serve_binds_one_front_and_one_backstop_and_reports_running(eng):
    seen = _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    try:
        kinds = [name for name, _p, _t in seen["endpoints"]]
        assert "DnsServer" in kinds
        assert "RecursiveResolver" in kinds
        assert forwarder.running is True
        assert len(seen["servers"]) == 1, "serve_tcp binds one TCP listener (BCP 235)"
    finally:
        forwarder.stop()


def test_serve_is_idempotent(eng):
    seen = _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    try:
        endpoints_after_first = len(seen["endpoints"])
        forwarder.serve()
        assert len(seen["endpoints"]) == endpoints_after_first, "a second serve() rebinds nothing"
    finally:
        forwarder.stop()


def test_the_relay_forwards_over_the_configured_transport_not_dot(eng):
    # The reuse trick: Upstream objects reach the server's forwarder unchanged, so a
    # plain udp upstream forwards over udp even though the parameter is dot_upstreams.
    _patch_loop(eng)
    forwarder = _served_forwarder(eng, upstreams=("10.1.1.1",))
    try:
        forwarder_st = forwarder._server._forwarder
        assert isinstance(forwarder_st, StubResolver)
        assert [u.host for u in forwarder_st.upstreams] == ["10.1.1.1"]
        assert forwarder_st.upstreams[0].transport == "udp"
    finally:
        forwarder.stop()


def test_a_query_is_relayed_and_recursion_is_never_reached(eng):
    _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    server = forwarder._server
    try:
        canned = types.SimpleNamespace(
            ID=0, questions=[], AA=True, AD=True, answers=["rec"], RCODE=DnsResponseCode.NO_ERROR
        )

        async def fake_forward(questions, **_kwargs):
            return canned

        server._forwarder.forward = fake_forward
        replies = []
        server._reply = lambda response, addr, **kw: replies.append((response, addr, kw))
        server._error = lambda *_a, **_k: pytest.fail("silence path taken, but upstream answered")

        async def no_recurse(*_a, **_k):  # pragma: no cover - must never run
            raise AssertionError("a forwarding server must not recurse")

        server.resolver.resolve = no_recurse

        _drive(eng, server, _query())
        assert len(replies) == 1
        response, addr, kwargs = replies[0]
        assert kwargs["request"].ID == 4242
        assert addr == ADDR
        assert response.ID == 4242, "the client's ID, not the forwarder's"
        assert response.AA is False, "authority is upstream's, never this relay's"
        assert next(iter(response.questions)).name == DomainName("example.com.")
    finally:
        forwarder.stop()


def test_silence_from_upstreams_answers_servfail_with_edn22(eng):
    _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    server = forwarder._server
    try:

        async def silent(questions, **_kwargs):
            return None

        server._forwarder.forward = silent
        errors = []
        server._error = lambda _p, _a, rcode, **kw: errors.append((rcode, kw))
        server._reply = lambda *_a, **_k: pytest.fail("answered path, but upstreams were silent")

        _drive(eng, server, _query())
        assert len(errors) == 1
        rcode, kwargs = errors[0]
        assert rcode == DnsResponseCode.SERVER_FAILURE
        edes = kwargs.get("extended_errors", ())
        assert any(int.from_bytes(opt.data[:2], "big") == 22 for opt in edes), (
            "EDE 22 No Reachable Authority"
        )
    finally:
        forwarder.stop()


def test_an_exception_from_the_forwarder_is_silence_not_a_traceback(eng):
    _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    server = forwarder._server
    try:

        async def boom(questions, **_kwargs):
            raise OSError("upstream socket died")

        server._forwarder.forward = boom
        errors = []
        server._error = lambda _p, _a, rcode, **_kw: errors.append(rcode)
        _drive(eng, server, _query())
        assert errors == [DnsResponseCode.SERVER_FAILURE]
    finally:
        forwarder.stop()


def test_stats_summarizes_the_in_memory_query_log(eng):
    _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    try:
        forwarder._query_log.emit({"origin": "forward", "rcode": 0})
        forwarder._query_log.emit({"origin": "forward", "rcode": 0})
        forwarder._query_log.emit({"origin": "forward", "rcode": 2})
        assert forwarder.stats() == {"served": 3, "by_origin": {"forward": 3}, "servfail": 1}
        forwarder.reset_stats()
        assert forwarder.stats()["served"] == 0
    finally:
        forwarder.stop()


def test_stop_frees_every_socket_and_listener(eng):
    _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    server_transport = forwarder._server_transport
    backstop_transport = forwarder._backstop_transport
    stream = forwarder._stream_server
    forwarder.stop()
    assert server_transport.closed
    assert backstop_transport.closed
    assert stream.closed
    assert forwarder.running is False


def test_stop_is_idempotent_and_a_borrowed_engine_survives(eng):
    _patch_loop(eng)
    forwarder = _served_forwarder(eng)
    forwarder.stop()
    forwarder.stop()  # second stop releases nothing twice and does not raise
    assert eng._closed is False, "a borrowed engine outlives the Forwarder that used it"


def test_serving_a_closed_forwarder_raises_by_name(eng):
    _patch_loop(eng)
    forwarder = Forwarder(["10.1.1.1"], engine=eng, name="namespy-forwarder-test")
    forwarder.serve()
    forwarder.stop()
    with pytest.raises(RuntimeError, match="closed"):
        forwarder.serve()


async def test_async_serve_and_stop(eng):
    _patch_loop(eng)
    forwarder = Forwarder(["10.1.1.1"], engine=eng, name="namespy-forwarder-test")
    async with forwarder as f:
        assert f.running is True
    assert forwarder.running is False
