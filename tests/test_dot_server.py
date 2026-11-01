"""The DoT server side of the transport (RFC 7858): namespy answering namespy.

Every test here is a real handshake on a real loopback socket -- the
certificate check, the ALPN offer and the length-prefixed framing under TLS
are the feature, and faking them would test the fake. The certificate is the
same static, test-only fixture the stub's DoT tests use (``tests/certs``,
for the reasons recorded there: a checked-in pair the handshake speaks
through stdlib alone, so no CI matrix job skips a whole transport).

The obligations carry their audited numbers: section 3.3 paragraph 1's
framing is the framing the stream protocol already speaks, section 3.2
paragraph 1 sends the client through [BCP195] -- which makes the *client's*
refusal of a wrong identity a test of the client's posture, honored here
rather than simulated, section 3.4 paragraph 1's reuse and section 3.1
paragraph 4's hour of refusal-memory arrive through the StubResolver
forwarder this server delegates to, and from RFC 9539 section 4.4 paragraph 2
the ALPN of 'dot' -- offered, and not a veto.

The reflex zone rides along deliberately: it is the only name that can
answer "which transport did this query actually cross", and a forwarding
chain with it -- cleartext in, TLS out, the answer naming the hop that is
encrypted -- is the closed loop this increment is named for.
"""

import asyncio
import pathlib
import ssl
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_server as srv

from namespy.edns import ERROR_OPTION_CODE, find_option
from namespy.enums import DnsQType, DnsResponseCode
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsQClass, DnsQuestion, Query
from namespy.server import (
    DOT_ALPN,
    DOT_DEFAULT_PORT,
    EDE_NO_REACHABLE_AUTHORITY,
    REFLEXIVE_NAME,
    DnsStreamServer,
    dot_ssl_context,
    whoami_responder,
)
from namespy.stub import StubResolver, Upstream

CERTS = pathlib.Path(__file__).parent / "certs"
CERT = str(CERTS / "dot-test.pem")
KEY = str(CERTS / "dot-test-key.pem")
CERT_NAME = "dot.test"
PEER = ("203.0.113.7", 53111)


class TrustingStub(StubResolver):
    """The stub with the fixture pinned -- the same seam test_stub_dot uses."""

    def _tls_context(self):
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=CERT)
        return context


async def _serve_dot(server, ssl_context=None):
    """The listener the CLI builds: the stream protocol, wrapped in TLS."""
    context = ssl_context if ssl_context is not None else dot_ssl_context(CERT, KEY)
    listener = await asyncio.get_running_loop().create_server(
        lambda: DnsStreamServer(server), host="127.0.0.1", port=0, ssl=context
    )
    return listener, listener.sockets[0].getsockname()[1]


async def _connect(port, *, alpn=("dot",), server_name=CERT_NAME):
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=CERT)
    if alpn:
        context.set_alpn_protocols(list(alpn))
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname=server_name
    )
    return reader, writer


async def _exchange(reader, writer, query):
    wire = bytes(query)
    writer.write(struct.pack("!H", len(wire)) + wire)  # section 3.3 paragraph 1
    await writer.drain()
    (length,) = struct.unpack("!H", await reader.readexactly(2))
    packet, _ = DnsPacket.parse(await reader.readexactly(length))
    return packet


def _whoami(qtype=DnsQType.TXT, packet_id=0x5501):
    return Query(ID=packet_id, questions=[DnsQuestion(REFLEXIVE_NAME, qtype, DnsQClass.IN)])


def _reflexive_server():
    server, _resolver, transport = srv.make_server()
    server.bind(REFLEXIVE_NAME, whoami_responder)
    return server, transport


def _txt_sentences(response):
    return " ".join(str(r.rdata) for r in response.answers)


async def _closed_port() -> int:
    """A port guaranteed to refuse: bound, read once, released."""
    probe = await asyncio.start_server(lambda *_: None, "127.0.0.1", 0)
    port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()
    return port


class TestTheListener:
    async def test_a_reflex_answer_arrives_over_tls_naming_dot(self):
        server, _ = _reflexive_server()
        listener, port = await _serve_dot(server)
        try:
            reader, writer = await _connect(port)
            try:
                response = await _exchange(reader, writer, _whoami())
                tls = writer.get_extra_info("ssl_object")
                assert tls.selected_alpn_protocol() == DOT_ALPN
            finally:
                writer.close()
        finally:
            listener.close()
        assert response.RCODE == DnsResponseCode.NO_ERROR
        sentence = _txt_sentences(response)
        # The whole point of the tls mark on the channel: a query that
        # crossed TLS answers "over dot", not "over tcp".
        assert "over dot" in sentence
        assert "127.0.0.1" in sentence

    async def test_the_alpn_is_an_offer_not_a_veto(self):
        server, _ = _reflexive_server()
        listener, port = await _serve_dot(server)
        try:
            reader, writer = await _connect(port, alpn=None)  # offer nothing
            try:
                response = await _exchange(reader, writer, _whoami())
                tls = writer.get_extra_info("ssl_object")
                assert tls.selected_alpn_protocol() is None
            finally:
                writer.close()
        finally:
            listener.close()
        # A negotiated result other than 'dot' is not grounds for rejection
        # -- neither RFC 7858 nor RFC 9539 makes it one, and inventing the
        # veto here would be stricter than either document.
        assert response.RCODE == DnsResponseCode.NO_ERROR
        assert "over dot" in _txt_sentences(response)

    async def test_a_wrong_identity_is_refused_by_the_client(self):
        # BCP 195's check is the client's (section 3.2 paragraph 1 sends it
        # there); what the server owes is an identity worth checking. This
        # asserts the pair holds: the pinned CA trusts this certificate, and
        # the hostname half -- the one that pins WHICH certificate -- still
        # fires. The server never hears the query the lie would have carried.
        server, _ = _reflexive_server()
        listener, port = await _serve_dot(server)
        try:
            with pytest.raises(ssl.SSLCertVerificationError):
                await _connect(port, server_name="evil.invalid")
        finally:
            listener.close()

    async def test_cleartext_bytes_on_the_tls_port_are_not_an_answer(self):
        server, _ = _reflexive_server()
        listener, port = await _serve_dot(server)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            query = bytes(_whoami())
            try:
                writer.write(struct.pack("!H", len(query)) + query)
                await writer.drain()
                # A framed query is not a ClientHello: the handshake dies,
                # and the TLS port answers nothing in cleartext -- the
                # "MUST NOT be port 53" separation made physical.
                header = await asyncio.wait_for(reader.readexactly(2), 2.0)
                raise AssertionError(f"cleartext query was answered: {header!r}")
            except (asyncio.IncompleteReadError, ConnectionResetError, ssl.SSLError):
                pass  # the honest outcome: silence and a closed stream
            finally:
                writer.close()
        finally:
            listener.close()


class TestForwarding:
    """The closed loop: this server's DoT client authenticating this server's DoT listener."""

    async def test_namespy_authenticates_namespy(self):
        upstream, _up_transport = _reflexive_server()
        up_listener, up_port = await _serve_dot(upstream)
        stub = None
        try:
            downstream, _resolver, down_transport = srv.make_server(
                dot_upstreams=[
                    Upstream("127.0.0.1", port=up_port, transport="dot", server_name=CERT_NAME)
                ]
            )
            # The seam the enterprise CA walks through is the seam the test
            # pins its fixture through: the forwarder is StubResolver, and
            # _tls_context is its documented extension point.
            stub = downstream._forwarder = TrustingStub(downstream._dot_upstreams)
            query = Query(
                ID=0x5502, questions=[DnsQuestion(REFLEXIVE_NAME, DnsQType.TXT, DnsQClass.IN)]
            )
            downstream.datagram_received(bytes(query), PEER)
            await srv.drain(downstream)

            (response,) = down_transport.replies
            assert response.ID == query.ID
            assert response.RCODE == DnsResponseCode.NO_ERROR
            assert response.AA is False  # relayed authority is not this server's to claim
            sentence = _txt_sentences(response)
            assert "over dot" in sentence  # the answered hop was the encrypted one
            assert "127.0.0.1" in sentence
        finally:
            if stub is not None:
                await stub.aclose()
            up_listener.close()

    async def test_forwarder_holds_one_connection_across_queries(self):
        upstream, _ = _reflexive_server()
        up_listener, up_port = await _serve_dot(upstream)
        stub = None
        try:
            downstream, _resolver, down_transport = srv.make_server(
                dot_upstreams=[
                    Upstream("127.0.0.1", port=up_port, transport="dot", server_name=CERT_NAME)
                ]
            )
            stub = downstream._forwarder = TrustingStub(downstream._dot_upstreams)
            for i in range(3):
                question = DnsQuestion(REFLEXIVE_NAME, DnsQType.TXT, DnsQClass.IN)
                downstream.datagram_received(
                    bytes(Query(ID=0x6000 + i, questions=[question])), PEER
                )
                await srv.drain(downstream)
            # Section 3.4 paragraph 1: reuse "to avoid excess TCP
            # connections, each with a single query" -- three answers, one
            # held session, and the second and third skip the handshake.
            assert len(stub._sessions) == 1
            assert len(down_transport.replies) == 3
        finally:
            if stub is not None:
                await stub.aclose()
            up_listener.close()

    async def test_bound_names_are_never_a_question_for_a_stranger(self):
        # The forwarder points at nobody (a port with no listener). A bound
        # name must still answer -- guards and responders precede the
        # forwarder -- while everything else falls to SERVFAIL.
        closed = await _closed_port()
        downstream, _resolver, down_transport = srv.make_server(
            dot_upstreams=[
                Upstream("127.0.0.1", port=closed, transport="dot", server_name=CERT_NAME)
            ]
        )
        downstream._forwarder = TrustingStub(downstream._dot_upstreams)
        downstream.bind(REFLEXIVE_NAME, whoami_responder)
        try:
            downstream.datagram_received(bytes(_whoami(packet_id=0x7001)), PEER)
            # Windows lets a connect to a just-closed loopback listener sit
            # the first SYN retransmission (~2 s) before refusing: the
            # silence is real, it is just not instantaneous here.
            await srv.drain(downstream, timeout=5.0)
            (response,) = down_transport.replies
            assert response.RCODE == DnsResponseCode.NO_ERROR
            assert "over udp" in _txt_sentences(response)  # and nothing left this box
        finally:
            await downstream.aclose()

    async def test_silence_answers_servfail_explaining_no_reachable_authority(self):
        closed = await _closed_port()
        downstream, _resolver, down_transport = srv.make_server(
            dot_upstreams=[
                Upstream("127.0.0.1", port=closed, transport="dot", server_name=CERT_NAME)
            ]
        )
        downstream._forwarder = TrustingStub(downstream._dot_upstreams)
        try:
            question = DnsQuestion(DomainName("forwarded.test."), DnsQType.A, DnsQClass.IN)
            query = Query(ID=0x7002, questions=[question])
            query.add_edns(1232)  # the explanation rides on OPT, and OPT goes
            # only to requestors that asked for EDNS (RFC 6891 section 7)
            downstream.datagram_received(bytes(query), PEER)
            await srv.drain(downstream, timeout=5.0)  # as above: the OS clock of refusal
            (response,) = down_transport.replies
            assert response.RCODE == DnsResponseCode.SERVER_FAILURE
            option = find_option(response.edns_options(), ERROR_OPTION_CODE)
            assert option is not None
            (info_code,) = struct.unpack("!H", option.data[:2])
            assert info_code == EDE_NO_REACHABLE_AUTHORITY
        finally:
            await downstream.aclose()


class TestTheContext:
    def test_context_floors_tls12_and_loads_the_fixture(self):
        context = dot_ssl_context(CERT, KEY)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        # The ALPN offer itself is asserted where it is observable: the
        # negotiated result on a live handshake, in TestTheListener.

    def test_context_reports_an_unloadable_pair(self):
        with pytest.raises(ValueError, match="cannot load DoT certificate"):
            dot_ssl_context(str(CERTS / "nope.pem"), KEY)

    def test_dot_port_default_is_853(self):
        assert DOT_DEFAULT_PORT == 853

    def test_forward_dot_upstream_requires_the_name(self):
        # The #<name> is not a label: without an identity the mandatory
        # check has nothing to check, and parsing says so.
        with pytest.raises(ValueError, match="names no server"):
            Upstream.parse("198.51.100.7:853", transport="dot")


class TestCliGuards:
    def test_serve_dot_without_identity_is_refused(self):
        from namespy.__main__ import main

        with pytest.raises(SystemExit) as exit_info:
            main(["--serve", "--serve-dot"])
        assert exit_info.value.code == 2

    def test_tls_flags_outside_serve_are_refused(self):
        from namespy.__main__ import main

        with pytest.raises(SystemExit):
            main(["--serve-dot", "example.org"])
        with pytest.raises(SystemExit):
            main(["--forward-dot", "198.51.100.7#up.example", "example.org"])

    def test_dot_port_defaults_to_the_dedicated_port(self):
        from namespy.__main__ import build_parser

        args = build_parser().parse_args(["--serve", "--serve-dot"])
        assert args.dot_port == DOT_DEFAULT_PORT
