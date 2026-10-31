"""DNS over HTTPS for the stub (RFC 8484), against servers that really answer.

The h2 tests need the optional extra (skip-gated below); the HTTP/1.1 tests
run without it, because the fallback path is stdlib-only -- that split is
the feature, and the test layout says so. The servers are real: TLS with a
generated certificate, ALPN negotiated for each side of the §5.2 line, and
the flow-control bookkeeping exercised by a response deliberately built
larger than HTTP/2's default 65535-octet window.

The assertions carry their paragraphs: §4.1.1's method/headers, §4.1¶8's
zero ID, §4.1¶2's base64url GET (the RFC's own encoded example as the
golden value), §4.2¶3's multi-streaming, §4.2.1¶2's non-answer statuses,
and §8.1¶1's authentication at the same door the dot transport uses.
"""

import asyncio
import base64
import ssl

import pytest
from test_stub_dot import TrustingStub, _make_cert

from namespy.doh import DNS_MESSAGE_MEDIA_TYPE, H2_AVAILABLE, base64url, get_path
from namespy.enums import DnsQClass, DnsQR, DnsQType, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Response
from namespy.stub import StubResolver, Upstream

QNAME = DomainName("doh.example.")
CERT_NAME = "dot.test"  # the name _make_cert's certificate is issued for


def question():
    return [DnsQuestion(QNAME, DnsQType.A)]


def small_answer(query):
    return Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RD=query.RD,
        questions=list(query.questions),
        answers=[DnsRecord(QNAME, DnsRType.A, DnsQClass.IN, 60, rdata=bytes([203, 0, 113, 1]))],
    )


def big_answer(query):
    """A reply past HTTP/2's default 65535-octet window: thousands of A records."""
    answers = [
        DnsRecord(
            QNAME, DnsRType.A, DnsQClass.IN, 60, rdata=bytes([203, 0, (i // 256) % 256, i % 256])
        )
        for i in range(5600)
    ]
    return Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RD=query.RD,
        questions=list(query.questions),
        answers=answers,
    )


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    return _make_cert(tmp_path_factory.mktemp("dohcerts"))


class DohServer:
    """A TLS DoH server answering over h2, http/1.1, or whichever ALPN wins."""

    def __init__(
        self,
        cert,
        key,
        *,
        alpn="h2",
        status=200,
        media=DNS_MESSAGE_MEDIA_TYPE,
        big=False,
        wrong_question=False,
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols([alpn])
        self._context = context
        self.status = status
        self.media = media
        self.big = big
        self.wrong_question = wrong_question
        self.connections = 0
        self.requests: list[dict] = []
        self.queries: list = []
        self.server = None

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=self._context)

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    def _answer_for(self, query):
        answer = big_answer(query) if self.big else small_answer(query)
        if self.wrong_question:
            answer.questions = [DnsQuestion(DomainName("other.example."), DnsQType.A)]
        return answer

    async def _handle(self, reader, writer):
        self.connections += 1
        tls = writer.get_extra_info("ssl_object")
        if tls is not None and tls.selected_alpn_protocol() == "h2":
            await self._handle_h2(reader, writer)
        else:
            await self._handle_h1(reader, writer)

    async def _handle_h2(self, reader, writer):  # pragma: no cover - needs h2
        import h2.config
        import h2.connection
        import h2.events

        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()
        streams: dict[int, dict] = {}
        try:
            while True:
                data = await reader.read(65535)
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        streams[event.stream_id] = {"headers": dict(event.headers), "body": b""}
                    elif isinstance(event, h2.events.DataReceived):
                        streams[event.stream_id]["body"] += event.data
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        self._respond_h2(conn, streams.pop(event.stream_id), event.stream_id)
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
        except Exception:  # noqa: S110 - a client hanging up mid-stream is the test's own doing
            pass
        finally:
            writer.close()

    def _respond_h2(self, conn, request, stream_id):  # pragma: no cover - needs h2
        self.requests.append(request)
        body = b""
        if self.status == 200 and self.media == DNS_MESSAGE_MEDIA_TYPE:
            query, _off = DnsPacket.parse(request["body"])
            self.queries.append(query)
            body = bytes(self._answer_for(query))
        conn.send_headers(stream_id, [(":status", str(self.status)), ("content-type", self.media)])
        if not body:
            conn.send_data(stream_id, b"", end_stream=True)
            return
        limit = int(conn.remote_settings.max_frame_size)  # one DATA frame's cap
        for start in range(0, len(body), limit):
            conn.send_data(
                stream_id, body[start : start + limit], end_stream=start + limit >= len(body)
            )

    async def _handle_h1(self, reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head.decode("ascii", "replace").split("\r\n")
                method, target, _version = lines[0].split(" ", 2)
                headers = {}
                for line in lines[1:]:
                    name, sep, value = line.partition(":")
                    if sep:
                        headers[name.strip().lower()] = value.strip()
                body = b""
                if "content-length" in headers:
                    body = await reader.readexactly(int(headers["content-length"]))
                self.requests.append(
                    {"method": method, "path": target, "headers": headers, "body": body}
                )
                dns_body = b""
                if self.status == 200 and self.media == DNS_MESSAGE_MEDIA_TYPE:
                    if method == "GET":
                        _, _, b64 = target.partition("?dns=")
                        dns_body = base64.urlsafe_b64decode((b64 + "=" * (-len(b64) % 4)).encode())
                    else:
                        dns_body = body
                    query, _off = DnsPacket.parse(dns_body)
                    self.queries.append(query)
                    dns_body = bytes(self._answer_for(query))
                reply = (
                    f"HTTP/1.1 {self.status} X\r\n"
                    f"content-type: {self.media}\r\n"
                    f"content-length: {len(dns_body)}\r\n"
                    "\r\n"
                ).encode("ascii")
                writer.write(reply + dns_body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, EOFError):
            pass
        finally:
            writer.close()


requires_h2 = pytest.mark.skipif(not H2_AVAILABLE, reason="HTTP/2 needs the doh extra")


@pytest.fixture
async def doh(cert):
    """Launch real DoH servers on demand; build upstreams and trusting stubs."""
    started: list[DohServer] = []

    async def launch(**server_kwargs):
        server = DohServer(cert[0], cert[1], **server_kwargs)
        await server.start()
        started.append(server)
        return server

    def upstream(server, name=CERT_NAME, path="/dns-query", **kwargs):
        return Upstream(
            "127.0.0.1", port=server.port, transport="doh", server_name=name, path=path, **kwargs
        )

    def stub(server, upstreams=None, **kwargs):
        return TrustingStub(
            upstreams if upstreams is not None else [upstream(server)], cafile=cert[0], **kwargs
        )

    yield launch, upstream, stub
    for server in started:
        await server.stop()


# ---------------------------------------------------------------- the conversation (h2)


@requires_h2
async def test_a_doh_forward_arrives_posted_and_comes_back_intact(doh):
    launch, _upstream, stub = doh
    server = await launch()
    resolver = stub(server)
    try:
        response = await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert response.RA is True
    record = server.requests[0]
    assert record["headers"][b":method"] == b"POST"  # RFC 8484 §4.1.1
    assert record["headers"][b":path"] == b"/dns-query"
    assert record["headers"][b"content-type"] == DNS_MESSAGE_MEDIA_TYPE.encode()
    assert record["headers"][b"accept"] == DNS_MESSAGE_MEDIA_TYPE.encode()
    assert server.queries[0].RD is True


@requires_h2
async def test_the_id_is_zero_on_the_wire(doh):
    """RFC 8484 §4.1¶8: HTTP correlates the exchange, not the DNS ID."""
    launch, _upstream, stub = doh
    server = await launch()
    resolver = stub(server)
    try:
        await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert server.queries[0].ID == 0


@requires_h2
async def test_the_connection_is_held_and_reused(doh):
    launch, _upstream, stub = doh
    server = await launch()
    resolver = stub(server)
    try:
        await resolver.forward(question())
        await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert server.connections == 1  # one HTTP/2 connection, two exchanges
    assert len(server.queries) == 2


@requires_h2
async def test_concurrent_queries_ride_streams_on_one_connection(doh):
    """§4.2¶3's multi-streaming: the whole point of the HTTP/2 half."""
    launch, _upstream, stub = doh
    server = await launch()
    resolver = stub(server)
    try:
        await resolver.forward(question())  # establish the connection first
        answers = await asyncio.gather(*[resolver.forward(question()) for _ in range(3)])
    finally:
        await resolver.aclose()
    assert all(a is not None and a.RA for a in answers)
    assert server.connections == 1
    assert len(server.queries) == 4


@requires_h2
async def test_a_response_larger_than_the_default_window_arrives(doh):
    """The 65535-octet default window would deadlock without the bookkeeping."""
    launch, _upstream, stub = doh
    server = await launch(big=True)
    resolver = stub(server)
    try:
        response = await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert response is not None
    assert len(response.answers) == 5600


# ---------------------------------------------------------------- the fallback (http/1.1)


async def test_http1_round_trips_and_reuses_the_connection(doh):
    launch, _upstream, stub = doh
    server = await launch(alpn="http/1.1")
    resolver = stub(server)
    try:
        first = await resolver.forward(question())
        second = await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert first is not None
    assert second is not None
    assert server.connections == 1  # keep-alive held, serialised by the lock
    assert len(server.queries) == 2
    record = server.requests[0]
    assert record["method"] == "POST"  # RFC 8484 §4.1.1's posting, in HTTP/1.1 dress
    assert record["path"] == "/dns-query"
    assert record["headers"]["content-type"] == DNS_MESSAGE_MEDIA_TYPE


async def test_http1_arms_its_idle_timer_after_an_answer(doh):
    launch, _upstream, stub = doh
    server = await launch(alpn="http/1.1")
    resolver = stub(server)
    try:
        await resolver.forward(question())
        session = next(iter(resolver._sessions.values()))
        assert session.timer is not None  # the conservative 30s life, not RFC 7828's advice
        assert session.lock.locked() is False  # and nobody is holding the line
    finally:
        await resolver.aclose()


async def test_get_carries_the_message_in_the_dns_parameter(doh):
    launch, _upstream, stub = doh
    server = await launch(alpn="http/1.1")
    resolver = stub(server, doh_method="GET")
    try:
        response = await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert response is not None
    record = server.requests[0]
    assert record["method"] == "GET"
    assert record["path"].startswith("/dns-query?dns=")  # §4.1's template, filled
    assert record["body"] == b""


def test_base64url_matches_rfc_8484s_own_example():
    """§4.1.1¶5's encoded message, byte for byte -- the golden vector."""
    example = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    wire = base64.urlsafe_b64decode(example + "==")  # 33 bytes: no padding to begin with
    assert base64url(wire) == example  # and back out, padded-off, unchanged
    packet, _off = DnsPacket.parse(wire)
    assert str(packet.questions[0].name) == "www.example.com."
    assert base64url(b"\xfb\xff") == "-_8"  # the alphabet's two exotic characters, §6¶4


# ---------------------------------------------------------------- refusals


async def test_a_non_200_is_not_an_answer(doh):
    """§4.2.1¶2: 400/405/500 say there is no answer to be had."""
    launch, _upstream, stub = doh
    server = await launch(alpn="http/1.1", status=400)
    resolver = stub(server)
    try:
        assert await resolver.forward(question()) is None
    finally:
        await resolver.aclose()


async def test_a_body_that_is_not_dns_message_is_not_an_answer(doh):
    launch, _upstream, stub = doh
    server = await launch(alpn="http/1.1", media="text/plain")
    resolver = stub(server)
    try:
        assert await resolver.forward(question()) is None
    finally:
        await resolver.aclose()


async def test_a_message_about_someone_else_is_not_an_answer(doh):
    """§4.2.1¶1: even a 200 with a parseable body must answer the question asked."""
    launch, _upstream, stub = doh
    server = await launch(alpn="http/1.1", wrong_question=True)
    resolver = stub(server)
    try:
        assert await resolver.forward(question()) is None
    finally:
        await resolver.aclose()


async def test_a_connection_failure_is_remembered():
    upstream = Upstream("127.0.0.1", port=9, transport="doh", server_name=CERT_NAME)
    resolver = StubResolver([upstream])
    try:
        assert await resolver.forward(question()) is None
        assert resolver._stream_dead  # doh shares the dot transport's memory
    finally:
        await resolver.aclose()


# ---------------------------------------------------------------- addressing


def test_doh_upstreams_carry_a_path_and_a_default_port():
    """The #<name>/<path> suffix (§3¶1's configured template) and §2.1's port."""
    doh = Upstream.parse("2001:db8::53#dns.example/dns-query", transport="doh")
    assert doh.transport == "doh"
    assert doh.port == 443  # RFC 8484 §2.1: the default derives from the declared transport
    assert doh.path == "/dns-query"
    assert doh.server_name == "dns.example"
    bespoke = Upstream.parse("198.51.100.8:8443#resolver.example/resolve", transport="doh")
    assert bespoke.path == "/resolve"
    assert bespoke.port == 8443  # an explicit port outranks the transport's default


def test_the_declared_transport_default_port_survives_parsing():
    """The bug this closes: replace-after-parse kept udp's 53 under dot."""
    assert Upstream.parse("1.2.3.4#dns.example", transport="dot").port == 853


def test_doh_without_a_name_is_refused():
    """§8.1¶1: no name, no DoH -- the same bar the dot transport clears."""
    with pytest.raises(ValueError, match="names no server"):
        Upstream("198.51.100.8", port=443, transport="doh")
    with pytest.raises(ValueError, match="names no server"):
        Upstream.parse("198.51.100.8", transport="doh")


def test_get_path_fills_the_template():
    assert get_path("/dns-query", b"\x00\x90") == "/dns-query?dns=" + base64url(b"\x00\x90")
    assert get_path("/dns-query", b"\x00\x90") == "/dns-query?dns=AJA"  # two-byte golden
