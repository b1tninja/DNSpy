"""DNS over TLS for the stub (RFC 7858) and the keepalive that paces it (RFC 7828).

These drive a real ``ssl`` server on loopback -- the handshake, the
certificate check and the length-prefixed framing are the feature, and
faking them would test the fake. The certificate is generated per session
(the ``crypto`` extra; the module skips without it), and the client's trust
is extended through the documented :meth:`StubResolver._tls_context` seam,
the same door an enterprise CA walks through.

The obligations under test carry their numbers: §3.3¶1's framing, §3.3¶3's
matching, §3.4's reuse ("SHOULD reuse a single TCP connection to the
recursive resolver"), §3.1¶4's hour of remembering a server that refused
TLS, §4.1's implicit corollary that a name to authenticate is required
(this build declines the unauthenticated profile outright), and from RFC
7828: §3.2.1¶4's empty request option, §3.2.2¶2's honouring of the offered
timeout, §3.2.2¶3's zero-means-close.
"""

import asyncio
import ipaddress
import ssl
import struct
from datetime import UTC, datetime, timedelta

import pytest

cryptography = pytest.importorskip(
    "cryptography", reason="the TLS fixture's certificate needs namespy[crypto]"
)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from namespy.edns import (  # noqa: E402
    KEEPALIVE_OPTION_CODE,
    EdnsOption,
    find_option,
    keepalive_of,
    keepalive_option,
)
from namespy.enums import DnsQR, DnsQType  # noqa: E402
from namespy.names import DomainName  # noqa: E402
from namespy.packet import DnsPacket, DnsQuestion, Response  # noqa: E402
from namespy.stub import (  # noqa: E402
    _KEEPALIVE_DEFAULT_S,
    _KEEPALIVE_FLOOR_S,
    StubResolver,
    Upstream,
)

QNAME = DomainName("dot.example.")
CERT_NAME = "dot.test"


def _make_cert(tmp_path):
    """A day-long self-signed ECDSA certificate for ``dot.test``/127.0.0.1."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_NAME)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(CERT_NAME), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "dot-test.pem"
    key_path = tmp_path / "dot-test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class DotServer:
    """A TLS DNS server: answers every well-framed query, records everything."""

    def __init__(self, cert, key, keepalive=100):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self._context = context
        # seconds to offer; None = send no option at all; "empty" = zero-length
        self.keepalive = keepalive
        self.connections = 0
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

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            while True:
                nbuf = await reader.readexactly(2)
                (n,) = struct.unpack("!H", nbuf)
                data = await reader.readexactly(n)
                query, _off = DnsPacket.parse(data)
                self.queries.append(query)
                answer = Response(
                    ID=query.ID,
                    QR=DnsQR.RESPONSE,
                    RA=True,
                    RD=query.RD,
                    questions=list(query.questions),
                )
                options = ()
                if self.keepalive == "empty":
                    options = (EdnsOption(KEEPALIVE_OPTION_CODE, b""),)
                elif self.keepalive is not None:
                    options = (
                        EdnsOption(KEEPALIVE_OPTION_CODE, struct.pack("!I", self.keepalive)),
                    )
                answer.add_edns(1232, options=options)
                wire = bytes(answer)
                writer.write(struct.pack("!H", len(wire)) + wire)  # §3.3¶1: one write
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass  # the client hung up: the normal end of an idle keepalive life
        finally:
            writer.close()


class TrustingStub(StubResolver):
    """The stub with one extra root -- the fixture's CA, through the seam."""

    def __init__(self, *args, cafile, **kwargs):
        self._cafile = cafile
        super().__init__(*args, **kwargs)

    def _tls_context(self):
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=self._cafile)
        return context


def question():
    return [DnsQuestion(QNAME, DnsQType.A)]


@pytest.fixture
async def dot(tmp_path):
    """A running DoT server plus factories for upstreams and trusting stubs."""
    cert, key = _make_cert(tmp_path)
    server = DotServer(cert, key)
    await server.start()

    def upstream(name=CERT_NAME, **kwargs):
        return Upstream("127.0.0.1", port=server.port, transport="dot", server_name=name, **kwargs)

    def stub(upstreams=None, **kwargs):
        return TrustingStub(
            upstreams if upstreams is not None else [upstream()], cafile=cert, **kwargs
        )

    yield server, upstream, stub
    await server.stop()


# ---------------------------------------------------------------- the conversation


async def test_a_dot_forward_arrives_authenticated_and_comes_back_intact(dot):
    server, _upstream, stub = dot
    resolver = stub()
    try:
        response = await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert response.RA is True
    assert [str(q.name) for q in server.queries[0].questions] == [str(QNAME)]
    assert server.queries[0].RD is True  # §4.1.1's arrangement, over TLS too
    assert server.connections == 1


async def test_the_query_asks_to_keep_the_connection_alive(dot):
    """RFC 7828 §3.2.1¶4: the client's option is present and empty."""
    server, _upstream, stub = dot
    resolver = stub()
    try:
        await resolver.forward(question())
    finally:
        await resolver.aclose()
    option = find_option(server.queries[0].edns_options(), KEEPALIVE_OPTION_CODE)
    assert option is not None
    assert option.data == b""


async def test_the_connection_is_held_and_reused(dot):
    """§3.4¶1-¶2: one connection for many queries, not one per query."""
    server, _upstream, stub = dot
    resolver = stub()
    try:
        first = await resolver.forward(question())
        second = await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert first is not None
    assert second is not None
    assert server.connections == 1
    assert len(server.queries) == 2


async def test_concurrent_queries_share_the_one_connection(dot):
    server, _upstream, stub = dot
    resolver = stub()
    try:
        await resolver.forward(question())  # establish first: no connection race
        pair = await asyncio.gather(resolver.forward(question()), resolver.forward(question()))
    finally:
        await resolver.aclose()
    first, second = pair
    assert first is not None
    assert second is not None
    assert server.connections == 1
    assert len(server.queries) == 3


# ---------------------------------------------------------------- the keepalive clock


async def test_a_zero_timeout_closes_the_stream_immediately(dot):
    """§3.2.2¶3: "send no more queries on that connection" means this one."""
    server, _upstream, stub = dot
    server.keepalive = 0
    resolver = stub()
    try:
        await resolver.forward(question())
        assert resolver._sessions == {}
        await resolver.forward(question())
    finally:
        await resolver.aclose()
    assert server.connections == 2  # the closed stream was not reused


async def test_an_offered_timeout_keeps_the_stream(dot):
    """§3.2.2¶2: with a timeout honoured, the connection is kept, not closed."""
    server, _upstream, stub = dot
    server.keepalive = 100
    resolver = stub()
    try:
        await resolver.forward(question())
        session = next(iter(resolver._sessions.values()))
        assert session.timer is not None  # armed; the horizon itself is _idle_seconds'
        session.cancel_idle()  # leave nothing scheduled behind the test
    finally:
        await resolver.aclose()


async def test_a_timeout_below_the_floor_still_keeps_the_stream(dot):
    server, _upstream, stub = dot
    server.keepalive = 1
    resolver = stub()
    try:
        await resolver.forward(question())
        session = next(iter(resolver._sessions.values()))
        assert session.timer is not None
        session.cancel_idle()
    finally:
        await resolver.aclose()


async def test_a_server_that_names_no_timeout_is_held_on_the_default(dot):
    server, _upstream, stub = dot
    server.keepalive = "empty"  # supports keepalive, offers no number
    resolver = stub()
    try:
        await resolver.forward(question())
        session = next(iter(resolver._sessions.values()))
        assert session.timer is not None
        session.cancel_idle()
    finally:
        await resolver.aclose()


def test_the_idle_horizon_is_the_offer_floored_or_the_default():
    from namespy.stub import _idle_seconds

    assert _idle_seconds(None) == _KEEPALIVE_DEFAULT_S
    assert _idle_seconds(100) == 100.0
    assert _idle_seconds(1) == _KEEPALIVE_FLOOR_S  # reuse at 1s costs more than it saves
    assert _idle_seconds(0) == _KEEPALIVE_FLOOR_S  # unreachable: close-now fires first


# ---------------------------------------------------------------- authentication


async def test_a_name_mismatch_fails_closed_and_is_remembered(dot):
    """§3.1¶4: a server whose handshake fails is not re-pounded for an hour."""
    server, upstream, stub = dot
    resolver = stub([upstream(name="evil.test")])
    try:
        assert await resolver.forward(question()) is None
        assert resolver._dot_dead  # the memory the paragraph asks for
        attempts = server.connections  # a failed handshake may never be accepted
        assert await resolver.forward(question()) is None
        assert server.connections == attempts  # remembered dead: not even a SYN
    finally:
        await resolver.aclose()


async def test_dot_without_a_name_to_authenticate_is_refused_at_the_door():
    with pytest.raises(ValueError, match="no server to authenticate"):
        Upstream("1.2.3.4", transport="dot")


def test_dot_defaults_to_853():
    assert Upstream("1.2.3.4", transport="dot", server_name="x.test").port == 853
    assert Upstream("1.2.3.4").port == 53
    assert Upstream.parse("[::1]:853#x.test").port == 853


# ---------------------------------------------------------------- the option parse


def test_keepalive_request_form_is_code_eleven_and_empty():
    option = keepalive_option()
    assert option.code == KEEPALIVE_OPTION_CODE == 11
    assert option.data == b""


def test_keepalive_of_reads_the_offerings():
    def opts(data):
        return (EdnsOption(KEEPALIVE_OPTION_CODE, data),)

    assert keepalive_of(opts(struct.pack("!I", 120))) == 120
    assert keepalive_of(opts(struct.pack("!I", 0))) == 0  # close now, not "none"
    assert keepalive_of(opts(b"\x1e")) == 30  # the draft-era octet form still says 30
    assert keepalive_of(opts(b"")) is None  # supports keepalive, offers no number
    assert keepalive_of(opts(b"\x01\x02")) is None  # a length nobody defined
    assert keepalive_of(()) is None  # the §3.2.2¶4 "no keepalive here"
