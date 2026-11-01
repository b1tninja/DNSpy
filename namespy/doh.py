"""DNS over HTTPS for the stub (RFC 8484), as the transport of a forwarded query.

The exchange is small -- one DNS message in, one DNS message out -- and
everything deliberate about this module comes from saying so in HTTP terms:

* the URI is the configured template (§3¶1), the document's one variable
  filled by the wire query;
* POST carries the body (§4.1.1's ``content-type: application/dns-message``)
  by default, because "POSTed requests are generally smaller than their GET
  equivalents" (§4.1¶5); the GET form (``?dns=<base64url>``, §4.1¶2's
  variable, base64url with no padding per §6) is the protocol's second
  MUST-facing half and is implemented -- ``method="GET"`` selects it;
* the transaction ID is 0 in every request (§4.1¶8: HTTP already
  correlates request and response, and a varying ID splits cache entries
  for identical questions);
* the header set is the minimum (§8.2¶10's advice "to expose the minimal
  set of data"): method, scheme, authority, path, ``accept``,
  ``content-type`` and the content framing -- no user-agent, no cookie,
  nothing else a server could use to group this stub's clients (§8.2's
  catalogue of correlation data, declined by construction);
* the server is authenticated (§8.1¶1: "DoH encrypts DNS traffic and
  requires authentication of the server"), against the same ``server_name``
  the ``dot`` transport verifies, and the scheme is https-only (§5¶1).

Beneath that, HTTP/2 when the ALPN conversation negotiates it (§5.2's
"minimum RECOMMENDED version": §4.2¶3's multi-streaming -- "each DNS
request-response pair is mapped to one HTTP exchange", deliverable in any
order -- becomes concurrent streams on one held connection) and HTTP/1.1
when it does not (§5.2¶2 concedes earlier HTTP "capable of conveying the
semantic requirements ... but may result in very poor performance": one
exchange at a time on a kept connection, closed conservatively when idle).
``h2`` is an optional extra; the HTTP/1.1 path is stdlib-only, so an
install without the extra still does DoH, just one query at a time.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import ssl

from .enums import DnsQR
from .packet import DnsPacket

try:  # the optional extra, probed at import the way namespy probes crypto
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings

    H2_AVAILABLE = True
except ImportError:  # pragma: no cover
    # The name stays unbound: every reference to h2 below the import sits
    # behind an H2_AVAILABLE check (open_doh_session raises the install
    # sentence before a session is built), so rebinding it to None here
    # only taught mypy a lie -- on a minimal install the import resolves
    # to Any, and the None assignment was the unused-ignore CI caught.
    H2_AVAILABLE = False

LOGGER = logging.getLogger("namespy.stub")

#: §6's media type for the DNS wire format, in both directions.
DNS_MESSAGE_MEDIA_TYPE = "application/dns-message"

#: The idle horizon for an HTTP/1.1 keep-alive connection: HTTP offers no
#: edns-tcp-keepalive equivalent at its own layer, so the stub applies the
#: same conservative 30-second reading it gives its TCP streams (RFC 7828
#: §6's suggested default, borrowed one layer up).
_HTTP1_IDLE_S = 30.0


def base64url(data: bytes) -> str:
    """§6's encoding: base64url, and "base64url MUST NOT be padded" (§6¶5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def get_path(template_path: str, wire: bytes) -> str:
    """Fill §4.1's URI template for a GET: ``<path>{?dns}`` over *wire*."""
    return f"{template_path}?dns={base64url(wire)}"


def _question_key(question) -> tuple:
    return (str(question.name).lower(), int(question.qtype), int(question.qclass))


def questions_echo(query_questions, response_questions) -> bool:
    """The response answers *these* questions -- §4.1.1's correlation, HTTP edition.

    With the ID deliberately zero (§4.1¶8), the question section is the
    whole of what ties an answer to its query: the datagram path's matching
    rule minus the ID, and just as unforgiving of anything else that
    arrives. §3¶3's refusal to honour "an unsolicited response that appears
    to be a valid answer" starts at this door.
    """
    if len(query_questions) != len(response_questions):
        return False
    return all(
        _question_key(a) == _question_key(b)
        for a, b in zip(query_questions, response_questions, strict=True)
    )


class _DohError(Exception):
    """The exchange did not produce an answer -- said, never guessed around."""


class _DohSession:
    """One authenticated HTTPS connection to a DoH server.

    Subclasses own the HTTP conversation; :func:`open_doh_session` picks
    between them from the negotiated ALPN, so the authentication, the URI
    discipline and the header minimum are shared no matter which HTTP
    answers.
    """

    def __init__(self, reader, writer, upstream, *, method: str = "POST"):
        self.reader = reader
        self.writer = writer
        self.upstream = upstream
        self.method = method
        self.lock = asyncio.Lock()
        self.timer: asyncio.TimerHandle | None = None
        self.closed = False

    @property
    def multiplexed(self) -> bool:
        """Whether concurrent queries may share this session at once."""
        return False

    async def dns_query(self, wire: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def keep_alive(self, loop) -> None:
        """Called with the connection still open after a successful exchange."""

    def cancel_idle(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

    def close_now(self) -> None:
        self.closed = True
        self.cancel_idle()
        writer, self.writer = self.writer, None
        if writer is not None:
            try:
                writer.close()
            except Exception as exc:  # best-effort teardown, said not raised
                LOGGER.debug("doh_close_failed(err=%s)", type(exc).__name__)
                del exc

    async def exchange(self, dns_packet, wire: bytes):
        """Send §4's message, parse the body, and refuse anything else.

        A non-2xx status carries no DNS answer (§4.2.1¶2 -- the caller
        decides among §4.2.1's retries; this client's part is not to invent
        a reply from an HTTP error), a foreign media type is the same
        refusal, and a message whose questions do not match the ones sent
        never becomes an answer at all.
        """
        body = await self.dns_query(wire)
        response, _off = DnsPacket.parse(body)
        if response.QR != DnsQR.RESPONSE or not questions_echo(
            dns_packet.questions, response.questions
        ):
            raise _DohError("response does not answer the query it carried")
        return response


class _Http2Session(_DohSession):
    """HTTP/2: concurrent streams on one held connection (§4.2¶3's multi-streaming).

    One reader task turns ``receive_data`` events into future resolutions;
    each in-flight query is a stream id and its future. The flow-control
    bookkeeping is what makes a full 64 KiB DNS response (plausible under
    DNSSEC) deliverable: the initial window is widened in the SETTINGS the
    connection opens with, and every DATA frame is acknowledged as its
    bytes are buffered here -- credit returned, the server free to send on.
    """

    def __init__(self, reader, writer, upstream, **kwargs):
        super().__init__(reader, writer, upstream, **kwargs)
        self.conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        self.conn.initiate_connection()
        self.conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1 << 20})
        # SETTINGS covers per-stream credit; the connection window starts at
        # 65535 and is a separate budget (RFC 7540 §6.9.2). A 90 KB DNSSEC
        # answer spends connection credit even inside the big streams, and a
        # server honouring the small one would stall until this side found
        # the answer in its own buffer and acked -- which a waiting reader
        # never does. Grant the connection room to answer, like every real
        # client does.
        self.conn.increment_flow_control_window(1 << 20)
        self.writer.write(self.conn.data_to_send())
        self._pending: dict[int, tuple[asyncio.Future, dict]] = {}
        self._reader_task: asyncio.Task | None = None

    @property
    def multiplexed(self) -> bool:
        return True

    def start_reader(self) -> None:
        self._reader_task = asyncio.get_running_loop().create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                data = await self.reader.read(65535)
                if not data:
                    raise _DohError("server closed the connection")
                for event in self.conn.receive_data(data):
                    self._on_event(event)
                out = self.conn.data_to_send()
                if out:
                    self.writer.write(out)
                    await self.writer.drain()
        except Exception as exc:
            self._fail_all(exc)

    def _on_event(self, event) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            self._headers(event)
        elif isinstance(event, h2.events.DataReceived):
            self._data(event)
        elif isinstance(event, h2.events.StreamEnded):
            self._end(event.stream_id)
        elif isinstance(event, h2.events.StreamReset):
            self._reset(event.stream_id)
        elif isinstance(event, h2.events.ConnectionTerminated):
            self._fail_all(_DohError("server sent GOAWAY"))

    def _headers(self, event) -> None:
        entry = self._pending.setdefault(
            event.stream_id, (asyncio.get_running_loop().create_future(), {})
        )
        # h2 hands headers as raw bytes on both sides of the colon; this
        # client's lookups (§4.2.1's status, §4.2.1¶1's media type) are text.
        entry[1].update({k.decode("ascii"): v.decode("ascii") for k, v in event.headers})

    def _data(self, event) -> None:
        entry = self._pending.get(event.stream_id)
        if entry is None:
            return
        entry[1]["body"] = entry[1].get("body", b"") + event.data
        # The bytes are buffered here, so they are consumed: return the
        # window credit and let a long response keep arriving.
        self.conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        out = self.conn.data_to_send()
        if out:
            self.writer.write(out)

    def _end(self, stream_id) -> None:
        entry = self._pending.pop(stream_id, None)
        if entry is None:
            return
        future, headers = entry
        status = int(headers.get(":status", 0))
        if not 200 <= status < 300:
            # §4.2.1¶2: a non-success carries no reply to the question.
            future.set_exception(_DohError(f"DoH server answered HTTP {status}"))
            return
        media = headers.get("content-type", "").split(";")[0].strip().lower()
        if media != DNS_MESSAGE_MEDIA_TYPE:
            future.set_exception(
                _DohError(f"DoH server answered {media!r}, not {DNS_MESSAGE_MEDIA_TYPE}")
            )
            return
        future.set_result(headers.get("body", b""))

    def _reset(self, stream_id) -> None:
        entry = self._pending.pop(stream_id, None)
        if entry is not None:
            entry[0].set_exception(_DohError(f"server reset stream {stream_id}"))

    def _fail_all(self, exc) -> None:
        error = exc if isinstance(exc, _DohError) else _DohError(str(exc) or type(exc).__name__)
        self.close_now()
        for future, _headers in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    def request_target(self, wire: bytes) -> str:
        if self.method == "GET":
            return get_path(self.upstream.path, wire)
        return self.upstream.path

    async def dns_query(self, wire: bytes) -> bytes:
        if self.closed or self.writer is None:
            raise _DohError("connection closed")
        stream_id = self.conn.get_next_available_stream_id()
        self._pending[stream_id] = (asyncio.get_running_loop().create_future(), {})
        headers = [
            (":method", self.method),
            (":scheme", "https"),
            (":authority", self.upstream.server_name),
            (":path", self.request_target(wire)),
            ("accept", DNS_MESSAGE_MEDIA_TYPE),
        ]
        if self.method == "POST":
            headers += [
                ("content-type", DNS_MESSAGE_MEDIA_TYPE),
                ("content-length", str(len(wire))),
            ]
        self.conn.send_headers(stream_id, headers, end_stream=self.method == "GET")
        if self.method == "POST":
            # RFC 7540 §6.5.2 bounds one DATA frame by the peer's setting,
            # and h2 refuses to split on its own -- a DNS query is far
            # under the 16384 default, and the loop costs one line.
            limit = int(self.conn.remote_settings.max_frame_size)
            for start in range(0, len(wire), limit):
                chunk = wire[start : start + limit]
                self.conn.send_data(stream_id, chunk, end_stream=start + limit >= len(wire))
        self.writer.write(self.conn.data_to_send())
        entry = self._pending.get(stream_id)
        if entry is None:  # failed between send and await
            raise _DohError("connection closed mid-query")
        return await entry[0]

    def close_now(self) -> None:
        was_open = not self.closed
        super().close_now()
        if was_open and self._reader_task is not None:
            self._reader_task.cancel()
            self._reader_task = None


class _Http1Session(_DohSession):
    """HTTP/1.1: one exchange at a time on a kept connection, serial by design.

    §5.2¶2's concession made flesh -- correct, kept alive conservatively,
    and deliberately not pipelined: a pipelined http/1.1 client owes
    reorder-failure recovery this stub would rather not own. The base
    class's lock is the serialiser; a caller holding it owns the connection
    for exactly one request-response pair.
    """

    async def dns_query(self, wire: bytes) -> bytes:
        if self.closed or self.writer is None:
            raise _DohError("connection closed")
        if self.method == "GET":
            target = get_path(self.upstream.path, wire)
            framing = ""
            body = b""
        else:
            target = self.upstream.path
            framing = f"Content-Type: {DNS_MESSAGE_MEDIA_TYPE}\r\nContent-Length: {len(wire)}\r\n"
            body = wire
        request = (
            f"{self.method} {target} HTTP/1.1\r\n"
            f"Host: {self.upstream.server_name}\r\n"
            f"Accept: {DNS_MESSAGE_MEDIA_TYPE}\r\n"
            f"{framing}"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("ascii")
        self.writer.write(request + body)
        await self.writer.drain()
        head = await self.reader.readuntil(b"\r\n\r\n")
        lines = head.decode("ascii", "replace").split("\r\n")
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
        if not 200 <= status < 300:
            raise _DohError(f"DoH server answered HTTP {status}")
        media = headers.get("content-type", "").split(";")[0].strip().lower()
        if media != DNS_MESSAGE_MEDIA_TYPE:
            raise _DohError(f"DoH server answered {media!r}, not {DNS_MESSAGE_MEDIA_TYPE}")
        if "content-length" in headers:
            body = await self.reader.readexactly(int(headers["content-length"]))
        elif headers.get("transfer-encoding", "").lower() == "chunked":
            body = await self._read_chunked()
        else:
            raise _DohError("DoH response carries no message length")
        if headers.get("connection", "").lower() == "close":
            self.close_now()
        return body

    async def _read_chunked(self) -> bytes:
        parts = []
        while True:
            size_line = await self.reader.readuntil(b"\r\n")
            size = int(size_line.split(b";")[0].strip(), 16)
            if size == 0:
                await self.reader.readuntil(b"\r\n")  # final CRLF after the last chunk
                break
            parts.append(await self.reader.readexactly(size))
            await self.reader.readexactly(2)  # CRLF terminating each chunk
        return b"".join(parts)

    def keep_alive(self, loop) -> None:
        if not self.closed:
            self.cancel_idle()
            self.timer = loop.call_later(_HTTP1_IDLE_S, self._on_idle)

    def _on_idle(self) -> None:
        self.timer = None
        self.close_now()


async def open_doh_session(reader, writer, upstream, **kwargs) -> _DohSession:
    """Wrap a connected TLS stream in the session its ALPN negotiated.

    §5.2 makes HTTP/2 the recommended floor and HTTP/1.1 legal, so the
    negotiated protocol -- not a config flag -- picks the session class,
    and a server that offers neither ALPN token gets the serial fallback
    rather than a hard failure.
    """
    tls = writer.get_extra_info("ssl_object")
    negotiated = tls.selected_alpn_protocol() if tls is not None else None
    if negotiated == "h2":
        if not H2_AVAILABLE:
            raise ImportError(
                "this DoH server negotiated HTTP/2, which needs the h2 package: "
                "install namespy[doh]"
            )
        session = _Http2Session(reader, writer, upstream, **kwargs)
        session.start_reader()
        return session
    return _Http1Session(reader, writer, upstream, **kwargs)


def doh_alpn(context: ssl.SSLContext) -> ssl.SSLContext:
    """Offer both HTTP versions, HTTP/2 first -- §5.2's order."""
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context
