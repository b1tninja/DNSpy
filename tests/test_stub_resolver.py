"""The stub resolver: the forwarding mode of RFC 1034 §5.3.1.

The tests drive :class:`~namespy.stub.StubResolver` the way the truncation
tests drive the walk's transport -- a recording stand-in for the datagram
socket, futures fulfilled by hand -- because what is under test is the
forwarding contract, not a network: ``RD`` set on the way out (§4.1.1's
"directs the name server to pursue the query recursively"), the answer
returned exactly as it arrived, a REFUSED read as this upstream declining the
arrangement (§4.1.1's "Recursive query support is optional") and the rest of
the list asked, and a SERVFAIL taken as an answer rather than a refusal --
that upstream did the work; the name failed.
"""

import asyncio

import pytest

from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.stub import StubResolver, Upstream, _host_address_record

QNAME = DomainName("example.com.")
UP_IP = "127.0.0.53"
BACKUP_IP = "127.0.0.54"


class RecordingTransport:
    """Stands in for the datagram transport, keeping what was sent where."""

    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))


def make_stub(upstreams):
    stub = StubResolver(upstreams)
    stub.transport = RecordingTransport()
    return stub


def answer_for(query, *, rcode=DnsResponseCode.NO_ERROR, ra=True, cd=False, ad=False):
    return Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        RA=ra,
        CD=cd,
        AD=ad,
        RD=query.RD,
        RCODE=rcode,
        questions=list(query.questions),
        answers=[DnsRecord(QNAME, DnsRType.A, DnsRClass.IN, 300, rdata=bytes([93, 184, 216, 34]))],
    )


async def start(stub, **kwargs):
    """Begin ``forward``; hand back the task and the (query, future) pending."""
    questions = [DnsQuestion(QNAME, DnsQType.A)]
    task = asyncio.get_running_loop().create_task(stub.forward(questions, **kwargs))
    await asyncio.sleep(0)
    key = next(iter(stub.queue))
    sent_query, future = stub.queue[key]
    return task, sent_query, future


# ------------------------------------------------------------------ the upstream record


def test_upstream_parse_addresses_with_and_without_ports():
    assert Upstream.parse("1.0.0.1") == Upstream("1.0.0.1", 53)
    assert Upstream.parse("1.0.0.1:5353") == Upstream("1.0.0.1", 5353)
    assert Upstream.parse(" 1.0.0.1:5353 ") == Upstream("1.0.0.1", 5353)
    assert Upstream.parse("2606:4700:4700::1001") == Upstream("2606:4700:4700::1001", 53)
    assert Upstream.parse("[2606:4700:4700::1001]:853") == Upstream("2606:4700:4700::1001", 853)


def test_upstream_normalizes_its_host_to_one_text_form():
    assert Upstream("FE80::0001").host == "fe80::1"
    assert Upstream("10.0.0.1").host == "10.0.0.1"


def test_upstream_refuses_names_ports_out_of_range_and_unknown_transports():
    with pytest.raises(ValueError, match="does not appear"):
        Upstream("ns.example.net")  # the stub resolves nothing, least of all itself
    with pytest.raises(ValueError, match="does not appear"):
        Upstream("010.0.0.1")  # ipaddress reads leading zeros as octal ambiguity, and so do we
    with pytest.raises(ValueError, match="usable port"):
        Upstream("10.0.0.1", port=0)
    with pytest.raises(ValueError, match="usable port"):
        Upstream("10.0.0.1", port=70000)
    with pytest.raises(ValueError, match="unknown upstream transport"):
        Upstream("10.0.0.1", transport="quic")
    with pytest.raises(ValueError, match="non-numeric port"):
        Upstream.parse("10.0.0.1:notaport")
    with pytest.raises(ValueError, match="unbalanced brackets"):
        Upstream.parse("[2001:db8::1")


def test_host_address_record_wraps_each_family():
    v4 = _host_address_record("10.0.0.1")
    assert int(v4.rtype) == int(DnsRType.A)
    v6 = _host_address_record("2001:db8::1")
    assert int(v6.rtype) == int(DnsRType.AAAA)


# ------------------------------------------------------------------ forwarding a query


async def drain_until(stub, attempts=10):
    """Let the forwarding loop run until the next upstream is pending."""
    for _ in range(attempts):
        await asyncio.sleep(0)
        if stub.queue:
            return next(iter(stub.queue.values()))
    raise AssertionError("the next upstream was never asked")


def resolve_pending(stub, answer):
    """Fulfil the pending question the way ``datagram_received`` would: pop, then answer."""
    key = next(iter(stub.queue))
    _query, future = stub.queue.pop(key)
    future.set_result(answer)


async def test_a_forwarded_query_asks_for_recursion_and_the_answer_comes_back_intact():
    stub = make_stub([Upstream(UP_IP)])
    task, sent_query, future = await start(stub)
    assert sent_query.RD is True  # §4.1.1: RD *is* the recursive arrangement
    upstream_answer = answer_for(sent_query, ra=True, ad=True)
    future.set_result(upstream_answer)
    response = await task
    assert response is upstream_answer  # returned as it arrived, not re-formed
    assert response.AD is True  # whatever the upstream asserted rides along
    assert response.RA is True


async def test_the_query_goes_to_the_configured_address_and_port():
    stub = make_stub([Upstream(UP_IP, port=5353)])
    task, sent_query, future = await start(stub)
    future.set_result(answer_for(sent_query))
    await task
    _wire, addr = stub.transport.sent[0]
    assert addr == (UP_IP, 5353)


async def test_client_cd_is_copied_onto_the_forwarded_query():
    """RFC 4035 §3.2.2: a forwarder that forgets CD shields a client that asked not to be."""
    stub = make_stub([Upstream(UP_IP)])
    task, sent_query, future = await start(stub, client_cd=True)
    assert sent_query.CD is True
    future.set_result(answer_for(sent_query))
    await task


async def test_rd_false_asks_the_upstream_authoritatively():
    stub = make_stub([Upstream(UP_IP)])
    task, sent_query, future = await start(stub, rd=False)
    assert sent_query.RD is False
    future.set_result(answer_for(sent_query))
    await task


async def test_a_refusal_asks_the_next_upstream_and_only_returns_it_if_none_will():
    """§4.1.1 optional recursion, read in the list's order: refusal is per-server."""
    stub = make_stub([Upstream(UP_IP), Upstream(BACKUP_IP)])
    task, sent_query, _future = await start(stub)
    resolve_pending(stub, answer_for(sent_query, rcode=DnsResponseCode.REFUSED, ra=False))
    # the backup is now the one being asked
    _query2, _future2 = await drain_until(stub)
    backup_answer = answer_for(sent_query, ra=True)
    resolve_pending(stub, backup_answer)
    response = await task
    assert response is backup_answer
    assert [addr for _wire, addr in stub.transport.sent] == [(UP_IP, 53), (BACKUP_IP, 53)]


async def test_when_every_upstream_refuses_the_refusal_is_the_answer():
    stub = make_stub([Upstream(UP_IP), Upstream(BACKUP_IP)])
    task, sent_query, _future = await start(stub)
    refusal = answer_for(sent_query, rcode=DnsResponseCode.REFUSED, ra=False)
    resolve_pending(stub, refusal)
    _query2, _future2 = await drain_until(stub)
    resolve_pending(stub, refusal)
    response = await task
    assert int(response.extended_rcode) == int(DnsResponseCode.REFUSED)


async def test_a_servfail_is_an_answer_not_a_refusal():
    """That upstream recursed and the name failed; the backups would say the same, later."""
    stub = make_stub([Upstream(UP_IP), Upstream(BACKUP_IP)])
    task, sent_query, _future = await start(stub)
    failure = answer_for(sent_query, rcode=DnsResponseCode.SERVER_FAILURE)
    resolve_pending(stub, failure)
    response = await task
    assert response is failure
    assert [addr for _wire, addr in stub.transport.sent] == [(UP_IP, 53)]  # no fan-out


async def test_silence_everywhere_answers_nothing():
    stub = make_stub([Upstream(UP_IP)])
    stub.query_timeout = 0.01  # the UDP answer never comes; the timeout is the test

    async def dead_tcp(host, wire, query_packet, port=53):
        return None

    stub._query_tcp = dead_tcp  # and neither does TCP (RFC 1035 §4.2.2's fallback tried)
    questions = [DnsQuestion(QNAME, DnsQType.A)]
    assert await stub.forward(questions) is None


async def test_a_tcp_upstream_asks_over_tcp_first_because_that_is_the_configuration():
    """force_tcp is the caller's transport choice, not a fallback this resolver inferred."""
    calls = []

    stub = make_stub([Upstream(UP_IP, port=853, transport="tcp")])
    stub.transport = RecordingTransport()

    async def tcp_answer(host, wire, query_packet, port=53):
        calls.append((host, port, query_packet.RD))
        return answer_for(query_packet)

    stub._query_tcp = tcp_answer
    questions = [DnsQuestion(QNAME, DnsQType.A)]
    response = await stub.forward(questions)
    assert int(response.extended_rcode) == int(DnsResponseCode.NO_ERROR)
    assert calls == [(UP_IP, 853, True)]
    assert stub.transport.sent == []  # UDP was never touched
