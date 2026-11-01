"""The query log: one JSON line per pair, from every rung of the ladder.

The unit half pins the sink contract -- line per record, append, a
broken sink costing nothing. The pipeline half runs the real
``test_server`` harness against a log in a StringIO and reads the
records back as JSON: the field names the roadmap row promised
(timestamp, client, ID, qname/qtype, RCODE + EDE, sizes, TC,
transport, elapsed, the stale flag) and the ``origin`` vocabulary
(``bind``, ``policy``, ``forward``, ``recurse``, ``reject``) are the
claims under test, one test per rung plus the two honest absences:
the record for a datagram that never parsed carries ``null`` where
the question would be (the truth rather than a guess), and no record
claims a cache-vs-walk distinction the pipeline does not keep.
"""

import io
import ipaddress
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_server as srv

from namespy.cache import MemoryDnsCache
from namespy.enums import DnsRType
from namespy.filtering import FilterPolicy
from namespy.names import DomainName
from namespy.packet import DnsQClass, DnsRecord
from namespy.querylog import QueryLog
from namespy.rdata import RData_A
from namespy.resolver import RecursiveResolver
from namespy.server import StreamChannel

PEER = ("203.0.113.7", 53111)


def _log():
    sink = io.StringIO()
    return QueryLog(sink), sink


def _records(sink):
    return [json.loads(line) for line in sink.getvalue().splitlines()]


# ---------------------------------------------------------------- the sink


def test_emit_writes_one_parsable_line_per_record():
    log, sink = _log()
    log.emit({"qname": "example.com", "rcode": "NO_ERROR"})
    (record,) = _records(sink)
    assert record == {"qname": "example.com", "rcode": "NO_ERROR"}


def test_emit_appends_records_in_arrival_order():
    log, sink = _log()
    log.emit({"id": 1})
    log.emit({"id": 2})
    assert [r["id"] for r in _records(sink)] == [1, 2]


def test_a_broken_sink_costs_a_debug_line_and_nothing_else():
    class Broken:
        def write(self, text):
            raise OSError("disk full")

        def flush(self):
            pass

    # The answer already left the socket; a log must not reach back and
    # turn it into an exception inside the transport callback.
    QueryLog(Broken()).emit({"id": 1})


def test_non_ascii_names_survive_the_line_readable():
    log, sink = _log()
    log.emit({"qname": "münchen.test"})
    assert "münchen" in sink.getvalue()  # ensure_ascii=False: no \uXXXX drift


# ------------------------------------------------------------- the pipeline


def _answering_resolver():
    """A real resolver whose one step hands back the fixture answer."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())

    async def resolve(packet):
        return srv.answered_response(packet)

    resolver.resolve = resolve
    return resolver


def _welded_resolver():
    resolver = RecursiveResolver(cache=MemoryDnsCache())

    async def no_network(_packet):
        raise AssertionError("unreachable in these tests")

    resolver.resolve = no_network
    return resolver


async def _ask(server, name="www.example"):
    packet = srv.query_packet(name=DomainName(name))
    server.datagram_received(bytes(packet), PEER)
    await srv.drain(server)
    return packet


async def test_a_recursed_answer_records_every_promised_field():
    log, sink = _log()
    server, _resolver, transport = srv.make_server(resolver=_answering_resolver(), query_log=log)
    packet = srv.query_packet(name=DomainName("www.example"))
    server.datagram_received(bytes(packet), PEER)
    await srv.drain(server)

    (record,) = _records(sink)
    assert record["client"] == f"{PEER[0]}:{PEER[1]}"
    assert record["transport"] == "udp"
    assert record["origin"] == "recurse"
    assert record["id"] == packet.ID
    assert record["qname"] == "www.example."  # the wire's own canonical spelling
    assert record["rcode"] == "NO_ERROR"
    assert record["ede"] == []
    assert record["tc"] is False
    assert record["ad"] is False
    assert record["stale"] is False
    assert record["in_bytes"] == len(bytes(packet))
    assert record["out_bytes"] == len(transport.sent[0][0])
    assert isinstance(record["ts"], float)
    assert record["elapsed_ms"] >= 0


async def test_a_refusal_records_the_reject_rung():
    log, sink = _log()
    server, _resolver, _transport = srv.make_server(resolver=_welded_resolver(), query_log=log)
    packet = srv.query_packet(name=DomainName("www.example"))
    packet.OPCODE = 4  # unassigned opcodes are plain ints by enums.py's design
    server.datagram_received(bytes(packet), PEER)
    await srv.drain(server)

    (record,) = _records(sink)
    assert record["origin"] == "reject"
    assert record["rcode"] == "NOT_IMPLEMENTED"


async def test_a_datagram_that_never_parsed_records_nulls_rather_than_guesses():
    log, sink = _log()
    server, _resolver, _transport = srv.make_server(resolver=_welded_resolver(), query_log=log)
    server.datagram_received(b"\x00garbage\x00", PEER)
    await srv.drain(server)

    (record,) = _records(sink)
    assert record["origin"] == "reject"
    assert record["rcode"] == "FORMAT_ERROR"
    assert record["qname"] is None  # there was no question to name
    assert record["in_bytes"] is None  # and the parse never saw a whole


async def test_a_bound_answer_names_its_rung():
    log, sink = _log()
    server, _resolver, _transport = srv.make_server(resolver=_welded_resolver(), query_log=log)
    record_data = DnsRecord(
        DomainName("www.example"),
        DnsRType.A,
        DnsQClass.IN,
        60,
        rdata=RData_A(ipaddress.IPv4Address("93.184.216.34")),
    )
    server.bind(DomainName("www.example"), lambda _r: [record_data])
    await _ask(server)

    (record,) = _records(sink)
    assert record["origin"] == "bind"
    assert record["rcode"] == "NO_ERROR"


async def test_a_policy_answer_names_its_rung_and_carries_its_code():
    log, sink = _log()
    server, _resolver, _transport = srv.make_server(
        resolver=_welded_resolver(),
        query_log=log,
        filter_policy=FilterPolicy.from_cli(["block:ads.example"]),
    )
    await _ask(server, name="ads.example")

    (record,) = _records(sink)
    assert record["origin"] == "policy"
    assert record["rcode"] == "NAME_ERROR"
    assert record["ede"] == [15]


async def test_a_stale_answer_raises_the_flag_the_resolver_stamped():
    log, sink = _log()
    resolver = RecursiveResolver(cache=MemoryDnsCache())

    async def stale(packet):
        response = srv.answered_response(packet)
        response.stale_answer = True
        return response

    resolver.resolve = stale
    server, _resolver, _transport = srv.make_server(resolver=resolver, query_log=log)
    await _ask(server)

    (record,) = _records(sink)
    assert record["stale"] is True
    assert record["ede"] == [3]  # the Stale Answer code, per §4.4
    assert record["origin"] == "recurse"  # stale is a flag, not a fifth rung


async def test_the_stream_channels_name_themselves():
    log, sink = _log()
    server, _resolver, _transport = srv.make_server(resolver=_answering_resolver(), query_log=log)
    sent = []
    await server.respond_to_packet(
        srv.query_packet(name=DomainName("www.example")),
        PEER,
        channel=StreamChannel(sent.append),
    )
    await server.respond_to_packet(
        srv.query_packet(name=DomainName("www.example")),
        PEER,
        channel=StreamChannel(sent.append, tls=True),
    )

    plain, tls = _records(sink)
    assert plain["transport"] == "tcp"
    assert tls["transport"] == "dot"  # the reflex's honesty, shared with the log
    assert plain["in_bytes"] is None  # respond_to_packet was entered directly


async def test_two_queries_are_two_lines_in_arrival_order():
    log, sink = _log()
    server, _resolver, _transport = srv.make_server(resolver=_answering_resolver(), query_log=log)
    await _ask(server, name="first.test")
    await _ask(server, name="second.test")

    assert [r["qname"] for r in _records(sink)] == ["first.test.", "second.test."]


def test_a_server_without_a_log_is_the_server_it_always_was():
    # The rule the module docstring opens with: default off is not a
    # format choice but the first rule of serving applied to a file.
    server, _resolver, _transport = srv.make_server(resolver=_answering_resolver())
    assert server._query_log is None


# ------------------------------------------------------------------ the CLI


def test_the_flag_requires_serve(capsys):
    from namespy.__main__ import main

    with pytest.raises(SystemExit):
        main(["--serve-query-log", "queries.jsonl", "example.com"])
    assert "--serve" in capsys.readouterr().err


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
