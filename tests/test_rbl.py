"""The blocklist client: names by RFC, etiquette by label, three states.

The name-building tests are the RFC half (octets reversed per RFC 1035
section 3.5, nibbles per RFC 3596 section 2.5). The interpret tests are
the convention half -- and the one that matters most is the smallest:
SERVFAIL must read as ``unknown``, never as ``not-listed``, because a
zone that declined to answer did not answer "innocent". The CLI half
stays off the network: validation errors are checked at the parser
(fail-fast, before anything binds), and the print-and-exit-code path
runs ``cli_rbl`` against a monkeypatched client with canned answers.
"""

import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_server as srv

from namespy.enums import DnsQClass, DnsResponseCode, DnsRType
from namespy.packet import DnsRecord, Response
from namespy.rbl import (
    MAX_LISTING_TTL,
    RblVerdict,
    interpret,
    rbl_query_name,
    reverse_address,
)
from namespy.rdata import RData_A, RData_TXT

ZONE = "zen.example"


def _a(address, ttl=300):
    return DnsRecord(
        rbl_query_name("203.0.113.7", ZONE),
        DnsRType.A,
        DnsQClass.IN,
        ttl,
        rdata=RData_A(ipaddress.IPv4Address(address)),
    )


def _txt(text, ttl=300):
    return DnsRecord(
        rbl_query_name("203.0.113.7", ZONE),
        DnsRType.TXT,
        DnsQClass.IN,
        ttl,
        rdata=RData_TXT([text.encode("utf-8")]),
    )


def _response(rcode=DnsResponseCode.NO_ERROR, answers=()):
    return Response(RCODE=rcode, answers=list(answers))


# ------------------------------------------------------------ the names


def test_an_ipv4_ptr_name_reverses_the_octets_under_in_addr_arpa():
    # RFC 1035 section 3.5's tree.
    assert str(reverse_address("203.0.113.7")) == "7.113.0.203.in-addr.arpa"


def test_an_ipv6_ptr_name_reverses_every_nibble_under_ip6_arpa():
    # RFC 3596 section 2.5: bit groups, all 32 nibbles, reversed.
    assert (
        str(reverse_address("2001:db8::1"))
        == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    )


def test_a_list_leaf_hangs_the_reversed_address_on_the_zone_not_on_arpa():
    # The classic wrong shape is the PTR name with a zone behind it --
    # no list publishes there; this pins the right one.
    assert str(rbl_query_name("203.0.113.7", ZONE)) == "7.113.0.203.zen.example"
    assert "in-addr" not in str(rbl_query_name("203.0.113.7", ZONE))


def test_an_ipv6_leaf_shares_the_ptr_nibbles_and_takes_the_zone_tail():
    leaf = str(rbl_query_name("2001:db8::1", ZONE))
    assert leaf.endswith(".8.b.d.0.1.0.0.2.zen.example")
    assert leaf.count(".") == 33  # 32 nibbles plus the zone's two labels


def test_address_objects_and_strings_build_the_same_name():
    got = reverse_address(ipaddress.IPv4Address("203.0.113.7"))
    assert got == reverse_address("203.0.113.7")


def test_a_non_address_is_refused_as_the_value_error_it_is():
    with pytest.raises(ValueError, match="does not appear"):
        reverse_address("nope")


# ------------------------------------------------------------ the verdict


def test_a_127_code_means_listed_and_carries_its_ttl():
    verdict = interpret("203.0.113.7", ZONE, _response(answers=[_a("127.0.0.2", ttl=60)]))
    assert verdict.status == "listed"
    assert verdict.listed is True
    assert verdict.codes == ("127.0.0.2",)
    assert verdict.ttl == 60
    assert verdict.zone_ttl == 60


def test_the_polite_cache_ceiling_caps_a_day_at_an_hour_and_says_so():
    assert MAX_LISTING_TTL == 3600
    verdict = interpret("203.0.113.7", ZONE, _response(answers=[_a("127.0.0.2", ttl=43200)]))
    assert verdict.ttl == 3600
    assert verdict.zone_ttl == 43200  # the cap is disclosed, not silent
    assert "zone asked for 43200s" in verdict.describe()


def test_several_codes_arrive_sorted_and_deduplicated():
    response = _response(answers=[_a("127.0.0.4"), _a("127.0.0.2"), _a("127.0.0.2")])
    verdict = interpret("203.0.113.7", ZONE, response)
    assert verdict.codes == ("127.0.0.2", "127.0.0.4")


def test_nxdomain_from_the_zone_is_the_only_no_the_zone_can_give():
    verdict = interpret("203.0.113.7", ZONE, _response(rcode=DnsResponseCode.NAME_ERROR))
    assert verdict.status == "not-listed"


def test_a_refusal_is_not_innocence():
    # The three-state promise: SERVFAIL is unknown, never not-listed.
    verdict = interpret("203.0.113.7", ZONE, _response(rcode=DnsResponseCode.SERVER_FAILURE))
    assert verdict.status == "unknown"
    assert "SERVER_FAILURE" in verdict.reason


def test_a_failed_lookup_is_unknown_too():
    assert interpret("203.0.113.7", ZONE, None).status == "unknown"


def test_noerror_without_a_loopback_code_declines_to_be_read():
    verdict = interpret("203.0.113.7", ZONE, _response(answers=[]))
    assert verdict.status == "unknown"
    verdict = interpret("203.0.113.7", ZONE, _response(answers=[_a("10.0.0.2")]))
    assert verdict.status == "unknown"


def test_txt_at_the_leaf_rides_as_the_explanation_best_effort():
    verdict = interpret(
        "203.0.113.7",
        ZONE,
        _response(answers=[_a("127.0.0.2")]),
        _response(answers=[_txt("listed by policy")]),
    )
    assert verdict.explanations == ("listed by policy",)
    assert 'explanation: "listed by policy"' in verdict.describe()


def test_a_split_txt_record_reads_back_as_one_text():
    # RFC 1035 section 3.3.14's multi-character-string encoding, re-joined.
    record = DnsRecord(
        rbl_query_name("203.0.113.7", ZONE),
        DnsRType.TXT,
        DnsQClass.IN,
        60,
        rdata=RData_TXT([b"long-", b"listing"]),
    )
    verdict = interpret(
        "203.0.113.7", ZONE, _response(answers=[_a("127.0.0.2")]), _response(answers=[record])
    )
    assert verdict.explanations == ("long-listing",)


def test_the_verdict_describes_itself_in_few_lines():
    verdict = RblVerdict("1.2.3.4", "z", "not-listed", reason="the leaf does not exist")
    assert verdict.describe() == "1.2.3.4 in z: NOT-LISTED (the leaf does not exist)"


# ------------------------------------------------------------------ the CLI


def test_the_bareword_subcommand_reaches_the_same_parser():
    from namespy.__main__ import main

    # The NAME-positional error can only be reached through --rbl, so it
    # proves the 'rbl ADDRESS ZONE name' rewrite happened.
    with pytest.raises(SystemExit):
        main(["rbl", "1.2.3.4", "zone.test", "extra-name"])


def test_a_bad_address_is_said_before_anything_leaves_the_process(capsys):
    from namespy.__main__ import main

    with pytest.raises(SystemExit):
        main(["--rbl", "nope", "zone.test"])
    assert "--rbl" in capsys.readouterr().err


def test_rbl_and_serve_are_different_jobs(capsys):
    from namespy.__main__ import main

    with pytest.raises(SystemExit):
        main(["--rbl", "1.2.3.7", "zone.test", "--serve"])
    assert "--serve" in capsys.readouterr().err


def test_ptr_refuses_to_fight_the_positionals(capsys):
    from namespy.__main__ import main

    with pytest.raises(SystemExit):
        main(["--ptr", "10.20.30.40", "example.com"])
    with pytest.raises(SystemExit):
        main(["--ptr", "not-an-ip"])


class _CannedAsker:
    """Answers the two RBL questions from memory; everything else is a bug."""

    def __init__(self, a_response, txt_response):
        self.a_response = a_response
        self.txt_response = txt_response
        self.seen = []

    async def resolve(self, query):
        qtype = int(query.questions[0].qtype)
        self.seen.append(qtype)
        if qtype == int(DnsRType.TXT):
            return self.txt_response
        return self.a_response

    async def aclose(self):
        pass


def _rbl_args(address="203.0.113.7", zone=ZONE):
    from types import SimpleNamespace

    return SimpleNamespace(
        rbl=[address, zone],
        forward=None,
        qclass=DnsQClass.IN,
        timeout=5,
        dnssec=False,
        no_edns=False,
        no_query_padding=True,
    )


async def _run_cli_rbl(monkeypatch, capsys, a_response, txt_response):
    import namespy.__main__ as entry

    asker = _CannedAsker(a_response, txt_response)

    class _ClosingTransport(srv.FakeTransport):
        def close(self):  # the CLI's finally closes the client socket
            pass

    async def fake_start(_loop, _args):
        return _ClosingTransport(), asker

    monkeypatch.setattr(entry, "_start_recursive_client", fake_start)
    code = await entry.cli_rbl(_rbl_args())
    return code, capsys.readouterr().out, asker


async def test_the_cli_prints_the_verdict_and_exits_zero_when_listed(monkeypatch, capsys):
    code, out, asker = await _run_cli_rbl(
        monkeypatch,
        capsys,
        _response(answers=[_a("127.0.0.2", ttl=60)]),
        _response(answers=[_txt("zen says so")]),
    )
    assert code == 0
    assert ": LISTED" in out  # the colon keeps NOT-LISTED from satisfying it
    assert "127.0.0.2" in out
    assert "zen says so" in out
    assert asker.seen == [int(DnsRType.A), int(DnsRType.TXT)]  # code first, why second


async def test_the_cli_exits_one_for_not_listed_and_two_for_unknown(monkeypatch, capsys):
    code, out, _asker = await _run_cli_rbl(
        monkeypatch, capsys, _response(rcode=DnsResponseCode.NAME_ERROR), None
    )
    assert code == 1
    assert "NOT-LISTED" in out

    code, out, _asker = await _run_cli_rbl(
        monkeypatch, capsys, _response(rcode=DnsResponseCode.SERVER_FAILURE), None
    )
    assert code == 2
    assert "UNKNOWN" in out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
