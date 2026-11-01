"""Filtering: the four refusals, honestly signalled (RFC 8914 §4.16-§4.19).

Two layers, mirroring the module's own split: the rules are data --
parse, match, decide -- and the server is a composition that answers
the chosen stance without telling the network, the cache, or the
client's trust store anything it should not. The end-to-end half runs
the real pipeline through the ``test_server`` harness with the resolver
welded shut, because "a filtered name reached the network" is precisely
the bug this file exists to catch.

The honesty assertions ride every composed answer: the EDE the operator
chose, no AA, no AD even for a DO client, the question echoed so the
client can match the refusal to its own query (RFC 5452 §4.2), and --
for the client that never sent an OPT -- silence about options, which
RFC 6891 §7 makes a MUST rather than a style choice.
"""

import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_server as srv

from namespy.cache import MemoryDnsCache
from namespy.edns import extended_errors_of
from namespy.enums import DnsQType, DnsResponseCode, DnsRType
from namespy.filtering import FilterAction, FilterPolicy, FilterRule
from namespy.names import DomainName
from namespy.packet import EDNS_DO_BIT, DnsQClass, DnsQuestion, DnsRecord, Query
from namespy.rdata import RData_A
from namespy.resolver import RecursiveResolver
from namespy.stub import Upstream

PEER = ("203.0.113.7", 53111)
SINKHOLE_IP = ipaddress.IPv4Address("127.0.0.1")


# ---------------------------------------------------------------- the rules


def test_the_four_stances_carry_their_registry_codes():
    assert FilterAction.BLOCK.value == 15  # §4.16
    assert FilterAction.CENSOR.value == 16  # §4.17
    assert FilterAction.FILTER.value == 17  # §4.18
    assert FilterAction.PROHIBIT.value == 18  # §4.19


def test_each_stance_answers_the_shape_its_section_describes():
    assert FilterAction.BLOCK.rcode is DnsResponseCode.NAME_ERROR
    assert FilterAction.CENSOR.rcode is DnsResponseCode.NAME_ERROR
    assert FilterAction.FILTER.rcode is DnsResponseCode.NO_ERROR  # NODATA
    assert FilterAction.PROHIBIT.rcode is DnsResponseCode.REFUSED  # §4.19's own word


def test_extra_text_is_short_and_names_the_sender():
    # RFC 8914 §3: "implementers and operators creating EDE options SHOULD
    # avoid lengthy EXTRA-TEXT contents", attributed to the sender.
    for action in FilterAction:
        text = action.extra_text
        assert text.startswith(b"namespy: ")
        assert len(text) < 32


def test_parse_reads_an_exact_rule():
    rule = FilterRule.parse("block:ads.example")
    assert rule.action is FilterAction.BLOCK
    assert rule.include_subdomains is False
    assert rule.trigger == DomainName("ads.example")


def test_parse_reads_a_zone_rule_from_its_leading_dot():
    rule = FilterRule.parse("censor:.ads.example")
    assert rule.action is FilterAction.CENSOR
    assert rule.include_subdomains is True
    assert rule.trigger == DomainName("ads.example")


def test_parse_refuses_a_verb_that_is_not_one_of_the_four():
    with pytest.raises(ValueError, match="block, censor, filter, prohibit"):
        FilterRule.parse("veto:ads.example")


def test_parse_refuses_a_rule_without_a_trigger():
    with pytest.raises(ValueError, match="ACTION:TRIGGER"):
        FilterRule.parse("block:")
    with pytest.raises(ValueError, match="ACTION:TRIGGER"):
        FilterRule.parse("block")


def test_an_exact_rule_fires_on_one_name_in_any_spelling():
    rule = FilterRule.parse("block:ads.example")
    assert rule.matches(DomainName("ads.example"))
    assert rule.matches(DomainName("ADS.Example."))
    assert not rule.matches(DomainName("x.ads.example"))
    assert not rule.matches(DomainName("ads.example.org"))


def test_a_zone_rule_covers_the_apex_and_every_descent():
    rule = FilterRule.parse("block:.ads.example")
    assert rule.matches(DomainName("ads.example"))  # apex, is_subdomain_of's own rule
    assert rule.matches(DomainName("x.ads.example"))
    assert rule.matches(DomainName("deep.x.ads.example"))
    assert not rule.matches(DomainName("ads.example.org"))


def test_the_root_zone_fires_on_everything_deliberately():
    policy = FilterPolicy.from_cli(["prohibit:."])
    assert policy.evaluate(DomainName("anything.at.all")) is not None


def test_the_first_rule_wins_and_the_list_reads_top_to_bottom():
    policy = FilterPolicy.from_cli(["filter:x.ads.example", "block:.ads.example"])
    assert policy.evaluate(DomainName("x.ads.example")).action is FilterAction.FILTER
    assert policy.evaluate(DomainName("y.ads.example")).action is FilterAction.BLOCK


def test_an_empty_policy_fires_on_nothing():
    assert FilterPolicy().evaluate(DomainName("www.example")) is None


# ------------------------------------------------------------ the pipeline


def _welded_resolver():
    """A real resolver with the door to everything else welded shut.

    The server enforces its resolver type (test_resolver_type_is_enforced),
    so the weld is the method the pipeline calls: any consultation for a
    filtered name raises, which is exactly the bug the tests assert away.
    """

    async def no_network(_packet):
        raise AssertionError("a filtered name reached the resolver")

    resolver = RecursiveResolver(cache=MemoryDnsCache())
    resolver.resolve = no_network
    return resolver


def _ask(name="ads.example", *, edns=True, do=False):
    extra = [srv.opt_record(flags=EDNS_DO_BIT if do else 0)] if edns else []
    return Query(
        ID=0xABCD,
        questions=[DnsQuestion(DomainName(name), DnsQType.A, DnsQClass.IN)],
        additional_records=extra,
    )


def _filtered_server(policy, **kwargs):
    return srv.make_server(resolver=_welded_resolver(), filter_policy=policy, **kwargs)


async def _ask_server(server, packet):
    server.datagram_received(bytes(packet), PEER)
    await srv.drain(server)
    return server.transport.replies[0]


async def test_a_blocked_name_answers_nxdomain_explained_by_code_15():
    cli = FilterPolicy.from_cli(["block:ads.example"])
    server, _resolver, _transport = _filtered_server(cli)
    parsed = await _ask_server(server, _ask())

    assert parsed.RCODE is DnsResponseCode.NAME_ERROR
    (error,) = extended_errors_of(parsed.edns_options())
    assert error.info_code == 15
    assert b"namespy: blocked" in error.extra_text
    assert parsed.AA is False  # a policy act is not an authority claim
    assert parsed.AD is False  # and it validated nothing
    assert parsed.questions[0].name == DomainName("ads.example")


async def test_a_censored_name_says_who_imposed_the_policy_with_code_16():
    server, _resolver, _transport = _filtered_server(FilterPolicy.from_cli(["censor:.ads.example"]))
    parsed = await _ask_server(server, _ask(name="x.ads.example"))

    assert parsed.RCODE is DnsResponseCode.NAME_ERROR
    (error,) = extended_errors_of(parsed.edns_options())
    assert error.info_code == 16


async def test_a_filtered_name_goes_nodata_with_code_17():
    cli = FilterPolicy.from_cli(["filter:ads.example"])
    server, _resolver, _transport = _filtered_server(cli)
    parsed = await _ask_server(server, _ask())

    assert parsed.RCODE is DnsResponseCode.NO_ERROR
    assert [int(r.rtype) for r in parsed.answers] == []  # the record set is withheld
    (error,) = extended_errors_of(parsed.edns_options())
    assert error.info_code == 17


async def test_a_prohibited_name_is_refused_and_says_so_with_code_18():
    cli = FilterPolicy.from_cli(["prohibit:ads.example"])
    server, _resolver, _transport = _filtered_server(cli)
    parsed = await _ask_server(server, _ask())

    assert parsed.RCODE is DnsResponseCode.REFUSED
    (error,) = extended_errors_of(parsed.edns_options())
    assert error.info_code == 18


async def test_a_do_client_gets_no_ad_from_a_policy_answer():
    cli = FilterPolicy.from_cli(["block:ads.example"])
    server, _resolver, _transport = _filtered_server(cli)
    parsed = await _ask_server(server, _ask(do=True))

    assert parsed.AD is False  # the DO bit asks for validation, not for a fiction


async def test_a_client_without_edns_gets_the_refusal_and_no_option():
    # RFC 6891 §7: no OPT in the request, so none -- and no EDE hiding inside
    # one -- may appear in the response. The RCODE still refuses.
    cli = FilterPolicy.from_cli(["block:ads.example"])
    server, _resolver, _transport = _filtered_server(cli)
    parsed = await _ask_server(server, _ask(edns=False))

    assert parsed.RCODE is DnsResponseCode.NAME_ERROR
    assert [r for r in parsed.additional_records if int(r.rtype) == 41] == []


async def test_an_unfiltered_name_still_walks_the_normal_path():
    seen = []
    resolver = _welded_resolver()

    async def record(packet):
        seen.append(packet)
        return

    resolver.resolve = record
    server, _resolver, _transport = srv.make_server(
        resolver=resolver, filter_policy=FilterPolicy.from_cli(["block:ads.example"])
    )
    parsed = await _ask_server(server, _ask(name="www.example"))

    assert seen  # the policy declined to fire, so the resolver was consulted
    assert parsed.RCODE is DnsResponseCode.SERVER_FAILURE  # the recorder's silence


async def test_a_bound_name_outranks_the_policy_that_covers_it():
    cli = FilterPolicy.from_cli(["block:.example"])
    server, _resolver, _transport = _filtered_server(cli)
    record = DnsRecord(
        DomainName("ads.example"), DnsRType.A, DnsQClass.IN, 60, rdata=RData_A(SINKHOLE_IP)
    )
    server.bind(DomainName("ads.example"), lambda _request: [record])
    parsed = await _ask_server(server, _ask())

    assert parsed.RCODE is DnsResponseCode.NO_ERROR
    assert parsed.AA is True  # a bind is a claim; a filter is not
    assert extended_errors_of(parsed.edns_options()) == ()


async def test_the_policy_outranks_the_forwarder():
    # The forwarder is pointed at a port nothing listens on: if the policy
    # answered second, this query would end in the forwarder's SERVFAIL.
    cli = FilterPolicy.from_cli(["block:ads.example"])
    server, _resolver, _transport = _filtered_server(
        cli,
        dot_upstreams=[Upstream.parse("127.0.0.1:65530#up.test", transport="dot")],
    )
    parsed = await _ask_server(server, _ask())

    (error,) = extended_errors_of(parsed.edns_options())
    assert error.info_code == 15


async def test_a_substitute_answers_noerror_without_claiming_authority():
    record = DnsRecord(
        DomainName("ads.example"), DnsRType.A, DnsQClass.IN, 60, rdata=RData_A(SINKHOLE_IP)
    )
    rule = FilterRule(
        trigger=DomainName("ads.example"), action=FilterAction.BLOCK, substitute=(record,)
    )
    server, _resolver, _transport = _filtered_server(FilterPolicy((rule,)))
    parsed = await _ask_server(server, _ask(do=True))

    assert parsed.RCODE is DnsResponseCode.NO_ERROR  # records beside NXDOMAIN lie
    assert [int(r.rtype) for r in parsed.answers] == [int(DnsRType.A)]
    assert parsed.AA is False  # invented data is policy output, not authority
    assert parsed.AD is False
    (error,) = extended_errors_of(parsed.edns_options())
    assert error.info_code == 15  # the substitute says where it came from


# ------------------------------------------------------------------ the CLI


def test_filter_without_serve_is_refused_before_anything_runs(capsys):
    from namespy.__main__ import main

    with pytest.raises(SystemExit):
        main(["--filter", "block:ads.example", "example.com"])
    assert "--serve" in capsys.readouterr().err


def test_a_malformed_rule_is_refused_before_the_port_opens(capsys):
    from namespy.__main__ import main

    with pytest.raises(SystemExit):
        main(["--serve", "--filter", "veto:ads.example"])
    assert "veto" in capsys.readouterr().err


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
