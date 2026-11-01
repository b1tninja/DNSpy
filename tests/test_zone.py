"""The zone module: RFC 1035 section 5.1 in, RFC 1034 section 4.3.2 out.

The parse tests walk the section 5.1 entry grammar -- defaults,
parentheses, quoting, the two control entries, RFC 3597's generic
form -- and its error sentences. The serve tests pin the answer shapes
step by step: 3a's copied RRs and CNAME clause, 3b's referral (the
answer's AA off is the whole test), 3c's synthesis with the *query's*
name as owner. The integration tests put a loaded zone behind the real
server dispatch: bind beats zone, and the egress door keeps its
question echo, OPT and section rules whatever section produced the
records.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_server as srv

from namespy.enums import DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.zone import Zone, ZoneParseError

MINIMAL = """
$TTL 300
$ORIGIN example.com.
@       SOA   ns1 admin ( 1 2 3 4 5 )
@       NS    ns1
ns1     A     192.0.2.1
www     A     203.0.113.5
"""


def zone(text=MINIMAL):
    return Zone.from_master_file(text)


def _key_of(record):
    return tuple(label.lower() for label in record.name.labels())


# ---------------------------------------------------------------- parse


def test_a_minimal_master_file_loads_and_names_its_apex_from_the_soa():
    z = zone()
    assert str(z.apex) == "example.com."
    assert len(z.records) == 4
    assert z.soa is not None


def test_owner_and_ttl_default_to_the_last_stated_values():
    # Indented continuation keeps the owner; a stated TTL replaces the
    # default, and the next indented record keeps *that* TTL.
    z = zone(
        """
$ORIGIN example.com.
$TTL 100
www     A       203.0.113.5
        A       203.0.113.6
fast    5    A  203.0.113.7
        600  A  203.0.113.8
"""
    )
    www = [r for r in z.records if _key_of(r) == (b"www", b"example", b"com")]
    assert [int(r.ttl) for r in www] == [100, 100]
    fast = [r for r in z.records if _key_of(r) == (b"fast", b"example", b"com")]
    assert [int(r.ttl) for r in fast] == [5, 600]
    assert {str(r.rdata) for r in fast} == {"203.0.113.7", "203.0.113.8"}


def test_class_and_ttl_come_in_either_order_because_the_mnemonics_are_disjoint():
    z = zone(
        """
$TTL 5
$ORIGIN example.com.
@    SOA ns1 admin 1 2 3 4 5
www  IN  90  A  203.0.113.5
mail 42  IN  A  203.0.113.6
"""
    )
    by_ip = {str(r.rdata): r for r in z.records if int(r.rtype) == int(DnsRType.A)}
    assert by_ip["203.0.113.5"].ttl == 90
    assert by_ip["203.0.113.6"].ttl == 42


def test_parentheses_continue_one_record_across_lines_and_comments_survive():
    z = zone(
        """
$ORIGIN example.com.
$TTL 60
@   SOA  ns1   admin     (  ; the rname is relative too
         2026110101 7200 ; refresh with a comment on it
         3600 1209600 45 )
"""
    )
    soa = z.soa
    assert int(soa.rdata.serial) == 2026110101
    assert int(soa.rdata.refresh) == 7200


def test_a_semicolon_inside_quotes_is_text_not_a_comment():
    z = zone(
        """
$ORIGIN example.com.
$TTL 60
@ SOA ns1 admin 1 2 3 4 5
txt TXT "still here ; not a comment"
"""
    )
    rec = next(r for r in z.records if int(r.rtype) == int(DnsRType.TXT))
    assert rec.rdata.text == "still here ; not a comment"


def test_escapes_work_in_names_the_way_section_5_1_escapes_them():
    z = zone(
        r"""
$TTL 60
$ORIGIN example.com.
@ SOA ns1 admin 1 2 3 4 5
weird\.dot TXT q
\046leading TXT l
"""
    )
    keys = {_key_of(r) for r in z.records if int(r.rtype) == int(DnsRType.TXT)}
    assert (b"weird.dot", b"example", b"com") in keys
    assert (b".leading", b"example", b"com") in keys


def test_txt_takes_one_or_more_character_strings():
    z = zone(
        """
$ORIGIN example.com.
$TTL 60
@ SOA ns1 admin 1 2 3 4 5
a TXT "one" "two"
b TXT bare
"""
    )
    recs = {r.name.labels()[0]: r for r in z.records if int(r.rtype) == int(DnsRType.TXT)}
    assert recs[b"a"].rdata.strings == [b"one", b"two"]
    assert recs[b"a"].rdata.text == "onetwo"
    assert recs[b"b"].rdata.strings == [b"bare"]


def test_rfc_3597_generic_rdata_loads_and_disagrees_about_length_out_loud():
    z = zone(
        """
$ORIGIN example.com.
$TTL 60
@ SOA ns1 admin 1 2 3 4 5
u TYPE654 \\# 3 abcdef
"""
    )
    rec = next(r for r in z.records if int(r.rtype) == 654)
    assert bytes(rec.rdata) == bytes.fromhex("abcdef")
    with pytest.raises(ZoneParseError, match="stated length"):
        zone("$ORIGIN e.com.\n$TTL 1\n@ SOA n a 1 2 3 4 5\nu TYPE654 \\# 9 abcdef\n")


def test_a_type_with_no_parser_says_rfc_3597_instead_of_lying():
    with pytest.raises(ZoneParseError, match="RFC 3597"):
        zone("$ORIGIN e.com.\n$TTL 1\n@ SOA n a 1 2 3 4 5\nx WIDGET 1 2 3\n")


def test_dollar_generate_is_refused_by_name():
    with pytest.raises(ZoneParseError, match=r"\$GENERATE"):
        zone("$ORIGIN e.com.\n$GENERATE 1-3 host$ A 10.0.0.$\n")


def test_include_pulls_a_file_in_without_disturbing_the_parent(tmp_path):
    (tmp_path / "inner.zone").write_text(
        "$ORIGIN inner.example.com.\n$TTL 30\nsub A 192.0.2.5\n", encoding="utf-8"
    )
    (tmp_path / "outer.zone").write_text(
        "$ORIGIN example.com.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4 5\n"
        "$INCLUDE inner.zone\nstill-outer A 192.0.2.6\n",
        encoding="utf-8",
    )
    z = Zone.from_file(tmp_path / "outer.zone")
    owners = {str(r.name) for r in z.records}
    assert "sub.inner.example.com." in owners  # inner keeps its own origin
    assert "still-outer.example.com." in owners  # parent's origin survives
    assert z.soa.name == DomainName("example.com.")


def test_include_without_a_file_to_include_from_says_so():
    with pytest.raises(ZoneParseError, match="directory to include from"):
        zone("$ORIGIN e.com.\n$INCLUDE other.zone\n")


def test_relative_names_need_an_origin_and_its_absence_is_said():
    with pytest.raises(ZoneParseError, match=r"no \$ORIGIN"):
        zone("$TTL 60\nwww A 203.0.113.5\n")


def test_no_ttl_in_effect_is_an_error_not_a_default_somebody_remembers():
    with pytest.raises(ZoneParseError, match="no TTL in effect"):
        zone("$ORIGIN e.com.\n@ SOA n a 1 2 3 4 5\nwww A 203.0.113.5\n")


def test_errors_carry_their_file_and_line():
    with pytest.raises(ZoneParseError) as exc:
        zone("$ORIGIN e.com.\n$TTL 5\n@ SOA n a 1 2 3 4 5\nbad  NAME  here\n")
    assert exc.value.line == 4
    assert exc.value.detail


def test_a_record_without_a_type_is_said_as_one():
    with pytest.raises(ZoneParseError, match="no type"):
        zone("$ORIGIN e.com.\n$TTL 5\n@ SOA n a 1 2 3 4 5\n@ 60\n")


def test_the_mx_srv_aaaa_and_ptr_fields_take_their_stated_shapes():
    z = zone(
        """
$ORIGIN example.com.
$TTL 60
@ SOA ns1 admin 1 2 3 4 5
@ MX 10 mail
_ldap._tcp SRV 0 5 389 mail
v6 AAAA 2001:db8::1
5.3.2.1.in-addr.arpa PTR host.example.com.
"""
    )
    by_type = {}
    for r in z.records:
        by_type.setdefault(int(r.rtype), r)
    assert int(by_type[int(DnsRType.MX)].rdata.preference) == 10
    assert int(by_type[int(DnsRType.SRV)].rdata.port) == 389
    assert str(by_type[int(DnsRType.AAAA)].rdata) == "2001:db8::1"
    assert str(by_type[int(DnsRType.PTR)].rdata) == "host.example.com."


def test_unbalanced_parentheses_never_yield_a_truncated_record():
    with pytest.raises(ZoneParseError, match="never closed"):
        zone("$ORIGIN e.com.\n$TTL 5\n@ SOA n a ( 1 2 3 4 5\n")


# --------------------------------------------------------------- serve

FULL = """
$TTL 300
$ORIGIN example.com.
@        SOA   ns1 admin ( 1 2 3 4 5 )
@        NS    ns1
@        NS    ns2.example.org.
ns1      A     192.0.2.1
ns2.example.org.  A  198.51.100.53
www      A     203.0.113.5
alias    CNAME www
loop1    CNAME loop2
loop2    CNAME loop1
sub      NS    ns1
sub      NS    deep.sub
deep.sub A     192.0.2.9
*        TXT   "wild saying"
gap      TXT   "explicit"
"""


def full():
    return zone(FULL)


A = int(DnsRType.A)
TXT = int(DnsRType.TXT)
NS = int(DnsRType.NS)
CNAME = int(DnsRType.CNAME)


def test_an_exact_node_answers_with_aa_and_the_apex_soa_in_authority():
    answer = full().serve("www.example.com", A)
    assert answer.aa is True
    assert [str(r.rdata) for r in answer.answers] == ["203.0.113.5"]
    assert int(answer.answers[0].rtype) == A
    assert int(answer.authority[0].rtype) == int(DnsRType.SOA)


def test_the_walk_folds_case_because_names_are_case_insensitive():
    assert full().serve("WWW.Example.COM", A).aa is True


def test_a_name_that_exists_without_the_type_is_nodata_not_nxdomain():
    answer = full().serve("ns1.example.com", TXT)
    assert answer.rcode is None
    assert answer.answers == ()
    assert int(answer.authority[0].rtype) == int(DnsRType.SOA)


def test_a_name_with_no_wildcard_above_it_is_the_authoritative_name_error():
    z = zone(
        """
$TTL 60
$ORIGIN example.com.
@ SOA ns1 admin 1 2 3 4 5
gap TXT "explicit"
"""
    )
    assert z.serve("nope.example.com", A).rcode is DnsResponseCode.NAME_ERROR


def test_the_wildcard_synthesizes_with_the_query_name_as_owner():
    answer = full().serve("anything.example.com", TXT)
    (rec,) = answer.answers
    assert str(rec.name) == "anything.example.com"
    assert rec.rdata.text == "wild saying"


def test_a_wildcard_without_the_queried_type_is_nodata():
    answer = full().serve("anything.example.com", A)
    assert answer.rcode is None
    assert answer.answers == ()


def test_a_cname_chain_inside_the_zone_is_answered_whole():
    answer = full().serve("alias.example.com", A)
    answers = [(int(r.rtype), str(r.rdata)) for r in answer.answers]
    assert answers == [(CNAME, "www.example.com."), (A, "203.0.113.5")]


def test_a_cname_query_stops_at_the_alias_because_that_is_what_was_asked():
    answer = full().serve("alias.example.com", CNAME)
    assert [(int(r.rtype), str(r.rdata)) for r in answer.answers] == [(CNAME, "www.example.com.")]


def test_an_alias_loop_stops_at_the_loop_with_the_cnames_it_followed():
    answer = full().serve("loop1.example.com", A)
    assert [int(r.rtype) for r in answer.answers] == [CNAME, CNAME]
    assert len(answer.answers) == 2  # and no third lap


def test_below_a_cut_the_answer_is_a_referral_with_aa_off_and_bailiwick_glue():
    answer = full().serve("x.sub.example.com", A)
    assert answer.aa is False
    assert answer.answers == ()
    assert {str(r.rdata) for r in answer.authority} == {
        "ns1.example.com.",
        "deep.sub.example.com.",
    }
    assert [str(r.rdata) for r in answer.additional] == ["192.0.2.9"]  # only in-bailiwick


def test_a_query_at_the_cut_node_itself_is_answered_authoritatively():
    answer = full().serve("sub.example.com", NS)
    assert answer.aa is True
    assert len(answer.answers) == 2


def test_wildcards_do_not_cross_the_zone_cut_the_referral_arrives_first():
    answer = full().serve("anything.sub.example.com", TXT)
    assert answer.aa is False
    assert answer.answers == ()


def test_a_name_below_an_explicit_encloser_gets_no_higher_wildcard():
    # 'gap' exists with only TXT; two labels below it the deepest existing
    # encloser is 'gap', and no *.gap wildcard exists to synthesize from.
    answer = full().serve("deep.gap.example.com", TXT)
    assert answer.rcode is DnsResponseCode.NAME_ERROR


def test_not_my_zone_and_not_my_class_say_none_so_the_next_thing_can_answer():
    assert full().serve("other.org", A) is None
    assert full().serve("www.example.com", A, qclass=int(DnsRClass.CH)) is None


def test_any_asks_for_everything_the_node_holds():
    answer = full().serve("example.com", int(DnsQType.ANY))
    types = {int(r.rtype) for r in answer.answers}
    assert types == {int(DnsRType.SOA), NS}


# ------------------------------------------------------- the server door

from namespy.packet import DnsRecord as _Rec  # noqa: E402
from namespy.querylog import QueryLog as _QueryLog  # noqa: E402
from namespy.rdata import RData_TXT as _TXT  # noqa: E402


async def _ask(server, name, qtype=A):
    packet = srv.query_packet(DomainName(name), qtype)
    server.datagram_received(bytes(packet), ("198.51.100.9", 40000))
    await srv.drain(server)
    return packet, server


async def test_a_loaded_zone_answers_over_the_wire_with_aa_and_the_soa():
    server, _resolver, transport = srv.make_server(zones=[full()])
    packet, _ = await _ask(server, "www.example.com")
    (reply,) = transport.replies
    assert reply.AA is True
    assert reply.RA is False
    assert reply.RCODE == srv.DnsResponseCode.NO_ERROR
    assert str(reply.answers[0].rdata) == "203.0.113.5"
    assert int(reply.answers[0].ttl) == 300
    assert int(reply.nameservers[0].rtype) == int(DnsRType.SOA)
    assert reply.ID == packet.ID  # the one egress door keeps its promises


async def test_a_name_the_zone_disowns_reaches_the_querent_as_nxdomain():
    z = zone(
        """
$TTL 60
$ORIGIN example.com.
@ SOA ns1 admin 1 2 3 4 5
"""
    )
    server, _resolver, transport = srv.make_server(zones=[z])
    await _ask(server, "gone.example.com")
    (reply,) = transport.replies
    assert reply.RCODE == DnsResponseCode.NAME_ERROR
    assert reply.AA is True


async def test_a_referral_leaves_the_door_with_aa_off_ns_and_glue():
    server, _resolver, transport = srv.make_server(zones=[full()])
    await _ask(server, "x.sub.example.com")
    (reply,) = transport.replies
    assert reply.AA is False
    assert {str(r.rdata) for r in reply.nameservers} == {
        "ns1.example.com.",
        "deep.sub.example.com.",
    }
    assert [str(r.rdata) for r in reply.additional_records] == ["192.0.2.9"]


async def test_a_bound_name_beats_the_zone_that_also_claims_it():
    server, _resolver, transport = srv.make_server(zones=[full()])
    server.bind(
        DomainName("www.example.com"),
        lambda request: [_Rec(request.name, DnsRType.TXT, ttl=0, rdata=_TXT(["bound wins"]))],
    )
    await _ask(server, "www.example.com", qtype=TXT)
    (reply,) = transport.replies
    assert reply.answers[0].rdata.text == "bound wins"


async def test_the_query_log_learns_a_new_rung():
    import io
    import json

    log_file = io.StringIO()
    server, _resolver, _transport = srv.make_server(zones=[full()], query_log=_QueryLog(log_file))
    await _ask(server, "www.example.com")
    record = json.loads(log_file.getvalue().strip().splitlines()[-1])
    assert record["origin"] == "zone"


def test_a_zone_that_does_not_claim_the_name_falls_through_untouched():
    server, _resolver, _transport = srv.make_server(zones=[full()])
    packet = srv.query_packet(DomainName("other.example"), A)
    assert server._consult_zones(packet, ("10.0.0.1", 5)) is None


def test_the_cli_accumulates_zone_flags_for_repeated_use():
    from namespy.__main__ import build_parser

    args = build_parser().parse_args(["--serve", "--zone", "a.zone", "--zone", "b.zone"])
    assert args.zone == ["a.zone", "b.zone"]
