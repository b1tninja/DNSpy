"""The route table: the two rules as executable claims (roadmap W3).

``namespy/apps/routing.py`` opens no socket and forwards nothing -- it decides
where a name *would* go -- so every claim here is a decision the table makes,
checked against the two rules the module docstring states: longest-suffix match,
and zone-match-excludes-the-general-path. Conventions borrowed from
``test_engine.py``: plain objects, no network, and one test per sentence.
"""

import pytest

from namespy.apps.routing import ROOT, Route, RouteTable, RoutingDecision
from namespy.names import DomainName
from namespy.stub import Upstream


def test_longest_suffix_beats_a_broader_zone_and_the_default():
    table = RouteTable(
        ["example=1.1.1.1", "internal.example=10.0.0.1"],
        default="8.8.8.8",
    )
    decision = table.route("www.internal.example")
    assert decision.route.zone == DomainName("internal.example")
    assert [u.host for u in decision.upstreams] == ["10.0.0.1"]


def test_a_broader_zone_wins_over_the_default_when_nothing_more_specific_matches():
    table = RouteTable(["example=1.1.1.1"], default="8.8.8.8")
    decision = table.route("www.example")
    assert decision.route.zone == DomainName("example")
    assert decision.exclusive is True, "the zone claimed it, so the general path is off the table"


def test_the_general_path_only_answers_when_no_zone_claims_the_name():
    table = RouteTable(["example=1.1.1.1"], default="8.8.8.8")
    decision = table.route("www.other.test")
    assert decision.route.zone == ROOT
    assert decision.exclusive is False
    assert [u.host for u in decision.upstreams] == ["8.8.8.8"]


def test_zone_match_never_falls_back_to_the_default():
    # The trap the module names: a zoned name must resolve to its zone, not the
    # general server, even though the root zone matches everything too.
    table = RouteTable(["example=10.0.0.1"], default="8.8.8.8")
    decision = table.route("deep.sub.example")
    assert decision.route.zone == DomainName("example")
    assert "8.8.8.8" not in [u.host for u in decision.upstreams]


def test_registration_order_does_not_change_the_match():
    a = RouteTable(["internal.example=10.0.0.1", "example=1.1.1.1"])
    b = RouteTable(["example=1.1.1.1", "internal.example=10.0.0.1"])
    assert a.route("x.internal.example").route.zone == b.route("x.internal.example").route.zone


def test_the_zone_apex_routes_to_itself_apex_or_below():
    table = RouteTable(["example=1.1.1.1"])
    assert table.route("example").route.zone == DomainName("example")


def test_a_name_no_zone_claims_is_unroutable_without_a_default():
    table = RouteTable(["example=1.1.1.1"])
    decision = table.route("www.other.test")
    assert decision.route is None
    assert decision.routable is False
    assert decision.upstreams == ()
    assert decision.exclusive is False


def test_matching_is_case_insensitive_like_every_name_comparison_here():
    table = RouteTable(["Example.=1.1.1.1"])
    assert table.route(DomainName("www.EXAMPLE")).route.zone == DomainName("example")


def test_route_accepts_a_string_or_a_domain_name():
    table = RouteTable(default="8.8.8.8")
    assert table.route("a.test").routable == table.route(DomainName("a.test")).routable


def test_multiple_servers_for_one_zone_keep_their_order():
    table = RouteTable(["example=1.1.1.1,9.9.9.9"])
    assert [u.host for u in table.route("www.example").upstreams] == ["1.1.1.1", "9.9.9.9"]


def test_zone_trailing_dot_is_optional_and_upstream_syntax_matches_the_stub():
    table = RouteTable(["example.=1.1.1.1:5353", "dot.test=8.8.8.8:853#dns.google"])
    zone_upstream = table.route("www.example").upstreams[0]
    dot_upstream = table.route("x.dot.test").upstreams[0]
    assert (zone_upstream.host, zone_upstream.port) == ("1.1.1.1", 5353)
    assert (dot_upstream.host, dot_upstream.port, dot_upstream.server_name) == (
        "8.8.8.8",
        853,
        "dns.google",
    )


def test_a_default_only_table_routes_everything_through_the_general_path():
    table = RouteTable(default="8.8.8.8")
    decision = table.route("anything.at.all")
    assert decision.route.zone == ROOT
    assert decision.exclusive is False


def test_route_parse_reads_the_empty_zone_as_the_default():
    route = Route.parse("=8.8.8.8")
    assert route.is_default is True
    assert route.specificity == 0


def test_route_parse_rejects_a_spec_without_an_upstream():
    with pytest.raises(ValueError, match="ZONE=UPSTREAM"):
        Route.parse("example=")


def test_route_parse_rejects_a_spec_without_a_separator():
    with pytest.raises(ValueError, match="ZONE=UPSTREAM"):
        Route.parse("example")


def test_a_table_refuses_two_general_paths():
    with pytest.raises(ValueError, match="one general path"):
        RouteTable([".=8.8.8.8"], default="9.9.9.9")


def test_specificity_orders_zones_by_label_count():
    assert Route(DomainName("internal.example"), (Upstream(host="1.1.1.1"),)).specificity == 2
    assert Route(ROOT, (Upstream(host="1.1.1.1"),)).is_default is True


def test_from_specs_builds_zones_and_default_together():
    table = RouteTable.from_specs(["example=1.1.1.1"], default="8.8.8.8")
    assert table.route("www.example").route.zone == DomainName("example")
    assert table.default is not None
    assert table.default.is_default


def test_default_property_is_none_when_no_general_path_is_registered():
    assert RouteTable(["example=1.1.1.1"]).default is None


def test_entries_lists_every_route_as_built():
    table = RouteTable(["example=1.1.1.1", "test=9.9.9.9"], default="8.8.8.8")
    assert len(table.entries) == 3


def test_routing_decision_upstreams_empty_when_unroutable():
    assert RoutingDecision(name=DomainName("x."), route=None).upstreams == ()
