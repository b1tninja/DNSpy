"""The special-use registry, answered before the walk (increment U, RFC 6761).

The bug this cements is invisible in a live test against the public DNS --
querying foo.invalid on the internet returns an NXDOMAIN eventually, from a
TLD server that had to be found first. So the load-bearing assertions here are
the absence: no packet leaves, the answer is immediate, the trace says which
paragraph authorized it, and the two entries the registry says to leave alone
(example names, 127.in-addr.arpa) are demonstrably ordinary.
"""

import pytest

from namespy import __main__ as cli
from namespy.enums import DnsQType, DnsResponseCode
from namespy.names import DomainName
from namespy.packet import DnsQuestion, Query
from namespy.resolver import RecursiveResolver, SpecialName, SpecialNamesPolicy
from namespy.special import SpecialNameAction, classify_special_use
from namespy.trace import Trace

# (queryable name, expected citation) for every registry answer that is a
# bare NXDOMAIN -- including the apexes, which the registry denies hardest,
# and a mixed-case name, because §6 turns on names not spellings.
NXDOMAIN_CASES = [
    ("foo.invalid.", "RFC 6761 §6.4¶4"),
    ("invalid.", "RFC 6761 §6.4¶4"),
    ("a.b.test.", "RFC 6761 §6.2¶4"),
    ("My.Computer.local.", "RFC 6762 §3¶3-4"),
    ("x.onion.", "RFC 7686 §2¶5"),
    ("1.168.192.in-addr.arpa.", "RFC 6761 §6.1¶7"),
    ("1.20.172.in-addr.arpa.", "RFC 6761 §6.1¶7"),
    (
        "1.1.1.1.1.1.1.1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.31.172.in-addr.arpa.",
        "RFC 6761 §6.1¶7",
    ),
]

# Names the registry does NOT reserve, each here because somebody might be
# tempted to block it: example.com is served for real (§6.5¶4 says resolve
# it normally), 127.in-addr.arpa is not in §6.1's eighteen zones, and the
# others are look-alikes that substring matching would sweep up.
ORDINARY_CASES = [
    "example.com.",
    "example.",
    "127.in-addr.arpa.",
    "99.in-addr.arpa.",
    "in-addr.arpa.",
    "notlocalhost.example.",
    "myonion.example.",
    "invalid.example.",
    ".",
]


def _never_ask(resolver):
    """Rig the resolver's only network door to fail the test if it rings."""

    async def refusing(*_args, **_kwargs):
        raise AssertionError("a special-use name must not reach the network")

    resolver.query = refusing
    return resolver


class TestClassify:
    @pytest.mark.parametrize(("name", "citation"), NXDOMAIN_CASES)
    def test_registry_names_verdict_nxdomain_with_citation(self, name, citation):
        verdict = classify_special_use(DomainName(name))
        assert verdict.action is SpecialNameAction.NXDOMAIN
        assert verdict.citation == citation

    @pytest.mark.parametrize("name", ["localhost.", "a.b.localhost.", "LOCALHOST."])
    def test_localhost_is_loopback_not_negative(self, name):
        verdict = classify_special_use(DomainName(name))
        assert verdict.action is SpecialNameAction.LOOPBACK

    @pytest.mark.parametrize("name", ORDINARY_CASES)
    def test_unregistered_names_pass_through(self, name):
        assert classify_special_use(DomainName(name)).action is SpecialNameAction.NONE


class TestResolverAnswersLocally:
    @pytest.mark.parametrize(("name", "_citation"), NXDOMAIN_CASES)
    async def test_nxdomain_names_answer_now_without_asking(self, name, _citation):
        resolver = _never_ask(RecursiveResolver())
        response = await resolver.resolve(Query(questions=[DnsQuestion(name, DnsQType.A)]))
        assert int(response.RCODE) == int(DnsResponseCode.NAME_ERROR)
        assert response.answers == []

    async def test_localhost_address_queries_get_the_loopback(self):
        resolver = _never_ask(RecursiveResolver())
        cases = ((DnsQType.A, "127.0.0.1"), (DnsQType.AAAA, "::1"))
        for qtype, expected in cases:
            question = DnsQuestion("x.localhost.", qtype)
            response = await resolver.resolve(Query(questions=[question]))
            assert int(response.RCODE) == int(DnsResponseCode.NO_ERROR)
            assert len(response.answers) == 1
            assert str(response.answers[0].rdata) == expected
            # §6.3¶7: the RDATA is defined by protocol, so it expires against
            # no zone -- TTL 0 is the only honest lifetime.
            assert response.answers[0].ttl == 0

    async def test_localhost_other_types_answer_negative(self):
        resolver = _never_ask(RecursiveResolver())
        question = DnsQuestion("localhost.", DnsQType.MX)
        response = await resolver.resolve(Query(questions=[question]))
        assert int(response.RCODE) == int(DnsResponseCode.NO_ERROR)
        assert response.answers == []

    async def test_the_registry_answer_is_not_cached(self):
        # Protocol-defined answers have no authority to expire: a cache entry
        # would invent one, and a shared backend would export the invention.
        resolver = _never_ask(RecursiveResolver())
        question = DnsQuestion("foo.invalid.", DnsQType.A)
        await resolver.resolve(Query(questions=[question]))
        assert resolver.cache.get(DomainName("foo.invalid."), DnsQType.A, 1) is None

    async def test_the_trace_names_the_paragraph_that_kept_the_packet_home(self):
        resolver = _never_ask(RecursiveResolver())
        question = DnsQuestion("x.onion.", DnsQType.A)
        response = await resolver.resolve(Query(questions=[question]))
        events = [event for event in response.trace.events if isinstance(event, SpecialName)]
        assert events
        assert events[0].citation == "RFC 7686 §2¶5"

    async def test_ignore_policy_walks_exactly_as_it_says(self):
        asked = []

        async def spy(*_args, **_kwargs):
            asked.append(1)

        resolver = RecursiveResolver(special_names="ignore")  # the string, too
        resolver.query = spy
        question = DnsQuestion("foo.invalid.", DnsQType.A)
        response = await resolver.resolve(Query(questions=[question]))
        assert asked, "IGNORE must restore the old walk"
        assert response is None  # the spy never answers; nothing special about that


class TestPolicyDoor:
    def test_default_is_respect_and_string_arrives(self):
        assert RecursiveResolver().special_names is SpecialNamesPolicy.RESPECT
        assert RecursiveResolver(special_names="ignore").special_names is (
            SpecialNamesPolicy.IGNORE
        )

    def test_a_typo_raises_at_the_door(self):
        with pytest.raises(ValueError, match="SpecialNamesPolicy"):
            RecursiveResolver(special_names="walk-anyway")


class TestTraceRendering:
    def test_text_and_mermaid_say_the_same_sentence(self):
        trace = Trace()
        trace.record(SpecialName("foo.invalid.", "NXDOMAIN", "RFC 6761 §6.4¶4"))
        text = trace.to_text()
        mermaid = trace.to_mermaid()
        assert "special-use foo.invalid.: NXDOMAIN (RFC 6761 §6.4¶4)" in text
        assert "special-use foo.invalid." in mermaid

    def test_live_echo_carries_the_line(self):
        seen = []
        trace = Trace(listener=seen.append)
        step = SpecialName("localhost.", "loopback A", "RFC 6761 §6.3¶4")
        trace.record(step)
        line = Trace.format_step(seen[0], 1)
        assert line == "  1   special-use localhost.: loopback A (RFC 6761 §6.3¶4)"


class TestCliFlag:
    def test_flag_arrives_as_ignore_and_warns(self, capsys):
        parser = cli.build_parser()
        args = parser.parse_args(["--ignore-special-names", "example.com"])
        assert cli._special_names(args) is SpecialNamesPolicy.IGNORE
        err = capsys.readouterr().err
        assert "WALKED" in err
        assert "leak" in err

    def test_default_respects_quietly(self, capsys):
        parser = cli.build_parser()
        args = parser.parse_args(["example.com"])
        assert cli._special_names(args) is SpecialNamesPolicy.RESPECT
        assert capsys.readouterr().err == ""
