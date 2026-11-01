"""The trace's two views: numbered lines for a terminal, Mermaid for a file.

Both renderers consume one _dispatch() pass, so the interesting assertions are
the ones that check the *shared* reading -- that every label the diagram draws,
the terminal also says, and that a step line names the zone being asked, which
is the fact --trace exists to show and that the bug report ("--trace doesn't
show the resolution steps") found missing. Event objects are the resolver's own;
duck-typed entry/question shapes stand in for the Slist, which the trace only
reads through .zone and .ns.
"""

from types import SimpleNamespace

from namespy.enums import DnsQType
from namespy.names import DomainName
from namespy.resolver import Answer, Demote, Done, Referral, SendQuery
from namespy.trace import Trace


def _sname(name="example.com.", qtype=DnsQType.A):
    return SimpleNamespace(qname=DomainName(name), qtype=qtype)


def _send(zone, qname="example.com.", qtype=DnsQType.A, **over):
    return SendQuery(
        entry=SimpleNamespace(zone=DomainName(zone), ns=f"ns.{zone}"),
        questions=[SimpleNamespace(name=DomainName(qname), qtype=qtype)],
        **over,
    )


def _walk():
    trace = Trace(_sname())
    trace.record(_send("."))
    trace.record(Referral(DomainName("."), DomainName("com."), 0, 1))
    trace.record(_send("com."))
    trace.record(
        Demote(entry=SimpleNamespace(ns="ns.com.", zone=DomainName("com.")), reason="no response")
    )
    trace.record(Answer(records=[1, 2]))
    trace.record(Done(None))
    return trace


class TestTextRenderer:
    def test_every_step_is_numbered_and_a_query_names_the_zone_asked(self):
        lines = _walk().to_text().splitlines()
        assert lines[0] == "; resolve example.com. A"
        assert lines[1].startswith("  1 -> .:")
        assert "example.com. A" in lines[1]
        assert "  2 <- referral com. (match 0->1)" in lines[2]
        assert any("ns.com." in line and "no response" in line for line in lines)
        assert any(line.startswith("  5 <- AA, 2 records") for line in lines)
        assert lines[-1].rstrip().endswith("done")

    def test_markers_for_probes_helpers_and_bundles_survive_into_the_lines(self):
        trace = Trace(_sname())
        trace.record(_send(".", probe=True, helper=True, extra_qtypes=(1, 2)))
        line = trace.to_text().splitlines()[1]
        assert "(probe) (dnssec) (mqtype +2)" in line


class TestLiveListener:
    """--trace echoes the walk *as* it happens: record() is the tap.

    The bug this cements was quieter than the original one: printing the text
    view only after resolve() returned meant a slow or stuck walk showed
    nothing at all -- indistinguishable from --trace doing nothing.
    """

    def test_each_step_is_echoed_at_record_time_in_order(self):
        seen = []
        trace = Trace(_sname(), listener=seen.append)
        trace.record(_send("."))
        assert [ev.__class__.__name__ for ev in seen] == ["SendQuery"]
        trace.record(Referral(DomainName("."), DomainName("com."), 0, 1))
        assert [ev.__class__.__name__ for ev in seen] == ["SendQuery", "Referral"]

    def test_children_inherit_the_listener(self):
        seen = []
        trace = Trace(_sname(), listener=seen.append)
        child = trace.child(_sname("ns.example.com."))
        child.record(_send("com."))
        assert [ev.__class__.__name__ for ev in seen] == ["SendQuery"]

    def test_the_live_line_and_the_recorded_line_are_the_same_text(self):
        # One formatter behind both views, so a reader who watched step 2 live
        # and a reader quoting "step 2" afterwards see one text, not two.
        trace = Trace(_sname())
        trace.record(_send("."))
        live = Trace.format_step(trace.events[0], 1)
        assert live == trace.to_text().splitlines()[1]

    def test_an_unnamed_step_is_silent(self):
        assert Trace.format_step(object(), 1) is None

    def test_sub_traces_arrive_indented_under_their_marker(self):
        parent = _walk()
        child = parent.child(_sname(name="ns1.example.", qtype=DnsQType.A))
        child.record(_send(".", qname="ns1.example."))
        text = parent.to_text()
        marker = text.index("+-- sub-trace")
        child_subject = text.index("; resolve ns1.example. A")
        assert child_subject > marker  # the child renders below the marker
        assert "\n     ; resolve ns1.example. A" in text  # five-space indent

    def test_no_sname_no_subject_line(self):
        trace = Trace()
        trace.record(Done(None))
        assert trace.to_text().startswith("  1")


class TestOneDispatch:
    def test_both_views_say_the_same_words_about_the_same_steps(self):
        """The drift this refactor exists to prevent, pinned as a test."""
        trace = _walk()
        labels = [label for _kind, _zone, label in trace._dispatch()]
        assert len(labels) == 6  # every recorded event dispatched
        mermaid = trace.to_mermaid()
        text = trace.to_text()
        for label in labels:
            assert label in mermaid, label
            assert label in text, label

    def test_mermaid_still_builds_one_lane_per_zone_in_order(self):
        mermaid = _walk().to_mermaid()
        assert "participant Z0 as ." in mermaid
        assert "participant Z1 as com." in mermaid
        assert "C->>Z0:" in mermaid
        assert "Z0-->>C: referral" in mermaid
