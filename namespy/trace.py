"""Resolution trace + Mermaid renderer.

A `Trace` is the recorded yield stream of a `resolve_steps` generator. The
async driver in `namespy.resolver` calls `record(step)` on the trace for
every yielded effect, and asks for a `child(sname)` whenever a sub-lookup
starts -- a glueless address chase, or one of the standalone re-asks that an
RFC 10029 bundle leaves behind. Two renderers read the stream: `to_text()`
numbers the steps for a terminal (what ``--trace`` prints live), and
`to_mermaid()` renders the same steps as a Mermaid `sequenceDiagram` with one
lane per zone-cut visited (what ``--trace`` writes to the file); nested
sub-resolutions are appended below the parent diagram (Mermaid sequence
diagrams do not nest). Both consume one `_dispatch()` pass, so a step is
described once and the two views cannot drift.

Trace stores opaque step objects and dispatches on `__class__.__name__`
so it never has to import the resolver module — keeping imports
unidirectional (`resolver -> trace`).
"""


class Trace:
    """The recorded walk, optionally echoed live.

    *listener*, when given, is called with each step as it is recorded --
    ``--trace`` uses this to print the walk while it happens rather than
    reconstructing it afterwards. Children inherit the listener: a glue chase
    that stays silent until the parent finishes is the silence the flag exists
    to remove. Recording never depends on the listener succeeding; the list is
    the record of truth and the echo is commentary.
    """

    def __init__(self, sname=None, listener=None):
        self.sname = sname
        self.events = []
        self.children = []
        self._listener = listener

    def record(self, step):
        self.events.append(step)
        if self._listener is not None:
            self._listener(step)

    def child(self, sname=None):
        c = Trace(sname, listener=self._listener)
        self.children.append(c)
        return c

    def __repr__(self):
        return (
            f"<Trace sname={self.sname!r} events={len(self.events)} children={len(self.children)}>"
        )

    def _subject(self) -> str:
        """The trace's own one-line subject, computed once for every renderer.

        Same getattr ladder the diagram already used: an SNAME carries the
        question, a bare DomainName does not, and a type the registry has never
        heard of still renders as its number.
        """
        if self.sname is None:
            return ""
        qname = getattr(self.sname, "qname", self.sname)
        qtype = getattr(self.sname, "qtype", None)
        qtype_name = getattr(qtype, "name", str(qtype)) if qtype is not None else ""
        return f"resolve {qname} {qtype_name}".rstrip()

    def _dispatch(self):
        """One reading of the recorded steps, yielded as (kind, zone, label).

        A step is a *query* (a send toward *zone*), a *reply* (the other side of
        the most recent send), or a *note* (everything else the walk did or
        learned), with the label wording fixed here once -- every renderer says
        the same sentence about the same step, which is the whole reason the
        dispatch lives beside one method rather than inside each of two.
        Dispatch is by class *name* so this module never imports the resolver
        (see the module docstring).
        """
        for ev in self.events:
            described = self._describe(ev)
            if described is not None:
                yield described

    @staticmethod
    def _describe(ev):
        """One step as (kind, zone, label), or None if this vocabulary has no name for it."""
        cn = ev.__class__.__name__
        if cn == "SendQuery":
            qname = ev.questions[0].name if ev.questions else "?"
            qtype = ev.questions[0].qtype if ev.questions else None
            qtype_name = getattr(qtype, "name", str(qtype))
            marker = " (probe)" if getattr(ev, "probe", False) else ""
            if getattr(ev, "helper", False):
                marker += " (dnssec)"
            # Counted, not named: this module deliberately dispatches on class names so
            # it never has to import the resolver, and the type *names* would mean an
            # import of the registry that knows them. The count is also the fact worth
            # seeing -- which hops bundled, and how much they asked for -- while the
            # list itself is already in the query's EDNS option if a reader wants it.
            bundled = getattr(ev, "extra_qtypes", ()) or ()
            if bundled:
                marker += f" (mqtype +{len(bundled)})"
            return ("query", ev.entry.zone, f"{qname} {qtype_name}{marker}")
        if cn == "Referral":
            return (
                "reply",
                None,
                f"referral {ev.new_zone} (match {ev.match_before}->{ev.match_after})",
            )
        if cn == "Answer":
            return ("reply", None, f"AA, {len(ev.records)} records")
        if cn == "Nodata":
            return ("note", None, f"NODATA SOA={ev.soa.name if ev.soa else '?'}")
        if cn == "Nxdomain":
            return ("note", None, "NXDOMAIN")
        if cn == "NxdomainCut":
            # Rendered *before* the NXDOMAIN it caused, and naming both
            # halves on purpose: the packets of a cut and of a fetched denial
            # are indistinguishable, so this line is the only place the
            # denied name and the ancestor that denied it appear together.
            return ("note", None, f"NXDOMAIN cut: {ev.name} below {ev.denied_by}")
        if cn == "AggressiveDenial":
            # The proof's name is rarely related to the queried one -- that
            # is the whole nature of the inference -- so the line says which
            # kind of denial was written and which entry vouched for it.
            return ("note", None, f"aggressive {ev.kind}: {ev.name} proven by {ev.proven_by}")
        if cn == "CompactDenial":
            # The one denial whose RCODE and its story can differ: restored
            # says whether the zone itself moved the code to NXDOMAIN under
            # the §5.1 signal or left it NOERROR with only the bit to say
            # so -- which is precisely what a reader of the trace line
            # cannot tell from the packet afterwards.
            return (
                "note",
                None,
                f"compact denial: {ev.name}"
                f"{' (NXDOMAIN restored)' if ev.restored else ' (NOERROR + NXNAME)'}",
            )
        if cn == "WildcardSynthesis":
            return ("note", None, f"wildcard answer: {ev.name} via {ev.via}")
        if cn == "ServeStale":
            return ("note", None, f"serve stale: {ev.name} (expired {ev.age}s ago)")
        if cn == "DnssecVerdict":
            # The verdict beside the zone that made the denial, ahead of the
            # NXDOMAIN it judges: with anchors configured this line is the
            # whole difference between "proved" and "asserted", and an
            # operator comparing two cuts reads the status first.
            return ("note", None, f"dnssec {ev.status}: {ev.zone}")
        if cn == "ChainFromCache":
            # The absence of a query is otherwise invisible; this line is
            # the only place a trace shows which chain leg the cache
            # carried instead of the network.
            return ("note", None, f"chain from cache: {ev.qtype} {ev.name}")
        if cn == "Demote":
            ns = ev.entry.ns if ev.entry is not None else "?"
            return ("note", None, f"demote {ns} ({ev.reason})")
        if cn == "NeedAddress":
            return ("note", None, f"glueless: resolve {ev.ns_name}")
        if cn == "VolunteeredGlue":
            # One line per nameserver a responder volunteered an address for.
            # Rendered under both policies on purpose: under the default the
            # line says the address was refused, and a trace full of those
            # lines is itself a measurement of who volunteers what.
            offered = ", ".join(str(address) for address in ev.addresses) or "undecodable"
            verdict = "believed" if ev.used else "discarded"
            return ("note", None, f"volunteered glue {ev.ns_name} ({offered}) {verdict}")
        if cn == "SpecialName":
            # The walk that never started is otherwise invisible: the packet
            # is indistinguishable from a cache answer, and the name says
            # nothing about the paragraph that let this resolver be certain.
            # The citation rides because "refused to ask" deserves a document.
            return ("note", None, f"special-use {ev.name}: {ev.action} ({ev.citation})")
        if cn == "Cname":
            return ("note", None, f"CNAME {ev.target}")
        if cn == "Done":
            return ("note", None, "done")
        if cn == "Fail":
            return ("note", None, f"FAIL {ev.reason}")
        return None

    # ------------------------------------------------------------------ views

    @staticmethod
    def _format_line(kind, zone, label, number):
        """One numbered terminal line in the --trace dialect.

        A method rather than an inlining inside to_text because the live
        listener must print exactly what to_text would have printed: the walk
        seen while it happens and the walk read afterwards are the same text,
        character for character. The zone is the whole point of a query line --
        the diagram has lanes for it and the terminal has nowhere else to say
        it.
        """
        if kind == "query":
            zkey = str(zone) if zone is not None else "."
            return f"{number:3d} -> {zkey}: {label}"
        if kind == "reply":
            return f"{number:3d} <- {label}"
        return f"{number:3d}   {label}"

    @classmethod
    def format_step(cls, step, number):
        """Format one resolver step for a live listener.

        None for a step this vocabulary has no name for -- a listener printing
        raw objects would show more than the diagram shows, and both views
        promising the same steps is the point of sharing the dispatch.
        """
        described = cls._describe(step)
        if described is None:
            return None
        return cls._format_line(described[0], described[1], described[2], number)

    def to_mermaid(self):
        """Render this trace, and any sub-traces, as Mermaid sequence diagrams.

        Output is a ``sequenceDiagram`` per trace: the client is always
        participant ``C``, and each zone visited gets ``Z0``, ``Z1``, ... in the
        order first queried, which mirrors the descent a reader is trying to
        follow. Sub-traces -- a glueless address chase, or a type the bundle left to a
        query of its own -- are appended as separate diagrams rather than nested, because
        Mermaid has no composition for that.
        """
        header = ["sequenceDiagram", "    participant C as client"]
        participants = {}
        body = []
        last_zone_id = ["C"]

        def participant_id(zone):
            key = str(zone) if zone is not None else "."
            if not key:
                key = "."
            if key not in participants:
                pid = f"Z{len(participants)}"
                participants[key] = pid
                header.append(f"    participant {pid} as {key}")
            return participants[key]

        subject = self._subject()
        title = f"    Note over C: {subject}" if subject else ""

        for kind, zone, label in self._dispatch():
            if kind == "query":
                pid = participant_id(zone)
                body.append(f"    C->>{pid}: {label}")
                last_zone_id[0] = pid
            elif kind == "reply":
                body.append(f"    {last_zone_id[0]}-->>C: {label}")
            else:
                body.append(f"    Note over C: {label}")

        lines = list(header)
        if title:
            lines.append(title)
        lines.extend(body)
        out = "\n".join(lines)
        for child in self.children:
            out += "\n\n" + child.to_mermaid()
        return out

    def to_text(self, indent: str = "") -> str:
        """The same steps as lines a terminal can read -- no Mermaid renderer needed.

        This is what ``--trace`` *shows*: numbered so a reader can quote "step 7",
        arrows so direction reads before words do, one event per line in the order
        it happened. Every label comes from the same :meth:`_dispatch` the diagram
        consumes, so the file and the terminal cannot tell two stories about one
        walk. Sub-traces arrive one level deeper under their own marker, each
        carrying its own subject line.
        """
        lines: list[str] = []
        subject = self._subject()
        if subject:
            lines.append(f"{indent}; {subject}")
        for number, (kind, zone, label) in enumerate(self._dispatch(), 1):
            lines.append(f"{indent}{self._format_line(kind, zone, label, number)}")
        for child in self.children:
            lines.append(f"{indent}   +-- sub-trace")
            lines.append(child.to_text(indent=indent + "     "))
        return "\n".join(lines)
