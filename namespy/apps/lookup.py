"""One-shot blocking lookup with a provenance line (roadmap W2).

``RecursiveResolver`` is an :class:`asyncio.Protocol`: asking it a question
means wiring up an event loop, binding a datagram endpoint, awaiting
:meth:`~namespy.resolver.RecursiveResolver.resolve`, and then closing *both* the
transport asyncio handed back and the private IPv6 socket the resolver opened
for itself. That is the right price for a resident object, and the wrong price
for "what is the A record for example.com". This module pays it once, on the
:class:`~namespy.engine.Engine` thread, and hands back the answer.

The line this returns is the reason the facade is worth having. The core already
knows *how* it reached an answer -- whether the descent left on the wire, whether
an answer was served from cache, whether it carried an assertion this build
validated, whether it rode the RFC 8767 serve-stale path -- and that knowledge
was, until now, only legible in
:attr:`~namespy.resolver.RecursiveResolver.last_trace` or on the wire flags.
:class:`Provenance` lifts those existing signals into one short sentence and
*nothing else*: it does not invent a verdict the library did not already reach.
See :meth:`Provenance.from_answer` for exactly which signal backs which word.

``via`` chooses the mechanism and nothing more: left ``None`` the question is
answered by the iterative walk; given one or more recursive servers it is
forwarded to them (RFC 1034 section 5.3.1's stub arrangement, wired to
:class:`~namespy.stub.StubResolver`). Over the walk, ``validated`` reflects what
this build proved; over a forward it reflects the upstream's ``AD`` flag, which
is that server's assertion, not our own validation -- the docstring on
:attr:`Provenance.validated` says so because the difference is the whole point of
a provenance line.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Callable, Iterable
from typing import Any

from .. import engine as _engine
from ..enums import DnsQType, DnsRClass
from ..names import DomainName
from ..packet import DnsQuestion, Query
from ..resolver import RecursiveResolver
from ..stub import StubResolver, Upstream

#: The blocking budget for a one-shot lookup. Generous because the walk can
#: descend many levels, and a one-shot caller has no loop of their own to
#: re-drive on a short timeout; the :class:`~namespy.engine.Engine` adds its own
#: small thread-hop grace on top, and either arm raises the same
#: :exc:`TimeoutError`.
DEFAULT_TIMEOUT_S = 10.0

__all__ = ["LookupResult", "Provenance", "lookup"]


@dataclasses.dataclass(frozen=True)
class Provenance:
    """How a :func:`lookup` came to know what it returned, and nothing more.

    Every field is read from a signal the core already produced; assembling this
    object adds no judgement of its own. :attr:`line` renders it the way the
    roadmap asks -- ``walk cache validated`` / ``forward unsigned stale``.
    """

    #: ``"walk"`` when the iterative descent answered, ``"forward"`` when a
    #: configured recursive server did (``via`` chose which).
    source: str
    #: The answer required no query on the wire: it was served from the resolver's
    #: cache, or from the RFC 6761 special-use registry consulted before the walk.
    #: Both leave no :class:`~namespy.resolver.SendQuery` in the trace, and both
    #: mean "this was not fetched just now", which is what the word *cache* is
    #: standing in for here.
    cached: bool = False
    #: Over the walk: this build validated the chain and set ``AD`` itself. Over a
    #: forward: the *upstream* set ``AD`` -- its assertion, not ours. The walk
    #: disregards a volunteered upstream ``AD`` (it is a validator or it is not),
    #: so a ``validated`` walk answer is one this library checked.
    validated: bool = False
    #: The answer rode RFC 8767 serve-stale: it is a cached RRset past its TTL,
    #: served because a refresh failed. EDE code 3 names it on the wire.
    stale: bool = False

    @classmethod
    def from_answer(cls, response: Any, trace: Any, source: str) -> Provenance:
        """Read the provenance a finished answer already carries.

        *trace* is the resolver's ``last_trace`` for a walk, ``None`` for a
        forward (a stub forms no verdict and keeps no trace). ``cached`` is
        derived conservatively -- only a walk that recorded no ``SendQuery`` at
        all claims the word -- so a partial cache hit that still asked something
        honestly reports ``walk`` rather than over-claiming.
        """
        cached = source == "walk" and trace is not None and _no_wire_query(trace)
        return cls(
            source=source,
            cached=cached,
            validated=bool(getattr(response, "AD", False)) if response is not None else False,
            stale=(
                bool(getattr(response, "stale_answer", False)) if response is not None else False
            ),
        )

    @property
    def line(self) -> str:
        """The one-line rendering: mechanism, [cache], validated-or-not, [stale]."""
        parts = [self.source]
        if self.cached:
            parts.append("cache")
        parts.append("validated" if self.validated else "unsigned")
        if self.stale:
            parts.append("stale")
        return " ".join(parts)


def _no_wire_query(trace: Any) -> bool:
    """Whether *trace* recorded no query that left on the wire.

    Dispatched on the event's class *name*, the way ``namespy/trace.py`` itself
    renders without importing the resolver: this composition tier must not reach
    down into the walk's effect types to answer a question the trace already
    records in its event list.
    """
    return not any(type(event).__name__ == "SendQuery" for event in trace.events)


@dataclasses.dataclass(frozen=True)
class LookupResult:
    """What :func:`lookup` returns: the records, and how they were reached."""

    #: The name the question asked about (after IDNA, if it came in as text).
    name: DomainName
    #: The numeric QTYPE asked -- an :class:`~namespy.enums.DnsQType` when one is
    #: registered, else the raw int, so an unregistered type round-trips (RFC 3597
    #: section 3).
    qtype: int
    #: The answer-section records, as they came; empty on a negative or silent
    #: answer. Iterate this in the common case.
    records: tuple[Any, ...] = ()
    #: The provenance sentence and its parts (see :class:`Provenance`).
    provenance: Provenance = dataclasses.field(default_factory=lambda: Provenance("walk"))
    #: The full :class:`~namespy.packet.Response`, or ``None`` when no server
    #: spoke -- present for callers who want ``AD``/``AA``/``RCODE`` themselves.
    response: Any | None = None
    #: The walk's :class:`~namespy.trace.Trace` for a ``walk`` lookup, else ``None``.
    trace: Any | None = None

    @property
    def line(self) -> str:
        """Shorthand for :attr:`provenance`'s one-line rendering."""
        return self.provenance.line


def resolve_qtype(token: Any) -> int:
    """Resolve a QTYPE given as a mnemonic, an enum member, or a number.

    A bare number with no registered mnemonic is accepted, mirroring the CLI and
    for the same reason: RFC 3597 section 3 makes unknown types legitimate wire
    values, and a freshly assigned type should be queryable on the day it is
    registered rather than after this library catches up.
    """
    if isinstance(token, int):
        return int(token)
    text = str(token).upper()
    try:
        return int(DnsQType[text])
    except KeyError:
        try:
            value = int(text)
        except ValueError as exc:
            raise ValueError(f"unrecognised record type {token!r}") from exc
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"record type {value} is not a 16-bit QTYPE") from None
        return value


def make_question(name: Any, qtype: Any = "A", qclass: Any = "IN") -> DnsQuestion:
    """Build the one :class:`~namespy.packet.DnsQuestion` both facades ask.

    A text name is punycoded the way the CLI punycodes its argument (RFC 5891
    section 5.3: U-labels become A-labels before the lookup); a name that is not
    one raises the parser's sentence rather than a traceback.
    """
    qname = name if isinstance(name, DomainName) else DomainName.from_unicode(str(name))
    if isinstance(qclass, DnsRClass):
        qclass_value = qclass
    elif isinstance(qclass, int):
        qclass_value = DnsRClass.parse(qclass)
    else:
        qclass_value = DnsRClass[str(qclass).upper()]
    return DnsQuestion(qname, resolve_qtype(qtype), qclass_value)


def coerce_upstreams(via: Any) -> tuple[Upstream, ...]:
    """Normalise ``via`` into the tuple of :class:`~namespy.stub.Upstream` to ask.

    Accepts one address or an iterable of them, each an :class:`Upstream` or the
    configuration text ``Upstream.parse`` reads; the empty list is refused,
    because a forwarder with nobody to forward to would silently answer nothing
    and call it a lookup.
    """
    if isinstance(via, (str, Upstream)):
        candidates: Iterable[Any] = (via,)
    else:
        candidates = via
    upstreams = tuple(Upstream.parse(u) if isinstance(u, str) else u for u in candidates)
    if not upstreams:
        raise ValueError("lookup(via=...) needs at least one recursive server")
    return upstreams


async def _resolve_on_loop(
    question: DnsQuestion, via: tuple[Upstream, ...] | None, kwargs: dict[str, Any]
) -> tuple[Any, Any, str]:
    """Bind, ask, and close -- the whole endpoint dance, on the engine's loop.

    Returns ``(response, trace, source)``. Both resolver classes are datagram
    protocols, so both are brought up the same way; a transport that is purely
    tcp/dot/doh still binds the uniform UDP socket the stub documents (cheap, and
    one shape of this function is worth it). Both sockets are closed in a
    ``finally`` -- the endpoint transport and the resolver's own ``aclose`` -- so a
    lookup that raises leaves neither behind, which is rule four of the engine
    carried up a layer.
    """
    loop = asyncio.get_running_loop()
    targets = () if via is None else via

    def make_walk() -> RecursiveResolver:
        return RecursiveResolver(**kwargs)

    def make_forward() -> StubResolver:
        return StubResolver(targets, **kwargs)

    factory: Callable[[], asyncio.Protocol] = make_forward if via is not None else make_walk
    source = "forward" if via is not None else "walk"
    transport, protocol = await loop.create_datagram_endpoint(factory, local_addr=("0.0.0.0", 0))
    resolver: Any = protocol  # RecursiveResolver or StubResolver, asked through either door
    try:
        if via is None:
            response = await resolver.resolve(Query(questions=[question]))
            trace = getattr(resolver, "last_trace", None)
        else:
            response = await resolver.forward([question])
            trace = None
    finally:
        transport.close()
        await resolver.aclose()
    return response, trace, source


def lookup(
    name: Any,
    qtype: Any = "A",
    *,
    via: Any = None,
    qclass: Any = "IN",
    timeout: float | None = DEFAULT_TIMEOUT_S,
    engine: _engine.Engine | None = None,
    **resolver_kwargs: Any,
) -> LookupResult:
    """Ask one question and block for the answer, records and provenance both.

    ``via`` picks the mechanism (``None`` walks the tree, an address or list of
    them forwards to recursive servers); ``qtype``/``qclass`` are the ordinary
    mnemonic-or-number pair (:func:`resolve_qtype` accepts an unregistered numeric
    type). Any remaining keyword is handed to the resolver class chosen --
    ``dnssec_ok=True``, ``trust_anchors=(...)``, ``serve_stale=...`` for the walk,
    ``dnssec_ok=...``/``query_timeout=...`` for the stub.

    It blocks on the shared default :class:`~namespy.engine.Engine` unless an
    *engine* is passed to isolate this call's thread. Because the work crosses
    into that engine's loop, a :func:`lookup` is legal from inside a thread that
    already runs its own event loop -- the nested-loop trap ``namespy.engine``
    fixed by construction, inherited for free here.
    """
    question = make_question(name, qtype, qclass)
    target = coerce_upstreams(via) if via is not None else None
    runner = engine if engine is not None else _engine.default_engine()
    response, trace, source = runner.run(
        _resolve_on_loop(question, target, resolver_kwargs), timeout=timeout
    )
    records = tuple(getattr(response, "answers", ()) or ()) if response is not None else ()
    provenance = Provenance.from_answer(response, trace, source)
    return LookupResult(
        name=question.name,
        qtype=question.qtype,
        records=records,
        provenance=provenance,
        response=response,
        trace=trace,
    )
