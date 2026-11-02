"""The one-shot lookup facade: provenance and wiring as executable claims (roadmap W2).

Every test here is one sentence from ``namespy/apps/lookup.py``, and a regression
of any of them would be the composition layer misreporting how it reached an
answer -- which is the whole product of ``lookup``. Conventions, borrowed from
``test_engine.py`` and ``test_cli.py``:

* no network. The engine's loop has ``create_datagram_endpoint`` patched to build
  the *real* resolver or stub protocol (construction is offline) and then take
  over its ask/close methods, so the facade is proven to drive the real object's
  contract -- a walk calls ``resolve`` with a ``Query``, a forward calls
  ``forward`` with a question list -- without a single datagram sent;
* every engine a test builds is closed in a ``finally``, so the class registry's
  atexit sweep is never the reason a test is quiet;
* a canned answer is a plain object exposing only the attributes the facade reads
  (``answers`` / ``AD`` / ``stale_answer``): the facade reads those by ``getattr``
  and nothing else, so the fake says exactly what is under test and no more.
"""

import asyncio
import types

import pytest

from namespy.apps.lookup import Provenance, lookup
from namespy.engine import Engine
from namespy.names import DomainName
from namespy.packet import Query
from namespy.resolver import RecursiveResolver, Resolver
from namespy.stub import StubResolver


class SendQuery:
    """Named to match the trace event the facade dispatches on by class name."""


def _answer(answers=(), *, ad=False, stale=False):
    return types.SimpleNamespace(answers=list(answers), AD=ad, stale_answer=stale)


def _trace(*events):
    return types.SimpleNamespace(events=list(events))


class _FakeTransport:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, key, default=None):
        return default

    def close(self):
        self.closed = True


def _stub_loop(eng, *, response, trace=None, resolve_exc=None):
    """Route the engine loop's endpoint creation to a real-but-silent resolver.

    Returns ``made``: one tuple per *main* bound resolver, ``(protocol, calls,
    transport)``, where ``calls`` records which ask-method the facade chose and with
    what, and ``transport.closed``/``calls['aclosed']`` say whether the facade closed
    both sockets on the way out. A ``Resolver``'s ``connection_made`` also brings up a
    private IPv6 socket through the same factory, so only the ``Resolver``/``Stub``
    endpoint is recorded -- the shim endpoint is answered with a trivial sink.
    ``resolve_exc`` makes the walk raise it, to prove the close happens anyway.
    """
    made = []

    async def fake_endpoint(factory, **_kwargs):
        protocol = factory()
        if not isinstance(protocol, Resolver):
            return _FakeTransport(), protocol  # the bring-up's IPv6 sink
        transport = _FakeTransport()
        protocol.connection_made(transport)  # the binder would have; send path reads it
        calls = {"aclosed": False}

        async def resolve(packet):
            calls["method"] = "resolve"
            calls["arg"] = packet
            protocol.last_trace = trace
            if resolve_exc is not None:
                raise resolve_exc
            return response

        async def forward(questions):
            calls["method"] = "forward"
            calls["arg"] = questions
            return response

        async def aclose():
            calls["aclosed"] = True

        protocol.resolve = resolve
        protocol.forward = forward
        protocol.aclose = aclose
        made.append((protocol, calls, transport))
        return transport, protocol

    eng._ensure_loop()
    eng._loop.create_datagram_endpoint = fake_endpoint
    return made


@pytest.fixture
def eng():
    engine = Engine("namespy-engine-lookup-test")
    try:
        yield engine
    finally:
        engine.close()


def test_walk_returns_records_and_a_walk_provenance(eng):
    record = object()
    made = _stub_loop(eng, response=_answer([record]), trace=_trace(SendQuery()))
    result = lookup("example.com", "A", engine=eng)
    assert result.records == (record,)
    assert result.line == "walk unsigned"
    protocol, calls, _transport = made[0]
    assert isinstance(protocol, RecursiveResolver), "via=None builds the walk"
    assert calls["method"] == "resolve"
    assert isinstance(calls["arg"], Query), "the walk is handed a Query"


def test_forward_asks_the_stub_and_reports_its_source(eng):
    made = _stub_loop(eng, response=_answer([]))
    result = lookup("example.com", "AAAA", via="10.1.1.1", engine=eng)
    protocol, calls, _transport = made[0]
    assert isinstance(protocol, StubResolver), "via=<server> builds the stub"
    assert calls["method"] == "forward"
    assert isinstance(calls["arg"], list), "forward takes a list of questions"
    assert int(calls["arg"][0].qtype) == 28  # AAAA
    assert result.line == "forward unsigned"
    assert result.trace is None, "a stub keeps no trace and so reports none"


def test_a_wire_silent_walk_is_reported_as_cached(eng):
    # A pure cache hit records no SendQuery; that absence is the only signal used.
    _stub_loop(eng, response=_answer([object()]), trace=_trace())
    result = lookup("example.com", engine=eng)
    assert result.provenance.cached is True
    assert result.line == "walk cache unsigned"


def test_a_walk_that_asked_anything_is_not_claimed_cached(eng):
    _stub_loop(eng, response=_answer([object()]), trace=_trace(SendQuery()))
    assert lookup("example.com", engine=eng).provenance.cached is False


def test_validated_tracks_ad_on_the_answer(eng):
    _stub_loop(eng, response=_answer([], ad=True), trace=_trace(SendQuery()))
    assert lookup("example.com", engine=eng).provenance.validated is True
    assert lookup("example.com", engine=eng).line == "walk validated"


def test_stale_tracks_the_serve_stale_marker(eng):
    _stub_loop(eng, response=_answer([], stale=True), trace=_trace(SendQuery()))
    result = lookup("example.com", engine=eng)
    assert result.provenance.stale is True
    assert result.line == "walk unsigned stale"


def test_silence_is_a_none_response_not_a_crash(eng):
    _stub_loop(eng, response=None, trace=_trace(SendQuery()))
    result = lookup("nosuch.test", engine=eng)
    assert result.response is None
    assert result.records == ()
    assert result.line == "walk unsigned"


def test_both_sockets_close_even_when_the_ask_raises(eng):
    made = _stub_loop(eng, response=_answer(), trace=_trace(), resolve_exc=ValueError("boom"))
    with pytest.raises(ValueError, match="boom"):
        lookup("example.com", engine=eng)
    _protocol, calls, transport = made[0]
    assert transport.closed is True, "the endpoint socket is closed in finally"
    assert calls["aclosed"] is True, "and so is the resolver's own aclose"


def test_resolver_kwargs_reach_the_chosen_class(eng):
    made = _stub_loop(eng, response=_answer(), trace=_trace())
    lookup("example.com", engine=eng, dnssec_ok=True)
    assert isinstance(made[0][0], RecursiveResolver)
    assert made[0][0].dnssec_ok is True


def test_lookup_blocks_from_inside_a_running_loop(eng):
    # The nested-loop trap the engine fixes by construction: a blocking lookup
    # called while this thread already runs a loop must still work.
    _stub_loop(eng, response=_answer([object()]), trace=_trace(SendQuery()))

    async def caller():
        return lookup("example.com", engine=eng)

    result = asyncio.run(caller())
    assert result.line == "walk unsigned"


def test_unregistered_numeric_qtype_passes_through(eng):
    _stub_loop(eng, response=_answer(), trace=_trace())
    assert lookup("example.com", 999, engine=eng).qtype == 999


def test_an_empty_via_list_is_refused_at_the_door(eng):
    with pytest.raises(ValueError, match="at least one"):
        lookup("example.com", via=[], engine=eng)


def test_provenance_line_reads_left_to_right():
    assert Provenance("forward", cached=True, validated=True, stale=True).line == (
        "forward cache validated stale"
    )


def test_name_is_parsed_to_a_domain_name(eng):
    _stub_loop(eng, response=_answer(), trace=_trace())
    assert lookup(DomainName("example.com."), engine=eng).name == DomainName("example.com.")


def test_an_unparseable_qtype_is_a_sentence_not_a_traceback(eng):
    _stub_loop(eng, response=_answer(), trace=_trace())
    with pytest.raises(ValueError, match="unrecognised record type"):
        lookup("example.com", "NOT A TYPE", engine=eng)


def test_a_qclass_reaches_the_question(eng):
    made = _stub_loop(eng, response=_answer(), trace=_trace())
    lookup("example.com", "A", qclass="CH", engine=eng)
    assert int(made[0][1]["arg"].questions[0].qclass) == 3  # CHAOS
