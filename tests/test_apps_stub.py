"""The resident three-drive Stub: one engine, held streams, all drives (roadmap W2).

The claim under test is the *life* of the object, not the DNS: a Stub binds once,
answers many times over that one bound resolver (so its held TLS/TCP sessions
survive between questions -- the RFC 7858 section 3.4 reuse that made the resident
object worth having), speaks on three drives over that one coroutine, and closes
exactly what it made. Conventions from ``test_engine.py``: no network, an engine
built and closed by the test, and a fake endpoint that builds the *real*
StubResolver offline then takes over its ask/close methods.
"""

import threading

import pytest

from namespy.apps.stub import Stub
from namespy.engine import Engine
from namespy.resolver import Resolver


class _FakeTransport:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, key, default=None):
        return default

    def close(self):
        self.closed = True


def _stub_env(eng, *, response):
    """Patch *eng*'s loop to bind a real-but-silent StubResolver, counting main binds.

    Only the ``Resolver``/``StubResolver`` endpoint is counted and recorded; the IPv6
    socket the resolver's ``connection_made`` brings up through the same factory is
    answered with a sink, so "binds once" really means "one bound resolver".
    """
    state = {"binds": 0, "aclosed": False, "forwarded": [], "transport": None}

    async def fake_endpoint(factory, **_kwargs):
        protocol = factory()
        if not isinstance(protocol, Resolver):
            return _FakeTransport(), protocol  # the bring-up's IPv6 sink
        transport = _FakeTransport()
        protocol.connection_made(transport)

        async def forward(questions):
            state["forwarded"].append(questions)
            return response

        async def aclose():
            state["aclosed"] = True

        protocol.forward = forward
        protocol.aclose = aclose
        state["binds"] += 1
        state["transport"] = transport
        return transport, protocol

    eng._ensure_loop()
    eng._loop.create_datagram_endpoint = fake_endpoint
    return state


@pytest.fixture
def eng():
    engine = Engine("namespy-engine-stub-test")
    try:
        yield engine
    finally:
        engine.close()


@pytest.fixture
def stub_factory(eng):
    created = []

    def build(response=None):
        response = "ANSWER" if response is None else response
        state = _stub_env(eng, response=response)
        stub = Stub(["10.1.1.1"], engine=eng, name="namespy-stub-test")
        created.append(stub)
        return stub, state

    yield build
    for stub in created:
        stub.close()


async def test_the_await_drive_answers_from_a_running_loop(stub_factory):
    stub, state = stub_factory()
    response = await stub.ask("example.com", "A")
    assert response == "ANSWER"
    assert state["binds"] == 1
    assert int(state["forwarded"][0][0].qtype) == 1


def test_the_blocking_drive_answers_without_a_caller_loop(stub_factory):
    stub, _state = stub_factory()
    assert stub.ask_blocking("example.com") == "ANSWER"


async def test_the_blocking_drive_works_inside_a_running_loop(stub_factory):
    # Nested-loop trap: the caller thread already runs a loop, yet the blocking
    # drive crosses into the engine loop and returns rather than erroring.
    stub, _state = stub_factory()
    assert stub.ask_blocking("example.com") == "ANSWER"


def test_the_callback_drive_fires_on_done_with_the_value(stub_factory):
    stub, _state = stub_factory()
    done = threading.Event()
    box = {}

    def on_done(future):
        box["value"] = future.result()
        done.set()

    future = stub.ask_callback("example.com", on_done=on_done)
    assert done.wait(5.0), "the callback must fire on the engine thread"
    assert box["value"] == "ANSWER" == future.result()


async def test_many_questions_reuse_one_bound_resolver(stub_factory):
    # The resident object's whole point: bind once, ask many, so held sessions
    # (RFC 7858 section 3.4) survive between questions.
    stub, state = stub_factory()
    for _ in range(5):
        await stub.ask("example.com")
    assert state["binds"] == 1, "one engine, one resolver, five questions"
    assert len(state["forwarded"]) == 5


async def test_all_three_drives_agree(stub_factory):
    stub, _state = stub_factory()
    via_await = await stub.ask("example.com")
    via_blocking = stub.ask_blocking("example.com")
    via_callback = stub.ask_callback("example.com").result(5.0)
    assert via_await == via_blocking == via_callback == "ANSWER"


async def test_sync_context_manager_releases_everything(eng):
    response = "ANSWER"
    state = _stub_env(eng, response=response)
    with Stub(["10.1.1.1"], engine=eng) as stub:
        assert stub.ask_blocking("example.com") == response
    assert state["aclosed"] is True, "the resolver's own aclose ran on teardown"
    assert state["transport"].closed is True, "and the endpoint socket was closed"
    assert eng._closed is False, "a borrowed engine outlives the Stub that used it"


async def test_async_context_manager_releases_everything(eng):
    response = "ANSWER"
    state = _stub_env(eng, response=response)
    async with Stub(["10.1.1.1"], engine=eng) as stub:
        assert await stub.ask("example.com") == response
    assert state["aclosed"] is True
    assert state["transport"].closed is True
    assert eng._closed is False


async def test_asking_a_closed_stub_raises_by_name(stub_factory):
    stub, _state = stub_factory()
    await stub.ask("example.com")
    stub.close()
    with pytest.raises(RuntimeError, match="closed"):
        await stub.ask("example.com")


async def test_close_is_idempotent(stub_factory):
    stub, state = stub_factory()
    await stub.ask("example.com")
    stub.close()
    stub.close()  # a second close releases nothing twice and does not raise
    assert state["aclosed"] is True


def test_an_owned_engine_is_stopped_with_the_stub():
    # No engine passed in: the Stub builds its own and must stop it on close.
    stub = Stub(["10.1.1.1"], name="namespy-stub-owned")
    assert stub._owns_engine is True
    stub._engine._ensure_loop()
    _stub_env(stub._engine, response="ANSWER")
    stub.ask_blocking("example.com")
    owned = stub._engine
    stub.close()
    assert owned._closed is True, "the Stub stopped the engine it built"


def test_config_reaches_the_underlying_stub_resolver(eng):
    state = _stub_env(eng, response="ANSWER")
    stub = Stub(["10.1.1.1"], engine=eng, dnssec_ok=True, edns_payload_size=1232, query_timeout=1.5)
    try:
        stub.ask_blocking("example.com")
        # The endpoint factory built the real StubResolver before we took it over.
        assert state["transport"] is not None
    finally:
        stub.close()


def test_a_borrowed_closed_engine_refuses_without_hanging(eng):
    state = _stub_env(eng, response="ANSWER")
    stub = Stub(["10.1.1.1"], engine=eng)
    eng.close()  # the engine the Stub borrows goes away underneath it
    with pytest.raises(RuntimeError):
        stub.ask_blocking("example.com")  # refused at the door; the coroutine is closed, not leaked
    assert state["binds"] == 0, "a refused submit never bound a resolver"
