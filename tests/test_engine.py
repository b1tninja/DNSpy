"""The engine seam: W1's rules as executable claims (roadmap row W1).

Every test here is one sentence from ``namespy/engine.py``'s docstring, and a
regression of any of them would be the facade layer inheriting a bug -- which
is the reason this suite exists before any facade does. The conventions:

* no network, no namespy protocol objects -- the engine is plumbing, so it is
  tested with plain coroutines;
* every engine a test builds is closed in a fixture or ``finally`` (the class
  registry's atexit sweep makes an abandoned engine loud, not silent);
* timings are generous on the success side and short-but-not-tight on the
  failure side: this suite must fail on a broken seam, not on a loaded CI box;
* one code path can only be reached by simulation -- the handoff a loop refuses
  after the engine already checked it -- and the test that does it patches
  ``asyncio.run_coroutine_threadsafe`` and says so where it does. Nothing here
  asserts on the warning channel: a deallocator report covers the whole process,
  so "no warnings" would fail for reasons the test did not cause.
"""

import asyncio
import concurrent.futures
import logging
import threading

import pytest

from namespy import engine as engine_module
from namespy.engine import Engine


@pytest.fixture
def eng():
    engine = Engine("namespy-engine-test")
    try:
        yield engine
    finally:
        engine.close()


async def _echo(value, delay=0.0):
    if delay:
        await asyncio.sleep(delay)
    return value


async def _boom(exc):
    raise exc


async def _which_loop():
    return asyncio.get_running_loop()


# -- the blocking drive -------------------------------------------------------


def test_run_returns_the_coroutines_value(eng):
    assert eng.run(_echo("answered")) == "answered"


def test_run_blocks_from_a_plain_thread_and_uses_the_engine_loop(eng):
    # The calling thread has no loop at all; the coroutine must have run on
    # the engine's own loop, not by magic in this one.
    assert eng.run(_which_loop()) is eng._loop


def test_exceptions_cross_the_seam_unchanged(eng):
    # "A facade that wraps errors invents a taxonomy nobody asked for."
    with pytest.raises(ValueError, match="wire said so"):
        eng.run(_boom(ValueError("wire said so")))


def test_a_blocking_call_works_from_inside_a_running_loop(eng):
    """The nested-loop trap, pinned as behavior rather than documented away.

    asyncio.run() from inside a running loop raises RuntimeError; the engine's
    blocking drive must not -- this is exactly the notebook/async-shell case
    W1 exists for. The inner call runs on its own thread (how a real caller
    escapes its blocked loop) while the outer drive proves the seam itself.
    """

    async def main():
        box = {}

        def worker():
            try:
                box["value"] = eng.run(_echo("from inside"), timeout=5.0)
            except BaseException as exc:  # reported, not swallowed
                box["error"] = exc

        thread = threading.Thread(target=worker)
        thread.start()
        while thread.is_alive():
            await asyncio.sleep(0.01)
        thread.join()
        return box

    outcome = eng.run(main())  # a coroutine awaiting another drive's completion
    assert "error" not in outcome, outcome.get("error")
    assert outcome["value"] == "from inside"


def test_asyncio_run_from_a_running_loop_is_the_trap_we_avoid():
    """The negative control: proves the trap above is real, not folklore.

    Same shape as the passing test, driven the naive way -- it must raise. If
    this ever stops raising, the premise of W1 needs re-reading, not the code.
    """

    async def main():
        # The coroutine is closed by hand because asyncio.run refuses to touch it:
        # that refusal *is* the trap, and a leaked coroutine here would put this
        # suite's own warning report on the same page as the seam's.
        doomed = _echo("nope")
        try:
            return asyncio.run(doomed)
        finally:
            doomed.close()

    control = Engine("namespy-engine-control")
    try:
        with pytest.raises(RuntimeError, match="cannot be called from a running event loop"):
            control.run(main(), timeout=5.0)
    finally:
        control.close()


# -- timeouts ------------------------------------------------------------------


def test_timeout_fires_inside_the_loop_and_cancels_the_coroutine(eng):
    cancelled = threading.Event()

    async def slow():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    with pytest.raises(TimeoutError):
        eng.run(slow(), timeout=0.2)
    assert cancelled.wait(2.0), "wait_for must cancel on the engine's loop, not just abandon"


def test_timeout_is_the_same_error_from_both_arms():
    # run()'s docstring leans on concurrent.futures and builtins sharing one
    # TimeoutError (3.11+). If a future Python ever unshares it, this fails
    # first -- which is the point of asserting the identity, not trusting it.
    assert concurrent.futures.TimeoutError is TimeoutError


def test_grace_only_applies_to_a_wedged_engine_not_a_late_answer(eng):
    import time

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        eng.run(_echo(None, delay=30), timeout=0.2)
    elapsed = time.monotonic() - started
    # The in-loop timeout fired; the seam must not have waited its own full
    # grace period before noticing.
    assert elapsed < 0.2 + engine_module._GRACE_S + 1.0


# -- the callback drive ---------------------------------------------------------


def test_submit_never_blocks_and_the_callback_gets_the_value(eng):
    got = {}
    done = threading.Event()

    def on_done(future):
        got["value"] = future.result()
        done.set()

    future = eng.submit(_echo("slip"), on_done=on_done)
    assert isinstance(future, concurrent.futures.Future)
    assert done.wait(5.0), "on_done must fire even when nothing else is waiting"
    assert got["value"] == "slip"


def test_callback_runs_on_the_engine_loop_thread(eng):
    seen = {}
    done = threading.Event()

    def on_done(future):
        future.result()  # retrieve, so a carried exception can never go unnoted
        seen["thread"] = threading.current_thread()
        done.set()

    eng.submit(_echo(1), on_done=on_done)
    assert done.wait(5.0)
    assert seen["thread"] is eng._thread


def test_a_raising_callback_is_logged_and_the_engine_survives(eng, caplog):
    def nasty(future):
        msg = future.result()
        raise RuntimeError(f"callback bug after {msg}")

    with caplog.at_level(logging.ERROR, logger="namespy.engine"):
        first = eng.submit(_echo("one"), on_done=nasty)
        assert first.result(timeout=5) == "one"
        # The engine must still serve: the callback's bug is not the engine's.
        assert eng.run(_echo("two"), timeout=5.0) == "two"
    assert any("engine_callback_failed" in r.getMessage() for r in caplog.records)


def test_callback_fires_even_when_the_work_times_out(eng):
    """The notification API must not have a silent arm."""
    done = threading.Event()
    seen = {}

    def on_done(future):
        try:
            seen["error"] = future.exception()
        except concurrent.futures.CancelledError:
            seen["error"] = "cancelled"
        done.set()

    eng.submit(_echo(None, delay=30), timeout=0.2, on_done=on_done)
    assert done.wait(5.0)
    assert isinstance(seen["error"], TimeoutError)


# -- lifecycle -------------------------------------------------------------------


def test_close_is_idempotent_and_the_engine_refuses_work_afterwards(eng):
    eng.close()
    eng.close()  # idempotent: a double close is a caller's shrug, not a bug
    coro = _echo("too late")
    with pytest.raises(RuntimeError, match="is closed"):
        eng.run(coro)
    coro.close()  # a refused caller-coroutine stays the caller's (rule four)


def test_a_closed_engine_never_runs_the_coroutine_it_was_handed(eng):
    """The refusal must be a refusal all the way down -- no orphaned work.

    Rule four, both ownerships: wrappers this seam created are closed by this
    seam (no "never awaited" warning, no value in limbo); the caller's own
    coroutine comes back untouched and refused loudly.
    """
    eng.close()

    awaited = threading.Event()

    async def tracked():
        awaited.set()

    # The caller hands over their own coroutine; the engine must neither run it
    # nor consume it -- close is the test's to make, and no warning escapes.
    coro = tracked()
    with pytest.raises(RuntimeError, match="is closed"):
        eng.run(coro)
    assert not awaited.wait(0.1), "a refused coroutine must not run"
    coro.close()


def test_work_handed_to_a_stopping_loop_is_answered_or_refused_never_held():
    """Rule four's third shape, forced on purpose rather than waited for.

    A plain function runs on the loop thread, submits, and asks the loop to stop in
    the same turn, so the handoff joins a queue of a loop that is on its way out.
    Which half wins is asyncio's to decide: the teardown's cancel-and-drain gives a
    queued handle the turn :func:`asyncio.run` would have given it, while the close
    that follows drops the ones it did not reach. So what gets pinned is the
    promise this seam makes either way -- the caller's future resolves, with the
    work's value or with a refusal that names the engine, and never by timing out
    on a loop that will never turn again -- plus the ledger, which is empty
    afterwards because nothing is left owned by nobody.
    """
    engine = Engine("namespy-engine-queued")
    loop = engine._ensure_loop()
    box = {}

    async def queued_work():
        return "answered"

    def queue_and_stop():
        coro = queued_work()
        box["coro"] = coro
        box["future"] = engine.submit(coro, timeout=5.0)
        loop.stop()

    loop.call_soon_threadsafe(queue_and_stop)
    engine._thread.join(5)
    assert not loop.is_running()

    refusal = None
    outcome = None
    try:
        outcome = box["future"].result(timeout=5.0)
    except RuntimeError as exc:
        refusal = str(exc)
    if refusal is not None:
        assert "namespy-engine-queued" in refusal, f"a refusal must name its engine: {refusal}"
    else:
        assert outcome == "answered", "the drain ran the handoff the loop was handed"
    assert not engine._pending, "nothing stays in the ledger once the thread is gone"
    box["coro"].close()  # a no-op if the work ran, and the caller's own business if not
    engine.close()


def test_a_loop_closed_behind_the_engine_refuses_by_name():
    """The refusal at the door, and the reason the door knows.

    Stopping the loop from inside lets the "stopped but still open" moment pass on
    its own: the thread's teardown closes the loop it owns. A submission that
    arrives afterwards therefore finds a closed loop in an engine that was never
    closed, and _pick_loop answers with the engine's own sentence before anything
    is registered -- asyncio's would name neither this object nor its name. The
    ledger stays empty, which is the point of refusing before wrapping rather than
    after: there is nothing to sweep because nothing was ever taken.
    """
    engine = Engine("namespy-engine-preclosed")
    loop = engine._ensure_loop()
    loop.call_soon_threadsafe(loop.stop)
    engine._thread.join(5)
    assert loop.is_closed(), "the thread closes the loop on the way out"

    async def tracked():  # pragma: no cover - must never run
        raise AssertionError("ran on a closed loop")

    coro = tracked()
    with pytest.raises(RuntimeError, match=r"namespy-engine-preclosed.*no usable loop"):
        engine.submit(coro, timeout=5.0)
    assert coro.cr_frame is not None, "a caller's coroutine stays theirs"
    assert not engine._pending, "a refusal registers nothing"
    coro.close()
    engine.close()


def test_a_refused_handoff_closes_exactly_what_submit_built(eng, monkeypatch):
    """The sliver between "this loop is open" and "this loop took the work".

    :func:`asyncio.run_coroutine_threadsafe` raises :exc:`RuntimeError` when a loop
    closes in that gap, and everything below the handoff belongs to the seam: the
    scheduling wrapper and, on the timeout path, the wait_for beneath it. The only
    door into the gap is that function itself -- submit reaches it as an attribute
    of :mod:`asyncio`, so that is what gets patched, and monkeypatch puts it back --
    which makes this the one place in the suite that pins a code path by simulation
    rather than by behavior. The wrapper is captured *from* the patch so the claim
    can be read off an object instead of off the warning channel: a deallocator
    report covers the whole process, so asserting "no warnings" here would fail for
    reasons this test did not cause. What the refusal owns is that frame; what it
    must not touch is the caller's.
    """
    handed_over = {}

    def refuse(coro, loop):  # exactly what asyncio raises on a loop just closed
        handed_over["wrapper"] = coro
        raise RuntimeError("Event loop is closed")

    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", refuse)

    async def tracked():  # pragma: no cover - never reached a loop at all
        raise AssertionError("ran without a handoff")

    coro = tracked()
    with pytest.raises(RuntimeError, match="Event loop is closed"):
        eng.submit(coro, timeout=5.0)
    assert handed_over["wrapper"].cr_frame is None, "the seam closed the wrapper it built"
    assert not eng._pending, "the refusal left no entry behind"
    assert coro.cr_frame is not None, "a caller's coroutine stays theirs"
    coro.close()


def test_an_engine_cannot_close_itself_from_its_own_loop(eng):
    async def suicide():
        eng.close()

    box = {}

    def worker():
        try:
            eng.run(suicide())
        except BaseException as exc:  # asserted below
            box["error"] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(10)
    assert isinstance(box.get("error"), RuntimeError)
    assert "cannot close itself" in str(box["error"])


def test_shutdown_cancels_pending_tasks_rather_than_abandoning_them(eng):
    """close() must not leave a task mid-await -- the socket-leak rule.

    "Pending" is the whole claim, so the test waits for the work to start before
    it closes: submit-then-close-immediately is a race in which the loop may never
    have run the handoff at all, and that shape -- a caller refused, not a task
    abandoned -- belongs to the sweep's tests above.
    """
    started = threading.Event()
    cancelled = threading.Event()

    async def never_ends():
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    future = eng.submit(never_ends())  # nobody waits for it; it is pending at close time
    assert started.wait(5.0), "the work has to be mid-await before close() runs"
    eng.close()
    assert cancelled.wait(5.0), "teardown must cancel-and-drain like asyncio.run"
    with pytest.raises(concurrent.futures.CancelledError):
        future.result(timeout=5.0)  # the caller is told, not left holding a live future


def test_the_sweep_refuses_what_a_lost_drain_leaves_behind(monkeypatch, caplog):
    """The one ledger entry a running loop cannot produce, forced from outside.

    While a loop turns, a handoff it was handed is eventually run -- so the entry
    the sweep exists for only appears when the drain is lost: the loop closes with
    a handle still queued. No public door does that (a running loop refuses to be
    closed), so the drain is replaced with the shape it takes when it fails, and
    the loop closes mid-teardown. What is then asserted is the promise, not the
    simulation: the caller is refused by name instead of left pending on a dead
    loop, the ledger empties, and a teardown that could not finish says so.
    """

    def drain_lost(loop):
        loop.close()  # the queue goes with it, which is what orphans the handoff
        raise RuntimeError("Event loop is closed")

    monkeypatch.setattr(engine_module, "_shutdown_loop", drain_lost)
    engine = Engine("namespy-engine-swept")
    loop = engine._ensure_loop()
    box = {}

    async def never_runs():  # pragma: no cover - the loop that would run it is gone
        raise AssertionError("ran on a loop that lost its drain")

    def queue_and_stop():
        box["coro"] = never_runs()
        box["future"] = engine.submit(box["coro"], timeout=5.0)
        loop.stop()

    with caplog.at_level(logging.ERROR, logger="namespy.engine"):
        loop.call_soon_threadsafe(queue_and_stop)
        engine._thread.join(5)

    with pytest.raises(RuntimeError, match=r"namespy-engine-swept' closed before this work"):
        box["future"].result(timeout=5.0)
    assert not engine._pending, "the sweep took what the closed loop abandoned"
    assert any("engine_shutdown_failed" in r.getMessage() for r in caplog.records)
    box["coro"].close()  # refused, never consumed: closing it stays the caller's job
    engine.close()


def test_shutdown_loop_on_an_already_closed_loop_is_a_no_op():
    """Teardown may be reached twice on the same loop; the second pass is silence."""
    loop = asyncio.new_event_loop()
    loop.close()
    engine_module._shutdown_loop(loop)  # must not raise: this runs on a dying thread


def test_the_context_manager_owns_the_engine_it_was_handed():
    """``with Engine()`` is the resident form, so both exits have to hold.

    Entry starts the loop (a facade built inside a ``with`` is usable on the first
    line), exit closes it, and an exception inside the block is *not* swallowed --
    :meth:`Engine.__exit__` returns False, which is the difference between a
    context manager and a lie. The refused submission after the block is the proof
    the close really happened.
    """
    with Engine("namespy-engine-with") as engine:
        assert engine.name == "namespy-engine-with"
        assert engine.run(_echo("inside"), timeout=5.0) == "inside"
    assert engine._closed
    coro = _echo("too late")
    with pytest.raises(RuntimeError, match="is closed"):
        engine.run(coro)
    coro.close()

    try:
        with Engine("namespy-engine-raising") as engine:
            raise KeyError("the block failed")
    except KeyError:
        pass  # the exception belongs to the caller, not to the engine
    assert engine._closed, "a context manager that leaks an open loop is a thread leak"


def test_the_daemon_thread_does_not_outlive_a_forgotten_engine():
    # An engine whose close() nobody called still exits the process: the thread
    # is daemonic, and the atexit sweep closes it. Here we assert both halves.
    forgotten = Engine("namespy-engine-forgotten")
    try:
        forgotten.run(_echo(1))
        thread = forgotten._thread  # close() clears the reference; keep our own
        assert thread.daemon
    finally:
        engine_module._close_all()  # exactly what atexit runs
    assert not thread.is_alive()


def test_default_engine_is_shared_and_rebuilt_after_close():
    first = engine_module.default_engine()
    assert engine_module.default_engine() is first
    assert first.run(_echo("shared")) == "shared"
    first.close()
    second = engine_module.default_engine()
    assert second is not first, "a closed default must be replaced, not reused"
    try:
        assert second.run(_echo("fresh")) == "fresh"
    finally:
        second.close()


def test_the_module_level_drives_use_the_shared_engine():
    """``engine.run`` and ``engine.submit`` are what a one-shot facade calls.

    They are the module's whole public surface for a caller who has no resident
    object, so they are driven here rather than assumed: the blocking form returns
    the value, the callback form reports it, and both went through the one engine
    :func:`namespy.engine.default_engine` hands out.
    """
    assert engine_module.run(_echo("one-shot"), timeout=5.0) == "one-shot"

    done = threading.Event()
    seen = {}

    def on_done(future):
        seen["value"] = future.result()
        done.set()

    future = engine_module.submit(_echo("fired"), timeout=5.0, on_done=on_done)
    assert done.wait(5.0), "the callback drive fires on the shared engine too"
    assert seen["value"] == "fired"
    assert future.result(timeout=5.0) == "fired"
    assert engine_module.default_engine()._pending == {}, "the shared ledger stays clean"
