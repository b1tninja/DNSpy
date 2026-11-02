"""The seam between asyncio and callers who do not speak it (roadmap W1).

Everything namespy does is an ``asyncio.Protocol``, so every public surface is
loop-bound: asking a question means having an event loop, or wiring one up.
This module is the adapter that removes that requirement for callers who want
a blocking call or a callback instead -- and it implements nothing. The async
engine stays the single real surface (the same principle that makes
:meth:`namespy.server.DnsServer._reply` the server's only egress door); a
blocking drive is the very same coroutine, awaited on a loop someone else owns
and handed back across the thread boundary.

Four rules shape the design, and each one names the failure it prevents:

* **One engine per object, for its whole life.** asyncio primitives are not
  thread-safe, so every coroutine sharing state -- sockets, held TCP/DoT
  sessions, caches -- must run on the same loop. :class:`Engine` owns that
  loop in one daemon thread; :meth:`Engine.run` and :meth:`Engine.submit`
  marshal work to it. A resident client object therefore holds one engine (and
  closes it when done); a one-shot convenience function may make its own.

* **The nested-loop trap is fixed by construction, not documented away.** The
  obvious way to write a blocking facade -- ``asyncio.run()`` in the calling
  thread -- raises ``RuntimeError: asyncio.run() cannot be called from a
  running event loop`` for exactly the callers who most want it (notebooks,
  async shells). Here the call crosses into the engine's loop via
  :func:`asyncio.run_coroutine_threadsafe`, so a blocking drive works no
  matter what the calling thread is doing.

* **Timeouts mean one thing on both sides of the seam.** The coroutine is
  wrapped in :func:`asyncio.wait_for` *inside* the loop -- cancellation
  reaches the engine's own machinery, which knows how to abandon a pending
  query -- and the caller waits no longer than that plus a small grace for
  the thread hop. Either way the error is the same :exc:`TimeoutError`; a
  hang would otherwise mean three different things depending on drive.

* **Work this seam will not run leaves nothing behind.** A coroutine nobody
  starts is still an object with a frame, and Python's deallocator warns about
  it -- a leak report this project treats as a smell, never as noise. So the
  engine keeps a register of every wrapper it builds (the scheduling wrapper and,
  on the timeout path, the :func:`asyncio.wait_for` below it) and drops the entry
  the instant the loop starts running that work. A submission refused at the door
  is closed there; everything still unstarted when the thread stops is closed
  from the register, and its caller's future is resolved with a refusal naming
  the engine instead of left pending forever. Teardown also cancels-and-drains
  tasks that had started, the way :func:`asyncio.run`'s does. Because the register
  holds only what this seam made, a caller's coroutine handed to a closed engine
  stays the caller's -- refused loudly, never silently consumed.

  The register replaced a first draft that read asyncio's own queues instead:
  ``loop._closed_attribute`` for the unrun handles and ``handle._args[0]`` for
  the coroutine inside them. Both were invented. There is no such attribute, and
  :func:`asyncio.run_coroutine_threadsafe` passes the coroutine in a closure it
  builds itself, with an empty argument tuple -- so the sweep found nothing on
  the Python this project develops on, while quietly promising a guarantee it
  never delivered, on a private name that owes this code nothing across patch
  releases. Owning the list is the portable and the honest version of the same
  claim, and it is why :meth:`Engine._take` registers and hands off inside one
  critical section: a sweep either sees an entry whole or not at all.

Callback drives are plain callables, not a promise type: adding a future
class of our own would be a fourth API to maintain beside coroutine, blocking
and callback. ``on_done(future)`` receives the resolved :mod:`concurrent.futures`
future -- await it in another loop, inspect it for the reason nothing came
back -- and a callback that raises is logged with its exception, never allowed
to reach the engine's loop (the rule :class:`~namespy.server.DnsServer` already
applies to bound responders: a handler's failure must not take the server down).

The module imports no other namespy module. It is plumbing for whoever builds
the next facade, and it keeps the import graph where the package's
``__init__`` put it: nothing protocol-shaped reaches in here from below.
"""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import logging
import threading
from collections.abc import Callable, Coroutine
from typing import Any, ClassVar, Literal

LOGGER = logging.getLogger("namespy.engine")

#: The thread hop is a queue handoff plus a context switch; half a second of
#: grace over the in-loop timeout separates "the answer is late" (the
#: coroutine's TimeoutError, with its reason) from "the engine thread is wedged"
#: (a sentence naming this constant). It is a liveness margin, not a policy:
#: no value here changes when the engine gives up on an answer.
_GRACE_S = 0.5


class Engine:
    """An asyncio event loop in one daemon thread, ready to run coroutines.

    The whole of W1's blocking and callback drives is this: one loop, owned by
    one thread, for the life of whatever shares state on it. :meth:`submit`
    schedules a coroutine on that loop from any thread; :meth:`run` waits for
    it with one timeout policy applied identically inside the loop and at the
    seam (module docstring, rule three).

    The thread is daemonic so an application that forgets to :meth:`close` can
    still exit; :func:`atexit` then shuts the loop down politely --
    cancel-and-drain, the same shutdown :func:`asyncio.run` performs, because
    tasks abandoned mid-query are exactly what a clean exit should not leave
    behind.
    """

    _instances: ClassVar[set[Engine]] = set()
    _registry_lock = threading.Lock()

    def __init__(self, name: str = "namespy-engine") -> None:
        self._name = name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._closed = False
        # Rule four's ledger: every wrapper this object built, from the moment it
        # exists until the moment the loop starts running it. Keyed by the
        # scheduling wrapper, because that is what the loop is handed; the value
        # is the timeout wrapper beneath it (None when there is none) and the
        # caller's future, which the handoff produces. The caller's own coroutine
        # is deliberately absent: this seam closes what it owns, nothing else.
        self._pending: dict[
            Coroutine[Any, Any, Any],
            tuple[Coroutine[Any, Any, Any] | None, concurrent.futures.Future[Any] | None],
        ] = {}
        with Engine._registry_lock:
            Engine._instances.add(self)

    # -- lifecycle ---------------------------------------------------------

    def _pick_loop(self) -> asyncio.AbstractEventLoop:
        """The engine's loop, starting its thread on first use. The caller holds the lock.

        Three answers, and each names the mistake it prevents. Starting is
        idempotent because two threads racing into a fresh engine must not
        produce two loops for one set of sockets -- holding the lock while a
        second racer waits means the loser reads the winner's loop, never a
        half-published one. A closed *engine* is refused outright: an engine's
        life is its loop's life, and state does not migrate between loops. A loop
        closed behind the engine's back is refused with the engine's own sentence
        rather than asyncio's, which names neither this object nor its name -- and
        that shape is not hypothetical, because this class's own teardown closes
        the loop as the thread exits, so anyone who stops the thread from inside
        (a test, a signal handler, a responder that called :meth:`close` on the
        loop it was serving) arrives here.
        """
        if self._closed:
            raise RuntimeError(
                f"engine {self._name!r} is closed; build a new one (an "
                "engine's life is its loop's life, and state does not "
                "migrate between loops)"
            )
        loop = self._loop
        if loop is None:
            loop = self._start_loop()
        if loop.is_closed():
            raise RuntimeError(
                f"engine {self._name!r} has no usable loop: it was closed "
                "outside the engine; build a new one"
            )
        return loop

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """Return the engine's loop without registering anything (see :meth:`_pick_loop`)."""
        with self._lock:
            return self._pick_loop()

    def _take(
        self,
        started: Coroutine[Any, Any, Any],
        timeout_wrapper: Coroutine[Any, Any, Any] | None,
    ) -> tuple[asyncio.AbstractEventLoop, concurrent.futures.Future[Any]]:
        """Register *started*, hand it to the loop, and return that loop and the future.

        One critical section on purpose. Registering before the handoff means the
        work is in the ledger before any thread can run it; recording the future
        before releasing the lock means a sweep never finds an entry that does not
        yet know whom to refuse. The wrapper :func:`run_coroutine_threadsafe`
        builds runs the moment the loop turns, so its first act -- :meth:`_claim`
        -- has to contend for this same lock and therefore cannot interleave.

        Both door shapes are answered inside the same lock. A loop that refused the
        work -- engine closed, or loop closed behind the engine's back -- and a loop
        that closed between the check and the handoff both leave this seam owning
        wrappers it will never run, so both are closed here before the error leaves.
        The caller's coroutine is in none of that: it was never registered, and a
        refusal is not a taking.
        """
        with self._lock:
            registered = False
            try:
                loop = self._pick_loop()
                self._pending[started] = (timeout_wrapper, None)
                registered = True
                handed_off: concurrent.futures.Future[Any] = asyncio.run_coroutine_threadsafe(
                    started, loop
                )
            except RuntimeError as exc:
                # Both door shapes, one body: the loop refused before anything was
                # written down, or it closed between the check and the handoff.
                # Either way the wrappers are this seam's own, and a refusal that
                # leaves them behind is exactly the leak rule four forbids -- the
                # caller's coroutine is not in this call's hands and stays open.
                if registered:
                    del self._pending[started]
                _abandon(
                    started,
                    timeout_wrapper,
                    None,
                    f"engine {self._name!r} refused this work: {exc}",
                )
                raise
            self._pending[started] = (timeout_wrapper, handed_off)
            return loop, handed_off

    def _claim(self, started: Coroutine[Any, Any, Any]) -> None:
        """The loop is running this work now: it is no longer the sweep's to close."""
        with self._lock:
            self._pending.pop(started, None)

    def _sweep(self, reason: str) -> None:
        """Close every registered-but-unstarted wrapper and refuse its caller.

        :param reason: the sentence the abandoned futures carry, naming this
            engine and what happened to the work it was handed.
        """
        with self._lock:
            abandoned = list(self._pending.items())
            self._pending.clear()
        for started, (timeout_wrapper, future) in abandoned:
            _abandon(started, timeout_wrapper, future, reason)

    def _start_loop(self) -> asyncio.AbstractEventLoop:
        """Build the loop and its thread. Called under the lock, once."""
        loop = asyncio.new_event_loop()
        thread = threading.Thread(
            target=self._serve_forever, args=(loop,), name=self._name, daemon=True
        )
        # The loop is published before the thread starts so a submit that
        # arrives at once already sees it; _serve_forever owns running and
        # closing it.
        self._loop = loop
        self._thread = thread
        thread.start()
        return loop

    def _serve_forever(self, loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            # Sweep after the loop is closed, never before it. _shutdown_loop's
            # run_until_complete gives an already-queued handoff the turn
            # asyncio.run would have given it, so closing wrappers before that
            # drain leaves asyncio to run a coroutine that is already closed --
            # "cannot reuse already awaited coroutine", plus a future this seam
            # had already finished. After the close nothing can run and
            # _pick_loop refuses, so this is the first moment abandonment is
            # certain and the last moment anything can still be registered:
            # whatever the queue lost is closed here and its caller refused,
            # rather than left pending on a loop that will never turn again.
            # Tasks that had already started get the cancellation asyncio.run
            # would have given them; a loop found already closed has already shed
            # its queue, and _shutdown_loop says so quietly instead of raising
            # through a dying thread. Either way the sweep after it is the loud
            # part: every caller whose work will never run is refused by name.
            try:
                _shutdown_loop(loop)
            except Exception:  # teardown must not raise on a daemon thread
                LOGGER.exception("engine_shutdown_failed(thread=%s)", self._name)
            finally:
                self._sweep(f"engine {self._name!r} closed before this work started")
                # asyncio's own contract (its docs on run/run_until_complete):
                # the event-loop policy forgets a loop that is done with. Until
                # this ran, a stopped engine left its loop as the thread's
                # current one -- and any later asyncio.run() *in this process*
                # would find it via get_event_loop(), refuse it for being
                # closed, and blame whoever called run() next.
                try:
                    asyncio.set_event_loop(None)
                except RuntimeError:  # pragma: no cover - policy gone mid-shutdown
                    pass

    def close(self) -> None:
        """Stop the loop and join the thread, then sweep what is left. Idempotent.

        Safe from any thread except the engine's own: calling this from the loop
        thread cannot work -- the join would deadlock against the loop it waits
        for -- so it raises instead, naming the mistake rather than hanging the
        process. A loop already closed behind the engine's back (a test, a signal
        handler) is treated as stopped: there is nothing left to ask of it, and
        the engine is closed either way.

        The sweep after the join is the last word on rule four. The thread's own
        teardown sweeps once, after it has drained and closed the loop; a
        submission accepted in the window before that close is this call's to
        account for, because after the join there is no longer a loop that could
        run the work. Anything abandoned here is closed and refused by name rather
        than left pending on a future nobody will ever resolve.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            loop, thread = self._loop, self._thread
            self._loop = self._thread = None
        with Engine._registry_lock:
            Engine._instances.discard(self)
        if threading.current_thread() is thread:
            raise RuntimeError(
                f"engine {self._name!r} cannot close itself from its own loop "
                "thread; close it from the thread that owns the object"
            )
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join()
        self._sweep(f"engine {self._name!r} closed before this work started")

    def __enter__(self) -> Engine:
        self._ensure_loop()
        return self

    def __exit__(self, *exc_info: object) -> Literal[False]:
        self.close()
        return False

    # -- the two drives ----------------------------------------------------

    def submit(
        self,
        coro: Coroutine[Any, Any, Any],
        *,
        timeout: float | None = None,
        on_done: Callable[[concurrent.futures.Future], None] | None = None,
    ) -> concurrent.futures.Future:
        """Schedule *coro* on the engine's loop and return a future. Never blocks.

        A racing close() has three shapes, and rule four (module docstring) says
        what each owes. A **closed engine, or a loop already closed**, refuses at
        the door: :meth:`_pick_loop` answers with the engine's own sentence before
        anything is registered, so nothing is orphaned and the caller's coroutine
        comes back untouched. The **sliver** where the loop closes between that
        check and the handoff is closed by :meth:`_take` inside the same critical
        section -- the wrappers this call created are closed, the ledger forgets
        them, and the :exc:`RuntimeError` leaves as asyncio wrote it. A
        **Stopped-but-open** is the third shape, and it is a moment rather than a
        state: the thread closes the loop on its way out, and its cancel-and-drain
        gives a queued handoff the turn :func:`asyncio.run` would have given it, so
        most of the time this future simply resolves with the work's own value.
        When the close wins, the sweep closes the wrappers and resolves *this*
        future with a refusal naming the engine, because a future left pending
        forever is the one answer a caller cannot act on.

        The returned :class:`concurrent.futures.Future` resolves with the
        coroutine's value or carries its exception -- including
        :exc:`TimeoutError`, when *timeout* is given, applied inside the loop
        via :func:`asyncio.wait_for` so cancellation reaches the engine's own
        machinery (module docstring, rule three).

        *on_done* is called with that future on the **engine's loop thread**,
        so a callback that wants its caller's world must hand off explicitly.
        It is documented as a plain callable because a promise type of our own
        would be a fourth API beside coroutine, blocking and callback. A
        callback that raises is logged with its exception and otherwise
        ignored -- the responder rule: one handler's bug does not take the
        engine down -- and ``on_done`` fires even when the work was cancelled
        (its future says so), because "never called" is the failure mode a
        notification API must not have.
        """
        wrapped = coro if timeout is None else _wait_for(coro, timeout)

        async def taken() -> Any:
            """The handover point of rule four, running on the engine's loop.

            Dropping the ledger entry is the first act, before anything is
            awaited: from here down the work belongs to the loop, to its own
            timeout, or to the caller -- never again to a sweep. Reading the
            running loop first is the assertion that a loop really is turning on
            this thread before anything below it starts.
            """
            asyncio.get_running_loop()  # nothing below this line runs blind
            self._claim(started)
            return await wrapped

        started = taken()
        loop, handed_off = self._take(started, None if wrapped is coro else wrapped)
        if on_done is not None:
            # Scheduled via call_soon_threadsafe rather than called here, so the
            # callback runs on the loop thread and the contract in the docstring
            # holds even when the future has already resolved; a future that is
            # done fires its callbacks on the next turn of that loop.
            loop.call_soon_threadsafe(handed_off.add_done_callback, _guarded(on_done, self._name))
        return handed_off

    def run(self, coro: Coroutine[Any, Any, Any], *, timeout: float | None = None) -> Any:
        """Block until *coro* finishes on the engine's loop; return its value.

        Safe from any thread, including one already running an event loop --
        the nested-loop trap this module exists to fix. Raises whatever the
        coroutine raised, unchanged: a facade that wraps errors invents a
        taxonomy nobody asked for. A *timeout* expiry raises
        :exc:`TimeoutError` whether it fired inside the loop (the answer was
        late) or here after timeout + :data:`_GRACE_S` (the engine thread is
        wedged); :mod:`concurrent.futures` and builtins share that one name on
        every Python this project supports, so both arms arrive as the same
        error -- a test asserts the identity rather than trusting it.
        """
        future = self.submit(coro, timeout=timeout)
        grace = None if timeout is None else timeout + _GRACE_S
        return future.result(timeout=grace)

    @property
    def name(self) -> str:
        return self._name


# -- module-level helpers and the shared default engine ----------------------


async def _wait_for(coro: Coroutine[Any, Any, Any], timeout: float) -> Any:
    """The timeout wrapper -- one layer of ours above :func:`asyncio.wait_for`.

    It is a coroutine of this module rather than a call buried in the handoff for
    two reasons. The ledger can name it and close it on a refusal path, which a
    wait_for the seam never sees would leave unreachable; and the cancellation
    lands on the engine's loop, where the machinery knows how to abandon a query
    in flight (module docstring, rule three). The caller's coroutine is what
    wait_for wraps, and it is never in the ledger: by the time this runs, wait_for
    has put it in a Task, and a Task is not something this seam closes on someone
    else's behalf.
    """
    return await asyncio.wait_for(coro, timeout)


def _guarded(callback: Callable[[concurrent.futures.Future], None], engine_name: str):
    """Wrap *callback* so raising is a logged event, never an engine failure."""

    def _done(future: concurrent.futures.Future) -> None:
        try:
            callback(future)
        except Exception:  # the one rule this adapter exists to enforce
            LOGGER.exception("engine_callback_failed(engine=%s callback=%r)", engine_name, callback)

    return _done


def _abandon(
    started: Coroutine[Any, Any, Any],
    timeout_wrapper: Coroutine[Any, Any, Any] | None,
    future: concurrent.futures.Future[Any] | None,
    reason: str,
) -> None:
    """Close the wrappers one submission owns and tell its future what happened.

    Only what the ledger holds is ever closed -- the scheduling wrapper and, on
    the timeout path, the wait_for beneath it. The caller's coroutine was never in
    the ledger, so it comes back untouched: an unstarted coroutine still has a
    frame on every Python this project supports, and closing it here would be this
    seam consuming work it had only refused (module docstring, rule four).

    A future that exists but will never be resolved by a loop is worse than a
    refusal, so it is finished here with the engine's own sentence. Retrieving
    that exception immediately is deliberate: :mod:`concurrent.futures` logs
    "Future exception was never retrieved" for a caller who never asks, and the
    asking here is this function's job, not a caller's chore.
    """
    started.close()
    if timeout_wrapper is not None:
        timeout_wrapper.close()
    if future is not None and not future.done():
        future.set_exception(RuntimeError(reason))
        future.exception()


def _shutdown_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel and drain every pending task, then close *loop*.

    The same shutdown :func:`asyncio.run` performs (its source is the
    reference; no RFC governs a thread's teardown). A plain ``loop.close()``
    after ``stop()`` would abandon tasks mid-await -- for a DNS engine that
    means sockets never told to stop and held streams never closed, the exact
    leaks this project draws attention to everywhere else.

    A loop found already closed is a loop already shut down: its queue went with
    the close, so there is nothing here to cancel, drain, or close a second time.
    Returning quietly is the honest answer -- raising through a daemon thread's
    teardown would log a failure where there is only a head start, and the sweep
    that follows still tells every abandoned caller its engine will not run its
    work. :meth:`asyncio.AbstractEventLoop.close` is itself idempotent, so the
    close below needs no guard of its own.
    """
    if loop.is_closed():
        return
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        # One more pass: a cancelled task's except/finally may have queued
        # callbacks (or even new tasks) that still owe the loop a turn.
        loop.run_until_complete(asyncio.sleep(0))
    finally:
        loop.close()


_default_lock = threading.Lock()
_default_engine: Engine | None = None


def default_engine() -> Engine:
    """The process-wide engine one-shot facades share.

    Lazily built, daemon-threaded, and closed at interpreter exit like every
    other engine. A resident object with sockets or held streams should own a
    named :class:`Engine` instead -- sharing this one is fine for correctness
    (one loop, one thread) but gives up the isolation of closing what you made.
    """
    global _default_engine
    with _default_lock:
        if _default_engine is None or _default_engine._closed:
            _default_engine = Engine("namespy-engine-default")
        return _default_engine


def run(coro: Coroutine[Any, Any, Any], *, timeout: float | None = None) -> Any:
    """Await *coro* on the default engine and block for its value (see :meth:`Engine.run`)."""
    return default_engine().run(coro, timeout=timeout)


def submit(
    coro: Coroutine[Any, Any, Any],
    *,
    timeout: float | None = None,
    on_done: Callable[[concurrent.futures.Future], None] | None = None,
) -> concurrent.futures.Future:
    """Schedule *coro* on the default engine and return its future (see :meth:`Engine.submit`)."""
    return default_engine().submit(coro, timeout=timeout, on_done=on_done)


def _close_all() -> None:
    with Engine._registry_lock:
        engines = list(Engine._instances)
    for engine in engines:
        try:
            engine.close()
        except Exception:  # pragma: no cover - interpreter exit is not the moment to raise
            LOGGER.exception("engine_atexit_close_failed(engine=%s)", engine.name)


atexit.register(_close_all)
