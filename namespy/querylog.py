"""The query log: one JSON object per query/response pair, on request.

The honest starting point for this module is that no document tells a
DNS server what a query log should contain. The formats people
half-remember are not published RFCs, and this row was checked against
the corpus at planning time (October 2026) before it was decided the
file would cite nothing rather than ghost a number. What the file does
carry are the house rules that needed no specification:

* **Default off.** The server module's first rule -- "never emit
  output the operator did not ask for" -- is load-bearing here more
  than anywhere else: a query log is a file that grows on someone's
  disk and records where their clients went. It exists because a
  ``--serve-query-log`` flag said so, and the path is the operator's
  choice, as are retention and rotation, which stay the file
  system's problem rather than this module's.
* **Client addresses are the point and the price.** A query log
  without a source address cannot answer who asked; that is also
  what makes it personal data. It goes where the operator pointed
  it and nowhere else -- no copy reaches the wire, the trace, or the
  process log.
* **One line per pair, parseable without a schema.** JSON lines: each
  record is one object, one ``\\n``, no cross-line state, so a tailed
  file reads and a truncated file loses one record rather than the
  format. Field names follow the packet and the trace, not invention:
  ``origin`` is the ladder the server already answers on --
  ``bind`` (a responder), ``zone`` (authoritative data from a loaded
  master file, answers and referrals alike), ``policy`` (a filter verdict),
  ``forward``
  (configured upstreams), ``recurse`` (the walk, cache included),
  ``reject`` (a refusal this server composed about the request).
  A cache answer is not called out separately because nothing else
  can call it out either -- the trace's own comment concedes a
  refused special-name answer is "indistinguishable from a cache
  answer", and this log would be inventing a distinction its
  source does not keep; ``stale`` rides instead because the resolver
  really does mark that one.

A write failure never costs an answer: the emit is a side effect of an
egress that already happened, and a full disk or closed handle is
logged to the debug stream, not raised into a client's response.
"""

import json
import logging
from typing import Protocol, runtime_checkable


@runtime_checkable
class _Sink(Protocol):
    """Anything that takes text and flushes -- a file, or a test's StringIO."""

    def write(self, text: str, /) -> object: ...

    def flush(self) -> None: ...


class QueryLog:
    """One JSON object per answered query, appended to *sink*.

    :param sink: a text-mode appendable (``open(path, "a")``). The log
        is line-buffered by obligation rather than by policy: each
        record is written and flushed whole, so the file a nervous
        operator tails shows every answer the server has already sent,
        at the cost of one flush per answer -- a cost a loopback
        fixture is happy to pay for a file that is never "answers
        still buffered when we crashed".
    """

    __slots__ = ("_log", "_sink")

    def __init__(self, sink: _Sink):
        self._sink = sink
        self._log = logging.getLogger("namespy.querylog")

    def emit(self, entry: dict) -> None:
        """Append *entry* as one line. Failures are debug-only, never fatal."""
        try:
            self._sink.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._sink.flush()
        except Exception as exc:
            # Deliberately broad: a closed handle (ValueError), a full
            # disk (OSError), a sink that simply broke -- none is a
            # reason an answer that already left the socket comes back
            # as an exception into the transport callback.
            self._log.debug("querylog_write_failed(err=%s)", type(exc).__name__)


__all__ = ["QueryLog"]
