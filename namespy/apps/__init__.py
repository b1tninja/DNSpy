"""The composition tier: facades that *assemble* the core (roadmap W2).

This package exists to draw one line in the codebase. Everything under
``namespy/`` above this directory is the RFC implementation -- codec, walk,
validation, transports, server gates. Everything in ``namespy.apps`` *composes*
that core and adds no protocol surface of its own: the import line here reads
"I am assembling", which is the distinction the project cares about (see
``docs/strategy.md``, the constitution). It is stdlib-only, like the rest of the
package.

The facades that ship so far:

* :func:`namespy.apps.lookup.lookup` (W2) -- a one-shot blocking lookup that returns
  records **and a provenance line** (how it knows: walk or forward, answered
  from cache or off the wire, validated or not). This is the request-the-answer
  convenience the raw resolver API does not offer, and it collapses the
  ``create_datagram_endpoint`` / ``wait_for`` / double-close dance into one call
  over the ``namespy.engine`` seam (W1).
* :class:`namespy.apps.stub.Stub` (W2) -- a resident forwarding client with all three
  drives (await, blocking, callback) and both context-manager forms, so a held
  DNS-over-TLS stream means something across a loop of many questions rather
  than being opened and thrown away per question (RFC 7858 section 3.4).
* :class:`namespy.apps.routing.RouteTable` (W3) -- conditional forwarding: a
  longest-suffix table of ``zone -> upstreams`` where a zone match excludes the
  general path, the one noun every production resolver grew and no RFC defines.
* :class:`namespy.apps.forwarder.Forwarder` (W4) -- a named forwarding-server
  handle (``serve`` / ``stop`` / ``stats``) that composes ``DnsServer``'s relay and
  ``StubResolver``'s upstream walk with zero new core code -- the composability
  proof the strategy rests on.

None of them touches the network at import time, and none resolves a name for you
that you did not ask about: the list of servers still arrives from outside, which
is the stub's stance since RFC 1034 section 5.3.1.
"""

from __future__ import annotations

from .forwarder import Forwarder
from .lookup import LookupResult, Provenance, lookup
from .routing import Route, RouteTable, RoutingDecision
from .stub import Stub

__all__ = [
    "Forwarder",
    "LookupResult",
    "Provenance",
    "Route",
    "RouteTable",
    "RoutingDecision",
    "Stub",
    "lookup",
]
