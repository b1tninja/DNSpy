"""Conditional forwarding: the route table (roadmap W3).

Every resolver that earns its keep in production learns one thing early -- not
every name should go to the same server. Internal hosts resolve inside, a vendor's
zone goes to the vendor's forwarder, and everything else goes to the general
upstream. dnsmasq made the shape deployment convention with
``--server=/zone/ip`` ("send names under *zone* to *ip*"), and unbound, BIND,
systemd-resolved and dnsdist all grew the same noun. **It is convention, not
protocol** -- no RFC defines a forwarding table -- so this module is labeled the
way ``namespy/rbl.py``'s reverse-address rule is: anchored to a documented
practice rather than to a section number. The one protocol word it borrows is
RFC 8914's extended error 22, ``extended_error_name(22)`` -- "No Reachable
Authority" -- the honest verdict a forwarder owes a query whose only server for
that name has gone silent.

Two rules carry the whole design, and they are the two rules the survey called
load-bearing:

* **Longest-suffix match.** A name routes to the *most specific* registered zone
  that contains it -- ``internal.example`` beats ``.example`` beats the general
  path -- comparing label-wise from the root, which is exactly
  :meth:`namespy.names.DomainName.is_subdomain_of` with its reflex reading. This
  is the one matching rule every forwarding table shares.

* **Zone-match means no fallback.** This is the trap dnsmasq documents and a naive
  table walks straight into: once a name matches a specific zone, that zone's
  servers are the *only* answer path. A dead zone-only forwarder must kill the
  query honestly (EDE 22) rather than quietly retry the general upstream, because
  leaking an internal name to a public resolver is exactly the failure
  conditional forwarding exists to prevent. :meth:`RouteTable.route` expresses
  this by returning a *single* route -- the most specific match -- and never a
  chain, so there is no "then try the default" to reach for; the ``exclusive``
  flag on the decision says out loud that the general path is now off the table.

The table holds decisions, not connections: it never opens a socket and forwards
nothing itself. :meth:`namespy.apps.stub.Stub` and the forwarder (W4) are the ones
that act on a :class:`RoutingDecision`. A general/default upstream is the root
zone ``.``; a query for a name no specific zone claims and with no default
registered is not routable at all, and ``route`` says so rather than inventing a
server to send it to.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from ..names import DomainName
from ..stub import Upstream
from .lookup import coerce_upstreams

__all__ = ["Route", "RouteTable", "RoutingDecision"]

#: The general path is the root zone: every name is within it, so a default entry
#: here is the fallback every *more-specific* zone route excludes by matching.
ROOT = DomainName(".")


@dataclasses.dataclass(frozen=True)
class Route:
    """One entry: every name under *zone* is sent to *upstreams*.

    *zone* is a :class:`~namespy.names.DomainName`; the root ``.`` is the general
    path (no specific zone), and any other value is a specific forward whose match
    excludes the general path (module docstring, rule two).
    """

    zone: DomainName
    upstreams: tuple[Upstream, ...]

    @classmethod
    def parse(cls, spec: str) -> Route:
        """Read one ``zone=upstream`` forwarding rule, the shape a CLI carries.

        ``example.=1.1.1.1`` routes ``example.`` and everything below it;
        ``example.=1.1.1.1,9.9.9.9`` names two servers for one zone; an empty zone
        (``=1.1.1.1``) is the general default path, which is dnsmasq's
        ``--server=ip`` with no ``/zone/`` in front. A zone's own trailing dot is
        optional -- ``example`` and ``example.`` mean the same zone -- and the
        upstream list is parsed by :meth:`~namespy.stub.Upstream.parse`, so port,
        IPv6 brackets and the ``#name`` an encrypted upstream authenticates all
        read exactly as they do in the stub's configuration.
        """
        zone_text, sep, servers = spec.partition("=")
        if not sep or not servers.strip():
            raise ValueError(
                f"route {spec!r} is not ZONE=UPSTREAM (an empty ZONE is the general path)"
            )
        zone_text = zone_text.strip()
        zone = DomainName(zone_text) if zone_text else ROOT
        return cls(zone=zone, upstreams=coerce_upstreams(servers.split(",")))

    @property
    def is_default(self) -> bool:
        """Whether this is the general path rather than a zone-specific forward."""
        return len(self.zone.labels()) == 0

    @property
    def specificity(self) -> int:
        """Label count from the root -- a longer zone is a more specific match."""
        return len(self.zone.labels())

    def matches(self, name: DomainName) -> bool:
        """Whether *name* is the zone itself or lies beneath it (apex-or-below)."""
        return name.is_subdomain_of(self.zone, include_self=True)


@dataclasses.dataclass(frozen=True)
class RoutingDecision:
    """What :meth:`RouteTable.route` decided about one name: where it goes, or that it does not.

    A decision names exactly one :class:`Route` -- the most specific match -- or
    ``None`` when nothing routes the name. It deliberately offers no "next server"
    to fall back to; that absence *is* rule two.
    """

    #: The name that was asked about.
    name: DomainName
    #: The single winning route, or ``None`` when the table routes this name nowhere.
    route: Route | None

    @property
    def routable(self) -> bool:
        """Whether any route claims this name."""
        return self.route is not None

    @property
    def upstreams(self) -> tuple[Upstream, ...]:
        """The servers to ask, in the order they were configured (empty if unroutable)."""
        return self.route.upstreams if self.route is not None else ()

    @property
    def exclusive(self) -> bool:
        """Whether a *zone-specific* route claimed the name -- so the general path is off the table.

        ``True`` means the forwarder must answer silence with EDE 22 rather than
        retry the default: this name belongs to a zone, and its zone's servers
        are the whole answer path (module docstring, rule two). ``False`` with a
        route means only the general path matched, so nothing more specific exists
        to fall back to either way -- a default that is silent is simply silent.
        """
        return self.route is not None and not self.route.is_default


class RouteTable:
    """A set of :class:`Route` entries plus the general path, and the two rules.

    Built from routes (an iterable of :class:`Route` or ``ZONE=UPSTREAM`` text) and
    an optional *default* (upstreams for the general path, dnsmasq's server with no
    ``/zone/``). Routes are stored most-specific-last-by-convention but matched by
    specificity, not order -- the longest zone that contains a name wins, whatever
    the registration order, because an operator should not have to sort a config
    file to get correct routing.
    """

    def __init__(self, routes: Any = (), default: Any = None) -> None:
        entries: list[Route] = []
        for item in routes:
            entries.append(item if isinstance(item, Route) else Route.parse(item))
        if default is not None:
            upstreams = coerce_upstreams(default)
            entries.append(Route(zone=ROOT, upstreams=upstreams))
        # The general path is one entry; a caller who both named default= and put a
        # root route in routes= has two roots, which would make "most specific"
        # ambiguous -- so the configuration error is said at the door, not resolved
        # by whichever was inserted last.
        roots = [e for e in entries if e.is_default]
        if len(roots) > 1:
            raise ValueError("a route table has one general path; do not set default= twice")
        self._entries = tuple(entries)

    @classmethod
    def from_specs(cls, specs: Any, *, default: Any = None) -> RouteTable:
        """Build from repeated ``ZONE=UPSTREAM`` strings (a CLI's repeated flag)."""
        return cls(tuple(Route.parse(spec) for spec in specs), default=default)

    @property
    def entries(self) -> tuple[Route, ...]:
        """The routes as stored (inspection and tests read this; matching does not)."""
        return self._entries

    @property
    def default(self) -> Route | None:
        """The general path, if one is registered."""
        return next((route for route in self._entries if route.is_default), None)

    def route(self, name: DomainName) -> RoutingDecision:
        """The single most-specific route for *name*, or an unroutable decision.

        Longest-suffix among matching routes (rule one); a zone match over the
        general path because the zone is more specific (rule two). Ties are
        impossible -- two routes cannot own the same zone string and stay distinct
        -- but the root, matching every name, is always the least specific, so a
        name with only a default registered resolves to it and a name with no
        match at all resolves to nothing.
        """
        if isinstance(name, str):
            name = DomainName(name)
        best: Route | None = None
        for entry in self._entries:
            if entry.matches(name) and (best is None or entry.specificity > best.specificity):
                best = entry
        return RoutingDecision(name=name, route=best)
