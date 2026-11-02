"""hosts-file honesty (roadmap W5).

Every resolver on earth consults a hosts file first, and almost none of them says
so: the address arrives as if DNS had produced it. The roadmap's research hazard
for this row is exactly that lie -- "a resolver that quietly overrode the lookup
is indistinguishable from one that got the same answer from the network." This
module keeps the two apart. A :class:`HostsFile` records *where* each mapping came
from -- the line number and the file -- so an answer drawn from it can name its
source instead of impersonating a query.

There is no RFC to anchor hosts-file semantics: the format predates the DNS
protocol documents and lives in ``man hosts`` and RFC 1123 section 6.1.2's thin
sketch ("the file ... should contain ... an IP address ... followed by one or more
host names"). Following the ``namespy/rbl.py`` precedent, the conventions this
parser adopts are labeled as conventions, not cited as requirements:

* one mapping per line, whitespace-separated: an address, then one or more names;
* ``#`` begins a comment that runs to end of line, and a line that is blank or all
  comment contributes nothing;
* an address that does not parse as IPv4 or IPv6 makes the whole line a no-op --
  ``man hosts`` says an implementation "should not" choke the rest of the file on a
  typo, and silently dropping a bad line beats dropping the file;
* the family decides the answer: an IPv4 entry answers ``A``, an IPv6 entry answers
  ``AAAA``, and nothing else. hosts files hold addresses, not MX records.

Two consumers share one :class:`HostsFile`. Client-side, :func:`namespy.apps.lookup`
consults it before any walk or forward (:meth:`HostsFile.match`) and reports the
line. Server-side, :meth:`HostsFile.bind` registers each name as a bound responder
whose answers carry **TTL 0** -- dnsmasq's local-answer stance, on the reasoning
that a mapping written by hand on this box is the most volatile thing in the answer
set and nothing downstream should hold it past the next query.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..enums import DnsQType, DnsRType
from ..names import DomainName
from ..packet import DnsRecord
from ..rdata import RData_A, RData_AAAA

__all__ = ["HostsEntry", "HostsFile", "HostsMatch"]


@dataclass(frozen=True)
class HostsEntry:
    """One ``address name`` mapping, remembered together with where it was read.

    *line* is the one-based line it came from and *source* is the file it was read
    from (empty for a parsed string), so :attr:`citation` can render the "says so"
    sentence the whole module exists for.
    """

    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    name: DomainName
    line: int
    source: str = ""

    @property
    def version(self) -> int:
        """``4`` for an IPv4 mapping (answers ``A``), ``6`` for IPv6 (``AAAA``)."""
        return self.address.version

    @property
    def citation(self) -> str:
        """Where this entry came from: ``line 42`` or ``line 42 of /etc/hosts``."""
        where = f"line {self.line}"
        return f"{where} of {self.source}" if self.source else where

    def record(self) -> DnsRecord:
        """This mapping as one answer-section record, at **TTL 0**.

        The zero is the convention, not a default: a hand-written local mapping is
        the least cacheable thing in the answer set (dnsmasq's local answers say the
        same). ``A`` for IPv4, ``AAAA`` for IPv6, in the IN class.
        """
        if self.address.version == 4:
            return DnsRecord(self.name, DnsRType.A, ttl=0, rdata=RData_A(str(self.address)))
        return DnsRecord(self.name, DnsRType.AAAA, ttl=0, rdata=RData_AAAA(str(self.address)))


def _normalize_host_name(token: str) -> DomainName | None:
    """One hosts-file name token as a :class:`DomainName`, or ``None`` if unusable.

    Normalized through :meth:`~namespy.names.DomainName.from_unicode` -- the exact
    call :func:`namespy.apps.lookup` makes on a query name -- so the two sides agree
    on spelling. A token IDNA cannot read returns ``None`` rather than raising: the
    parser's convention is that a bad name voids itself, not the file.
    """
    try:
        return DomainName.from_unicode(token)
    except Exception:
        return None


class HostsFile:
    """A parsed hosts file: entries in read order, consulted before any lookup."""

    __slots__ = ("entries", "source")

    def __init__(self, entries: Sequence[HostsEntry] = (), *, source: str = "") -> None:
        self.entries: tuple[HostsEntry, ...] = tuple(entries)
        self.source = source

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:
        return f"HostsFile(entries={len(self.entries)}, source={self.source!r})"

    @classmethod
    def parse(cls, text: str, *, source: str = "") -> HostsFile:
        """Read hosts-file *text* into entries, one per ``address name`` pair.

        A name that repeats an address yields one entry per name (so ``10.0.0.1 a b``
        answers for both ``a`` and ``b``). The names are normalized exactly the way
        :func:`namespy.apps.lookup` normalizes a query name -- through
        :meth:`~namespy.names.DomainName.from_unicode` -- so a hosts entry and the
        question it satisfies compare equal without either spelling winning.
        """
        entries: list[HostsEntry] = []
        for number, raw in enumerate(text.splitlines(), start=1):
            content = raw.split("#", 1)[0].strip()
            if not content:
                continue
            fields = content.split()
            if len(fields) < 2:
                continue  # an address with no name, or a stray token: nothing to map
            try:
                address = ipaddress.ip_address(fields[0])
            except ValueError:
                continue  # convention: a bad address voids its own line, not the file
            for token in fields[1:]:
                name = _normalize_host_name(token)
                if name is None:
                    continue  # an unusable name on an otherwise-good line is just skipped
                entries.append(HostsEntry(address=address, name=name, line=number, source=source))
        return cls(entries, source=source)

    @classmethod
    def from_file(cls, path: Any) -> HostsFile:
        """Read a hosts file from *path*, remembering it as the :attr:`source`."""
        with open(os.fspath(path), encoding="utf-8") as handle:
            return cls.parse(handle.read(), source=os.fspath(path))

    def names(self) -> tuple[DomainName, ...]:
        """The distinct names this file maps, in first-seen order."""
        seen: list[DomainName] = []
        for entry in self.entries:
            if entry.name not in seen:
                seen.append(entry.name)
        return tuple(seen)

    def has(self, name: DomainName) -> bool:
        """Whether *name* is mapped here at all, whatever family it holds."""
        return any(entry.name == name for entry in self.entries)

    def records_for(self, name: DomainName, qtype: int) -> tuple[DnsRecord, ...]:
        """The TTL-0 answers *name* has for *qtype*, empty if it has none of that kind.

        ``A`` draws the IPv4 entries, ``AAAA`` the IPv6, ``ANY`` both; any other
        QTYPE answers empty, because a hosts file holds addresses and nothing else.
        An empty return for a name that *is* present is a deliberate NODATA (the
        name is known here, this family is not), distinct from a name that is absent
        entirely -- which :meth:`match` reports with ``None``.
        """
        wanted = int(qtype)
        want_v4 = wanted == int(DnsQType.A) or wanted == int(DnsQType.ANY)
        want_v6 = wanted == int(DnsQType.AAAA) or wanted == int(DnsQType.ANY)
        records: list[DnsRecord] = []
        for entry in self.entries:
            if entry.name != name:
                continue
            if (want_v4 and entry.version == 4) or (want_v6 and entry.version == 6):
                records.append(entry.record())
        return tuple(records)

    def match(self, name: DomainName, qtype: int) -> HostsMatch | None:
        """The hosts answer for *name*, or ``None`` when this file does not know it.

        This is the door :func:`namespy.apps.lookup` consults before the walk: a
        ``None`` means "not mine, go ask the network", while a :class:`HostsMatch`
        -- even one whose ``records`` is empty -- means "this file answered", and its
        :attr:`~HostsMatch.citation` is the sentence that keeps the two honest.
        """
        first = next((entry for entry in self.entries if entry.name == name), None)
        if first is None:
            return None
        return HostsMatch(records=self.records_for(name, qtype), citation=first.citation)

    def bind(self, server: Any, *, include_subdomains: bool = False) -> tuple[DomainName, ...]:
        """Register this file's names on a :class:`~namespy.server.DnsServer` as
        bound responders, and return the names bound.

        One responder per distinct name, each answering from :meth:`records_for` at
        TTL 0 -- the local-answer stance (module docstring). ``include_subdomains``
        is False because hosts entries are exact names, not zones: an operator who
        means ``*.example`` to resolve locally can pass it, but nothing here
        invents that reading. A query for a family the name lacks answers NODATA
        rather than falling through, because binding a name is the operator
        declaring this server its authority.
        """
        from ..server import DynamicResponse  # local import: keeps the pure-parser path light

        bound: list[DomainName] = []
        for name in self.names():

            def handler(request: Any, _file: HostsFile = self) -> Any:
                return DynamicResponse(answers=_file.records_for(request.name, request.qtype))

            server.bind(name, handler, include_subdomains=include_subdomains)
            bound.append(name)
        return tuple(bound)


@dataclass(frozen=True)
class HostsMatch:
    """A hosts-file answer: the records, and the citation that says where they came from."""

    records: tuple[DnsRecord, ...]
    citation: str
