"""The authoritative arc, first leg: a zone from a master file, answers as §4.3.2 writes them.

Parsing is RFC 1035 section 5.1, almost sentence by sentence. The file
is "a sequence of entries", "predominantly line-oriented, though
parentheses can be used to continue a list of items across a line
boundary", comments start with ";", and an RR is
``[<TTL>] [<class>] <type> <RDATA>`` in either bracket order because
"Since type and class mnemonics are disjoint, the parse is unique."
Owners default to "the last stated owner"; relative names concatenate
with the origin from ``$ORIGIN`` (also §5.1) or, for ``$TTL``, from the
master-file extension RFC 2308 states verbatim: "The Master File format
[RFC 1035 Section 5] is extended to include the following directive:
$TTL <TTL> [comment]". Types this package has no parser for are not an
error: RFC 3597 section 5's opaque ``\\# <rdlength> <hex>`` form loads
as a blob, the text mirror of what the wire parser already does with
unknown types. TTLs are plain decimal integers — "TTL is a decimal
integer" is §5.1's own words, and no unit-suffix mechanism gets a
citation it cannot show, so none is accepted.

Serving is RFC 1034 section 4.3.2's algorithm, and the shapes it names
are the shapes a walk already consumes, because this is the same text
the resolver was built to read from the other side: an exact node match
copies the matching RRs (step 3a); "If a match would take us out of the
authoritative data, we have a referral. ... Copy the NS RRs for the
subzone into the authority section of the reply. Put whatever addresses
are available into the additional section" (step 3b) — with AA off,
because the answer belongs to someone else; a failed label consults the
wildcard, which §4.3.3 calls "instructions for synthesizing RRs" and
step 3c commands to apply as "set the owner of the RR to be QNAME, and
not the node with the \"*\" label" (so synthesized records really carry
the queried name out on the wire).

Two scope decisions, stated rather than silent. Chasing a CNAME stays
inside the zone (step 3a's "go back to step 1" re-enters the zone
search; a target outside this zone ends the chain and the accumulated
CNAMEs are the answer — this module serves data and does not walk).
And ``$GENERATE`` is refused by name: it is not in §5.1's entry list,
and inventing an un-cited expansion language is the ghost-sentence
error this project keeps catching in its own prose.
"""

import ipaddress
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from .enums import DnsQType, DnsRClass, DnsRType
from .names import DomainName, unescape_label
from .packet import DnsRecord
from .rdata import (
    RData,
    RData_A,
    RData_AAAA,
    RData_CNAME,
    RData_MX,
    RData_NS,
    RData_PTR,
    RData_SOA,
    RData_SRV,
    RData_TXT,
)

__all__ = ["Zone", "ZoneAnswer", "ZoneParseError"]


class ZoneParseError(ValueError):
    """A master file that cannot be loaded, said with its file and line."""

    def __init__(self, message: str, *, filename: str, line: int):
        super().__init__(f"{filename}:{line}: {message}")
        self.filename = filename
        self.line = line
        self.detail = message


# ------------------------------------------------------- name mechanics


def _unescape(text: str) -> str:
    """Resolve the §5.1 quoting conventions inside one token.

    Backslash sequences: "\\DDD where each D is a digit is the octet
    corresponding to the decimal number described by DDD" (RFC 1035
    section 5.1's escape table); any other ``\\X`` is that character
    quoted "so that its special meaning does not apply".
    """
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 3 < len(text) and text[i + 1 : i + 4].isdigit():
            out.append(chr(int(text[i + 1 : i + 4])))
            i += 4
        elif i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
        else:  # a trailing backslash is its own character, loudly
            out.append("\\")
            i += 1
    return "".join(out)


def _split_labels(token: str, *, context) -> list[bytes]:
    """Split one name token into raw label octets.

    Quoting is the token's own outer pair (a name with spaces lives
    inside double quotes in a master file); the per-label escapes are
    handed to :func:`~namespy.names.unescape_label`, which already
    implements section 5.1's ``\\DDD`` and ``\\c`` conventions -- one
    implementation of the octet rules, not two that can drift.
    """
    text = token
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        text = text[1:-1]
    parts: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            current.append(ch)
            if i + 1 < len(text):
                current.append(text[i + 1])
                i += 2
                continue
            raise context("a trailing backslash escapes nothing")
        if ch == ".":
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    absolute = text.endswith(".")
    tail = "".join(current)
    if tail:
        parts.append(tail)
    elif not absolute and not parts:
        raise context('a bare empty token is not a name; "." must end in a dot')
    if absolute:
        parts = parts[:-1] if parts == [""] else parts  # the root: zero labels
    if any(part == "" for part in parts):
        raise context(f'"{token}" carries an empty label')
    return [unescape_label(part) for part in parts]


def _resolve_name(word: str, origin: DomainName | None, *, context) -> DomainName:
    """One name token against the current origin, §5.1's absolute/relative rule.

    "Domain names that end in a dot are called absolute, and are taken
    as complete"; a relative name is the concatenation with the origin,
    and "a relative name is an error when no origin is available."
    ``@`` is the origin itself (the convention every master file uses
    for the zone apex; section 5.1 leaves the loading routine to supply
    it, which is what the origin parameter is).
    """
    if word == "@":
        if origin is None:
            raise context('"@" names the origin, and no origin is available yet')
        return origin
    labels = _split_labels(word, context=context)
    if word.endswith("."):
        return DomainName.from_labels(labels)
    if origin is None:
        raise context(f'relative name "{word}" with no $ORIGIN in effect')
    return DomainName.from_labels(labels + list(origin.labels()))


@dataclass(frozen=True)
class _Entry:
    line: int  # where the entry started, for the error messages
    indented: bool  # §5.1: a leading blank means "owner defaults to the last stated"
    tokens: tuple[str, ...]


def _entries(text: str) -> Iterator[_Entry]:
    """The master file as entries: line breaks end them, parentheses suspend them.

    A single character-state scanner, because section 5.1 mixes three
    quoting regimes (quoted text literals that may contain CRLF,
    backslash escapes, a ";" comment that only counts outside quotes)
    and a regex per line would get each of them wrong in turn.
    """
    tokens: list[str] = []
    depth = 0
    entry_line: int | None = None
    indented = False
    token: list[str] = []
    in_token = False
    in_quote = False
    last_lineno = 0
    for lineno, physical in enumerate(text.splitlines(), start=1):
        last_lineno = lineno
        chars = iter(physical)
        while True:
            ch = next(chars, None)
            if ch is None:
                break
            if not in_token:
                if ch in " \t":
                    continue
                if ch == ";":  # comment to end of line, outside any token
                    break
                if ch in "()":
                    depth += 1 if ch == "(" else -1
                    continue
                in_token = True
                in_quote = ch == '"'
                if entry_line is None:
                    entry_line = lineno
                    indented = physical[0] in " \t"
                token = [ch]
                continue
            # Inside a token: quotes and escapes pass through verbatim;
            # the builders unescape, so what a builder sees is the token
            # exactly as written, quoting intact.
            if ch == "\\":
                token.append(ch)
                nxt = next(chars, None)
                if nxt is None:
                    raise ValueError(f"line {lineno}: a trailing backslash escapes nothing")
                token.append(nxt)
                continue
            if ch == '"':  # the quote toggles the quoted region of a token
                token.append(ch)
                in_quote = not in_quote
                continue
            if in_quote:
                token.append(ch)
                continue  # spaces belong to the token inside the quotes
            if ch in "()":
                # "www (" and "www(" are the same entry: the paren closes
                # the token it sits against, then does its depth work.
                depth += 1 if ch == "(" else -1
                tokens.append("".join(token))
                token = []
                in_token = False
                continue
            if ch in " \t":
                tokens.append("".join(token))
                token = []
                in_token = False
                continue
            token.append(ch)
        if in_quote:
            # section 5.1: "text literals can contain CRLF within the
            # text" -- an open quote keeps the token gathering, next
            # line included (the line break joins the literal, which is
            # what containing a CRLF means), so nothing is emitted
            # mid-string.
            token.append("\n")
            continue
        if depth <= 0 and (in_token or tokens):
            if in_token:
                tokens.append("".join(token))
                token = []
                in_token = False
            yield _Entry(line=entry_line or lineno, indented=indented, tokens=tuple(tokens))
            tokens = []
            entry_line = None
            indented = False
        elif depth <= 0:
            # a line that carried only a comment or a stray paren: blank
            # entries are allowed anywhere, so nothing to emit.
            entry_line = None
            tokens = []
    if depth != 0:
        raise ValueError("unbalanced parentheses: the last entry never closed")
    if tokens or in_token:
        if in_token:
            tokens.append("".join(token))
        yield _Entry(line=entry_line or last_lineno, indented=indented, tokens=tuple(tokens))


# ------------------------------------------------------------ rdata

_TYPES = {member.name: int(member) for member in DnsRType}
_TYPE_NAMES = {int(member): member.name for member in DnsRType}
_CLASSES = {member.name: int(member) for member in DnsRClass}
_NAMED = ("NS", "CNAME", "PTR")
_BUILDER_TYPES = {
    int(DnsRType.A),
    int(DnsRType.AAAA),
    int(DnsRType.NS),
    int(DnsRType.CNAME),
    int(DnsRType.PTR),
    int(DnsRType.SOA),
    int(DnsRType.MX),
    int(DnsRType.TXT),
    int(DnsRType.SRV),
}


def _uint(token: str, context, field: str) -> int:
    try:
        value = int(token)
    except ValueError:
        raise context(f'{field} must be a decimal integer, got "{token}"') from None
    if not 0 <= value <= 0xFFFFFFFF:
        raise context(f"{field} {value} does not fit the 32-bit field")
    return value


def _character_string(token: str, context) -> bytes:
    """Unquote and unescape one <character-string>, §5.1's quoting rules."""
    text = token
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        text = text[1:-1]
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 3 < len(text) and text[i + 1 : i + 4].isdigit():
            value = int(text[i + 1 : i + 4])
            if value > 255:
                raise context(f"\\{text[i + 1 : i + 4]} exceeds a single octet")
            out.append(value)
            i += 4
            continue
        if ch == "\\":
            if i + 1 >= len(text):
                raise context("a trailing backslash escapes nothing")
            out.extend(text[i + 1].encode("utf-8"))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    if len(out) > 255:
        raise context("one character-string cannot exceed 255 octets; split it")
    return bytes(out)


def _rdata_for(rtype: int, tokens: tuple[str, ...], origin: DomainName | None, context):
    """Build the RDATA object for one record's field tokens.

    Types with a syntax in the standard get a builder; everything else
    must arrive through RFC 3597 section 5's generic encoding: "the
    special token \\# ... which identifies the RDATA as having the
    generic encoding defined herein rather than a traditional
    type-specific encoding", followed by the decimal length and the
    hex. It is also the loader for any type this package has no parser
    for -- no special-casing, and no silent dropping.
    """
    name = _TYPE_NAMES.get(rtype, f"TYPE{rtype}")
    if tokens and tokens[0] == "\\#":
        if len(tokens) < 3:
            raise context('RFC 3597 format is \\# <length> <hex>; got "' + " ".join(tokens) + '"')
        length = _uint(tokens[1], context, "generic RDATA length")
        blob = bytes.fromhex("".join(tokens[2:]).replace(" ", "")) if _hexy(tokens[2:]) else None
        if blob is None:
            raise context("generic RDATA must be hex digits")
        if len(blob) != length:
            raise context(f"generic RDATA is {len(blob)} octets, the stated length says {length}")
        return RData(blob)
    if rtype == int(DnsRType.A):
        _exactly_one(len(tokens), name, context)
        try:
            return RData_A(ipaddress.IPv4Address(tokens[0]))
        except ValueError:
            raise context(f'A RDATA "{tokens[0]}" is not a dotted quad') from None
    if rtype == int(DnsRType.AAAA):
        _exactly_one(len(tokens), name, context)
        try:
            return RData_AAAA(ipaddress.IPv6Address(tokens[0]))
        except ValueError:
            raise context(f'AAAA RDATA "{tokens[0]}" is not an IPv6 address') from None
    if name in _NAMED:
        _exactly_one(len(tokens), name, context)
        target = _resolve_name(tokens[0], origin, context=context)
        return {"NS": RData_NS, "CNAME": RData_CNAME, "PTR": RData_PTR}[name](target)
    if rtype == int(DnsRType.SOA):
        if len(tokens) != 7:
            raise context(f"SOA takes mname rname and five integers, got {len(tokens)} fields")
        return RData_SOA(
            _resolve_name(tokens[0], origin, context=context),
            _resolve_name(tokens[1], origin, context=context),
            *[_uint(tok, context, "SOA integer") for tok in tokens[2:]],
        )
    if rtype == int(DnsRType.MX):
        if len(tokens) != 2:
            raise context("MX takes < preference> <exchange>")
        return RData_MX(
            _resolve_name(tokens[1], origin, context=context),
            preference=_uint(tokens[0], context, "MX preference"),
        )
    if rtype == int(DnsRType.SRV):
        if len(tokens) != 4:
            raise context("SRV takes < priority> <weight> <port> <target>")
        return RData_SRV(
            _resolve_name(tokens[3], origin, context=context),
            priority=_uint(tokens[0], context, "SRV priority"),
            weight=_uint(tokens[1], context, "SRV weight"),
            port=_uint(tokens[2], context, "SRV port"),
        )
    if rtype == int(DnsRType.TXT):
        if not tokens:
            raise context("TXT takes at least one character-string")
        return RData_TXT([_character_string(tok, context) for tok in tokens])
    raise context(
        f"no parser for {name}; RFC 3597's opaque form loads any type: {name} \\# <len> <hex>"
    )


def _hexy(tokens) -> bool:
    return all(re.fullmatch(r"[0-9A-Fa-f]+", tok) for tok in tokens)


def _exactly_one(count: int, name: str, context) -> None:
    if count != 1:
        raise context(f"{name} takes exactly one field, got {count}")


# ---------------------------------------------------------------- zone


def _type_of(token: str, context):
    """A type token to an int: mnemonic, or RFC 3597 section 5's TYPE####."""
    if m := re.fullmatch(r"TYPE(\d+)", token.upper()):
        value = int(m.group(1))
        if not 0 <= value <= 0xFFFF:
            raise context(f"TYPE{m.group(1)} exceeds the 16-bit field")
        return value
    if token.upper() in _TYPES:
        return _TYPES[token.upper()]
    raise context(
        f'unknown record type "{token}"; RFC 3597 section 5 spells unregistered '
        "types TYPE<number> and loads their RDATA through the generic form"
    )


def _key(name: DomainName) -> tuple[bytes, ...]:
    """The dict key a zone's nodes live under: octets, case-folded.

    str() is not canonical -- from_labels renders an embedded dot as
    ``\\046`` while a presentation input keeps ``\\.``, and a key made
    of strings would store one owner under two spellings. The label
    octets are the name; §2.4.4's folding is a lower() over those
    octets, which for the wire alphabet is exactly the case-insensitive
    comparison the responder matching already makes.
    """
    return tuple(label.lower() for label in name.labels())


class Zone:
    """One zone's authoritative data, loaded from a master file.

    The record store is a dict of folded owner names to the records
    that own them; folding is RFC 1035 section 2.4.4's case-insensitive
    equality, applied here as a lowercase key because a dict compares
    by hash before it compares by the folding ``__eq__``.
    """

    def __init__(self, apex: DomainName, records: Sequence[DnsRecord]):
        self.apex = apex
        self.records = tuple(records)
        self._nodes: dict[tuple[bytes, ...], list[DnsRecord]] = {}
        for record in self.records:
            self._nodes.setdefault(_key(record.name), []).append(record)
        self._soa = next((r for r in self.records if int(r.rtype) == int(DnsRType.SOA)), None)

    @property
    def soa(self) -> DnsRecord | None:
        return self._soa

    def serve(self, name: str | DomainName, qtype: int, qclass: int = 1) -> "ZoneAnswer | None":
        """The section-4.3.2 answer for one question; None for not-my-zone."""
        return _serve_answer(self, name, qtype, qclass)

    @classmethod
    def from_file(cls, path: str | Path) -> "Zone":
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        return cls.from_master_file(text, base_dir=path.parent, filename=str(path))

    @classmethod
    def from_master_file(
        cls,
        text: str,
        *,
        origin: DomainName | None = None,
        base_dir: Path | None = None,
        filename: str = "<master file>",
    ) -> "Zone":
        records, final_origin = _parse(text, origin=origin, base_dir=base_dir, filename=filename)
        apex = None
        for record in records:
            if int(record.rtype) == int(DnsRType.SOA):
                apex = record.name
                break
        if apex is None:
            # A master file without an SOA still says which zone it is if
            # it states an $ORIGIN -- the origin in effect when the file
            # ends is the origin the file was written under.
            apex = final_origin
        if apex is None:
            raise ZoneParseError(
                "cannot tell which zone this is: no SOA and no $ORIGIN",
                filename=filename,
                line=1,
            )
        return cls(apex, records)


def _parse(
    text: str,
    *,
    origin: DomainName | None,
    base_dir: Path | None,
    filename: str,
    records: list | None = None,
) -> tuple[list[DnsRecord], DomainName | None]:
    found = [] if records is None else records
    owner: DomainName | None = origin
    ttl: int | None = None
    qclass = int(DnsRClass.IN)
    try:
        entries = list(_entries(text))
    except ValueError as exc:  # the scanner's line-carrying complaints
        raise ZoneParseError(str(exc), filename=filename, line=0) from None
    for entry in entries:

        def context(message: str, _line: int = entry.line):
            return ZoneParseError(message, filename=filename, line=_line)

        first = entry.tokens[0]
        upper = first.upper()
        if upper == "$ORIGIN":
            if len(entry.tokens) != 2:
                raise context("$ORIGIN takes exactly one name")
            origin = _resolve_name(entry.tokens[1], origin, context=context)
            continue
        if upper == "$TTL":
            if len(entry.tokens) != 2:
                raise context("$TTL takes exactly one value")
            ttl = _uint(entry.tokens[1], context, "$TTL value")
            continue
        if upper == "$INCLUDE":
            if base_dir is None:
                raise context("$INCLUDE needs a file-loaded zone with a directory to include from")
            if not 2 <= len(entry.tokens) <= 3:
                raise context("$INCLUDE takes a file name and an optional domain name")
            included = base_dir / _unescape(entry.tokens[1])
            sub_origin = origin
            if len(entry.tokens) == 3:
                sub_origin = _resolve_name(entry.tokens[2], origin, context=context)
            try:
                sub_text = included.read_text(encoding="utf-8")
            except OSError as exc:
                raise context(f"$INCLUDE cannot read {included}: {exc}") from None
            # Section 5.1: the include "never changes the relative origin
            # of the parent file" -- so the recursion gets its own origin
            # and its own defaults, and only its records come back.
            _parse(
                sub_text,
                origin=sub_origin,
                base_dir=included.parent,
                filename=str(included),
                records=found,
            )
            continue
        if upper == "$GENERATE":
            raise context(
                "$GENERATE is refused: it is not in RFC 1035 section 5.1's entry list, "
                "and this parser does not invent an expansion language to match"
            )
        if entry.indented:
            if owner is None:
                raise context("an indented entry needs a previously stated owner")
            rest = entry.tokens
        else:
            owner = _resolve_name(first, origin, context=context)
            rest = entry.tokens[1:]
        # [<TTL>] [<class>] or [<class>] [<TTL>], then the type, then RDATA:
        # "Since type and class mnemonics are disjoint, the parse is unique."
        while rest:
            token = rest[0]
            if token.isdigit():
                ttl = _uint(token, context, "TTL")
                rest = rest[1:]
                continue
            if token.upper() in _CLASSES and len(rest) > 1:
                qclass = _CLASSES[token.upper()]
                rest = rest[1:]
                continue
            break
        if not rest:
            raise context("entry carries no type")
        rtype = _type_of(rest[0], context)
        if ttl is None:
            raise context("no TTL in effect: state one with $TTL or on the record")
        rdata = _rdata_for(rtype, rest[1:], origin, context)
        found.append(DnsRecord(owner, rtype, qclass, ttl, rdata=rdata))
    return found, origin


# ------------------------------------------------------------- serving


@dataclass(frozen=True)
class ZoneAnswer:
    """What the zone says, in the sections RFC 1034 section 4.3.2 names.

    ``rcode`` ``None`` means NOERROR; ``NAME_ERROR`` is the authoritative
    name error of step 3c. ``aa`` is the flag the algorithm earns rather
    than assumes: True for answers this zone's data produced, False for
    the referral of step 3b, where the composing sentence names someone
    else's data as the one to ask.
    """

    rcode: object | None = None
    aa: bool = True
    answers: tuple[DnsRecord, ...] = ()
    authority: tuple[DnsRecord, ...] = ()
    additional: tuple[DnsRecord, ...] = ()


_ANY = int(DnsQType.ANY)


def _apex_soa(zone: Zone) -> tuple[DnsRecord, ...]:
    return (zone.soa,) if zone.soa is not None else ()


def _synthesize(records: Sequence[DnsRecord], qname: DomainName) -> tuple[DnsRecord, ...]:
    """Step 3c, verbatim: "set the owner of the RR to be QNAME, and not
    the node with the \"*\" label"."""
    return tuple(DnsRecord(qname, r.rtype, r.rclass, r.ttl, rdata=r.rdata) for r in records)


class _Walk:
    """serve()'s per-query state, kept off the Zone so the data stays data."""

    def __init__(self, zone: Zone, qname: DomainName, qtype: int):
        self.zone = zone
        self.qname = qname
        self.qtype = qtype
        self.q_labels = list(qname.labels())
        self.apex_len = len(list(zone.apex.labels()))
        self.rel = len(self.q_labels) - self.apex_len

    def prefix(self, depth: int) -> DomainName:
        """Apex plus the first *depth* relative labels, nearest to the apex.

        labels() runs left to right (deepest first), so the prefix that
        is *shallower* sits at the tail of the list: take the last
        ``apex_len + depth`` labels and the query name's own tail grows
        from there.
        """
        keep = self.apex_len + depth
        return DomainName.from_labels(self.q_labels[len(self.q_labels) - keep :])

    def records_at(self, name: DomainName) -> list[DnsRecord]:
        return self.zone._nodes.get(_key(name), [])

    def has_node(self, name: DomainName) -> bool:
        return _key(name) in self.zone._nodes

    def matching(self, records: Sequence[DnsRecord]) -> list[DnsRecord]:
        if self.qtype == _ANY:
            return list(records)
        return [r for r in records if int(r.rtype) == self.qtype]

    def nodata(self, chain: Sequence[DnsRecord] = ()) -> ZoneAnswer:
        return ZoneAnswer(answers=tuple(chain), authority=_apex_soa(self.zone))

    def nxdomain(self) -> ZoneAnswer:
        from .enums import DnsResponseCode  # local: the parse path never needs it

        return ZoneAnswer(rcode=DnsResponseCode.NAME_ERROR, authority=_apex_soa(self.zone))


def _serve_answer(
    zone: Zone, name: str | DomainName, qtype: int, qclass: int = 1
) -> ZoneAnswer | None:
    """The zone's answer for one question, or None for "not my zone".

    This is RFC 1034 section 4.3.2's steps 2 and 3 written for one
    zone's data: find the zone (step 2's sweep is the not-my-branch),
    then match down label by label -- node (3a), cut or referral (3b),
    wildcard (3c).
    """
    if int(qclass) != int(DnsRClass.IN):
        return None
    qname = name if isinstance(name, DomainName) else DomainName(str(name))
    if not (qname == zone.apex or qname.is_subdomain_of(zone.apex)):
        return None
    walk = _Walk(zone, qname, int(qtype))

    # Step 3b on the way down: any cut at or above the query name owns
    # everything below it, and the answer belongs to someone else.
    for depth in range(1, walk.rel + 1):
        node = walk.prefix(depth)
        if node == zone.apex:
            continue
        ns = [r for r in walk.records_at(node) if int(r.rtype) == int(DnsRType.NS)]
        if not ns:
            continue
        if depth == walk.rel and walk.qtype in (int(DnsRType.NS), _ANY):
            # The cut node's own NS query lands inside this zone's data:
            # the parent really is authoritative for the child's NS RRset.
            return ZoneAnswer(
                answers=tuple(walk.matching(walk.records_at(node))),
                authority=_apex_soa(zone),
            )
        return _referral(walk, node, ns)

    # Step 3a, with 3a's CNAME clause looping back through it; 3c after.
    chain: list[DnsRecord] = []
    seen: set[tuple[bytes, ...]] = set()
    current = qname
    while True:
        key = _key(current)
        if key in seen:
            # An alias loop, said as far as we dare: the CNAMEs we
            # followed, and nothing past them.
            return ZoneAnswer(answers=tuple(chain))
        seen.add(key)
        records = walk.records_at(current)
        if records:
            cnames = [r for r in records if int(r.rtype) == int(DnsRType.CNAME)]
            if walk.qtype in (int(DnsRType.CNAME), _ANY):
                matches = walk.matching(records)
            else:
                matches = [r for r in walk.matching(records) if r not in cnames]
            if matches:
                return ZoneAnswer(answers=tuple(chain + matches), authority=_apex_soa(zone))
            if cnames:
                chain.extend(cnames)
                target = DomainName(str(cnames[0].rdata))
                if not (target == zone.apex or target.is_subdomain_of(zone.apex)):
                    # Step 3a says go back to step 1 -- another zone's or
                    # the cache's turn. This module serves one zone's data
                    # and never walks, so the chain is the answer.
                    return walk.nodata(chain)
                current = target
                continue
            return walk.nodata(chain)
        # The node does not exist: step 3c. The wildcard applies at the
        # deepest existing encloser -- everything deeper is absent by
        # construction, and an encloser node is exactly §4.3.3's
        # "explicit evidence ... to the contrary" against wildcards
        # further up.
        deepest = walk.rel - 1
        while deepest >= 0 and not walk.has_node(walk.prefix(deepest)):
            deepest -= 1
        encloser = walk.prefix(deepest).labels() if deepest >= 0 else []
        wildcard = DomainName.from_labels([b"*", *list(encloser)])
        wrecords = walk.records_at(wildcard)
        if not wrecords:
            return walk.nxdomain() if not chain else ZoneAnswer(answers=tuple(chain))
        matches = [r for r in walk.matching(wrecords) if int(r.rtype) != int(DnsRType.CNAME)]
        if not matches and walk.qtype != int(DnsRType.CNAME):
            matches = [r for r in wrecords if int(r.rtype) == int(DnsRType.CNAME)]
        if matches:
            return ZoneAnswer(
                answers=tuple(chain + list(_synthesize(matches, current))),
                authority=_apex_soa(zone),
            )
        return walk.nodata(chain)


def _referral(walk: _Walk, cut: DomainName, ns: list[DnsRecord]) -> ZoneAnswer:
    """Step 3b, verbatim: the NS RRs "into the authority section of the
    reply", "whatever addresses are available into the additional
    section" -- and no AA, because the answer belongs to the zone being
    handed to."""
    glue: list[DnsRecord] = []
    for record in ns:
        target = DomainName(str(record.rdata))
        if target != cut and not target.is_subdomain_of(cut):
            continue  # out of bailiwick: no obligation, and no right, of glue
        for candidate in walk.records_at(target):
            if int(candidate.rtype) in (int(DnsRType.A), int(DnsRType.AAAA)):
                glue.append(candidate)
    return ZoneAnswer(aa=False, authority=tuple(ns), additional=tuple(glue))
