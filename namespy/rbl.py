"""The blocklist client's arithmetic: names, codes, and a verdict.

The mechanics are RFCs. RFC 1035 section 3.5 lays out the reverse tree:
"hosts which desire to be included ... should have a domain name
corresponding to their 32-bit Internet address" written with the octets
reversed under ``in-addr.arpa``. RFC 3596 section 2.5 does the same for
IPv6 with bit groups -- nibbles, reversed, under ``ip6.arpa``. The
reversed labels live here once (:func:`reverse_address` hangs them under
the arpa trees for PTR; :func:`rbl_query_name` hangs them under a
blocklist zone for the listing question), because a list leaf and a PTR
name are the same address spoken backwards and the same mistake.

The etiquette has no anchor in this corpus, and this module says so
rather than ghosting a citation: asking *the list's own authorities*
(a walk ends there naturally; a random recursive's 127.0.0.x means
nothing), reading A answers in 127.0.0.0/8 as LISTED with the low octets
a per-zone bitfield the zone's own documentation interprets, fetching
TXT at the same name for the operator's explanation, and caching for at
most an hour -- all deployed convention, labelled as such below where
each one lands.

One convention is not etiquette but arithmetic, and it is the reason
this module exists at all: **a refusal is not innocence**. NXDOMAIN from
the zone means not-listed; SERVFAIL, timeouts and every other failure
mean *unknown*. Treating an outage as clearance is the direction that
gets mail deleted or hosts blocked by weather, and the status field
keeps the three states separate so a caller can never confuse them by
reading a boolean.
"""

import ipaddress
from dataclasses import dataclass

from .enums import DnsResponseCode, DnsRType
from .names import DomainName

__all__ = ["MAX_LISTING_TTL", "RblVerdict", "interpret", "rbl_query_name", "reverse_address"]

#: The polite-cache ceiling: listings are meant to expire quickly, and a
#: zone publishing a day's TTL on a listing answer is asking to be
#: believed about something that may be stale by lunch. Deployed
#: convention (no anchor in the corpus), enforced by :func:`interpret`.
MAX_LISTING_TTL = 3600

_LOOPBACK_PREFIX = ipaddress.IPv4Address("127.0.0.0").packed[:3]  # 127.0.0.


def _reversed_labels(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """The address's own labels, reversed: octets for v4, nibbles for v6.

    This is the RFC mechanic three callers share: RFC 1035 section 3.5
    reverses the octets for ``in-addr.arpa``, RFC 3596 section 2.5
    reverses the nibbles for ``ip6.arpa``, and a blocklist zone hangs
    the same reversed labels under its own name. Only the tail differs
    -- the two arpa trees for reverse lookup, the zone for a listing.
    """
    if ip.version == 4:
        return ".".join(str(octet) for octet in reversed(ip.packed))
    return ".".join(reversed("".join(f"{byte:02x}" for byte in ip.packed)))


def reverse_address(
    address: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> DomainName:
    """The reverse-DNS name for *address*, its octets or nibbles before the tree.

    IPv4: RFC 1035 section 3.5's reversed dotted quad under
    ``in-addr.arpa``. IPv6: RFC 3596 section 2.5's bit groups -- every
    nibble of the 128-bit address, most-significant-last, under
    ``ip6.arpa``. This is the PTR question's name; :func:`rbl_query_name`
    reuses the same reversed labels under a different tail.
    """
    ip = ipaddress.ip_address(address)
    tree = "in-addr.arpa" if ip.version == 4 else "ip6.arpa"
    return DomainName(f"{_reversed_labels(ip)}.{tree}")


def rbl_query_name(
    address: str | ipaddress.IPv4Address | ipaddress.IPv6Address, zone: str | DomainName
) -> DomainName:
    """The leaf *address* occupies inside blocklist *zone*.

    The reversed labels, the zone as the tail -- NOT the PTR name with
    a zone stuck behind ``in-addr.arpa``, which is a name no list has
    ever published. The zone's authorities answer for this leaf and
    nobody else's 127.0.0.x means anything.
    """
    ip = ipaddress.ip_address(address)
    return DomainName(f"{_reversed_labels(ip)}.{zone}")


@dataclass(frozen=True)
class RblVerdict:
    """What the zone said about one address. Three states, never two.

    :param status: ``listed``, ``not-listed``, or ``unknown`` -- see the
        module docstring for why the third is not negotiable.
    :param codes: the 127.0.0.0/8 addresses the zone returned, sorted
        textually. Their *meaning* (which bit is which blacklist, what
        the second octet encodes) belongs to the zone's documentation,
        not to this module; inventing bit names here would be exactly
        the phantom-citation move this project keeps catching in its
        own prose, so the numbers ride uninterpreted.
    :param explanations: TXT strings at the same name, best-effort:
        deployed convention, not every zone publishes them.
    :param ttl: the listing's effective ceiling -- the zone's own TTL
        capped at :data:`MAX_LISTING_TTL`.
    :param zone_ttl: what the zone actually asked for, kept visible so
        the cap is a disclosed decision rather than a silent edit.
    """

    address: str
    zone: str
    status: str
    reason: str = ""
    codes: tuple[str, ...] = ()
    explanations: tuple[str, ...] = ()
    ttl: int | None = None
    zone_ttl: int | None = None

    @property
    def listed(self) -> bool:
        return self.status == "listed"

    def describe(self) -> str:
        """The CLI's few lines: verdict first, detail under it."""
        head = f"{self.address} in {self.zone}: {self.status.upper()}"
        if self.reason:
            head += f" ({self.reason})"
        lines = [head]
        if self.codes:
            lines.append("  codes: " + ", ".join(self.codes))
        for text in self.explanations:
            lines.append(f'  explanation: "{text}"')
        if self.listed and self.ttl is not None:
            cap = "" if self.ttl == self.zone_ttl else f" (zone asked for {self.zone_ttl}s)"
            lines.append(f"  cache: at most {self.ttl}s{cap}")
        return "\n".join(lines)


def _listing_code(record) -> str | None:
    """The dotted quad of *record* if it is an A in 127.0.0.0/8, else None."""
    if int(record.rtype) != int(DnsRType.A):
        return None
    try:
        text = str(record.rdata)
        ip = ipaddress.IPv4Address(text)
    except (ValueError, ipaddress.AddressValueError):
        return None
    return text if ip.packed[:3] == _LOOPBACK_PREFIX else None


def interpret(address, zone, a_response, txt_response=None) -> RblVerdict:
    """Read a blocklist zone's two answers into a verdict.

    *a_response* is the A lookup of :func:`rbl_query_name`; *txt_response*
    the same name's TXT, if it was asked for. ``None`` means the lookup
    failed outright -- one of the ``unknown`` shapes. The reading is the
    deployed convention as described in the module docstring; nothing
    here pretends a document signed off on it.
    """
    addr_text, zone_text = str(address), str(zone).rstrip(".")
    if a_response is None:
        return RblVerdict(addr_text, zone_text, "unknown", reason="no answer from the zone")

    try:
        rcode = DnsResponseCode(int(a_response.extended_rcode))
    except ValueError:
        rcode = DnsResponseCode(int(a_response.RCODE))

    if rcode is DnsResponseCode.NAME_ERROR:
        return RblVerdict(
            addr_text, zone_text, "not-listed", reason="the zone says the leaf does not exist"
        )
    if rcode is not DnsResponseCode.NO_ERROR:
        # The refusal-is-not-innocence branch: SERVFAIL, REFUSED, and
        # company all answer "unknown", because the zone declined to
        # say, which is not the same sentence.
        return RblVerdict(addr_text, zone_text, "unknown", reason=f"rcode {rcode.name}")

    codes, ttls = [], []
    for record in a_response.answers:
        code = _listing_code(record)
        if code is not None:
            codes.append(code)
            ttls.append(int(record.ttl))
    if not codes:
        return RblVerdict(
            addr_text, zone_text, "unknown", reason="NOERROR carried no 127.0.0.0/8 listing code"
        )

    explanations: tuple[str, ...] = ()
    if txt_response is not None:
        texts = []
        for record in txt_response.answers:
            if int(record.rtype) == int(DnsRType.TXT):
                text = getattr(record.rdata, "text", None) or str(record.rdata)
                if text:
                    texts.append(text)
        explanations = tuple(texts)

    zone_ttl = min(ttls)
    return RblVerdict(
        addr_text,
        zone_text,
        "listed",
        codes=tuple(sorted(set(codes))),
        explanations=explanations,
        ttl=min(zone_ttl, MAX_LISTING_TTL),
        zone_ttl=zone_ttl,
    )
