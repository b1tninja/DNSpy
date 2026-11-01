"""Special-use domain names: the registry the walk must refuse to enter.

RFC 6761 created the registry and wrote, for each entry, a list of
"Domain Name Reservation Considerations" -- one paragraph per kind of
software that touches a name. The caching-resolver paragraph (number 4 of
each entry) speaks in the voice of the software namespy is, and unusually
concretely:

* ``invalid.`` -- "Caching DNS servers SHOULD ... generate immediate
  NXDOMAIN responses for all such queries" (§6.4¶4), "to avoid unnecessary
  load on the root name servers and other name servers". The reason is
  stated in the text, and it is this project's reason too: those queries
  have no answer anywhere, and walking one is walking every server between
  here and a TLD that will deny it.
* ``localhost.`` -- "generate an immediate positive response giving the IP
  loopback address" for address queries, "and for all other query types,
  generate an immediate negative response" (§6.3¶4). §6.3¶7 then closes the
  door on variation: the effective RDATA "is defined by protocol
  specification and cannot be modified by local configuration". That is why
  the synthesized answers this module authorizes carry TTL 0 downstream:
  protocol-defined data has no authority whose expiry it could inherit.
* ``test.`` and the RFC 1918 reverse-mapping zones -- negative by default,
  and each entry names its own escape hatch: a caching server "SHOULD offer
  a configuration option (disabled by default) to enable upstream
  resolving", for networks where a private authority really does serve them
  (§6.2¶4, §6.1¶7). :attr:`~namespy.resolver.SpecialNamesPolicy.IGNORE` is
  that option, and §6.1¶2's table -- eighteen zones: ``10``, ``16`` through
  ``31`` under ``172``, and ``168.192`` -- is transcribed below exactly,
  because the list is the registration.
* ``local.`` -- RFC 6762 §3 puts this domain outside unicast DNS. §3¶3 makes
  every name under it link-local, "meaningful only on the link where they
  originate", and §3¶4's MUST sends queries for them to the multicast
  group. A unicast resolver that does not speak mDNS has no honest packet
  to send; answering the name locally is what §3¶3 leaves a name to when
  its meaning does not travel the network.
* ``onion.`` -- RFC 7686 §2¶5 holds the only caching-server sentence that is
  a MUST rather than a SHOULD: "They MUST generate NXDOMAIN for all such
  queries" (unless adapted for Tor, which is a different software's job).
  It is also the entry whose opt-out costs more than wasted packets: asking
  public DNS about a ``.onion`` name announces an interest in a hidden
  service to every server on the walk. That is why opting out warns.

Two absences are as deliberate as the entries:

* **Example names.** §6.5¶4 instructs caching servers "SHOULD NOT recognize
  example names as special and SHOULD resolve them normally" -- and
  ``example.com`` really is served, by IANA, per §6.5¶8. Blocking it would
  be a local invention wearing a citation that says the opposite.
* **``127.in-addr.arpa``.** §6.1's table is the RFC 1918 reverse zones and
  nothing else; the loopback reverse zone is not in the registry this
  module implements, so PTR queries there walk like any other arpa name.
  What the registry does not reserve, this module does not invent.
"""

from __future__ import annotations

import enum

from .names import DomainName


class SpecialNameAction(enum.Enum):
    """What the registry says a resolver owes a query for this name."""

    #: Not a registered name: the walk proceeds normally.
    NONE = "none"

    #: §6.3: address queries get the loopback address, every other query
    #: type gets an immediate negative response. Nothing goes to the network.
    LOOPBACK = "loopback"

    #: An immediate NXDOMAIN: §6.4¶4 (``invalid.``), §6.2¶4 (``test.``),
    #: §6.1¶7 (private reverse zones), RFC 6762 §3¶3-4 (``local.``), and
    #: RFC 7686 §2¶5's MUST (``onion.``).
    NXDOMAIN = "nxdomain"


class SpecialNameVerdict:
    """The registry's answer about one name: which action, which paragraph.

    *citation* travels into the trace line and the CLI's sentences, because
    "we refused to ask" is exactly the sort of decision a reader of a trace
    deserves to be able to check against a document.
    """

    __slots__ = ("action", "citation")

    def __init__(self, action: SpecialNameAction, citation: str):
        self.action = action
        self.citation = citation

    def __repr__(self):
        return f"SpecialNameVerdict({self.action.value}, {self.citation!r})"


_NOT_SPECIAL = SpecialNameVerdict(SpecialNameAction.NONE, "")

# Registered TLDs whose queries end at this table, each beside the paragraph
# that says so. Matching is via DomainName.is_subdomain_of with its default
# include_self, so the apex itself -- a query for the TLD's own records -- is
# special too: the registry entries direct that no one may register these
# names (§6.2¶8, §6.3¶7, §6.4¶7, §6.1¶10; RFC 7686 §2¶8's MUST NOT), which
# makes the apex the clearest case of "there is no server to ask".
_TLD_RULES = (
    (DomainName("invalid."), "RFC 6761 §6.4¶4"),
    (DomainName("test."), "RFC 6761 §6.2¶4"),
    (DomainName("local."), "RFC 6762 §3¶3-4"),
    (DomainName("onion."), "RFC 7686 §2¶5"),
)

# RFC 6761 §6.3: "the domain 'localhost.' and any names falling within
# '.localhost.'" -- the apex is special too, which is what §6.3¶1's user
# assurance ("will always resolve to the respective IP loopback address")
# is about.
_LOCALHOST = DomainName("localhost.")

# RFC 6761 §6.1¶2, transcribed: the RFC 1918 reverse-mapping zones. Eighteen
# -- 10/8, the sixteen second-level zones of 172.16/12, and 192.168/16 --
# and nothing else. Notably not 127: the loopback reverse zone is managed
# inside the namespace and no paragraph above reserves it here.
_PRIVATE_REVERSE = tuple(
    DomainName(zone)
    for zone in (
        ["10.in-addr.arpa."]
        + [f"{second}.172.in-addr.arpa." for second in range(16, 32)]
        + ["168.192.in-addr.arpa."]
    )
)


def classify_special_use(name: DomainName) -> SpecialNameVerdict:
    """The registry's verdict for one QNAME: which action, which paragraph.

    Case-insensitivity is inherited from :class:`~namespy.names.DomainName`
    comparison itself (RFC 1035 §2.4.4, RFC 4343): ``LOCALHOST.`` is the same
    name, and §6.3 turns on the name, not its spelling. Only the QNAME is
    judged -- see the module docstring for why a chain that *ends* at a
    registry name is the publishing zone's rudeness rather than this table's
    business.
    """
    if name.is_subdomain_of(_LOCALHOST):
        return SpecialNameVerdict(SpecialNameAction.LOOPBACK, "RFC 6761 §6.3¶4")
    for zone, citation in _TLD_RULES:
        if name.is_subdomain_of(zone):
            return SpecialNameVerdict(SpecialNameAction.NXDOMAIN, citation)
    for zone in _PRIVATE_REVERSE:
        if name.is_subdomain_of(zone):
            return SpecialNameVerdict(SpecialNameAction.NXDOMAIN, "RFC 6761 §6.1¶7")
    return _NOT_SPECIAL
