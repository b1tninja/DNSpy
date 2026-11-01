"""Policy filtering: the four refusals RFC 8914 gave names to.

A server that refuses a name for policy reasons has always had ways to
hide what it did -- an NXDOMAIN that reads like a denial of existence,
a NODATA that reads like a missing record, a synthesized address that
sends the curious somewhere quiet. RFC 8914 built the channel to say it
instead, and four sections name the stances an operator actually takes:

* 15 -- Blocked: "The server is unable to respond to the request because
  the domain is on a blocklist due to an internal security policy
  imposed by the operator of the server resolving or forwarding the
  query." (section 4.16)
* 16 -- Censored: the same refusal when the list answers to "an external
  requirement imposed by an entity other than the operator of the
  server resolving or forwarding the query.  Note that how the imposed
  policy is applied is irrelevant" (section 4.17).
* 17 -- Filtered: "The server is unable to respond to the request
  because the domain is on a blocklist as requested by the client.
  Functionally, this amounts to 'you requested that we filter domains
  like this one.'" (section 4.18).
* 18 -- Prohibited: "An authoritative server or recursive resolver that
  receives a query from an 'unauthorized' client can annotate its
  REFUSED message with this code." (section 4.19) -- the one code whose
  section names its own RCODE.

Which RCODE travels with which code is the operator's choice, not the
protocol's: section 2 "does not allow or prohibit any particular
extended error codes and information to be matched with any particular
RCODEs", and this server has quoted that sentence while composing its
own errors since the day it first sent one. The pairings below are the
same kind of choice, made from each section's own words. Blocked and
censored answer NXDOMAIN, because refusing "to respond to the request"
is a refusal to acknowledge the name, which is what a blocklist has
always looked like on the wire. Filtered answers NODATA: the client
asked for this filtering, so the name is not denied -- the record set
simply is not handed over. Prohibited answers REFUSED because section
4.19's sentence says its message is a REFUSED.

What a filter answer deliberately never does matters as much as what it
says. No AA: a policy act is not an authority claim about the name. No
AD: nothing was validated, and a refusal carrying AD would teach clients
to trust policy fictions. And no cache entry anywhere -- these bytes are
composed, never learned, which is why this module holds no resolver or
cache door: there is nothing here that should ever be remembered.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from .enums import DnsResponseCode
from .names import DomainName

__all__ = ["FilterAction", "FilterPolicy", "FilterRule"]


class FilterAction(Enum):
    """The stances of RFC 8914 sections 4.16-4.19, as their registry codes."""

    BLOCK = 15
    CENSOR = 16
    FILTER = 17
    PROHIBIT = 18

    @property
    def rcode(self) -> DnsResponseCode:
        """The answer shape this stance takes; see the module docstring."""
        if self is FilterAction.FILTER:
            return DnsResponseCode.NO_ERROR  # NODATA: empty answer, name undenied
        if self is FilterAction.PROHIBIT:
            return DnsResponseCode.REFUSED  # section 4.19 names its own RCODE
        return DnsResponseCode.NAME_ERROR

    @property
    def extra_text(self) -> bytes:
        """The EXTRA-TEXT, short and attributed the way section 3 asks.

        The registry's own nouns -- "Blocked", not the verb of the CLI
        verb -- because the text explains the code it travels with, and
        the code's name is the sentence's subject (§4.16-§4.19).
        """
        return b"namespy: " + _STANCE_NOUNS[self].encode("ascii")


_STANCE_NOUNS = {
    FilterAction.BLOCK: "blocked",
    FilterAction.CENSOR: "censored",
    FilterAction.FILTER: "filtered",
    FilterAction.PROHIBIT: "prohibited",
}


#: One verb per stance, no synonyms: four words with four documents
#: between them, and an operator choosing among them should be choosing
#: between policies, not between spellings.
_VERBS = {action.name.lower(): action for action in FilterAction}


@dataclass(frozen=True)
class FilterRule:
    """One policy decision: what fires on *trigger*, and how it answers.

    :param trigger: the name the rule fires on.
    :param include_subdomains: when true the rule is a zone, matching
        the trigger itself and every name beneath it -- ``is_subdomain_of``
        covers the apex too, so this is the same apex-or-below matching
        :meth:`namespy.server.DnsServer.bind` does, and the two
        configuration surfaces agree on what "under a name" means.
    :param action: the stance to answer with.
    :param substitute: records to answer with instead of the refusal,
        NOERROR forced -- records beside an NXDOMAIN would contradict
        the one field every client reads first. They still never earn
        AA: an invented answer is policy output, not authority over
        the name (module docstring, last paragraph).
    """

    trigger: DomainName
    include_subdomains: bool = False
    action: FilterAction = FilterAction.BLOCK
    substitute: Sequence[object] = ()

    @classmethod
    def parse(cls, text: str) -> "FilterRule":
        """Read one ``ACTION:TRIGGER`` rule, the shape ``--filter`` carries.

        A leading dot makes the trigger a zone (``.ads.example`` covers
        ``ads.example`` and everything below it); without one the rule
        matches exactly. The root is a legal zone: an operator who means
        to refuse everything has that choice to make deliberately, with
        the flag in front of them, rather than a pattern the parser
        quietly talks them out of.
        """
        verb, colon, rest = text.partition(":")
        action = _VERBS.get(verb.strip().lower())
        rest = rest.strip()
        if action is None or not colon or not rest:
            raise ValueError(
                f"filter rule {text!r} is not ACTION:TRIGGER (ACTION: {', '.join(sorted(_VERBS))})"
            )
        zone = rest.startswith(".")
        name_text = rest[1:] if zone else rest
        try:
            trigger = DomainName(name_text)
        except Exception:
            raise ValueError(f"filter rule {text!r}: {name_text!r} is not a domain name") from None
        return cls(trigger=trigger, include_subdomains=zone, action=action)

    def matches(self, name: DomainName) -> bool:
        """Whether *name* fires this rule, in the trigger's own spelling."""
        if self.include_subdomains:
            return name.is_subdomain_of(self.trigger)
        return name == self.trigger


@dataclass(frozen=True)
class FilterPolicy:
    """Rules in order, first match wins -- a policy is read top to bottom.

    First-match rather than most-specific: the shape hosts-file habits
    and repeated-flag configs already share, and the one that lets a
    broad zone rule carry a default with narrow exceptions written above
    it. An empty policy fires on nothing, which is the same silence as
    no policy at all -- the server's default posture is and stays
    unfiltered.
    """

    rules: Sequence[FilterRule] = ()

    @classmethod
    def from_cli(cls, texts: Sequence[str]) -> "FilterPolicy":
        """Build the policy from repeated ``--filter`` strings."""
        return cls(tuple(FilterRule.parse(text) for text in texts))

    def evaluate(self, name: DomainName) -> FilterRule | None:
        """The first rule *name* fires, or ``None`` to answer normally."""
        for rule in self.rules:
            if rule.matches(name):
                return rule
        return None
