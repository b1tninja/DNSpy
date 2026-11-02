"""hosts-file honesty: parsing, the TTL-0 answers, and the "says so" line (roadmap W5).

``namespy/apps/hosts.py`` adds no protocol logic -- it reads a file every OS already
reads and answers from it -- so the tests here pin the *conventions* the module
adopts (comments, bad-line voiding, one entry per name, family decides the answer),
the honesty contract (a hosts answer names its line; a name it lacks answers NODATA
rather than falling through), and the two doors: ``lookup(hosts=...)`` consulting
first, and ``bind`` handing a server a responder that speaks the server's own
``ResponderRequest``/``DynamicResponse`` currency. No socket, no system file.
Conventions from ``test_apps_lookup.py`` and ``test_apps_routing.py``.
"""

import ipaddress

import pytest

from namespy.apps.hosts import HostsEntry, HostsFile, HostsMatch
from namespy.enums import DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.server import DynamicResponse, ResponderRequest

TEXT = (
    "# a comment line contributes nothing\n"
    "\n"
    "127.0.0.1   localhost        # loopback, both families\n"
    "::1         localhost\n"
    "10.0.0.5    web.internal  api.internal\n"
    "not-an-ip   broken.internal\n"
    "127.0.0.1\n"  # address with no name: nothing to map
)


@pytest.fixture
def hosts():
    return HostsFile.parse(TEXT, source="/etc/hosts")


def _entry(name, addr, line, source=""):
    return HostsEntry(
        address=ipaddress.ip_address(addr), name=DomainName(name), line=line, source=source
    )


def test_parse_one_entry_per_name_and_skips_junk_lines(hosts):
    # localhost (v4), localhost (v6), web.internal, api.internal -> 4 entries; the
    # comment, blank, bad-address, and address-only lines contribute none.
    assert len(hosts) == 4
    assert [str(e.name) for e in hosts.entries] == [
        "localhost",
        "localhost",
        "web.internal",
        "api.internal",
    ]


def test_parse_remembers_line_numbers_counting_skipped_lines(hosts):
    by_name = {str(e.name): e for e in hosts.entries}
    assert by_name["web.internal"].line == 5  # lines 1-4 include the skipped comment/blank
    assert by_name["web.internal"].address == ipaddress.ip_address("10.0.0.5")
    assert by_name["web.internal"].source == "/etc/hosts"


def test_parse_family_is_the_address_version(hosts):
    assert hosts.entries[0].version == 4  # 127.0.0.1
    assert hosts.entries[1].version == 6  # ::1


def test_inline_comment_is_trimmed_from_the_names(hosts):
    # the "# loopback, both families" comment must not become a name.
    assert all("#" not in str(e.name) for e in hosts.entries)


def test_records_for_chooses_family(hosts):
    localhost = DomainName.from_unicode("localhost")
    v4 = hosts.records_for(localhost, int(DnsQType.A))
    v6 = hosts.records_for(localhost, int(DnsQType.AAAA))
    anyq = hosts.records_for(localhost, int(DnsQType.ANY))
    assert [int(r.rtype) for r in v4] == [int(DnsRType.A)]
    assert [int(r.rtype) for r in v6] == [int(DnsRType.AAAA)]
    assert len(anyq) == 2  # both families under ANY


def test_records_for_a_missing_family_is_nodata(hosts):
    web = DomainName.from_unicode("web.internal")
    assert hosts.records_for(web, int(DnsQType.AAAA)) == ()  # v4-only name
    assert hosts.records_for(web, int(DnsQType.MX)) == ()  # hosts hold no MX


def test_records_are_ttl_zero_in_the_in_class(hosts):
    web = DomainName.from_unicode("web.internal")
    (record,) = hosts.records_for(web, int(DnsQType.A))
    assert record.ttl == 0, "local answers must not be cached (dnsmasq precedent)"
    assert int(record.rclass) == int(DnsRClass.IN)
    assert str(record.rdata) == "10.0.0.5"


def test_names_is_distinct_in_first_seen_order(hosts):
    assert [str(n) for n in hosts.names()] == ["localhost", "web.internal", "api.internal"]


def test_has_distinguishes_known_from_unknown(hosts):
    assert hosts.has(DomainName.from_unicode("api.internal")) is True
    assert hosts.has(DomainName.from_unicode("nowhere.internal")) is False


def test_match_names_the_line_a_hosts_answer_came_from(hosts):
    web = DomainName.from_unicode("web.internal")
    hit = hosts.match(web, int(DnsQType.A))
    assert isinstance(hit, HostsMatch)
    assert hit.citation == "line 5 of /etc/hosts"  # the honesty: file + line, not "DNS"
    assert len(hit.records) == 1


def test_match_of_a_known_name_wrong_family_is_nodata_not_none(hosts):
    web = DomainName.from_unicode("web.internal")
    hit = hosts.match(web, int(DnsQType.AAAA))
    assert hit is not None  # the name IS here; this family is not
    assert hit.records == ()


def test_match_of_an_unknown_name_is_none(hosts):
    assert hosts.match(DomainName.from_unicode("nowhere.internal"), int(DnsQType.A)) is None


def test_citation_omits_the_source_when_parsed_from_a_string():
    entry = _entry("x.test", "1.2.3.4", 9)
    assert entry.citation == "line 9"


def test_from_file_remembers_the_path_as_source(tmp_path):
    path = tmp_path / "hosts"
    path.write_text("192.168.0.7   printer.lan\n", encoding="utf-8")
    hosts = HostsFile.from_file(path)
    assert hosts.source == str(path)
    hit = hosts.match(DomainName.from_unicode("printer.lan"), int(DnsQType.A))
    assert hit is not None
    assert hit.citation == f"line 1 of {path}"


# -- the client door: lookup(hosts=...) --------------------------------------


class _MustNotRun:
    """An engine that would fail the test if a hosts hit reached the walk."""

    def run(self, coro, *, timeout=None):
        coro.close()
        raise AssertionError("a hosts hit must short-circuit before any walk/forward")


class _FakeResp:
    answers = ()
    AD = False
    stale_answer = False


class _Walks:
    """An engine standing in for the DNS path, returning an unsigned walk answer."""

    def run(self, coro, *, timeout=None):
        coro.close()
        return _FakeResp(), None, "walk"


def test_lookup_answers_from_hosts_and_says_the_line(hosts):
    from namespy.apps.lookup import lookup

    result = lookup("localhost", "A", hosts=hosts, engine=_MustNotRun())
    assert result.provenance.source == "hosts"
    assert "line 3" in result.provenance.note  # the first localhost entry's line
    assert result.provenance.line.startswith("hosts line 3 of /etc/hosts")
    assert result.provenance.line.endswith("unsigned")  # hosts is never DNSSEC-validated
    assert len(result.records) == 1
    assert str(result.records[0].rdata) == "127.0.0.1"
    assert result.response is None  # no server spoke; this was never a query


def test_lookup_hosts_nodata_does_not_fall_through(hosts):
    # web.internal is mapped (IPv4). Asking AAAA is a name the file KNOWS, so hosts
    # answers NODATA -- it does not hand the question to the network. _MustNotRun
    # proves the walk is never reached.
    from namespy.apps.lookup import lookup

    result = lookup("web.internal", "AAAA", hosts=hosts, engine=_MustNotRun())
    assert result.provenance.source == "hosts"
    assert result.records == ()


def test_lookup_falls_through_when_hosts_does_not_know_the_name(hosts):
    from namespy.apps.lookup import lookup

    result = lookup("nowhere.internal", "A", hosts=hosts, engine=_Walks())
    assert result.provenance.source == "walk"  # a hosts miss is not a hosts answer
    assert result.provenance.note == ""  # no line is claimed


def test_lookup_skips_hosts_for_a_non_in_class(hosts):
    from namespy.apps.lookup import lookup

    # A hosts file maps IN-class addresses; a CH query cannot be answered from it,
    # so it is passed straight to DNS rather than "matched" on the name.
    result = lookup("localhost", "A", qclass="CH", hosts=hosts, engine=_Walks())
    assert result.provenance.source == "walk"


# -- the server door: bind ----------------------------------------------------


class _FakeServer:
    def __init__(self):
        self.bindings = []

    def bind(self, name, handler, *, include_subdomains=False):
        self.bindings.append((name, handler, include_subdomains))


def test_bind_registers_one_responder_per_distinct_name(hosts):
    server = _FakeServer()
    bound = hosts.bind(server)
    assert [str(n) for n in bound] == [str(n) for n in hosts.names()]
    assert len(server.bindings) == 3
    assert all(sub is False for _n, _h, sub in server.bindings)  # exact names by default


def test_bind_honours_include_subdomains(hosts):
    server = _FakeServer()
    hosts.bind(server, include_subdomains=True)
    assert all(sub is True for _n, _h, sub in server.bindings)


def _request(name, qtype):
    return ResponderRequest(
        name=name,
        qtype=qtype,
        qclass=int(DnsRClass.IN),
        address=("0.0.0.0", 0),
        transport="udp",
        dnssec_ok=False,
        cd=False,
        packet=None,
    )


def test_bound_handler_speaks_the_servers_responder_contract(hosts):
    server = _FakeServer()
    hosts.bind(server)
    web = DomainName.from_unicode("web.internal")
    handler = next(h for n, h, _s in server.bindings if n == web)
    verdict = handler(_request(web, int(DnsQType.A)))
    assert isinstance(verdict, DynamicResponse)  # the type the server's bind() expects
    assert len(verdict.answers) == 1
    assert str(verdict.answers[0].rdata) == "10.0.0.5"
    assert verdict.answers[0].ttl == 0
    # the family the name lacks answers NODATA (empty answers), not None (fall through)
    nodata = handler(_request(web, int(DnsQType.AAAA)))
    assert isinstance(nodata, DynamicResponse)
    assert nodata.answers == ()
