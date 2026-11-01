"""RFC 9471: the referral shape through this server's truncation rules.

The document is short and its §3 is shorter, but the row it pins (roadmap
line 181) stayed open for a specific reason: every truncation test written
before this round truncated an *answer* -- fat TXT records in the answer
section -- and a referral carries its payload in the other two sections:
the NS set in AUTHORITY, the glue in ADDITIONAL. §3.1¶1's rule reads
through that shape: "when a name server generates a referral response, it
MUST include all available glue records for in-domain name servers in the
additional section or MUST set TC=1 if constrained by message size." The
update §3.3 makes to RFC 1034's step 4c says the same thing from the other
end: "If all glue RRs for in-domain name servers do not fit, set TC=1."

The mechanism is increment J's :meth:`namespy.server.DnsServer._fit_datagram`
-- additional records give way before authority ones, which is exactly the
referral's priority (a resolver can sub-resolve a nameserver's address,
roadmap line 107; it cannot invent a nameserver), and anything dropped
raises TC. What this file adds is the shape: glue whole when it fits, glue
trimmed and TC raised when it does not, the NS set standing while any
authority data is promised to, and the OPT floor under all of it.

The other half of §3.1 (¶2, "most iterative clients... retry over TCP upon
receiving a response with the TC flag set") is the walker's existing
obligation, pinned in ``test_resolver_truncation.py``; §3.2's sibling-domain
SHOULD is declined with the reason in the roadmap row: this fixture serves
no zone, so it has no bailiwick to classify glue by -- and §3.2 makes
partial sibling omission legal without TC anyway, while J's blanket TC on
any drop is the stricter message.

Harness borrowed from :mod:`tests.test_server`, as in the fragmentation
round: the server is not tested against a mock of itself.
"""

import test_server as srv

from namespy.enums import DnsQClass, DnsQR, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsRecord, Response
from namespy.rdata import RData_NS

CHILD = DomainName("child.example.")


def _glue(ns_name: DomainName, last_octet: int):
    return [
        DnsRecord(ns_name, DnsRType.A, DnsQClass.IN, 86400, rdata=bytes([192, 0, 2, last_octet])),
        DnsRecord(
            ns_name,
            DnsRType.AAAA,
            DnsQClass.IN,
            86400,
            rdata=bytes([0x20, 0x01, 0x0D, 0xB8]) + b"\x00" * 11 + bytes([last_octet]),
        ),
    ]


def referral(packet, *, ns_count: int):
    """A referral-shaped reply: NS set in AUTHORITY, A+AAAA glue per server
    in ADDITIONAL -- RFC 9471 §2.1's example, multiplied to a size."""
    nameservers = []
    additional = []
    for i in range(1, ns_count + 1):
        ns_name = DomainName(f"ns{i}.{CHILD}")
        nameservers.append(
            DnsRecord(CHILD, DnsRType.NS, DnsQClass.IN, 86400, rdata=RData_NS(ns_name))
        )
        additional.extend(_glue(ns_name, i))
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RD=packet.RD,
        questions=list(packet.questions),
        nameservers=nameservers,
        additional_records=additional,
    )


def glue_count(reply) -> int:
    return sum(
        1 for r in reply.additional_records if int(r.rtype) in (int(DnsRType.A), int(DnsRType.AAAA))
    )


# ------------------------------------------------------- §3.1: all the glue, or TC


async def test_a_referral_that_fits_carries_every_glue_record_and_no_tc():
    """The MUST's normal branch: include all available glue, say nothing else."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: referral(p, ns_count=3))
    server.datagram_received(bytes(srv.query_packet().add_edns(1232)), srv.ADDR)
    await srv.drain(server)

    reply = transport.replies[0]
    assert not reply.TC, "a complete referral is not a truncated one"
    assert len(reply.nameservers) == 3
    assert glue_count(reply) == 6, "every A and AAAA the zone was handed"
    assert reply.ARCOUNT == len(reply.additional_records)
    assert reply.opt() is not None


async def test_a_referral_whose_glue_will_not_fit_says_so_with_tc():
    """§3.1's constrained branch, which is the whole reason this row was open.

    Six nameservers and their twelve glue records clear the 512 the client
    advertises (name compression notwithstanding), so the reply leaves the
    socket with TC=1 (§3.3's update to RFC 1034 step 4c) -- and with the NS
    set *whole*, because the glue is what gives way: the client that retries
    over TCP at least never has to wonder which servers were being named.
    Partial glue beside a TC is the shape the "or MUST set TC=1" clause
    licenses; partial glue in silence was the bug.
    """
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: referral(p, ns_count=6))
    server.datagram_received(bytes(srv.query_packet().add_edns(512)), srv.ADDR)
    await srv.drain(server)

    data, _addr = transport.sent[0]
    assert len(data) <= 512
    reply = DnsPacket.parse(data)[0]
    assert reply.TC, "glue was dropped, and §3.1 says the header must say so"
    assert len(reply.nameservers) == 6, "the NS set outlives the glue, record for record"
    assert reply.NSCOUNT == 6
    assert glue_count(reply) < 12, "and something did go, which is what TC now reports"
    assert reply.opt() is not None, "RFC 6891 §7¶6's floor holds on this shape too"
    assert reply.ARCOUNT == len(reply.additional_records)


async def test_a_legacy_referral_client_gets_the_same_rule_at_512():
    """No OPT asks 1035 §4.2.1's 512 of the server and 9471 asks the same TC:
    the glue-complete small referral needs neither number's mercy."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: referral(p, ns_count=2))
    server.datagram_received(bytes(srv.query_packet()), srv.ADDR)  # no EDNS at all
    await srv.drain(server)

    reply = transport.replies[0]
    assert not reply.TC, "small glue fits the legacy floor"
    assert glue_count(reply) == 4
    assert reply.opt() is None  # §7¶2: no OPT, never one

    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: referral(p, ns_count=6))
    server.datagram_received(bytes(srv.query_packet()), srv.ADDR)
    await srv.drain(server)

    reply = transport.replies[0]
    assert reply.TC, "12 records of glue do not fit 512, and silence is not an option"
    assert len(reply.nameservers) == 6, "not even a fat referral pays with its NS set"


async def test_the_truncation_promise_outranks_the_stingy_advertisement():
    """A 128-octet advertisement is a 512 cap (§6.2.3¶2), so a referral whose
    glue fits inside 512 is never trimmed on account of a number the client
    was not allowed to mean -- the TC bit stays reserved for real constraint."""
    server, resolver, transport = srv.make_server()
    await srv.answer_with(resolver, lambda p: referral(p, ns_count=3))
    server.datagram_received(bytes(srv.query_packet().add_edns(128)), srv.ADDR)
    await srv.drain(server)

    reply = transport.replies[0]
    assert not reply.TC
    assert glue_count(reply) == 6
