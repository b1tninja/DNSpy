"""The blocklist, end to end: a zone that lists, a client that reads it.

Two halves of increment Z share one port here. The server binds a
whole fake list zone -- ``blocked.test`` -- with the answer policy a
real list has: known leaves answer their 127.0.0.x codes (A) and their
sentences (TXT), and every other name under the zone gets the zone's
honest ``NXDOMAIN`` (a list zone answers for its whole tree, and an
absent leaf is how "not listed" is spoken). The client is
``namespy --rbl``, whose name-building this very file reuses to
construct the bindings -- one reversal, both directions, no drift.

The ``--ptr`` line closes the loop the other way: the same reversed
labels, hung under ``in-addr.arpa`` instead of the list zone, answered
from a binding. It is the demo's quiet lesson -- PTR and RBL names are
the same address spoken backwards.

Run it (no admin rights; PORT fallback logic as elsewhere):

    python examples/blocklist.py

Then, from another terminal, with PORT from the banner:

    namespy --forward 127.0.0.1:PORT --rbl 203.0.113.7 blocked.test
    namespy --forward 127.0.0.1:PORT --rbl 198.51.100.2 blocked.test
    namespy --forward 127.0.0.1:PORT --ptr 203.0.113.7

Exit codes say it for scripts: 0 listed, 1 not-listed, 2 unknown --
and note which one a dead zone produces. That is the whole point.
"""

import asyncio
import sys
from pathlib import Path

# So the example runs straight from a checkout, no install step.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ipaddress

from namespy.enums import DnsQClass, DnsQType, DnsResponseCode
from namespy.packet import DnsRecord
from namespy.rbl import reverse_address
from namespy.rdata import RData_A, RData_PTR, RData_TXT
from namespy.resolver import RecursiveResolver
from namespy.server import DnsServer, DynamicResponse

#: Preferred demo port; if Windows has reserved it, fall back and say where.
PORT = 5353

ZONE = "blocked.test"

#: The listings. Addresses are RFC 5737 documentation space -- this file
#: never touches a real list, because a demo that lists a real host is
#: an accusation.
LISTINGS = {
    "203.0.113.7": ("127.0.0.2", "example listing: policy says so"),
}

PTR_HOST = "listed.blocked.test."


def zone_handler(request):
    """A whole zone from one binding: leaf answers, or the zone's NXDOMAIN.

    The fall-through a bound responder usually has (``return None`` ->
    ask the world) is exactly wrong for a list zone: the zone IS the
    world for these names, and an absent leaf is an answer, not a
    question. So the default here is DynamicResponse(NAME_ERROR).
    """
    address = _leaf_address(request.name)
    entry = LISTINGS.get(address) if address else None
    if entry is None:
        return DynamicResponse(rcode=DnsResponseCode.NAME_ERROR)
    code, sentence = entry
    if request.qtype in (int(DnsQType.A), int(DnsQType.ANY)):
        return [
            DnsRecord(
                request.name,
                DnsQType.A,
                DnsQClass.IN,
                60,
                rdata=RData_A(ipaddress.IPv4Address(code)),
            )
        ]
    if request.qtype in (int(DnsQType.TXT), int(DnsQType.ANY)):
        return [
            DnsRecord(request.name, DnsQType.TXT, DnsQClass.IN, 60, rdata=RData_TXT([sentence]))
        ]
    return []  # NODATA: the leaf exists, this type does not


def _leaf_address(leaf_name):
    """The address a list leaf encodes: octets un-reversed, first label last."""
    labels = str(leaf_name).rstrip(".").split(".")
    if len(labels) < 5:
        return None
    octets = labels[:4]
    return ".".join(reversed(octets))


async def main():
    loop = asyncio.get_running_loop()
    _resolver_transport, resolver = await loop.create_datagram_endpoint(
        lambda: RecursiveResolver(), local_addr=("0.0.0.0", 0)
    )
    try:
        _transport, server = await loop.create_datagram_endpoint(
            lambda: DnsServer(resolver), local_addr=("127.0.0.1", PORT)
        )
    except OSError:
        _transport, server = await loop.create_datagram_endpoint(
            lambda: DnsServer(resolver), local_addr=("127.0.0.1", 0)
        )
    port = _transport.get_extra_info("sockname")[1]

    # The list zone, suffix-bound: one handler, the whole tree.
    server.bind(ZONE, zone_handler, include_subdomains=True)
    # The same reversal under the arpa tree: --ptr's name, answered.
    server.bind(
        reverse_address("203.0.113.7"),
        lambda request: (
            [
                DnsRecord(
                    request.name,
                    DnsQType.PTR,
                    DnsQClass.IN,
                    60,
                    rdata=RData_PTR(PTR_HOST),
                )
            ]
            if request.qtype in (int(DnsQType.PTR), int(DnsQType.ANY))
            else DynamicResponse(rcode=DnsResponseCode.NAME_ERROR)
        ),
    )

    print(f"blocklist demo answering on 127.0.0.1:{port} (Ctrl+C stops)")
    print(f"  zone: {ZONE}  (203.0.113.7 listed as 127.0.0.2; every other leaf NXDOMAIN)")
    print("Try, from another terminal:")
    print(f"  namespy --forward 127.0.0.1:{port} --rbl 203.0.113.7 {ZONE}    # exit 0")
    print(f"  namespy --forward 127.0.0.1:{port} --rbl 198.51.100.2 {ZONE}   # exit 1")
    print(f"  namespy --forward 127.0.0.1:{port} --ptr 203.0.113.7")

    # The demo's job now is to stay: the answers live in the event loop that
    # asyncio.run keeps open only while this coroutine does. Returning here
    # would close the socket between the banner and the first query -- a
    # server that existed only in the past tense.
    try:
        await asyncio.Event().wait()
    finally:
        _transport.close()
        _resolver_transport.close()
        await server.aclose()
        await resolver.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
