"""Dynamic responders: the DNS you can write with a lambda.

A tour of ``DnsServer.bind`` (namespy's U1 hook) and the shipped reflexive
responder (U2) -- four names, four handlers, no zone file anywhere:

* ``whoami.``  -- the calling-number announcement circuit: answers the
  address and port the query arrived from, and the transport it arrived on.
  Only the socket can give this answer, which is what makes it honest.
* ``roll.``    -- a lambda, because binding needs no more ceremony than that.
* ``time.``    -- a handler that answers differently every time, TTL 0.
* ``echo.``    -- a suffix binding (``include_subdomains=True``): every name
  below it answers with its own name, a mirror with no zone beneath it.

Run it (no admin rights needed -- it binds an ordinary high port on the
loopback interface; Windows reserves some high ports for itself, so if the
preferred one is taken the OS assigns a free one and the banner says which):

    python examples/dynamic_responders.py

Then, from another terminal -- the CLI's --forward door is the client, and
PORT is the number the banner printed:

    namespy --forward 127.0.0.1:PORT whoami TXT
    namespy --forward 127.0.0.1:PORT roll TXT
    namespy --forward 127.0.0.1:PORT anything.echo TXT
    namespy --forward 127.0.0.1:PORT WHOAMI. AAAA   # NODATA: no v6 visible here

Ctrl+C stops. Compare answers between UDP and a TCP-forced client and watch
the TXT sentence name the transport: the answer belongs to the wire, not a
zone. That is the whole demo.
"""

import asyncio
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

# So the example runs straight from a checkout, no install step.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from namespy.enums import DnsQType
from namespy.packet import DnsRecord
from namespy.rdata import RData_TXT
from namespy.resolver import RecursiveResolver
from namespy.server import (
    REFLEXIVE_NAME,
    DnsServer,
    whoami_responder,
)

#: Preferred demo port. 5353 is the customary DNS-alt and Windows is known to
#: reserve it (Hyper-V and WinNAT hold exclusion ranges without asking); if the
#: bind is refused the demo falls back to an OS-picked port and prints it, so
#: the instructions can never lie about where the server is.
PORT = 5353


def txt(request, sentence):
    """The answer shape a handler returns: records, NOERROR implied."""
    return [DnsRecord(request.name, DnsQType.TXT, ttl=0, rdata=RData_TXT([sentence]))]


def mirror(request):
    """The suffix-bound handler: answer with the name you were asked about."""
    if request.qtype in (int(DnsQType.TXT), int(DnsQType.ANY)):
        return txt(
            request,
            f"you asked {request.name} over {request.transport} from {request.address[0]}",
        )
    return []  # empty list is NODATA: "we are the whole zone, and it has none"


async def main():
    loop = asyncio.get_running_loop()
    # The resolver is what every other answer would go ask the network for;
    # bound names never touch it. It exists here so the demo is a real server
    # for unbound names too -- forward example.com A at this port and watch
    # the difference between bound and unbound.
    _resolver_transport, resolver = await loop.create_datagram_endpoint(
        lambda: RecursiveResolver(), local_addr=("0.0.0.0", 0)
    )
    try:
        _transport, server = await loop.create_datagram_endpoint(
            lambda: DnsServer(resolver), local_addr=("127.0.0.1", PORT)
        )
    except OSError:
        # The port is Windows', not ours: take whatever it offers instead of
        # dying, and let the banner tell the truth about where we ended up.
        _transport, server = await loop.create_datagram_endpoint(
            lambda: DnsServer(resolver), local_addr=("127.0.0.1", 0)
        )
    port = _transport.get_extra_info("sockname")[1]

    server.bind(REFLEXIVE_NAME, whoami_responder)
    # secrets, not random: the dice do not need crypto, but an example that
    # imports the honest module for a demo roll teaches the right reflex.
    server.bind("roll.", lambda request: txt(request, f"1d6 => {secrets.randbelow(6) + 1}"))
    server.bind("time.", lambda request: txt(request, datetime.now(UTC).isoformat()))
    server.bind("echo.", mirror, include_subdomains=True)

    # flush, not by accident: a demo whose banner stays in a stdout buffer
    # when the process is backgrounded or piped prints nothing where anyone
    # can read the port it chose.
    print(f"namespy dynamic demo on 127.0.0.1:{port} (Ctrl+C to stop)", flush=True)
    print("try:", flush=True)
    for line in (
        "whoami TXT",
        "roll TXT",
        "time TXT",
        "anything.at.all.echo TXT",
        "whoami AAAA",
    ):
        print(f"  namespy --forward 127.0.0.1:{port} {line}", flush=True)
    await asyncio.Event().wait()  # the answers are all on the socket now


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
