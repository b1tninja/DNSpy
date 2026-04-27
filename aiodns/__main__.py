#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4  # for binding :53 on Linux

import asyncio
import logging
import traceback

from .names import DomainName
from .packet import DnsPacket, DnsQuestion, Query
from .resolver import RecursiveResolver
from .server import DnsServer

# Must match the DnsServer listen address in main().
LOCAL_DNS: tuple[str, int] = ("127.0.0.1", 53)
EXAMPLE_NAME = "example.org"
# Recursive resolution can be slow; the resolver is WIP.
LOOKUP_TIMEOUT_S = 120.0


class _LocalDnsResponseWaiter(asyncio.DatagramProtocol):
    """Wait for a single UDP datagram, then close the client transport."""

    def __init__(self, on_packet: asyncio.Future) -> None:
        self._on_packet = on_packet
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self._on_packet.done():
            self._on_packet.set_result((data, addr))
        if self.transport is not None:
            self.transport.close()

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        if not self._on_packet.done():
            self._on_packet.set_exception(exc)


async def _lookup_example_org_via_local_server(loop: asyncio.AbstractEventLoop) -> None:
    future: asyncio.Future = loop.create_future()
    client_transport, _ = await loop.create_datagram_endpoint(
        lambda: _LocalDnsResponseWaiter(future),
        local_addr=("0.0.0.0", 0),
    )
    try:
        # A / IN; use wire values (1, 1) so packing matches DNS even if IntEnum members are odd.
        query = Query(questions=[DnsQuestion(DomainName(EXAMPLE_NAME), 1, 1)], RD=True)
        client_transport.sendto(bytes(query), LOCAL_DNS)
        data, raddr = await asyncio.wait_for(future, timeout=LOOKUP_TIMEOUT_S)
    except TimeoutError:
        logging.error(
            "Timed out after %s s waiting for %s A from local DnsServer %s (resolver may be WIP).",
            LOOKUP_TIMEOUT_S,
            EXAMPLE_NAME,
            LOCAL_DNS,
        )
    except Exception:
        logging.exception("UDP client error while waiting for %s", EXAMPLE_NAME)
    else:
        try:
            pkt, _off = DnsPacket.parse(data)
        except Exception:
            logging.exception("Failed to parse DNS response from %s", raddr)
        else:
            logging.info("example.org lookup via local DnsServer %s -> %s", LOCAL_DNS, pkt)
    finally:
        client_transport.close()


async def main() -> None:
    try:
        loop = asyncio.get_running_loop()

        _resolver_transport, resolver_protocol = await loop.create_datagram_endpoint(
            lambda: RecursiveResolver(),
            local_addr=("0.0.0.0", 0),
        )
        logging.debug(
            "%s bound to: %s", resolver_protocol, _resolver_transport.get_extra_info("sockname")
        )

        _server_transport, _server_protocol = await loop.create_datagram_endpoint(
            lambda: DnsServer(resolver_protocol),
            local_addr=("127.0.0.1", 53),
        )
        logging.debug(
            "%s bound to: %s", _server_protocol, _server_transport.get_extra_info("sockname")
        )

    except BaseException:
        traceback.print_exc()
    else:
        logging.info("Startup successful. Querying %s (A) through DnsServer %s ...", EXAMPLE_NAME, LOCAL_DNS)
        await _lookup_example_org_via_local_server(loop)
        logging.info("Press Ctrl+C to stop.")
        # Block so UDP transports keep serving until interrupted.


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutting down.")
