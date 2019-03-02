#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4

import asyncio

import logging
import signal
import traceback

from .resolver import RecursiveResolver
from .server import DnsServer


async def main():
    try:
        loop = asyncio.get_event_loop()

        resolver_transport, resolver_protocol = await loop.create_datagram_endpoint(RecursiveResolver,
                                                                                    local_addr=('0.0.0.0', 0))
        logging.debug("%s bound to: %s", resolver_protocol, resolver_transport.get_extra_info('sockname'))

        server_transport, server_protocol = await loop.create_datagram_endpoint(lambda: DnsServer(resolver_protocol),
                                                                                local_addr=('127.0.0.1', 53))
        logging.debug("%s bound to: %s", server_protocol, server_transport.get_extra_info('sockname'))

    except:
        traceback.print_exc()
    else:
        logging.info("Startup successful.")


if __name__ == '__main__':
    signal.signal(signal.SIGINT, exit)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.run_forever()
