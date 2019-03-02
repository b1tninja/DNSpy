import asyncio
import socket

import logging

from . import console, IP_MTU_DISCOVER, IP_PMTUDISC_DO
from .packet import DnsPacket
from .enums import DnsQR
from .resolver import RecursiveResolver


class DnsServer(asyncio.Protocol):
    loop = asyncio.get_event_loop()

    def __init__(self, resolver):
        assert isinstance(resolver, RecursiveResolver)
        self.resolver = resolver
        self.log = logging.Logger('server')
        self.log.addHandler(console)

    def connection_made(self, transport):
        sock = transport.get_extra_info('socket')

        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)

    async def respond_to_packet(self, dns_packet, addr):
        # self.resolver.db.store_packet(dns_packet, source=addr)

        if dns_packet.QR == DnsQR.query:
            try:
                response = await self.resolver.resolve(dns_packet)
            except asyncio.CancelledError:
                self.log.debug("Task cancelled.")
            except asyncio.InvalidStateError:
                self.log.debug("Got result, but future was already cancelled.")
            else:
                if response:
                    print(response)
                    # TODO: RFC2181 FORBIDS mixed TTL values in a record set.
                    # response = Response(dns_packet.ID, DnsQR.response, DnsOpCode.query, False, False, True, False, 0, DnsResponseCode.no_error, questions=dns_packet.questions, answers=answers, nameservers=nameservers, additional_records=additional_records)
                    # TODO: consider making a responses table that refrences a packet to a destination addr,port
                    # self.resolver.db.store_packet(response, destination=addr)
                    self.transport.sendto(bytes(response), addr)
                    pass

    def datagram_received(self, data, addr):
        (host, port) = addr
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except AssertionError as e:
            self.log.warning('Unable to parse packet %s from %s. %s', data, host, e)
        else:
            self.log.info('Incoming packet: %s' % dns_packet)
            task = asyncio.Task(self.respond_to_packet(dns_packet, addr))
            # loop.call_later(60, task.cancel) # TODO: play around with timeout parameter
            # loop.run_until_complete(task)
