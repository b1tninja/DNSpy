import asyncio

import ipaddress
import logging
import os
import random
import re
import socket
import urllib.request
from socket import gaierror

from . import IP_PMTUDISC_DO, IP_MTU_DISCOVER, IP_MTU, console
from .enums import DnsRClass, DnsRType, DnsQType, DnsQR, DnsResponseCode
from .names import DomainName
from .packet import DnsRecord, DnsPacket, DnsQuestion, Query, Response
from .rdata import RData_SOA


class Resolver(asyncio.Protocol):
    async def query(self, questions, nameserver_record, address_record, **kwargs):
        if nameserver_record:
            assert isinstance(nameserver_record, DnsRecord)
        if address_record:
            assert isinstance(address_record, DnsRecord)

        future = asyncio.Future()

        # cached_record = self.db.lookup_response(questions, nameserver_record.pk, address_record.pk)
        # if cached_record:
        #     future.set_result(cached_record)
        # else:
        ip = ipaddress.ip_address(address_record.rdata)
        dns_packet = Query(questions=questions, **kwargs)
        # self.db.store_packet(dns_packet, destination=(ip.exploded, 53))
        # self.db.create_query(dns_packet.pk, nameserver_record.pk, address_record.pk, parent_id)
        key = (ip.exploded, dns_packet.ID)
        if isinstance(ip, ipaddress.IPv4Address):
            self.queue[key] = (dns_packet, future)
            self.transport.sendto(bytes(dns_packet), (ip.exploded, 53))
        else:
            future.cancel()
            # TODO: try to catch the exception on giaerror
            # TODO: handle condition when IPV6 fails?
            # del self.queue[key]
            # future.cancel()

        return future

    @staticmethod
    def enumerate_nameserver_addresses(nameserver_records, additional_records):
        nameserver_records = list(nameserver_records)
        additional_records = list(additional_records)
        random.shuffle(nameserver_records)
        random.shuffle(additional_records)

        # TODO: consider moving away from ns,addr pairs, and just using addr soley
        for nameserver_record in nameserver_records:
            assert isinstance(nameserver_record, DnsRecord)
            if nameserver_record.rtype == DnsRType.NS:
                # TODO: support domain name label compression for NS rdata
                ns_name = nameserver_record.name
                for address_record in additional_records:
                    assert isinstance(address_record, DnsRecord)
                    if address_record.name == nameserver_record.rdata and address_record.rtype in [DnsRType.A,
                                                                                                   DnsRType.AAAA]:
                        yield (nameserver_record, address_record)


class Forwarder(asyncio.Protocol):
    def __init__(self, nameservers=None):
        if nameservers is None:
            nameservers = ['8.8.8.8', '8.8.4.4', '4.2.2.2', '1.1.1.1']


class RecursiveResolver(Resolver):
    loop = asyncio.get_event_loop()

    def error_received(self, exception):
        if isinstance(exception, gaierror):
            pass
        self.log.critical(exception)

    def record_reader(self, zone_file):
        with open(zone_file, 'r') as root_hints_file:
            for i, line in enumerate(root_hints_file):
                if not line or line[0] == ';':
                    continue
                tokens = re.split(r'\s+', line.rstrip())
                if len(tokens) == 5:
                    (name, ttl, rclass, rtype, rdata) = tokens
                    rclass = DnsRClass[rclass]
                elif len(tokens) == 4:
                    (name, ttl, rtype, rdata) = tokens
                    rclass = DnsRClass.IN  # lets just assume
                else:
                    logging.warning("Unrecognized entry on line %d of zone file: %s", i, zone_file)
                    continue

                try:
                    rtype = DnsRType[rtype]
                    ttl = int(ttl)
                except ValueError:
                    self.log.critical('Malformed glue records.')
                    continue

                name = DomainName(name)
                if rtype == DnsRType.SOA:
                    pass
                if rtype == DnsRType.NS:
                    record = DnsRecord(name, rtype, rclass, ttl, rdata=DomainName(rdata))
                elif rtype == DnsRType.A:
                    record = DnsRecord(name, rtype, rclass, ttl, rdata=ipaddress.IPv4Address(rdata).packed)
                elif rtype == DnsRType.AAAA:
                    record = DnsRecord(name, rtype, rclass, ttl, rdata=ipaddress.IPv6Address(rdata).packed)
                else:
                    logging.warning("Skipping %s record for %s from zone: %s", rtype, name, zone_file)
                    continue

                yield record

    def __init__(self, db=None, root_hints_path='named.root'):
        self.queue = {}
        # self.db = db
        self.log = logging.Logger('resolver')
        self.log.addHandler(console)
        self.root_hints = self.bootstrap(root_hints_path)

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info('socket')
        # self.MTU = sock.getsockopt(socket.IPPROTO_IP, IP_MTU)
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)

    def datagram_received(self, data, addr):
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except AssertionError as e:
            self.log.warning('Unable to parse packet: %s. %s', data, e)
        else:
            self.log.info('resolver_datagram_recieved(%s, %s)' % (dns_packet, addr))
            # self.db.store_packet(dns_packet, source=addr)
            (host, port) = addr
            key = (str(host), dns_packet.ID)
            if key in self.queue:
                (query_packet, future) = self.queue[key]
                del self.queue[key]
                # TODO: asserts about answer matching query_packet
                # self.db.update_query_response(query_packet.pk, dns_packet.pk)
                future.set_result(dns_packet)
            else:
                self.log.warning("Unexpected packet.")

    def bootstrap(self, root_hints_path):
        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]
        # response = self.db.lookup_response(questions)

        # if response is None:
        try:
            if not os.path.isfile(root_hints_path):
                urllib.request.urlretrieve('http://www.internic.net/domain/named.root', root_hints_path)
                self.log.info('Attempting to retrieve root hints from internic.')
            else:
                self.log.debug('Found root hints, %s' % os.path.basename(root_hints_path))

        except IOError:
            self.log.critical('Unable to retrieve root hints.')

        else:

            nameservers = []
            additional_records = []
            for record in self.record_reader(root_hints_path):
                if record.rtype == DnsRType.NS:
                    nameservers.append(record)
                if record.rtype == DnsRType.A or record.rtype == DnsRType.AAAA:
                    additional_records.append(record)

            query = Query(QR=DnsQR.query, RD=False, questions=questions)
            response = Response(QR=DnsQR.response, ID=query.ID, AA=True, RD=False, RA=False,
                                questions=questions,
                                nameservers=nameservers,
                                additional_records=additional_records)

            # self.db.store_packet(query)
            # self.db.store_packet(response)
            #
            # self.db.create_query(query.pk, response_id=response.pk)

        return response

    async def resolve(self, dns_packet):
        assert isinstance(dns_packet, DnsPacket)
        # assert hasattr(dns_packet, 'pk')

        # TODO: consider http://tools.ietf.org/html/draft-ietf-dnsext-edns1-03
        # TODO: try/except to set proper RCODE
        assert dns_packet.QDCOUNT > 0
        if dns_packet.QDCOUNT > 1:
            assert all(map(lambda question: question.name == dns_packet.questions[0].name, dns_packet.questions[1:]))
            assert all(
                map(lambda question: question.qclass == dns_packet.questions[0].qclass, dns_packet.questions[1:]))

        # response = self.db.lookup_response(dns_packet.questions)
        # if response:
        #     return response

        # TODO: deduplicate at the packet level?
        # self.db.create_query(dns_packet.pk)

        # TODO: if not zone_cut bootstrap() ?

        # root_hints = self.db.lookup_response(DnsQuestion(root_label, DnsQType.NS))

        for question in dns_packet.questions:
            next_zone_cut = self.root_hints

            # Determine NS

            # Determine SOA
            for zone in question.name.hierarchy():
                # TODO: opportunity here for async operation
                question = DnsQuestion(zone, DnsQType.SOA)
                # zone_soa = self.db.lookup_response(question)
                zone_soa = None

                # next_zone_cut = root_hints ???
                next_zone_cut = self.root_hints

                while next_zone_cut and not zone_soa:
                    assert isinstance(next_zone_cut, Response)

                    zone_cut = next_zone_cut
                    next_zone_cut = None

                    # for nameserver in [Nameserver(ns) for ns in zone_cut.nameservers]:
                    for (nameserver, additional_record) in self.enumerate_nameserver_addresses(zone_cut.nameservers,
                                                                                               zone_cut.additional_records):
                        # TODO: Use/Check resolved AA queries from cached records, from zone_cut
                        # As fallback, use glue
                        # TODO: Nameserver(nameserver_record)?
                        ns_name = nameserver.rdata
                        try:
                            response = await self.query([question], nameserver, additional_record, RD=False)
                            assert isinstance(response, Response)
                        except asyncio.CancelledError:
                            pass
                        except asyncio.InvalidStateError:
                            pass
                        except AssertionError:
                            pass
                        else:
                            self.log.debug('resolve() %s' % response)
                            if response.RCODE == DnsResponseCode.no_error:
                                # TODO: and rtype == SOA etc
                                if response.ANCOUNT == 0:
                                    if response.NSCOUNT > 0:
                                        # TODO: lame delegation
                                        # TODO: if RD
                                        # TODO: when we ask com for example.com our zone=example.com, when zone_cut is a.iana-servers.net, should attempt to resolve the address of the NS first, then rely on glue... this will require another recursion
                                        # for _ns in response.nameservers:
                                        #     #TODO: ask for A or AAAA based on the ipv4/6 of socket
                                        #     #TODO: check for a cached record, if one is not found, attempt to resolve it, if that fails, use glue
                                        #     #cached_response = await self.resolve(Query(questions=[DnsQuestion(DomainName.parse(_ns.rdata), DnsQType.A)]))
                                        #     # if cached_response:
                                        #     #     next_zone_cut = cached_response
                                        #     #     break # We found a cached address for the ns, break out so we can use this as next zone cut
                                        #         # TODO: this whole thing is a mess, and needs rewritting... the break here will prevent continuing in the event that the address we have cached is non responsive... a stack type mechanism would be much more suitable, then recursion depth could be controlled in a sane fashion
                                        # else:
                                        # Use the glue
                                        next_zone_cut = response
                                        break
                                elif response.ANCOUNT >= 1:
                                    # TODO: ANCOUNT == 1 probably shouldn't be a requirement
                                    next_zone_cut = zone_cut  # Reuse the zone_cut that produced this authorative response
                                    for record in response.answers:
                                        if record.rtype == DnsRType.SOA:
                                            pass
                                            zone_soa = RData_SOA.parse_from(record.rdata)
                                    if ns_name != zone_soa.mname:
                                        pass

                                    for response_question in response.questions:

                                        if response_question.name == question.name:
                                            result = await self.query(dns_packet.questions, nameserver,
                                                                      additional_record)
                                            if isinstance(result, Response):
                                                result.ID = dns_packet.ID
                                                return result
                                            # We received an authorative SOA response, but not from the preferred NS
                                            # TODO: consider using zone_soa as parent_id?
                                            # TODO: enforce expires/refresh/minimum TTL values
                                            # TODO: support negative caching (if response.AA)

                                else:
                                    pass

                            # zone_cut = response
                            break  # TODO: parallel requests, this line skips the rest of the ns,addr pairs

                    # if not response:
                    #     pass
                else:
                    pass
