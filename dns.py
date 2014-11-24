from __future__ import unicode_literals

#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4

__author__ = 'b1tninja'

# For parsing named.root
import re
import os
import urllib.request


# For the database
from contextlib import closing
import mysql.connector

# For async io
import asyncio
try:
    import signal
except ImportError:
    signal = None

# For logging
import logging

# For everything else
from dns_packet import *
from enums import DnsRType, DnsRClass
import ipaddress
from collections import defaultdict


import hashlib

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s'))


class Nameserver(DomainName):
    pass
    #TODO: would be nice if nameservers could get a database context to look up their address records... maybe

class DnsResolver(asyncio.Protocol):
    loop = asyncio.get_event_loop()
    root_hints = None

    def record_reader(self, root_hints_path):
        with open(root_hints_path,'r') as root_hints_file:
            for line in root_hints_file:
                if not line or line[0] == ';':
                    continue
                tokens = re.split(r'\s*\s',line.rstrip())
                if len(tokens) == 5:
                    (name, ttl, rclass, rtype, rdata) = tokens
                    rclass = DnsRClass[rclass]
                elif len(tokens) == 4:
                    (name, ttl, rtype, rdata) = tokens
                    rclass = DnsRClass.IN  # lets just assume
                else:
                    continue # Don't know what this is
                try:
                    rtype = DnsRType[rtype]
                    ttl = int(ttl)
                except ValueError:
                    self.log.critical('Malformed glue records.')
                    continue

                name = DomainName.from_string(name)
                if rtype == DnsRType.NS:
                    record = DnsRecord(name,rtype,rclass,ttl,rdata=DomainName.from_string(rdata).encode())
                elif rtype == DnsRType.A:
                    record = DnsRecord(name,rtype,rclass,ttl,rdata=ipaddress.IPv4Address(rdata).packed)
                elif rtype == DnsRType.AAAA:
                    record = DnsRecord(name,rtype,rclass,ttl,rdata=ipaddress.IPv6Address(rdata).packed)
                self.log.debug('Glue record: %s' % record)
                yield record

    def __init__(self, db, RA=False):
        self.queue = {}
        self.db = db
        self.RA = RA
        self.log = logging.Logger('resolver')
        self.log.addHandler(console)
        root_hints_path = 'named.root'
        root_label = DomainName.from_string('.')

        self.db.get_name_id(root_label)

        try:
            if not os.path.isfile(root_hints_path):
                urllib.request.urlretrieve('http://www.internic.net/domain/named.root', root_hints_path)
                self.log.info('Attempting to retrieve root hints from internic.')
            else:
                self.log.debug('Found root hints, %s' % os.path.basename(root_hints_path))


            questions = [DnsQuestion(root_label, qtype=DnsQType.NS)]
            nameservers = []
            additional_records = []
            for record in self.record_reader(root_hints_path):
                if record.rtype == DnsRType.NS:
                    nameservers.append(record)
                if record.rtype == DnsRType.A or record.rtype == DnsRType.AAAA:
                    additional_records.append(record)
            dns_packet = DnsPacket(QR=DnsQR.response, RD=False, RA=False, questions=questions, nameservers=nameservers, additional_records=additional_records)
            self.root_hints = dns_packet
#            self.db.store_packet(dns_packet)

        except IOError:
            self.log.critical('Unable to parse root hints.')

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            (dns_packet,offset) = DnsPacket.parse(data)
        except AssertionError as e:
            self.log.warning("Unable to parse packet:", data)
        else:
            self.log.info('resolver_datagram_recieved(%s, %s)' % (dns_packet, addr))
            packet_id = self.db.store_packet(dns_packet, source=addr)
            (host,port) = addr
            key = (str(host),dns_packet.ID)
            if key in self.queue:
                (packet_id, future) = self.queue[key]
                future.set_result(dns_packet)
            else:
                self.log.warn("Unexpected packet.")

    def bootstrap(self):
        root_label = DomainName.from_string('.')
        (answer)



    @asyncio.coroutine
    def resolve(self, packet, ns=None, addr=None):
        # Enumerate NS for zone, starting from root label
        #  Enumerate addresses for given NS
        #   Query <SOA.zone> from NS,ADDR
        #   On response,
        #    resolve
        #   If error, try next A/AAAA?
        #  Next NS
        #
        #    Query <NS,zone> from NS,ADDR
        #    Query <MX,zone> from NS,ADDR
        #    Query <MX,zone> from NS,ADDR

        # TODO: consider http://tools.ietf.org/html/draft-ietf-dnsext-edns1-03
        assert(packet.QDCOUNT == 1)
        question = packet.questions[0]
        for label in reversed(question.name):
            zone_cut = yield from self.query(DnsQuestion(label, DnsQType.NS))
            print(zone_cut)

            print(label)

        return ([],[],[])

        root_label = DomainName.from_string('.')
        response = yield from self.query(DnsQuestion(root_label, DnsQType.SOA))
        resposne

        if len(answers) == 0:
            ns_map = {}
            for record in additional_records:
                if record.rtype == DnsRType.A:
                    ns_map[record.name] = ipaddress.IPv4Address(record.rdata)
                elif record.rtype == DnsRType.AAAA:
                    ns_map[record.name] = ipaddress.IPv6Address(record.rdata)
            for ns_record in nameservers:
                if DomainName.parse(ns_record.rdata) in ns_map:
                    print(ns_map[ns_record.name])

        for name in  [question.name[n-1:] for n in range(len(question.name),0,-1)]:
            (answers, nameservers, additional_records) = self.query(DnsQuestion(name, DnsQType.SOA), query)
            print(name, answers, nameservers, additional_records)

    def get_root_servers(self):
        if self.root_hints:
            return self.root_hints
        # else:
        #     ns_map = {}
        #     addr_map = defaultdict(list)
        #     for (id, record) in self.db.lookup_records(None):
        #         if record.rtype == DnsRType.NS:
        #             ns_name = DomainName.parse(record.rdata)
        #             ns_map[ns_name] = (id, record)
        #         elif record.rtype == DnsRType.A:
        #             addr_map[record.name].append((id, ipaddress.IPv4Address(record.rdata)))
        #         elif record.rtype == DnsRType.AAAA:
        #             addr_map[record.name].append((id, ipaddress.IPv6Address(record.rdata)))
        #
        #     root_hints = {}
        #     for ns_name in ns_map:
        #         (id, record) = ns_map[ns_name]
        #         root_hints[ns_name] = (id, addr_map[ns_name])
        #
        #     self.root_hints = root_hints
        #     return self.root_hints


    def _query(self, ns_id, addr_id, host, question):
        future = asyncio.Future()
        question_id = self.db.get_resource_header_id(question)
        query_id = self.db.get_query_id(question_id, ns_id, addr_id)
        dns_packet = Query(questions=[question], RD=False)
        addr = (str(host),53)
        self.db.store_packet(dns_packet, destination=addr)
        self.queue[(str(host), dns_packet.ID)] = (packet_id, future)
        self.transport.sendto(dns_packet.encode(), addr)


    def query(self, question, ns=None, addr=None):
        future = asyncio.Future()
        return future
#        question_id = self.db.get_question_id(question)
        # Walk the database starting form the root
        question = DnsQuestion(DomainName.from_string('.'), DnsQType.SOA)

        root_hints = self.get_root_servers()
        for ns_name in root_hints:
            (ns_id, address_records) = root_hints[ns_name]
            for (addr_id, addr) in address_records:
                self._query(ns_id, addr_id, addr, question)

# def query2():
#         answers = []
#         nameservers = []
#         additional_records = []
#
#         ns_map = {}
#         addr_map = defaultdict(list)
#
#
#
#         for (id, record) in self.db.lookup_records(None):
#             if record.rtype == DnsRType.NS:
#                 ns_name = DomainName.parse(record.rdata)
#                 ns_map[ns_name] = (id, record)
#                 nameservers.append(record)
#             else:
#                 additional_records.append(record)
#
#                 if record.rtype == DnsRType.A:
#                     addr_map[record.name].append((id, ipaddress.IPv4Address(record.rdata)))
#                 if record.rtype == DnsRType.AAAA:
#                     addr_map[record.name].append((id, ipaddress.IPv4Address(record.rdata)))
#
#             ns_name = DomainName.parse(ns_record.rdata)
#             for (rid,record) in self.db.lookup_records(DnsQuestion(ns_name, DnsQType.A), query):
#                 ns_map[ns_name].append((rid,ipaddress.IPv4Address(record.rdata)))
#                 self.db.get_query_id(nid, rid, question)
#
# #                self.query(qid, question)
#             for (rid,record) in self.db.lookup_records(DnsQuestion(ns_name, DnsQType.AAAA), query):
#                 ns_map[ns_name].append((rid,ipaddress.IPv6Address(record.rdata)))
#                 self.db.get_query_id(nid, rid, question)
# #                self.query(qid, question)
#         return (answers, nameservers, additional_records)
# TODO: a dict would be more pythonic for the additional_records[nameserver] type stuff, but this is closer to dns spec


class DnsServer(asyncio.Protocol):
    loop = asyncio.get_event_loop()

    def __init__(self, resolver):
        assert(isinstance(resolver, DnsResolver))
        self.resolver = resolver
        self.log = logging.Logger('server')
        self.log.addHandler(console)

    def connection_made(self, transport):
        self.transport = transport

    @asyncio.coroutine
    def respond_to_packet(self, dns_packet, addr):
        try:
            if dns_packet.QR == DnsQR.query:
                # Apparently the internet is lame.
                #assert(dns_packet.QDCOUNT == 1)
                # TODO: make proposal with TC bit

                # TODO: wait_for?
                (answers, nameservers, additional_records) = yield from self.resolver.resolve(dns_packet)
                # TODO: RFC2181 FORBIDS mixed TTL values in a record set.
                response = Response(dns_packet.ID, DnsQR.response, DnsOpCode.query, False, False, True, False, 0, DnsResponseCode.no_error, questions=dns_packet.questions, answers=answers, nameservers=nameservers, additional_records=additional_records)

                self.resolver.db.store_packet(response, destination=addr)
                self.transport.sendto(response.encode(), addr)
        except asyncio.CancelledError:
            self.log.debug("Task cancelled.")
        except asyncio.InvalidStateError:
            self.log.debug("Got result, but future was already cancelled.")

    def datagram_received(self, data, addr):
        (host,port) = addr
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except AssertionError:
            self.log.warn('Unable to parse packet %s from %s.' % (data, host))
        else:
            self.log.info('Incoming packet: %s' % dns_packet)
            packet_id = self.resolver.db.store_packet(dns_packet, source=addr)
            task = asyncio.async(self.respond_to_packet(dns_packet, addr))
            loop.call_later(3, task.cancel)


class Database(object):

    def __init__(self, database='dns', user=None, password=None, host='localhost', port=3306):
        self.db = mysql.connector.connect(database=database, user=user, password=password, host=host, port=port)
        self.log = logging.Logger('db')
        self.log.addHandler(console)
        self._cached_names = {}
        self._cached_questions = {}
        self._cached_queries = {}

    def get_blob_id(self, blob):
        with closing(self.db.cursor()) as cursor:
            sha1 = self._get_digest(blob)
            self.log.debug('get_blob_id(%s): %s' % (blob, sha1))
            # TODO: consider more friendly name than sql reserved word blob
            cursor.execute('INSERT IGNORE INTO dns.blob (`sha1`, `blob`) VALUES (%s, %s)', (sha1, blob))
            self.db.commit()
            return sha1


    def get_ipaddr_blob_id(self, ip):
        ip = ipaddress.ip_address(ip)
        return self.get_blob_id(ip.packed)

    def _get_digest(self, blob):
        # TODO: consider adding salt
        return hashlib.sha1(blob).digest()


    def store_packet(self, dns_packet, source=None, destination=None):
        assert(len(dns_packet.questions) == dns_packet.QDCOUNT)
        assert(len(dns_packet.answers) == dns_packet.ANCOUNT)
        assert(len(dns_packet.nameservers) == dns_packet.NSCOUNT)
        assert(len(dns_packet.additional_records) == dns_packet.ARCOUNT)

        record_set = dns_packet.answers + dns_packet.nameservers + dns_packet.additional_records

        if source is None:
            (source_addr, source_port) = (None, 0)
        else:
            (source_addr, source_port) = source
            source = ipaddress.ip_address(source_addr).packed

        if destination is None:
            (destination_addr, destination_port) = (None, 53)
        else:
            (destination_addr, destination_port) = destination
            destination = ipaddress.ip_address(destination_addr).packed

        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO packet ('
                           '`source`,'
                           '`source_port`,'
                           '`destination`,'
                           '`destination_port`,'
                           '`txnid`,'
                           '`qr`,'
                           '`opcode`,'
                           '`aa`,'
                           '`tc`,'
                           '`rd`,'
                           '`z`,'
                           '`rcode`,'
                           '`qdcount`,'
                           '`ancount`,'
                           '`nscount`,'
                           '`arcount`,'
                           '`queryset`,'
                           '`recordset`'
                           ') VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                           (source,
                            source_port,
                            destination,
                            destination_port,
                            dns_packet.ID,
                            int(dns_packet.QR),
                            int(dns_packet.OPCODE),
                            dns_packet.AA,
                            dns_packet.TC,
                            dns_packet.RD,
                            dns_packet.Z,
                            int(dns_packet.RCODE),
                            dns_packet.QDCOUNT,
                            dns_packet.ANCOUNT,
                            dns_packet.NSCOUNT,
                            dns_packet.ARCOUNT,
                            self.get_queryset_id(dns_packet.questions),
                            # TODO: reread RFC2181, unsure if ameservers+additional_records are part of the "record set"
                            self.get_recordset_id(record_set)
                           )
                          )

            self.db.commit()
            packet_id = cursor.lastrowid
            self.log.debug('create_packet(%s): %s' % (dns_packet, packet_id))

            # Questions
            for question in dns_packet.questions:
                self.create_packet_question(packet_id, question)

            # Answers + Nameservers + Additional Records
            for record in record_set:
                self.create_packet_record(packet_id, record)

            return cursor.lastrowid

    # def get_query_id(self, question_id, ns_id, addr_id):
    #     key = (question_id,ns_id,addr_id,)
    #
    #     self.log.debug('get_query(%d,%d,%d)' % (ns_id, addr_id, question_id))
    #
    #     if key in self._cached_queries:
    #         return self._cached_queries[key]
    #
    #     with closing(self.db.cursor()) as cursor:
    #         cursor.execute('SELECT id FROM query WHERE `question`=%s AND `nameserver`=%s AND `address`=%s LIMIT 1',
    #                        (question_id, ns_id, addr_id))
    #
    #         r = cursor.fetchone()
    #         if r is None:
    #             id = self.create_query(question_id,ns_id,addr_id)
    #         else:
    #             id = int(r[0])
    #             self.log.debug('get_query(%d,%d,%d) Found: %d' % (question_id, ns_id, addr_id, id))
    #
    #         self._cached_queries[key] = id
    #         return id


    def resolve_name(self, name_id):
        with closing(self.db.cursor()) as cursor:
            sequence = []
            for foo in range(256): # dns labels are limited to 256 depths anyway
                cursor.execute('SELECT parent,name FROM names WHERE `id`=%s LIMIT 1', (name_id,))
                (name_id,label) = cursor.fetchone()
                sequence.append(label)
                if name_id is None:
                    return DomainName(sequence)



    def lookup_records(self, query=None):
        #TODO: to self.get_question_id(question) or not to?

        # try:
        #     rtype = int(DnsRType(question.qtype))
        #     rclass = int(DnsRType(question.qclass))
        #
        # except ValueError:
        #     return [] # TODO Handle QTYPES such as ANY
        #
        # name_id = self.get_name_id(question.name)

        with closing(self.db.cursor()) as cursor:
            if query is None:
                cursor.execute('SELECT id,name,type,class,ttl,rdata FROM records WHERE `query` IS NULL AND (`ttl`+`cached`) >= UNIX_TIMESTAMP() ORDER BY `cached` DESC')
            else:
                cursor.execute('SELECT id,name,type,class,ttl,rdata FROM records WHERE `query`=%s AND (`ttl`+`cached`) >= UNIX_TIMESTAMP() ORDER BY `cached` DESC', (query))

            for tokens in cursor.fetchall():
                (id, name_id, rtype, rclass, ttl, rdata) = tokens
                # TODO: return the name that is cached in the database (case sensitivity thing) DomainName.from_database(self) perhaps
                name = self.resolve_name(name_id)
                yield (id, DnsRecord(name, rtype, rclass, ttl, rdata=rdata))

    # def get_nameserver_records(self, name, query=None):
    #     assert(isinstance(name, DomainName))
    #     yield from self.lookup_records(DnsQuestion(name, DnsQType.NS), query=query)
    #
    # def get_address_records(self, name, query=None):
    #     assert(isinstance(name, DomainName))
    #     for (rid, record) in self.lookup_records(DnsQuestion(name, DnsQType.A), query):
    #         yield record
    #     for (rid, record) in self.lookup_records(DnsQuestion(name, DnsQType.AAAA), query):
    #         yield record

    def create_name(self, label, parent, casemap=str.lower):
        if not label and parent is None:
            label = '.'
        else:
            label = casemap(label)

        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO name (`name`, `parent`) VALUES (%s, %s)', (casemap(label), parent))
            self.db.commit()
            self.log.debug('create_name(%s,%s) created with id: %d' % (label, parent, cursor.lastrowid))
            return cursor.lastrowid

    def create_resource_header(self, resource):
        if(isinstance(resource, DnsQuestion)):
            (resource_type, resource_class) = (int(resource.qtype), int(resource.qclass))
        elif(isinstance(resource, DnsRecord)):
            (resource_type, resource_class) = (int(resource.rtype), int(resource.rclass))
        else:
            raise ValueError # TODO: exception handling

        name_id = self.get_name_id(resource.name)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO resource_header (`name`, `type`, `class`) VALUES (%s, %s, %s)',
                           (name_id, resource_type, resource_class))
            self.db.commit()
            self.log.debug('create_resource_header(%s,%s,%s) created with id: %d' %
                           (resource.name, resource_type, resource_class, cursor.lastrowid))
            return cursor.lastrowid
    #
    # def create_query(self, question_id, ns_id, addr_id):
    #     with closing(self.db.cursor()) as cursor:
    #         cursor.execute('INSERT INTO query (`question`, `nameserver`, `address`) VALUES (%s, %s, %s)', (question_id, ns_id, addr_id))
    #         self.db.commit()
    #         self.log.debug('create_query(%d,%d,%d) created with id: %d' % (question_id, ns_id, addr_id, cursor.lastrowid))
    #         return cursor.lastrowid

    def get_question_id(self, question):
        self.log.debug('get_question(%s)' % question)

        if question in self._cached_questions:
            return self._cached_questions[question]

        name_id = self.get_name_id(question.name)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('SELECT id FROM question WHERE `name`=%s AND `qtype`=%s AND `qclass`=%s LIMIT 1', (name_id, int(question.qtype), int(question.qclass)))
            r = cursor.fetchone()
            if r is None:
                question_id = self.create_resource_header(question)
            else:
                question_id = int(r[0])
                self.log.debug('get_name(%s) Found: %d' % (question, question_id))

            self._cached_questions[question] = question_id
            return question_id

    def get_name_id(self, name, casemap=str.lower):
        key = casemap(str(name))
        if key in self._cached_names:
            return self._cached_names[key]

        with closing(self.db.cursor()) as cursor:
            node = None
            for label in reversed(name):
                with closing(self.db.cursor()) as cursor:
                    if node:
                        cursor.execute('SELECT id FROM name WHERE name=%s AND parent=%s LIMIT 1', (label, node)) # %d
                    else:
                        if not label:
                            label = '.'
                        cursor.execute('SELECT id FROM name WHERE name=%s AND parent IS NULL LIMIT 1', (label,)) # (label,) is a tuple (label) is a string...

                    r = cursor.fetchone()
                    if r is None:
                        node = self.create_name(label, node)
                    else:
                        node = int(r[0])
                        self.log.debug('get_name(%s) Found: %s (%d)' % (name, label, node))

            self._cached_names[key] = node
            return node

    def create_query(self, dns_packet):
        assert(isinstance(dns_packet, Query))
        pass

    def get_record_id(self, record):
        assert(isinstance(record, DnsRecord))

        resource_header_id = self.get_resource_header_id(record)
        rdata_blob_id = self.get_blob_id(record.rdata)

        with closing(self.db.cursor()) as cursor:
            cursor.execute('SELECT id FROM resource_record WHERE `header`=%s AND `rdata`=%s LIMIT 1',
                           (resource_header_id, rdata_blob_id))

            r = cursor.fetchone()
            if r is None:
                id = self.create_record(record)
            else:
                id = int(r[0])

            self.log.debug('get_record_id(%s): %d' % (record, id))
            return id

    def get_resource_header_id(self, resource):
        if(isinstance(resource, DnsQuestion)):
            (resource_type, resource_class) = (int(resource.qtype), int(resource.qclass))
        elif(isinstance(resource, DnsRecord)):
            (resource_type, resource_class) = (int(resource.rtype), int(resource.rclass))
        else:
            raise ValueError # TODO: exception handling

        name_id = self.get_name_id(resource.name)
        # TODO: question id cache
        with closing(self.db.cursor()) as cursor:
            cursor.execute('SELECT id FROM resource_header WHERE `name`=%s AND `type`=%s AND `class`=%s LIMIT 1',
                           (name_id, resource_type, resource_class))

            r = cursor.fetchone()
            if r is None:
                id = self.create_resource_header(resource)
            else:
                id = int(r[0])

            self.log.debug('get_resource_header_id(%s): %d' % (resource, id))
            return id


    def create_record(self, record):
        self.log.info('create_record(%s)' % record)
        assert(isinstance(record, DnsRecord))
        record_header_id = self.get_resource_header_id(record)
        rdata_blob = self.get_blob_id(record.rdata)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO `resource_record` (`header`, `rdata`) '
                           'VALUES (%s, %s)',
                           (record_header_id, rdata_blob))
            self.db.commit()
            return cursor.lastrowid

    # the queryset id and recordset id is designed to match:
    # select packet.id,unhex(sha1(group_concat(packet_question.`question` ORDER BY `question` ASC))) as `queryset`,unhex(sha1(group_concat(packet_record.`record` ORDER BY `record` ASC))) as `recordset` FROM packet JOIN  packet_question on packet.id=packet_question.packet JOIN packet_record ON packet_question.packet=packet_record.packet GROUP BY `packet`.`id`;
    # TODO: consider alternative implementation, perhaps one that uses the values instead of the database IDs for "offline" calculation

    def get_queryset_id(self, questions):
        self.log.debug('get_queryset_id(%s)' % questions)
        return self._get_digest(','.join(map(str,(sorted(map(self.get_resource_header_id, questions))))).encode('ascii'))

    def get_recordset_id(self, records):
        self.log.debug('get_recordset_id(%s)')
        return self._get_digest(','.join(map(str,(sorted(map(self.get_record_id, records))))).encode('ascii'))

    def create_packet_record(self, packet_id, record):
        assert(isinstance(packet_id, int))
        record_id = self.get_record_id(record)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO `packet_record` (`packet`, `record`, `ttl`) VALUES (%s, %s, %s)', (packet_id, record_id, record.ttl))

    def create_packet_question(self, packet_id, question):
        assert(isinstance(packet_id, int))
        question_id = self.get_resource_header_id(question)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO `packet_question` (`packet`, `question`) VALUES (%s, %s)', (packet_id, question_id,))


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    if signal is not None:
        loop.add_signal_handler(signal.SIGINT, loop.stop)

    # print(DomainName.parse(bytearray([0xc0,4,0,0,1,97,1,98,1,99,0,])))
    # assert(DomainName.parse(bytearray([0xc0,4,0,0,1,97,1,98,1,99,0,])))
    # assert(DomainName.from_string('') == DomainName.from_string('.') == DomainName.parse(bytearray([0])))
    # assert(DomainName.parse(DomainName.from_string('.').encode()) == DomainName.from_string(''))
    # assert(DomainName.from_string('a.b.c') == DomainName.from_string('a.b.c.') == DomainName.parse(bytearray([1,97,1,98,1,99,00])))
    # packet = DnsPacket(RD=False,questions=[DnsQuestion(DomainName.from_string('.'),DnsQType.SOA)]).encode()
    # DnsPacket.parse(packet)

    db = Database('dns', 'dns', '123qwe', 'localhost')

    resolver_startup_task = asyncio.Task(loop.create_datagram_endpoint(lambda: DnsResolver(db), local_addr=('0.0.0.0',0)))
    loop.run_until_complete(resolver_startup_task)
    (resolver_transport, resolver_protocol) = resolver_startup_task.result()

    start_server_task = asyncio.Task(loop.create_datagram_endpoint(lambda: DnsServer(resolver_protocol), local_addr=('127.0.0.1',53)))
    loop.run_until_complete(start_server_task)
    # (server_transport, server_protocol) = start_server_task.result()

    loop.run_forever()
