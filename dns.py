from __future__ import unicode_literals

#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4

__author__ = 'b1tninja'

# For parsing named.root
import re
import os
import urllib.request

from contextlib import closing
import mysql.connector

import hashlib
import ipaddress

import asyncio
try:
    import signal
except ImportError:
    signal = None

import logging

from dns_packet import DnsPacket, DnsQuestion, DnsRecord, DomainName, Query, Response
# Enums
from enums import DnsQR, DnsQType, DnsQClass, DnsRType, DnsRClass, DnsOpCode, DnsResponseCode
# Constants
from dns_packet import root_label

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s'))


class Nameserver(DomainName):
    pass
    #TODO: would be nice if nameservers could get a database context to look up their address records... maybe

class DnsResolver(asyncio.Protocol):
    loop = asyncio.get_event_loop()

    def record_reader(self, zone_file):
        with open(zone_file,'r') as root_hints_file:
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
                    # Don't know what this is
                    continue
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


    def __init__(self, db, root_hints_path=None):
        self.queue = {}
        self.db = db
        self.log = logging.Logger('resolver')
        self.log.addHandler(console)
        self.root_hints = self.bootstrap(root_hints_path)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            (dns_packet,offset) = DnsPacket.parse(data)
        except AssertionError as e:
            self.log.warning('Unable to parse packet:', data)
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

    def bootstrap(self,root_hints_path='named.root'):
        questions = [DnsQuestion(root_label, qtype=DnsQType.NS)]
        response = self.db.lookup_response(questions)

        if response is None:
            try:
                if not os.path.isfile(root_hints_path):
                    urllib.request.urlretrieve('http://www.internic.net/domain/named.root', root_hints_path)
                    self.log.info('Attempting to retrieve root hints from internic.')
                else:
                    self.log.debug('Found root hints, %s' % os.path.basename(root_hints_path))

            except IOError:
                self.log.critical('Unable to parse root hints.')

            else:

                nameservers = []
                additional_records = []
                for record in self.record_reader(root_hints_path):
                    if record.rtype == DnsRType.NS:
                        nameservers.append(record)
                    if record.rtype == DnsRType.A or record.rtype == DnsRType.AAAA:
                        additional_records.append(record)

                query = Query(QR=DnsQR.query, RD=False, questions = questions)
                response = Response(QR=DnsQR.response, ID=query.ID, AA=True, RD=False, RA=False,
                                    questions=questions,
                                    nameservers=nameservers,
                                    additional_records=additional_records)

                query_id = self.db.store_packet(query)
                response_id = self.db.store_packet(response)

                self.db.create_query(query_id, response_id=response_id)

        return response


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

        response = yield from self.query(DnsQuestion(root_label, DnsQType.SOA))

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

    # TODO: query()
    # @asyncio.coroutine
    # def query(self, questions):
    #     if isinstance(questions, DnsQuestion):
    #         questions = [questions]
    #     assert(isinstance(questions, list))
    #     for question in questions:
    #         assert(isinstance(question, DnsQuestion))
    #
    #     response = self.db.lookup_response(questions)
    #     if response:
    #         # Cached
    #         pass
    #         # TODO: return response?
    #     else:
    #         # Not cached
    #         query = Query(QR=DnsQR.query, RD=False, questions=questions)
    #         query_id = self.db.store_packet(query)
    #         self.db.create_query(query_id)
    # TODO: subquery()
    # def subquery(self, ns_id, addr_id, host, question):
    #     future = asyncio.Future()
    #     question_id = self.db.get_resource_header_id(question)
    #     query_id = self.db.get_query_id(question_id, ns_id, addr_id)
    #     dns_packet = Query(questions=[question], RD=False)
    #     addr = (str(host),53)
    #     self.db.store_packet(dns_packet, destination=addr)
    #     self.queue[(str(host), dns_packet.ID)] = (packet_id, future)
    #     self.transport.sendto(dns_packet.encode(), addr)

    # TODO: discover_soa()
    # @asyncio.coroutine
    # def discover_soa(self, domain_name):
    #     return asyncio.Future()
    #     question = DnsQuestion(DomainName.from_string('.'), DnsQType.SOA)
    #     question_id = self.db.get_question_id(question)
    #     # Walk the database starting form the root
    #     root_hints = self.get_root_servers()
    #     for ns_name in root_hints:
    #         (ns_id, address_records) = root_hints[ns_name]
    #         for (addr_id, addr) in address_records:
    #             self._query(ns_id, addr_id, addr, question)

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
        self.queries = 0

    def get_blob_id(self, blob):
        with closing(self.db.cursor()) as cursor:
            sha1 = self._get_digest(blob)
            self.log.debug('get_blob_id(%s): %s' % (blob, sha1))
            # TODO: consider more friendly name than sql reserved word blob
            cursor.execute('INSERT IGNORE INTO dns.blob (`sha1`, `blob`) VALUES (%s, %s)', (sha1, blob))
            self.queries += 1
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

        effective_ttl = min([record.ttl for record in record_set]) if record_set else 0

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
                           '`effective_ttl`,'
                           '`questionset`,'
                           '`recordset`'
                           ') VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
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
                            effective_ttl,
                            self.get_questionset_id(dns_packet.questions),
                            # TODO: reread RFC2181, unsure if ameservers+additional_records are part of the "record set"
                            self.get_recordset_id(record_set)
                           )
                          )
            self.queries += 1
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


    def get_name(self, name_id):
        with closing(self.db.cursor()) as cursor:
            sequence = []
            for foo in range(256): # dns labels are limited to 256 depths anyway
                cursor.execute('SELECT parent,name FROM name WHERE `id`=%s LIMIT 1', (name_id,))
                self.queries += 1
                (name_id,label) = cursor.fetchone()
                sequence.append(label)
                if name_id is None:
                    return DomainName(sequence)

    def create_name(self, label, parent, casemap=str.lower):
        if not label and parent is None:
            label = '.'
        else:
            label = casemap(label)

        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO name (`name`, `parent`) VALUES (%s, %s)', (casemap(label), parent))
            self.queries += 1
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
            self.queries += 1
            self.db.commit()
            self.log.debug('create_resource_header(%s,%s,%s) created with id: %d' %
                           (resource.name, resource_type, resource_class, cursor.lastrowid))
            return cursor.lastrowid

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

                    self.queries += 1
                    r = cursor.fetchone()
                    if r is None:
                        node = self.create_name(label, node)
                    else:
                        node = int(r[0])
                        self.log.debug('get_name(%s) Found: %s (%d)' % (name, label, node))

            self._cached_names[key] = node
            return node


    def create_query(self, packet_id, ns_id=None, addr_id=None, response_id=None):
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO query (`packet`, `nameserver`, `address`, `response`) VALUES (%s, %s, %s, %s)',
                           (packet_id, ns_id, addr_id, response_id))
            self.queries += 1
            self.db.commit()
            self.log.debug('create_query(%s,%s,%s,%s) created with id: %d' %
                           (packet_id, ns_id, addr_id, response_id, cursor.lastrowid))
            return cursor.lastrowid


    def update_query_response(self, query_id, response_id):
        with closing(self.db.cursor()) as cursor:
            cursor.execute('UPDATE query SET `response` = %s WHERE `packet` = %s LIMIT 1',
                           (query_id, response_id))
            self.queries += 1
            self.db.commit()
            self.log.debug('update_query_response(%s,%s)' %
                           (query_id, response_id))

            if cursor.rowcount != 1:
                raise ValueError


    def get_record_id(self, record):
        assert(isinstance(record, DnsRecord))

        resource_header_id = self.get_resource_header_id(record)
        rdata_blob_id = self.get_blob_id(record.rdata)

        with closing(self.db.cursor()) as cursor:
            cursor.execute('SELECT id FROM resource_record WHERE `header`=%s AND `rdata`=%s LIMIT 1',
                           (resource_header_id, rdata_blob_id))
            self.queries += 1
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
            self.queries += 1
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
            self.queries += 1
            self.db.commit()
            return cursor.lastrowid


    def lookup_response(self, questions, **kwargs):
        response_id = self.lookup_response_id(questions, **kwargs)
        if response_id:
            return self.get_packet(response_id)


    def lookup_response_id(self, questions, ns_id=None, addr_id=None):
        questionset = self.get_questionset_id(questions)
        with closing(self.db.cursor()) as cursor:
            if ns_id is not None and addr_id is not None:
                cursor.execute('SELECT response FROM query JOIN packet AS packet_query JOIN packet AS packet_response ON query.packet=packet_query.id AND query.response=packet_response.id WHERE response IS NOT NULL AND nameserver=%s AND address=%s AND packet_query.questionset=%s AND TIMESTAMPADD(second,packet_response.effective_ttl,packet_response.cached) >= NOW() ORDER BY packet_response.cached DESC LIMIT 1',
                               (ns_id, addr_id, questionset))
            else:
                # TODO: see if there is a better way to handle the WHERE col=NULL problem
                cursor.execute('SELECT response FROM query JOIN packet AS packet_query JOIN packet AS packet_response ON query.packet=packet_query.id AND query.response=packet_response.id WHERE response IS NOT NULL AND nameserver IS NULL AND address IS NULL AND packet_query.questionset=%s AND TIMESTAMPADD(second,packet_response.effective_ttl,packet_response.cached) >= NOW() ORDER BY packet_response.cached DESC LIMIT 1',
                               (questionset,))
            self.queries += 1
            r = cursor.fetchone()
            if r is None:
                self.log.debug('lookup_response(%s,%s,%s): Not Found' % (questions, ns_id, addr_id))
                # return None
            else:
                id = int(r[0])
                self.log.debug('lookup_response(%s,%s,%s): %d' % (questions, ns_id, addr_id, id))
                return id


    def get_packet_questions(self, packet_id):
        questions = []
        with closing(self.db.cursor()) as cursor:
            self.log.debug('get_packet_questions(%d)' % (packet_id,))
            cursor.execute('SELECT resource_header.name,resource_header.type,resource_header.class FROM packet_question JOIN resource_header ON packet_question.question = resource_header.id  WHERE packet_question.question=%s ORDER BY packet_question.id ASC', (packet_id,))
            self.queries += 1
            rows = cursor.fetchall()
            for row in rows:
                (name_id, qtype, qclass) = row
                name = self.get_name(name_id)
                questions.append(DnsQuestion(name, qtype, qclass))

        return questions


    def get_packet_records(self, packet_id):
        records = []
        with closing(self.db.cursor()) as cursor:
            self.log.debug('get_packet_records(%d)' % (packet_id,))
            cursor.execute('SELECT resource_header.name,resource_header.type,resource_header.class,packet_record.ttl,dns.blob.blob FROM packet_record JOIN resource_record JOIN resource_header JOIN dns.blob ON packet_record.record = resource_record.id AND resource_header.id = resource_record.header AND dns.blob.sha1=resource_record.rdata WHERE packet_record.packet = %s ORDER BY packet_record.id ASC', (packet_id,))
            self.queries += 1
            rows = cursor.fetchall()
            for row in rows:
                (name_id, rtype, rclass, ttl, rdata) = row
                name = self.get_name(name_id)
                records.append(DnsRecord(name, rtype, rclass, ttl, rdata=rdata))

        return records


    def get_packet(self, packet_id):
        with closing(self.db.cursor()) as cursor:
            self.log.debug('get_packet(%s)' % (packet_id,))
            # TODO: `source`, `source_port`, `destination`, `destination_port`, `effective_ttl`, `questionset`, `recordset`
            cursor.execute('SELECT `txnid`, `qr`, `opcode`, `aa`, `tc`, `rd`, `z`, `rcode`, `qdcount`, `ancount`, `nscount`, `arcount` FROM packet WHERE packet.id=%s LIMIT 1', (packet_id,))
            self.queries += 1
            r = cursor.fetchone()

        if r is not None:
            questions = self.get_packet_questions(packet_id)
            records = self.get_packet_records(packet_id)

            cls = Query if r[1] == DnsQR.query else Response
            # TODO: dictionary, or some type of mapping?
            dns_packet = cls(ID=r[0],
                                   QR=r[1],
                                   OPCODE=r[2],
                                   AA=r[3],
                                   TC=r[4],
                                   RD=r[5],
                                   Z=r[6],
                                   RCODE=r[7],
                                   QDCOUNT=r[8],
                                   ANCOUNT=r[9],
                                   NSCOUNT=r[10],
                                   ARCOUNT=r[11],
                                   questions=questions, # [:r[8]] implied
                                   answers=records[:r[9]],
                                   nameservers=records[r[9]:r[9]+r[10]],
                                   additional_records=records[r[9]+r[10]:]  # :r[11] implied, could also use -r[11]
                                   )
            return dns_packet


    # the questionset id and recordset id is designed to match:
    # select packet.id,unhex(sha1(group_concat(packet_question.`question` ORDER BY `question` ASC))) as `questionset`,unhex(sha1(group_concat(packet_record.`record` ORDER BY `record` ASC))) as `recordset` FROM packet JOIN  packet_question on packet.id=packet_question.packet JOIN packet_record ON packet_question.packet=packet_record.packet GROUP BY `packet`.`id`;
    # TODO: consider alternative implementation, perhaps one that uses the values instead of the database IDs for "offline" calculation

    def get_questionset_id(self, questions):
        self.log.debug('get_questionset_id(%s)' % questions)
        return self._get_digest(','.join(map(str,(sorted(map(self.get_resource_header_id, questions))))).encode('ascii'))

    def get_recordset_id(self, records):
        self.log.debug('get_recordset_id(%s)')
        return self._get_digest(','.join(map(str,(sorted(map(self.get_record_id, records))))).encode('ascii'))

    def create_packet_record(self, packet_id, record):
        assert(isinstance(packet_id, int))
        record_id = self.get_record_id(record)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO `packet_record` (`packet`, `record`, `ttl`) VALUES (%s, %s, %s)', (packet_id, record_id, record.ttl))
            self.queries += 1


    def create_packet_question(self, packet_id, question):
        assert(isinstance(packet_id, int))
        question_id = self.get_resource_header_id(question)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO `packet_question` (`packet`, `question`) VALUES (%s, %s)', (packet_id, question_id,))
            self.queries += 1


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    if signal is not None:
        loop.add_signal_handler(signal.SIGINT, loop.stop)

    db = Database('dns', 'dns', '123qwe', 'localhost')

    resolver_startup_task = asyncio.Task(loop.create_datagram_endpoint(lambda: DnsResolver(db), local_addr=('0.0.0.0',0)))
    loop.run_until_complete(resolver_startup_task)
    (resolver_transport, resolver_protocol) = resolver_startup_task.result()

    start_server_task = asyncio.Task(loop.create_datagram_endpoint(lambda: DnsServer(resolver_protocol), local_addr=('127.0.0.1',53)))
    loop.run_until_complete(start_server_task)
    # (server_transport, server_protocol) = start_server_task.result()

    loop.run_forever()
