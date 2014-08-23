#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4

__author__ = 'Justin Capella'

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


console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s'))


class Nameserver(DomainName):
    pass
    #TODO: would be nice if nameservers could get a database context to look up their address records... maybe

class DnsResolver(asyncio.Protocol):
    loop = asyncio.get_event_loop()

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

        try:
            if not os.path.isfile(root_hints_path):
                urllib.request.urlretrieve('http://www.internic.net/domain/named.root', root_hints_path)
                self.log.info('Attempting to retrieve root hints from internic.')
            else:
                self.log.debug('Found root hints, %s' % os.path.basename(root_hints_path))

            for record in self.record_reader(root_hints_path):
                self.db.cache(record)
        except IOError:
            self.log.critical('Unable to parse root hints.')

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            (dns_packet,offset) = DnsPacket.parse(data)
        except AssertionError:
            self.log.warning("Unable to parse packet:", data)
        else:
            print(dns_packet)
            key = (dns_packet.ID, addr)
            if key in self.queue:
                self.queue[key].set_result(dns_packet)
            else:
                self.log.warn("Unexpected packet.")

    @asyncio.coroutine
    def answer(self, question):
        # TODO: should be given the full DnsPacket, so that the RD/RA flags can be set properly. Or have a lookup for both.

        question_id = self.db.get_question_id(question)
        answers = yield from self.db.lookup_records(question)
        nameservers = []
        additional_records = []
        query = None
        for ns_record in self.db.get_nameserver_records(question.name):
            nameservers.append(ns_record)
            ns_name = DomainName.parse(ns_record.rdata)
            self.log.debug("Nameserver: %s" % ns_name)
            self.log.debug("Additional Records:")
            for record in self.db.lookup_records(DnsQuestion(ns_name, DnsQType.A), query):
                self.log.debug(ipaddress.IPv4Address(record.rdata))
                additional_records.append(record)
            for record in self.db.lookup_records(DnsQuestion(ns_name, DnsQType.AAAA), query):
                self.log.debug(ipaddress.IPv6Address(record.rdata))
                additional_records.append(record)

        return (answers, nameservers, additional_records)

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
                assert(dns_packet.QDCOUNT == 1) # Apparently the internet is lame. TODO:  make proposal with TC bit
                (answer,nameservers,additional_records) = yield from self.resolver.answer(dns_packet.questions[0])
                if answer is None:
                        answer = []
#                response = Response(dns_packet.ID, DnsQR.response, DnsOpCode.query, False, False, True, False, 0, DnsResponseCode.no_error, answers=answer, nameservers=nameservers, additional_records=additional_records)
                response = Response(dns_packet.ID, DnsQR.response, DnsOpCode.query, False, False, True, False, 0, DnsResponseCode.no_error, answers=answer)
                self.transport.sendto(response.encode(), addr)
        except asyncio.CancelledError:
            print("Task cancelled.")
            pass
        except asyncio.InvalidStateError:
            print("Got result, but future was already cancelled.")

    def datagram_received(self, data, addr):
        try:
            (dns_packet,offset) = DnsPacket.parse(data)
        except AssertionError:
            print("Unable to parse packet:", data)
        else:
            print(dns_packet)
            task = asyncio.async(self.respond_to_packet(dns_packet, addr))
            loop.call_later(3, task.cancel)


class Database(object):
    def __init__(self, database='dns', user=None, password=None, host='localhost', port=3306):
        self.db = mysql.connector.connect(database=database, user=user, password=password, host=host, port=port)
        self.log = logging.Logger('db')
        self.log.addHandler(console)
        self._cached_names = {}
        self._cached_questions = {}

    def lookup_records(self, question, query = None):
        assert(isinstance(question, DnsQuestion))
        self.get_question_id(question)

        try:
            rtype = int(DnsRType(question.qtype))
            rclass = int(DnsRType(question.qclass))

        except ValueError:
            return [] # TODO Handle QTYPES such as ANY

        name_id = self.get_name_id(question.name)

        with closing(self.db.cursor()) as cursor:
            if query is None:
                cursor.execute('SELECT type,class,ttl,rdata FROM records WHERE `query` IS NULL AND `name`=%s AND `type`=%s AND `class`=%s AND (`ttl`+`cached`) >= UNIX_TIMESTAMP() GROUP BY `name`, `type`, `class`, `rdata` ORDER BY `cached` DESC', (name_id, rtype, rclass))
            else:
                cursor.execute('SELECT type,class,ttl,rdata FROM records WHERE `query`=%s AND `name`=%s AND `type`=%s AND `class`=%s AND (`ttl`+`cached`) >= UNIX_TIMESTAMP() GROUP BY `name`, `type`, `class`, `rdata` ORDER BY `cached` DESC', (query, name_id, rtype, rclass))

            for tokens in cursor.fetchall():
                (rtype, rclass, ttl, rdata) = tokens
                # TODO: return the name that is cached in the database (case sensitivity thing)
                yield DnsRecord(question.name,rtype, rclass, ttl, rdata=rdata)



    def get_nameserver_records(self, name, query=None):
        assert(isinstance(name, DomainName))
        yield from self.lookup_records(DnsQuestion(name, DnsQType.NS), query=query)

    def get_address_records(self, name, query=None):
        assert(isinstance(name, DomainName))
        for record in self.lookup_records(DnsQuestion(name, DnsQType.A), query):
            yield record
        for record in self.lookup_records(DnsQuestion(name, DnsQType.AAAA), query):
            yield record

    # def lookup_query(self, question):
    #     assert(isinstance(question, DnsQuestion))
    #     #
    #     try:
    #         rtype = DnsRType(question.qtype)
    #         if DnsRType.NS == rtype:
    #             return [DnsRecord(question.name, rtype, rdata=DomainName(['example','com']).encode())]
    #         if DnsRType.A == rtype:
    #             return [DnsRecord(question.name, rtype, rdata=bytearray([127,0,0,1]) )]
    #
    #     except ValueError:
    #         pass
    #
    def create_name(self, label, parent):
        if not label and parent is None:
            label = '.'
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO names (`name`, `parent`) VALUES (%s, %s)', (label, parent))
            self.db.commit()
            self.log.debug('create_name(%s,%s) created with id: %d' % (label, parent, cursor.lastrowid))
            return cursor.lastrowid

    def create_question(self, question):
        name_id = self.get_name_id(question.name)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO questions (`name`, `type`, `class`) VALUES (%s, %s, %s)', (name_id, int(question.qtype), int(question.qclass)))
            self.db.commit()
            self.log.debug('create_question(%s,%s,%s) created with id: %d' % (question.name, question.qtype, question.qclass, cursor.lastrowid))
            return cursor.lastrowid

    def get_question_id(self, question):
        self.log.debug('get_question(%s)' % question)

        key = (str(question.name).lower(), question.qclass, question.qtype)
        if key in self._cached_questions:
            return self._cached_questions[key]

        name_id = self.get_name_id(question.name)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('SELECT * FROM questions WHERE `name`=%s AND `type`=%s AND `class`=%s GROUP BY `name`, `type`, `class` LIMIT 1', (name_id, int(question.qtype), int(question.qclass)))
            r = cursor.fetchone()
            if r is None:
                question_id = self.create_question(question)
            else:
                question_id = int(r[0])
                self.log.debug('get_name(%s) Found: %d' % (question, question_id))

            self._cached_questions[key] = question_id
            return question_id

    def get_name_id(self, name):
        key = str(name).lower()
        if key in self._cached_names:
            return self._cached_names[key]

        with closing(self.db.cursor()) as cursor:
            node = None
            for label in reversed(name):
                with closing(self.db.cursor()) as cursor:
                    if node:
                        cursor.execute('SELECT id FROM names WHERE name=%s AND parent=%s LIMIT 1', (label, node)) # %d
                    else:
                        if not label:
                            label = '.'
                        cursor.execute('SELECT id FROM names WHERE name=%s AND parent IS NULL LIMIT 1', (label,)) # (label,) is a tuple (label) is a string...

                    r = cursor.fetchone()
                    if r is None:
                        node = self.create_name(label, node)
                    else:
                        node = int(r[0])
                        self.log.debug('get_name(%s) Found: %s (%d)' % (name, label, node))

            self._cached_names[key] = node
            return node

    def get_record(self, record, query=None):
        self.log.debug('get_record(%s,%s)' % (record, query))
        name_id = self.get_name_id(record.name)
        with closing(self.db.cursor()) as cursor:
            if query is None:
                cursor.execute('SELECT * FROM records WHERE `query` IS NULL AND `name`=%s AND `type`=%s AND `class`=%s AND `rdata`=%s AND (`ttl`+`cached`) >= UNIX_TIMESTAMP() ORDER BY `cached` DESC LIMIT 1', (name_id, int(record.rtype), int(record.rclass), record.rdata))
            else:
                cursor.execute('SELECT * FROM records WHERE `query`=%d AND `name`=%d AND `type`=%d AND `class`=%d AND `rdata`=%s AND (`ttl`+`cached`) >= UNIX_TIMESTAMP() ORDER BY `cached` DESC LIMIT 1', (query, name_id, int(record.rtype), int(record.rclass), record.rdata))
            return cursor.fetchone()


    def cache(self, obj, query=None):
        self.log.info('cache: %s' % obj)
        if isinstance(obj, DnsRecord):
            name_id = self.get_name_id(obj.name)
            record = self.get_record(obj)
            if record:
                self.log.debug("cache_record(%s,%s,%s) Record already cached! %s" % (name_id, query, obj, record))
                return
            else:
                self.log.info('cache_record(%s,%s,%s)' % (name_id, query, obj))
                with closing(self.db.cursor()) as cursor:
                    cursor.execute('INSERT INTO `records` (`query`, `name`, `type`, `class`, `ttl`, `rdata`) VALUES (%s, %s, %s, %s, %s, %s)', (query, name_id, int(obj.rtype), int(obj.rclass), obj.ttl, bytes(obj.rdata)))
                    self.db.commit()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    if signal is not None:
        loop.add_signal_handler(signal.SIGINT, loop.stop)

    assert(DomainName.from_string('a.b.c') == DomainName.from_string('a.b.c.') == DomainName.parse(bytearray([1,97,1,98,1,99,00])))
    db = Database('dns', 'dns', '123qwe', 'ninjaserv')

    resolver_startup_task = asyncio.Task(loop.create_datagram_endpoint(lambda: DnsResolver(db), local_addr=('0.0.0.0',0)))
    loop.run_until_complete(resolver_startup_task)
    (resolver_transport, resolver_protocol) = resolver_startup_task.result()

    start_server_task = asyncio.Task(loop.create_datagram_endpoint(lambda: DnsServer(resolver_protocol), local_addr=('127.0.0.1',53)))
    loop.run_until_complete(start_server_task)
    # (server_transport, server_protocol) = start_server_task.result()

    loop.run_forever()