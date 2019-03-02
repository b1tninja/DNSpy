exit()  # obsolete code / it burns my eyes

import hashlib
import ipaddress
import logging
# import mysql.connector
from contextlib import closing

from .database import Database
from .dns import console
from .enums import DnsQR, DnsOpCode, DnsResponseCode
from .names import DomainName
from .packet import DnsQuestion, DnsRecord, Query, Response


class SQLDatabase(Database):
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
        assert len(dns_packet.questions) == dns_packet.QDCOUNT
        assert len(dns_packet.answers) == dns_packet.ANCOUNT
        assert len(dns_packet.nameservers) == dns_packet.NSCOUNT
        assert len(dns_packet.additional_records) == dns_packet.ARCOUNT

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
                           '`suffix`,'
                           '`effective_ttl`,'
                           '`questionset`,'
                           '`recordset`'
                           ') VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
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
                            dns_packet.suffix if dns_packet.suffix else None,  # don't include b''
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

            # TODO: reconsider using the dns_packet as a mutable object...
            dns_packet.pk = packet_id
            # return cursor.lastrowid

    def get_name(self, name_id):
        with closing(self.db.cursor()) as cursor:
            sequence = []
            for foo in range(256):  # dns labels are limited to 256 depths anyway
                cursor.execute('SELECT parent,name FROM name WHERE `id`=%s LIMIT 1', (name_id,))
                self.queries += 1
                (name_id, label) = cursor.fetchone()
                sequence.append(label)
                if name_id is None:
                    return DomainName(sequence)

    def create_name(self, label, parent, casemap=str.upper):
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
        if (isinstance(resource, DnsQuestion)):
            (resource_type, resource_class) = (int(resource.qtype), int(resource.qclass))
        elif (isinstance(resource, DnsRecord)):
            (resource_type, resource_class) = (int(resource.rtype), int(resource.rclass))
        else:
            raise ValueError  # TODO: exception handling

        name_id = self.get_name_id(resource.name)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO resource_header (`name`, `type`, `class`) VALUES (%s, %s, %s)',
                           (name_id, resource_type, resource_class))
            self.queries += 1
            self.db.commit()
            self.log.debug('create_resource_header(%s,%s,%s) created with id: %d' %
                           (resource.name, resource_type, resource_class, cursor.lastrowid))
            return cursor.lastrowid

    def get_name_id(self, name, casemap=str.upper):
        key = casemap(str(name))
        if key in self._cached_names:
            return self._cached_names[key]

        with closing(self.db.cursor()) as cursor:
            node = None
            for label in reversed(name):
                with closing(self.db.cursor()) as cursor:
                    if node:
                        cursor.execute('SELECT id FROM name WHERE name=%s AND parent=%s LIMIT 1', (label, node))  # %d
                    else:
                        if not label:
                            label = '.'
                        cursor.execute('SELECT id FROM name WHERE name=%s AND parent IS NULL LIMIT 1',
                                       (label,))  # (label,) is a tuple (label) is a string...

                    self.queries += 1
                    r = cursor.fetchone()
                    if r is None:
                        node = self.create_name(label, node)
                    else:
                        node = int(r[0])
                        self.log.debug('get_name(%s) Found: %s (%d)' % (name, label, node))

            self._cached_names[key] = node
            return node

    def create_query(self, packet_id, ns_id=None, addr_id=None, parent_id=None, response_id=None):
        with closing(self.db.cursor()) as cursor:
            cursor.execute(
                'INSERT INTO query (`packet`,`nameserver`,`address`,`parent`,`response`) VALUES (%s,%s,%s,%s,%s)',
                (packet_id, ns_id, addr_id, parent_id, response_id))
            self.queries += 1
            self.db.commit()
            self.log.debug('create_query(%s,%s,%s,%s,%s) created with id: %d' %
                           (packet_id, parent_id, ns_id, addr_id, response_id, cursor.lastrowid))
            return cursor.lastrowid

    def update_query_response(self, query_id, response_id):
        with closing(self.db.cursor()) as cursor:
            cursor.execute('UPDATE query SET `response` = %s WHERE `packet` = %s LIMIT 1',
                           (response_id, query_id))
            self.queries += 1
            self.db.commit()
            self.log.debug('update_query_response(%s,%s)' %
                           (query_id, response_id))

            if cursor.rowcount != 1:
                raise ValueError

    def get_record_id(self, record):
        assert isinstance(record, DnsRecord)

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
        if (isinstance(resource, DnsQuestion)):
            (resource_type, resource_class) = (int(resource.qtype), int(resource.qclass))
        elif (isinstance(resource, DnsRecord)):
            (resource_type, resource_class) = (int(resource.rtype), int(resource.rclass))
        else:
            raise ValueError  # TODO: exception handling

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
        assert isinstance(record, DnsRecord)
        record_header_id = self.get_resource_header_id(record)
        rdata_blob = self.get_blob_id(record.rdata)
        with closing(self.db.cursor()) as cursor:
            cursor.execute('INSERT INTO `resource_record` (`header`, `rdata`) '
                           'VALUES (%s, %s)',
                           (record_header_id, rdata_blob))
            self.queries += 1
            self.db.commit()
            return cursor.lastrowid

    def lookup_response(self, *args, **kwargs):
        response_id = self.lookup_response_id(*args, **kwargs)
        if response_id:
            return self.get_packet(response_id)

    def lookup_response_id(self, questions, ns_id=None, addr_id=None):
        if isinstance(questions, DnsQuestion):
            questions = [questions]
        questionset = self.get_questionset_id(questions)
        with closing(self.db.cursor()) as cursor:
            if ns_id is not None and addr_id is not None:
                cursor.execute(
                    'SELECT response FROM query JOIN packet AS packet_query JOIN packet AS packet_response ON query.packet=packet_query.id AND query.response=packet_response.id WHERE response IS NOT NULL AND nameserver=%s AND address=%s AND packet_query.questionset=%s AND TIMESTAMPADD(second,packet_response.effective_ttl,packet_response.cached) >= NOW() ORDER BY packet_response.cached DESC LIMIT 1',
                    (ns_id, addr_id, questionset))
            else:
                # TODO: see if there is a better way to handle the WHERE col=NULL problem
                cursor.execute(
                    'SELECT response FROM query JOIN packet AS packet_query JOIN packet AS packet_response ON query.packet=packet_query.id AND query.response=packet_response.id WHERE response IS NOT NULL AND nameserver IS NULL AND address IS NULL AND packet_query.questionset=%s AND TIMESTAMPADD(second,packet_response.effective_ttl,packet_response.cached) >= NOW() ORDER BY packet_response.cached DESC LIMIT 1',
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
        # TODO: consider using yield?
        questions = []
        with closing(self.db.cursor()) as cursor:
            self.log.debug('get_packet_questions(%d)' % (packet_id,))
            cursor.execute(
                'SELECT resource_header.id, resource_header.name,resource_header.type,resource_header.class, compressed_name FROM packet_question JOIN resource_header ON packet_question.resource_header = resource_header.id WHERE packet_question.packet=%s ORDER BY packet_question.id ASC',
                (packet_id,))
            self.queries += 1
            rows = cursor.fetchall()
            for row in rows:
                (pk, name_id, qtype, qclass, compressed_name) = row
                name = self.get_name(name_id)
                if compressed_name:
                    self.name.compressed_name = compressed_name
                question = DnsQuestion(name, qtype, qclass)
                question.pk = pk
                questions.append(question)

        return questions

    def get_packet_records(self, packet_id):
        # TODO: consider using yield?
        records = []
        with closing(self.db.cursor()) as cursor:
            self.log.debug('get_packet_records(%d)' % (packet_id,))
            cursor.execute(
                'SELECT resource_record.id, resource_header.name,resource_header.type,resource_header.class,packet_record.ttl,dns.blob.blob, compressed_name FROM packet_record JOIN resource_record JOIN resource_header JOIN dns.blob ON packet_record.record = resource_record.id AND resource_header.id = resource_record.header AND dns.blob.sha1=resource_record.rdata WHERE packet_record.packet = %s ORDER BY packet_record.id ASC',
                (packet_id,))
            self.queries += 1
            rows = cursor.fetchall()
            for row in rows:
                (pk, name_id, rtype, rclass, ttl, rdata, compressed_name) = row
                name = self.get_name(name_id)
                if compressed_name:
                    name.compressed_name = compressed_name
                record = DnsRecord(name, rtype, rclass, ttl, rdlength, rdata=rdata)
                records.append(record)

        return records

    def get_packet(self, packet_id):
        with closing(self.db.cursor()) as cursor:
            self.log.debug('get_packet(%s)' % (packet_id,))
            # TODO: `source`, `source_port`, `destination`, `destination_port`, `effective_ttl`, `questionset`, `recordset`
            cursor.execute(
                'SELECT `id`,`txnid`, `qr`, `opcode`, `aa`, `tc`, `rd`, `z`, `rcode`, `qdcount`, `ancount`, `nscount`, `arcount` FROM packet WHERE packet.id=%s LIMIT 1',
                (packet_id,))
            self.queries += 1
            row = cursor.fetchone()

        if row is not None:
            (ID, TXNID, QR, OPCODE, AA, TC, RD, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = row
            QR = DnsQR(QR)
            OPCODE = DnsOpCode(OPCODE)
            RCODE = DnsResponseCode(RCODE)
            questions = self.get_packet_questions(packet_id)
            assert len(questions) == QDCOUNT

            records = self.get_packet_records(packet_id)

            answers = records[:ANCOUNT]
            assert len(answers) == ANCOUNT
            nameservers = records[ANCOUNT:ANCOUNT + NSCOUNT]
            assert len(nameservers) == NSCOUNT
            additional_records = records[ANCOUNT + NSCOUNT:]
            assert len(additional_records) == ARCOUNT

            cls = Query if QR == DnsQR.query else Response

            dns_packet = cls(ID=TXNID, QR=QR, OPCODE=OPCODE, AA=AA, TC=TC, RD=RD, Z=Z, RCODE=RCODE,
                             QDCOUNT=QDCOUNT, ANCOUNT=ANCOUNT, NSCOUNT=NSCOUNT, ARCOUNT=ARCOUNT,
                             questions=questions,
                             answers=answers,
                             nameservers=nameservers,
                             additional_records=additional_records)
            dns_packet.pk = ID
            return dns_packet

    # the questionset id and recordset id is designed to match:
    # select packet.id,unhex(sha1(group_concat(packet_question.`question` ORDER BY `question` ASC))) as `questionset`,unhex(sha1(group_concat(packet_record.`record` ORDER BY `record` ASC))) as `recordset` FROM packet JOIN  packet_question on packet.id=packet_question.packet JOIN packet_record ON packet_question.packet=packet_record.packet GROUP BY `packet`.`id`;
    # TODO: consider alternative implementation, perhaps one that uses the values instead of the database IDs for "offline" calculation

    def get_questionset_id(self, questions):
        self.log.debug('get_questionset_id(%s)' % questions)
        return self._get_digest(
            ','.join(map(str, (sorted(map(self.get_resource_header_id, questions))))).encode('ascii'))

    def get_recordset_id(self, records):
        self.log.debug('get_recordset_id(%s)')
        return self._get_digest(','.join(map(str, (sorted(map(self.get_record_id, records))))).encode('ascii'))

    def create_packet_record(self, packet_id, record):
        assert isinstance(packet_id, int)
        record_id = self.get_record_id(record)
        record.pk = record_id

        if hasattr(record.name, 'compressed_name') and record.name.encode() != record.name.compressed_name:
            compressed_name = record.name.compressed_name
        else:
            compressed_name = None

        if hasattr(record, 'compressed_rdata'):
            compressed_rdata = self.get_blob_id(record.compressed_rdata)
        else:
            compressed_rdata = None

        with closing(self.db.cursor()) as cursor:
            cursor.execute(
                'INSERT INTO `packet_record` (`packet`, `record`, `ttl`, `compressed_name`, `compressed_rdata`) VALUES (%s, %s, %s, %s, %s)',
                (packet_id, record_id, record.ttl, compressed_name, compressed_rdata))
            self.queries += 1

    def create_packet_question(self, packet_id, question):
        assert isinstance(packet_id, int)
        resource_header_id = self.get_resource_header_id(question)

        if hasattr(question.name, 'compressed_name') and question.name.encode() != question.name.compressed_name:
            compressed_name = question.name.compressed_name
        else:
            compressed_name = None

        question.pk = resource_header_id
        with closing(self.db.cursor()) as cursor:
            cursor.execute(
                'INSERT INTO `packet_question` (`packet`, `resource_header`, `compressed_name`) VALUES (%s, %s, %s)',
                (packet_id, resource_header_id, compressed_name,))
            self.queries += 1