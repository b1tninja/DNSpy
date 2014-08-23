import random

import binascii
import random
import string
import struct
from enums import DnsQType, DnsRClass, DnsQClass, DnsRType, DnsQR, DnsOpCode, DnsResponseCode

__author__ = 'Justn Capella'


class DnsQuestion(object):
    def __init__(self, qname, qtype=DnsQType.ANY, qclass=DnsRClass.IN):
        self.name = qname
        self.qtype = qtype
        self.qclass = qclass

    @staticmethod
    def parse(data, offset):
        (name, offset) = DomainName.parse_from(data, offset)
        (qtype, qclass,) = struct.unpack_from('!HH', data, offset)
        offset += 4

        try:
            qtype = DnsQType(qtype)
            qclass = DnsQClass(qclass)
        except ValueError:
            pass

        return (DnsQuestion(name, qtype, qclass), offset,)

    def __repr__(self):
        return "<DnsQuestion:%s,%s,%s>" % (self.name, self.qtype, self.qclass)

    def encode(self):
        return self.name.encode() + struct.pack('!HH', self.qtype, self.qclass)


class DnsRecord(object):
    def __init__(self, name, rtype=DnsRType.A, rclass=DnsRClass.IN , ttl=0, rdlength=None, rdata=b""):
        if rdlength is None:
            rdlength = len(rdata)

        if isinstance(rdata, str):
            rdata = bytes(rdata, 'ascii')

        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata
        assert (len(rdata) == rdlength)

    @staticmethod
    def parse(data, offset):
        (name, offset) = DomainName.parse_from(data, offset)
        (rtype, rclass, ttl, rdlength) = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        try:
            rtype = DnsRType(rtype)
            rclass = DnsRClass(rclass)
        except ValueError:
            pass

        return (DnsRecord(name, rtype, rclass, ttl, rdlength, rdata), offset,)

    def __repr__(self):
        return "<Record:%s,%s,%s,%d,%d,%s>" % (
        self.name, self.rtype, self.rclass, self.ttl, self.rdlength, binascii.b2a_hex(self.rdata))

    def encode(self):
        return self.name.encode() + struct.pack('!HHIH', self.rtype, self.rclass, self.ttl, self.rdlength) + self.rdata


class DnsPacket(object):

    def __init__(self, ID=random.getrandbits(16), QR=DnsQR.query, OPCODE=DnsOpCode.query, AA = False, TC = False, RD = True, RA = True, Z = 0, RCODE=DnsResponseCode.no_error, QDCOUNT=None, ANCOUNT=None, NSCOUNT=None, ARCOUNT=None, questions=[], answers=[], nameservers=[], additional_records=[]):
        if QDCOUNT is None:
            QDCOUNT = len(questions)
        if ANCOUNT is None:
            ANCOUNT = len(answers)
        if NSCOUNT is None:
            NSCOUNT = len(nameservers)
        if ARCOUNT is None:
            ARCOUNT = len(additional_records)

        self.ID = ID
        self.QR = QR
        self.OPCODE = OPCODE
        self.AA = AA
        self.TC = TC
        self.RD = RD
        self.RA = RA
        self.Z = Z
        self.RCODE = RCODE
        self.QDCOUNT = QDCOUNT
        self.ANCOUNT = ANCOUNT
        self.NSCOUNT = NSCOUNT
        self.ARCOUNT = ARCOUNT
        self.questions = questions
        self.answers = answers
        self.nameservers = nameservers
        self.additional_records = additional_records

    def __repr__(self):
        return "<DnsPacket:%s, questions:%s, answers:%s, nameservers:%s, additional_records: %s>" % (hex(self.ID), self.questions, self.answers, self.nameservers, self.additional_records)

    @staticmethod
    def parse(data, offset=None):
        # self.datagram = data
        # Transaction ID 16
        (ID,) = struct.unpack_from('!H', data)
        # Query/Response 1
        QR = (data[2] & 0b1000000)
        # OpCode 4
        OPCODE = DnsOpCode((data[2] & 0b01111000) >> 3)
        # Authoratative Answer 1
        AA = data[2] & 0b100 != 0
        # Truncation 1
        TC = data[2] & 0b10 != 0
        # Recursion Desired 1
        RD = data[2] & 0b1 != 0
        # Recursion Available 1
        RA = data[3] & 0b10000000 != 0
        # Reserved for future, zero value
        Z = (data[3] & 0b01110000) >> 4
        #assert(Z == 0) # Newer RFCs obsolete this
        RCODE = DnsResponseCode(data[3] & 0b1111)
        (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT,) = struct.unpack_from('!HHHH', data, 4)

        if offset is None:
            offset = 12

        questions = []
        while (len(questions) < QDCOUNT):
            (question, offset) = DnsQuestion.parse(data, offset)
            questions.append(question)

        answers = []
        nameservers = []
        additional_records = []
        while offset < len(data):
            (rr, offset) = DnsRecord.parse(data, offset)
            if (len(answers) < ANCOUNT):
                answers.append(rr)
            elif (len(nameservers) < NSCOUNT):
                nameservers.append(rr)
            elif (len(additional_records) < ARCOUNT):
                additional_records.append(rr)
            else:
                raise Exception('Too many/too few records.')
        else:
            assert(len(questions) == QDCOUNT)
            assert(len(answers) == ANCOUNT)
            assert(len(nameservers) == NSCOUNT)
            assert(len(additional_records) == ARCOUNT)
            cls = (Query if QR else Response)
            return (cls(ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT, questions, answers, nameservers, additional_records),offset,)

    def encode(self):
        data = struct.pack('!HBBHHHH', self.ID,
                           ((0b10000000 if self.QR == DnsQR.response else 0) |
                            (self.OPCODE << 3) |
                            (0b100 if self.AA else 0) |
                            (0b010 if self.TC else 0) |
                            (0b001 if self.RD else 0)),
                           ((0b10000000 if self.RA else 0) |
                            self.Z << 4 |
                            self.RCODE),
                           self.QDCOUNT,
                           self.ANCOUNT,
                           self.NSCOUNT,
                           self.ARCOUNT,
                           )

        for record in self.questions:
            data += record.encode()

        for record in self.answers:
            data += record.encode()

        for record in self.nameservers:
            data += record.encode()

        for record in self.additional_records:
            data += record.encode()

        return data


class Query(DnsPacket):
    pass


class Response(DnsPacket):
    pass


class DomainName(list):
    def __str__(self):
        return '.'.join(self)

    @staticmethod
    def from_string(name):
        labels = name.rstrip('.').split('.')
        return DomainName(labels)

    @classmethod
    def parse(cls, data):
        return cls.parse_from(data)[0]

    @staticmethod
    def parse_from(data, offset=0):
        allowed_charset = set(string.ascii_letters + string.digits + '-')
        sequence = []
        while (data[offset]):
            if data[offset] < 64:
                label = data[offset + 1:offset + 1 + data[offset]].decode('ascii')
                assert(allowed_charset.issuperset(label))
                offset += data[offset]
                sequence.append(label)
            elif data[offset] >= 0b11000000:
                # pointer
                assert (data[data[offset]] < 64)  # Don't allow pointers to pointers
                # TODO: shouldn't allow pointing to 'same label offset' either
                (label, n,) = DomainName.parse_from(data, data[offset] & 0b111111)  # RECURSE
                sequence.extend(label)
            else:
                raise Exception('Unknown/Invalid DNS Label')

            offset += 1
            assert (sum(map(len, sequence)) < 256)

        else:
            offset += 1  # consume the null terminator
            return (DomainName(sequence if sequence != [] else ['']), offset,)

        # Should not reach the following...
        raise Exception('Malformed DNS label')

    def encode(self):
        data = bytearray()
        for label in self:
            data.append(len(label))
            if label:
                data.extend(bytes(label, 'ascii'))
            else:
                # Root Label
                break
        data.append(0)
        return bytes(data)