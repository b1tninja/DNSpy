import logging
import random

from .rdata import *
from .enums import DnsQType, DnsRClass, DnsQClass, DnsRType, DnsQR, DnsOpCode, DnsResponseCode


class DnsQuestion(object):
    _STRUCT_FMT = '!HH'
    _STRUCT_SIZE = struct.calcsize(_STRUCT_FMT)

    def __hash__(self):
        return hash((self.name, self.qtype, self.qclass))

    def __init__(self, qname, qtype=DnsQType.ANY, qclass=DnsRClass.IN):
        self.name = qname
        self.qtype = qtype
        self.qclass = qclass

    @staticmethod
    def parse(data, offset):
        (label, offset) = DomainName.parse_from(data, offset)
        (qtype, qclass,) = struct.unpack_from(DnsQuestion._STRUCT_FMT, data, offset)
        offset += DnsQuestion._STRUCT_SIZE

        try:
            qtype = DnsQType(qtype)
        except ValueError:
            pass
        try:
            qclass = DnsQClass(qclass)
        except ValueError:
            pass

        return (DnsQuestion(label, qtype, qclass), offset,)

    def __repr__(self):
        return "<DnsQuestion:%s,%s,%s>" % (self.name, self.qtype, self.qclass)

    def __bytes__(self):
        return bytes(self.name) + struct.pack('!HH', self.qtype, self.qclass)


class DnsRecord(object):
    _RDATA_CLASSES = dict([(cls.RType.value, cls) for cls in RData.__subclasses__()])

    def __init__(self, name, rtype=DnsRType.A, rclass=DnsRClass.IN, ttl=0, rdlength=None, rdata=b""):
        if isinstance(rdata, str):
            rdata = bytes(rdata, 'ascii')

        self.name = name

        try:
            self.rtype = DnsRType(rtype)
        except ValueError:
            logging.warning("Record type: %d is not implemented", rtype)

        try:
            self.rclass = DnsRClass(rclass)
        except ValueError:
            self.rclass = int(rclass)

        self.ttl = int(ttl)
        if rdlength is None:
            rdlength = len(bytes(rdata))
        self.rdlength = rdlength
        self.rdata = rdata

    @classmethod
    def parse(cls, data, offset):
        (name, offset) = DomainName.parse_from(data, offset)
        (rtype, rclass, ttl, rdlength) = struct.unpack_from('!HHIH', data, offset)

        try:
            rtype = DnsRType(rtype)
        except ValueError:
            pass

        try:
            rclass = DnsRClass(rclass)
        except ValueError:
            pass

        offset += struct.calcsize('!HHIH')

        rdata = data[offset:][:rdlength]
        assert len(rdata) == rdlength

        # Message compression is allowed for the DomainNames in these record types
        # Store normalized data in rdata, and offer compressed_rdata as needed, to reconstruct original packet

        if rtype not in cls._RDATA_CLASSES:
            logging.warning("No handler for RType %s", rtype)

        # uncompressed_rdata = RData.get_handler(rtype).parse(data, offset).encode()
        # if uncompressed_rdata != compressed_rdata:
        #     record = cls(name, rtype, rclass, ttl, uncompressed_rdata)
        #     record.compressed_rdata = compressed_rdata  # TODO: don't add member variables to classes like this
        rdata = cls._RDATA_CLASSES.get(rtype.value, RData).parse_from(data, offset, rdlength, )

        record = cls(name, rtype, rclass, ttl, rdlength, rdata)

        offset += rdlength
        return record, offset,

    def __repr__(self):
        return "<Record:%s,%s,%s,%d,%d,%s>" % (
            self.name, self.rtype, self.rclass, self.ttl, self.rdlength, repr(self.rdata))

    def __bytes__(self):
        return bytes(self.name) + struct.pack('!HHIH', self.rtype, self.rclass, self.ttl, self.rdlength) + bytes(
            self.rdata)


class DnsPacket(object):
    def __init__(self, ID=random.getrandbits(16), QR=DnsQR.query, OPCODE=DnsOpCode.query, AA=False, TC=False, RD=True,
                 RA=True, Z=0, RCODE=DnsResponseCode.no_error, QDCOUNT=None, ANCOUNT=None, NSCOUNT=None, ARCOUNT=None,
                 questions=[], answers=[], nameservers=[], additional_records=[], suffix=bytes()):
        if QDCOUNT is None:
            QDCOUNT = len(questions)
        if ANCOUNT is None:
            ANCOUNT = len(answers)
        if NSCOUNT is None:
            NSCOUNT = len(nameservers)
        if ARCOUNT is None:
            ARCOUNT = len(additional_records)
        if not isinstance(QR, DnsQR):
            QR = DnsQR(QR)
        if not isinstance(OPCODE, DnsOpCode):
            OPCODE = DnsOpCode(OPCODE)
        if not isinstance(RCODE, DnsResponseCode):
            RCODE = DnsResponseCode(RCODE)

        self.ID = int(ID)
        self.QR = QR
        self.OPCODE = OPCODE
        self.AA = bool(AA)
        self.TC = bool(TC)
        self.RD = bool(RD)
        self.RA = bool(RA)
        self.Z = int(Z)
        self.RCODE = RCODE
        self.QDCOUNT = int(QDCOUNT)
        self.ANCOUNT = int(ANCOUNT)
        self.NSCOUNT = int(NSCOUNT)
        self.ARCOUNT = int(ARCOUNT)

        assert isinstance(questions, list)
        self.questions = questions

        assert isinstance(answers, list)
        self.answers = answers

        assert isinstance(nameservers, list)
        self.nameservers = nameservers

        assert isinstance(additional_records, list)
        self.additional_records = additional_records

        assert suffix is None or isinstance(suffix, bytes)
        self.suffix = suffix

    def __repr__(self):
        return "<DnsPacket:%s, questions:%s, answers:%s, nameservers:%s, additional_records: %s>" % (
            hex(self.ID), self.questions, self.answers, self.nameservers, self.additional_records)

    @classmethod
    def parse(cls, data, offset=0):
        # self.datagram = data
        # Transaction ID 16
        (ID,) = struct.unpack_from('!H', data, offset)
        # Query/Response 1
        QR = DnsQR((data[offset + 2] & 0b10000000) >> 7)
        # OpCode 4
        OPCODE = DnsOpCode((data[offset + 2] & 0b01111000) >> 3)
        # Authoratative Answer 1
        AA = data[offset + 2] & 0b100 != 0
        # Truncation 1
        TC = data[offset + 2] & 0b10 != 0
        # Recursion Desired 1
        RD = data[offset + 2] & 0b1 != 0
        # Recursion Available 1
        RA = data[offset + 3] & 0b10000000 != 0
        # Reserved for future, zero value
        Z = (data[offset + 3] & 0b01110000) >> 4
        # assert Z == 0 # Newer RFCs obsolete this
        RCODE = DnsResponseCode(data[offset + 3] & 0b1111)
        (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT,) = struct.unpack_from('!HHHH', data, offset + 4)

        # if offset is None:
        #     offset = struct.calcsize('!HHHH')
        offset += struct.calcsize('!HHHHHH')

        questions = []
        while len(questions) < QDCOUNT:
            (question, offset) = DnsQuestion.parse(data, offset)
            questions.append(question)

        answers = []
        nameservers = []
        additional_records = []
        while offset < len(data):
            (rr, offset) = DnsRecord.parse(data, offset)
            if len(answers) < ANCOUNT:
                answers.append(rr)
            elif len(nameservers) < NSCOUNT:
                nameservers.append(rr)
            elif len(additional_records) < ARCOUNT:
                additional_records.append(rr)
            else:
                raise Exception('Too many/too few records.')
        else:
            assert len(questions) == QDCOUNT
            assert len(answers) == ANCOUNT
            assert len(nameservers) == NSCOUNT
            assert len(additional_records) == ARCOUNT
            cls = (Query if QR == DnsQR.query else Response)
            return (cls(ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE,
                        QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT,
                        questions, answers, nameservers, additional_records, suffix=data[offset:]),
                    offset,)

    def __bytes__(self):
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
            data += bytes(record)

        for record in self.answers:
            data += bytes(record)

        for record in self.nameservers:
            data += bytes(record)

        for record in self.additional_records:
            data += bytes(record)

        return data


class Query(DnsPacket):
    pass


class Response(DnsPacket):
    pass
