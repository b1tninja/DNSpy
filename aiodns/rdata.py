import ipaddress
import struct

from .enums import DnsRType
from .names import DomainName


class RData:
    RType = None

    def __init__(self, blob):
        self.blob = blob

    @classmethod
    def parse_from(cls, buffer, offset=0, length=None):
        return cls(buffer[offset:][:length])

    def __repr__(self):
        if isinstance(self.blob, bytes):
            return self.blob.hex()
        else:
            return repr(self.blob)

    def __str__(self):
        if isinstance(self.blob, str):
            return self.blob
        elif isinstance(self.blob, bytes):
            return self.blob.decode('ascii')
        else:
            return str(self.blob)

    def __bytes__(self):
        return bytes(self.blob)


class RData_SOA(RData):
    RType = DnsRType.SOA

    def __init__(self, serial, refresh, retry, expire, mname, rname):
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.mname = mname
        self.rname = rname

    @classmethod
    def parse_from(cls, buffer, offset=0, length=None):
        # TODO: consider some wizardry with locals()
        (mname, offset) = DomainName.parse_from(buffer, offset)
        (rname, offset) = DomainName.parse_from(buffer, offset)
        (serial, refresh, retry, expire) = struct.unpack_from('!IIII', rdata, offset)
        return cls(serial, refresh, retry, expire, mname, rname)

    def encode(self):
        return self.mname.encode() + self.rname.encode() + struct.pack('!IIII',
                                                                       self.serial,
                                                                       self.refresh,
                                                                       self.retry,
                                                                       self.expire)

    def __repr__(self):
        return "%d %d %d %d %s %s" % (self.serial, self.refresh, self.retry, self.expire, self.mname, self.rname)


class RData_SingleName:
    def __init__(self, name):
        assert isinstance(name, DomainName)
        self.name = name

    @classmethod
    def parse_from(cls, rdata, offset=0, length=None):
        (name, offset) = DomainName.parse_from(rdata, offset)
        return cls(name)

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return repr(self.name)


class RData_A(RData):
    RType = DnsRType.A
    ipaddress = ipaddress.IPv4Address

    def __init__(self, ip):
        self.ip = ip

    @classmethod
    def parse_from(cls, buffer, offset=0, length=None):
        return cls(cls.ipaddress(buffer[offset:][:length]))

    def __bytes__(self):
        return self.ip.packed

    def __repr__(self):
        return self.ip.compressed


class RData_AAAA(RData_A, RData):
    RType = DnsRType.AAAA
    ipaddress = ipaddress.IPv6Address


class RData_NS(RData_SingleName, RData):
    RType = DnsRType.NS
