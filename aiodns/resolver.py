import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
import struct
import urllib.request
from socket import gaierror

from . import IP_MTU_DISCOVER, IP_PMTUDISC_DO, console
from .enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from .names import DomainName
from .packet import DnsPacket, DnsPacketParseError, DnsQuestion, DnsRecord, Query, Response
from .trace import Trace

# RFC 1034 §5.3.3 caps; tunable knobs in this module.
MAX_HOPS = 32
MAX_DEPTH = 24

# Per-query timeout. RFC 1034 §5.3.3 step 3 says the resolver picks the
# "best" server, sends a query, and on timeout moves on to another entry —
# but the spec leaves the wait time to the implementation. A small budget
# is essential: without it, one unreachable anycast NS hangs the whole
# resolution (and any glueless sub-resolution rooted in it) until the
# caller's outer timeout fires. BIND uses 1.5–5 s initially; we pick 5 s.
QUERY_TIMEOUT_S = 5.0


class Resolver(asyncio.Protocol):
    #: Optional DNS suffix the resolver assumes for *relative* names — those
    #: whose presentation form does not end in the root terminator (``.``).
    #: A trailing ``.`` on the SNAME prevents this suffix from being assumed
    #: (RFC 1035 §3.1's wire form is always absolute; the trailing dot in
    #: presentation form is a hint to the resolver, not a wire identity).
    #: Set to a ``str`` or :class:`~aiodns.names.DomainName`; left ``None``,
    #: relative names are simply anchored at the root.
    dns_suffix = None

    async def query(self, questions, nameserver_record, address_record, **kwargs):
        if nameserver_record:
            assert isinstance(nameserver_record, DnsRecord)
        if address_record:
            assert isinstance(address_record, DnsRecord)

        future = asyncio.get_running_loop().create_future()

        ip = ipaddress.ip_address(bytes(address_record.rdata))
        dns_packet = Query(questions=questions, **kwargs)
        # RFC 5936: AXFR uses TCP.
        try:
            q0 = questions[0] if questions else None
            if q0 is not None and getattr(q0, "qtype", None) == DnsQType.AXFR:
                self.log.debug("resolver_force_tcp_axfr(dst=%s id=%s)", ip.exploded, dns_packet.ID)
                return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet.ID)
        except Exception:
            pass
        key = (ip.exploded, dns_packet.ID)
        try:
            q0 = questions[0] if questions else None
            self.log.debug(
                "resolver_sendto(dst=%s id=%s q=%s %s %s)",
                ip.exploded,
                dns_packet.ID,
                getattr(q0, "name", ""),
                getattr(getattr(q0, "qtype", None), "name", getattr(q0, "qtype", "")),
                getattr(getattr(q0, "qclass", None), "name", getattr(q0, "qclass", "")),
            )
        except Exception:
            pass
        if isinstance(ip, ipaddress.IPv6Address):
            # Use IPv6 glue when available.
            if hasattr(self, "_ensure_v6_transport"):
                try:
                    await self._ensure_v6_transport()
                except Exception:
                    pass
            transport_v6 = getattr(self, "transport_v6", None)
            queue_v6 = getattr(self, "queue_v6", None)
            if transport_v6 is None or queue_v6 is None:
                future.cancel()
                return None

            queue_v6[key] = (dns_packet, future)
            # On Windows, IPv6 sendto expects the full 4-tuple (host, port, flowinfo, scopeid).
            transport_v6.sendto(bytes(dns_packet), (ip.exploded, 53, 0, 0))
            try:
                return await asyncio.wait_for(future, timeout=QUERY_TIMEOUT_S)
            except TimeoutError:
                queue_v6.pop(key, None)
                self.log.debug("resolver_timeout_udp(dst=%s id=%s ip_version=6)", ip.exploded, dns_packet.ID)
                return None

        if not isinstance(ip, ipaddress.IPv4Address):
            future.cancel()
            return None

        self.queue[key] = (dns_packet, future)
        self.transport.sendto(bytes(dns_packet), (ip.exploded, 53))
        try:
            return await asyncio.wait_for(future, timeout=QUERY_TIMEOUT_S)
        except TimeoutError:
            # Drop the queue slot so a late response doesn't try to fulfil
            # a cancelled future (and so the slot doesn't leak); the caller
            # treats ``None`` as "no response" and demotes the entry.
            self.queue.pop(key, None)
            self.log.debug("resolver_timeout_udp(dst=%s id=%s ip_version=4)", ip.exploded, dns_packet.ID)
            # UDP may be blocked; try TCP (RFC 1035).
            tcp = await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet.ID)
            return tcp

    async def _query_tcp(self, host, wire, qid):
        self.log.debug("resolver_tcp_try(dst=%s id=%s)", host, qid)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 53), timeout=QUERY_TIMEOUT_S
            )
        except Exception as e:
            self.log.debug("resolver_tcp_connect_failed(dst=%s id=%s err=%s)", host, qid, type(e).__name__)
            return None
        try:
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            nbuf = await asyncio.wait_for(reader.readexactly(2), timeout=QUERY_TIMEOUT_S)
            (n,) = struct.unpack("!H", nbuf)
            data = await asyncio.wait_for(reader.readexactly(n), timeout=QUERY_TIMEOUT_S)
            (pkt, _off) = DnsPacket.parse(data)
            self.log.debug("resolver_tcp_ok(dst=%s id=%s rcvd_len=%d)", host, getattr(pkt, "ID", -1), len(data))
            return pkt
        except Exception as e:
            self.log.debug("resolver_tcp_failed(dst=%s id=%s err=%s)", host, qid, type(e).__name__)
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def enumerate_nameserver_addresses(nameserver_records, additional_records):
        nameserver_records = list(nameserver_records)
        additional_records = list(additional_records)
        random.shuffle(nameserver_records)
        random.shuffle(additional_records)

        for nameserver_record in nameserver_records:
            assert isinstance(nameserver_record, DnsRecord)
            if nameserver_record.rtype == DnsRType.NS:
                for address_record in additional_records:
                    assert isinstance(address_record, DnsRecord)
                    if address_record.name == nameserver_record.rdata and address_record.rtype in [
                        DnsRType.A,
                        DnsRType.AAAA,
                    ]:
                        yield (nameserver_record, address_record)


class Forwarder(asyncio.Protocol):
    def __init__(self, nameservers=None):
        if nameservers is None:
            nameservers = ["8.8.8.8", "8.8.4.4", "4.2.2.2", "1.1.1.1"]


# RFC 1034 §5.3.2 resolver state.
#
# Sname  — the search name, plus QTYPE/QCLASS, plus a `.questions` list ready
#          to drop into a query.
# SlistEntry — one (zone, NS, addresses, history) row.
# Slist  — ordered candidate list for the current zone-cut.
# Sbelt  — safety-belt list seeded from named.root.

class Sname:
    def __init__(self, qname, qtype=DnsQType.A, qclass=DnsRClass.IN):
        if not isinstance(qname, DomainName):
            qname = DomainName(str(qname))
        try:
            qtype = DnsQType(qtype)
        except ValueError:
            pass
        try:
            qclass = DnsRClass(qclass)
        except ValueError:
            pass
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass
        self.questions = [DnsQuestion(qname, qtype, qclass)]

    @classmethod
    def from_question(cls, question):
        return cls(question.name, question.qtype, question.qclass)

    def match_count(self, zone):
        """Number of labels SNAME shares with `zone`, counted from the root.

        Implements the §5.3.3 step 4b "closer" test.
        """
        a = str(self.qname).strip().rstrip(".").upper()
        b = str(zone).strip().rstrip(".").upper()
        a_labels = a.split(".") if a else []
        b_labels = b.split(".") if b else []
        n = 0
        for x, y in zip(reversed(a_labels), reversed(b_labels), strict=False):
            if x == y:
                n += 1
            else:
                break
        return n

    def __repr__(self):
        return "<Sname %s %s %s>" % (self.qname, self.qtype, self.qclass)


class SlistEntry:
    def __init__(self, zone, ns, addresses=None):
        self.zone = zone
        self.ns = ns
        self.addresses = list(addresses or [])
        self.history = {"sent": 0, "received": 0, "demoted": False}

    def __repr__(self):
        return "<SlistEntry zone=%r ns=%r addrs=%d demoted=%s>" % (
            self.zone, self.ns, len(self.addresses), self.history["demoted"],
        )


class Slist:
    def __init__(self, sname, entries=None):
        self.sname = sname
        self.entries = list(entries or [])
        self.zone = DomainName(".")
        self.match = 0

    def best(self):
        glued = next(
            (e for e in self.entries if not e.history["demoted"] and e.addresses),
            None,
        )
        if glued is not None:
            return glued
        return next(
            (e for e in self.entries if not e.history["demoted"]),
            None,
        )

    def demote(self, entry):
        if entry is not None:
            entry.history["demoted"] = True

    def __repr__(self):
        return "<Slist zone=%r match=%d entries=%d>" % (
            self.zone, self.match, len(self.entries),
        )


class Sbelt(Slist):
    @classmethod
    def from_response(cls, response):
        sb = cls(sname=None)
        sb.zone = DomainName(".")
        sb.match = 0
        if response is None:
            return sb
        for ns in response.nameservers:
            if ns.rtype != DnsRType.NS:
                continue
            ns_target = ns.rdata
            addresses = []
            for ar in response.additional_records:
                if ar.name == ns_target and ar.rtype in (DnsRType.A, DnsRType.AAAA):
                    ip = ipaddress.ip_address(bytes(ar.rdata))
                    addresses.append(ip)
            sb.entries.append(SlistEntry(DomainName("."), ns_target, addresses))
        return sb

    def copy_for(self, sname):
        s = Slist(sname)
        s.zone = DomainName(".")
        s.match = sname.match_count(s.zone) if sname is not None else 0
        s.entries = [SlistEntry(e.zone, e.ns, list(e.addresses)) for e in self.entries]
        random.shuffle(s.entries)
        return s


# Effect / step / trace event types.
#
# A `resolve_steps` generator yields one of these each time it needs the
# driver to do something (SendQuery, NeedAddress) or just wants to record a
# decision (Referral, Answer, Nodata, …). The driver records every yield into
# a Trace, then either fulfills the effect or moves on.

class SendQuery:
    def __init__(self, entry, questions):
        self.entry = entry
        self.questions = questions

    def __repr__(self):
        return "<SendQuery to=%r q=%r>" % (self.entry.ns, self.questions)


class NeedAddress:
    def __init__(self, ns_name):
        self.ns_name = ns_name

    def __repr__(self):
        return "<NeedAddress %r>" % (self.ns_name,)


class Referral:
    def __init__(self, old_zone, new_zone, match_before, match_after):
        self.old_zone = old_zone
        self.new_zone = new_zone
        self.match_before = match_before
        self.match_after = match_after

    def __repr__(self):
        return "<Referral %r->%r match %d->%d>" % (
            self.old_zone, self.new_zone, self.match_before, self.match_after,
        )


class Answer:
    def __init__(self, records):
        self.records = list(records)

    def __repr__(self):
        return "<Answer %d>" % len(self.records)


class Nodata:
    def __init__(self, soa):
        self.soa = soa

    def __repr__(self):
        return "<Nodata soa=%r>" % (self.soa,)


class Nxdomain:
    def __repr__(self):
        return "<Nxdomain>"


class Cname:
    def __init__(self, target):
        self.target = target

    def __repr__(self):
        return "<Cname %r>" % (self.target,)


class Demote:
    def __init__(self, entry, reason):
        self.entry = entry
        self.reason = reason

    def __repr__(self):
        ns = self.entry.ns if self.entry is not None else None
        return "<Demote %r %s>" % (ns, self.reason)


class Done:
    def __init__(self, response):
        self.response = response

    def __repr__(self):
        return "<Done>"


class Fail:
    def __init__(self, reason):
        self.reason = reason

    def __repr__(self):
        return "<Fail %s>" % self.reason


def classify(response, sname, slist, entry):
    """Apply RFC 1034 §5.3.3 step 4 to a single response.

    Yields a sequence of trace events. Mutates `slist` for valid referrals
    (extends entries, advances zone/match). Each yielded `Demote` carries
    the entry the caller should mark demoted; each terminal `Done`
    completes the lookup.
    """
    if response is None:
        yield Demote(entry, "no response")
        return

    if response.RCODE == DnsResponseCode.name_error:
        yield Nxdomain()
        yield Done(response)
        return

    if response.RCODE != DnsResponseCode.no_error:
        yield Demote(entry, "rcode " + response.RCODE.name)
        return

    if response.AA:
        if response.ANCOUNT == 0:
            soa = next((r for r in response.nameservers if r.rtype == DnsRType.SOA), None)
            yield Nodata(soa)
            yield Done(response)
            return
        for r in response.answers:
            if r.rtype == DnsRType.CNAME and sname.qtype != DnsQType.CNAME:
                yield Cname(r.rdata)
                break
        yield Answer(response.answers)
        yield Done(response)
        return

    if response.ANCOUNT == 0 and response.NSCOUNT > 0:
        new_zone = None
        ns_targets = []
        for r in response.nameservers:
            if r.rtype == DnsRType.NS:
                if new_zone is None:
                    new_zone = r.name
                ns_targets.append(r.rdata)

        if new_zone is None:
            yield Demote(entry, "no NS in authority")
            return

        match_after = sname.match_count(new_zone)
        if match_after <= slist.match:
            yield Demote(entry, "referral not closer")
            return

        old_zone = slist.zone
        match_before = slist.match

        new_entries = []
        for ns_target in ns_targets:
            addresses = []
            v6 = 0
            for ar in response.additional_records:
                if ar.name == ns_target and ar.rtype == DnsRType.A:
                    ip = ipaddress.ip_address(bytes(ar.rdata))
                    if isinstance(ip, ipaddress.IPv4Address):
                        addresses.append(ip)
                elif ar.name == ns_target and ar.rtype == DnsRType.AAAA:
                    ip = ipaddress.ip_address(bytes(ar.rdata))
                    if isinstance(ip, ipaddress.IPv6Address):
                        addresses.append(ip)
                        v6 += 1
            new_entries.append(SlistEntry(new_zone, ns_target, addresses))
        random.shuffle(new_entries)

        slist.entries = new_entries
        slist.zone = new_zone
        slist.match = match_after

        yield Referral(old_zone, new_zone, match_before, match_after)
        return

    if response.ANCOUNT > 0:
        # Non-authoritative answer (cached upstream); take it as final.
        yield Answer(response.answers)
        yield Done(response)
        return

    yield Demote(entry, "empty response")


def resolve_steps(sname, slist):
    """Drive resolution as a generator of effect/trace events.

    The generator is fully synchronous; it never touches sockets. The async
    driver `RecursiveResolver._drive` fulfills `SendQuery` / `NeedAddress`
    yields and feeds results back via `gen.send(...)`.
    """
    for _ in range(MAX_HOPS):
        # TODO: §5.3.3 step 1 — consult cache here before hitting the network.
        entry = slist.best()
        if entry is None:
            yield Fail("no servers")
            return
        if not entry.addresses:
            addrs = yield NeedAddress(entry.ns)
            if not addrs:
                yield Demote(entry, "no address")
                slist.demote(entry)
                continue
            entry.addresses.extend(addrs)
            continue
        response = yield SendQuery(entry, sname.questions)
        terminal = False
        for step in classify(response, sname, slist, entry):
            yield step
            if isinstance(step, Done):
                terminal = True
                break
            if isinstance(step, Demote):
                slist.demote(step.entry)
        if terminal:
            return
    yield Fail("max hops")


class RecursiveResolver(Resolver):
    def error_received(self, exception):
        if isinstance(exception, gaierror):
            pass
        self.log.critical(exception)

    def record_reader(self, zone_file):
        with open(zone_file, "r") as root_hints_file:
            for i, line in enumerate(root_hints_file):
                if not line or line[0] == ";":
                    continue
                tokens = re.split(r"\s+", line.rstrip())
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
                    self.log.critical("Malformed glue records.")
                    continue

                name = DomainName(name)
                if rtype == DnsRType.SOA:
                    pass
                if rtype == DnsRType.NS:
                    record = DnsRecord(name, rtype, rclass, ttl, rdata=DomainName(rdata))
                elif rtype == DnsRType.A:
                    record = DnsRecord(
                        name, rtype, rclass, ttl, rdata=ipaddress.IPv4Address(rdata).packed
                    )
                elif rtype == DnsRType.AAAA:
                    record = DnsRecord(
                        name, rtype, rclass, ttl, rdata=ipaddress.IPv6Address(rdata).packed
                    )
                else:
                    logging.warning(
                        "Skipping %s record for %s from zone: %s", rtype, name, zone_file
                    )
                    continue

                yield record

    def __init__(self, db=None, root_hints_path="named.root", dns_suffix=None):
        self.queue = {}
        self.queue_v6 = {}
        self.transport_v6 = None
        self._v6_ready = None
        self.log = logging.Logger("resolver")
        self.log.addHandler(console)
        self.root_hints = self.bootstrap(root_hints_path)
        self.sbelt = Sbelt.from_response(self.root_hints)
        self.last_trace = None
        if dns_suffix is not None:
            self.dns_suffix = dns_suffix

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        # Start bringing up an IPv6 UDP transport in the background so AAAA glue
        # can be used when IPv4 anycast is unreachable.
        try:
            loop = asyncio.get_running_loop()
            if self._v6_ready is None:
                self._v6_ready = loop.create_task(self._ensure_v6_transport())
        except RuntimeError:
            # No running loop (should not happen in normal asyncio usage).
            pass

    async def _ensure_v6_transport(self):
        if self.transport_v6 is not None:
            return self.transport_v6

        parent = self

        class _V6Shim(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                parent.transport_v6 = transport

            def datagram_received(self, data, addr):
                parent._datagram_received_v6(data, addr)

            def error_received(self, exc):
                parent.error_received(exc)

        loop = asyncio.get_running_loop()
        try:
            transport, _proto = await loop.create_datagram_endpoint(
                lambda: _V6Shim(),
                local_addr=("::", 0),
                family=socket.AF_INET6,
            )
            self.transport_v6 = transport
            try:
                self.log.debug("resolver_v6_ready(sockname=%s)", transport.get_extra_info("sockname"))
            except Exception:
                pass
            return transport
        except Exception as e:
            self.log.debug("resolver_v6_failed(err=%s)", type(e).__name__)
            self.transport_v6 = None
            return None

    def _datagram_received_v6(self, data, addr):
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except DnsPacketParseError:
            return

        host = addr[0]
        key = (str(host), dns_packet.ID)
        if key in self.queue_v6:
            (_query_packet, future) = self.queue_v6[key]
            del self.queue_v6[key]
            if not future.done():
                future.set_result(dns_packet)
        else:
            pass

    def datagram_received(self, data, addr):
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except DnsPacketParseError as e:
            self.log.warning(
                "parse failed in resolver: err=%s offset=%s len=%d hex=%s",
                e,
                e.offset,
                len(e.data),
                e.wire_hex(),
            )
        else:
            self.log.debug("resolver_datagram_recieved(%s, %s)" % (dns_packet, addr))
            (host, port) = addr
            key = (str(host), dns_packet.ID)
            if key in self.queue:
                (query_packet, future) = self.queue[key]
                del self.queue[key]
                # The future may already be cancelled if the per-query
                # timeout fired before this late response arrived; ignore
                # that race rather than propagating InvalidStateError out
                # of the protocol callback.
                if not future.done():
                    future.set_result(dns_packet)
            else:
                self.log.debug("resolver_unexpected_packet(src=%s id=%s)", host, dns_packet.ID)

    def bootstrap(self, root_hints_path):
        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]

        try:
            if not os.path.isfile(root_hints_path):
                urllib.request.urlretrieve(
                    "http://www.internic.net/domain/named.root", root_hints_path
                )
                self.log.info("Attempting to retrieve root hints from internic.")
            else:
                self.log.debug("Found root hints, %s" % os.path.basename(root_hints_path))

        except IOError:
            self.log.critical("Unable to retrieve root hints.")
            return None

        else:
            nameservers = []
            additional_records = []
            for record in self.record_reader(root_hints_path):
                if record.rtype == DnsRType.NS:
                    nameservers.append(record)
                if record.rtype == DnsRType.A or record.rtype == DnsRType.AAAA:
                    additional_records.append(record)

            query = Query(QR=DnsQR.query, RD=False, questions=questions)
            response = Response(
                QR=DnsQR.response,
                ID=query.ID,
                AA=True,
                RD=False,
                RA=False,
                questions=questions,
                nameservers=nameservers,
                additional_records=additional_records,
            )

        return response

    async def _send_for_entry(self, entry, questions):
        """Send the query to this entry, trying all known addresses."""
        if not entry.addresses:
            return None

        ns_record = DnsRecord(entry.zone, DnsRType.NS, DnsRClass.IN, 0, rdata=entry.ns)

        for address in list(entry.addresses):
            if hasattr(address, "packed"):
                packed = address.packed
            else:
                packed = bytes(address)
            if len(packed) not in (4, 16):
                continue

            addr_rtype = DnsRType.A if len(packed) == 4 else DnsRType.AAAA
            addr_record = DnsRecord(entry.ns, addr_rtype, DnsRClass.IN, 0, rdata=packed)
            try:
                response = await self.query(questions, ns_record, addr_record, RD=False)
            except asyncio.InvalidStateError:
                response = None

            if response is not None:
                return response

        return None

    async def _drive(self, gen, trace, depth=0):
        """Pump the resolve_steps generator and fulfill its effects."""
        if depth > MAX_DEPTH:
            return None
        sent = None
        while True:
            try:
                step = gen.send(sent)
            except StopIteration:
                return None
            trace.record(step)

            if isinstance(step, SendQuery):
                sent = await self._send_for_entry(step.entry, step.questions)
                continue
            if isinstance(step, NeedAddress):
                child_sname = Sname(step.ns_name, DnsQType.A, DnsRClass.IN)
                child_slist = self.sbelt.copy_for(child_sname)
                child_trace = trace.child(child_sname)
                sub_gen = resolve_steps(child_sname, child_slist)
                sub_response = await self._drive(sub_gen, child_trace, depth + 1)
                addrs = []
                if isinstance(sub_response, Response):
                    for r in sub_response.answers:
                        if r.rtype == DnsRType.A:
                            ip = ipaddress.ip_address(bytes(r.rdata))
                            if isinstance(ip, ipaddress.IPv4Address):
                                addrs.append(ip)
                sent = addrs
                continue
            if isinstance(step, Done):
                return step.response
            if isinstance(step, Fail):
                return None
            sent = None

    async def resolve(self, dns_packet):
        assert isinstance(dns_packet, DnsPacket)
        assert dns_packet.QDCOUNT > 0

        if dns_packet.QDCOUNT > 1:
            assert all(q.name == dns_packet.questions[0].name for q in dns_packet.questions[1:])
            assert all(q.qclass == dns_packet.questions[0].qclass for q in dns_packet.questions[1:])

        # Apply the resolver's DNS suffix. Names already terminated by a
        # trailing ``.`` pass through unchanged; relative names are promoted
        # to absolute by appending :attr:`dns_suffix` (or just the root).
        question = dns_packet.questions[0]
        qname = question.name.qualify(dns_suffix=self.dns_suffix)
        sname = Sname(qname, question.qtype, question.qclass)
        self.last_trace = Trace(sname)
        slist = self.sbelt.copy_for(sname)
        gen = resolve_steps(sname, slist)
        response = await self._drive(gen, self.last_trace)
        if isinstance(response, Response):
            response.ID = dns_packet.ID
            response.trace = self.last_trace
        return response
