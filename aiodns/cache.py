import datetime


class DnsNameserver:
    pass


class DnsCacheAnswer:
    pass


class DnsCacheQuestion:
    pass


class DnsCacheRecord:
    # isGlue? (Additional, non-authorative Records)
    pass


class DnsZoneCache:
    def update(self, records, authorative=False):
        pass


class DnsCache:
    def __init__(self):
        self.nameservers = {}
        self.zones = {}

    def cache_zone(self, zone, records, authorative=False):
        self.zones.setdefault(zone, DnsZoneCache())
        self.zones[zone].update(records, authorative)

    def cache_root_hints(self, root_hints):
        self.cache_zone(DnsRootLabel, root_hints, authorative=True)

    def cache_response(self, nameserver, response):
        pass

    def lookup(self, questions, nameserve=None, authorative=True):
        pass
