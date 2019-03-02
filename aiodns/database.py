import logging

from .dns import console


class Database(object):
    def __init__(self, database='dns', user=None, password=None, host='localhost', port=3306):
        self.log = logging.Logger('db')
        self.log.addHandler(console)
        self._cached_names = {}
        self._cached_questions = {}
        self._cached_queries = {}
        self.queries = 0

    def get_blob_id(self, blob):
        pass

    def get_ipaddr_blob_id(self, ip):
        pass

    def _get_digest(self, blob):
        pass

    def store_packet(self, dns_packet, source=None, destination=None):
        pass

    def get_name(self, name_id):
        pass

    def create_name(self, label, parent, casemap=str.upper):
        pass

    def create_resource_header(self, resource):
        pass

    def get_name_id(self, name, casemap=str.upper):
        pass

    def create_query(self, packet_id, ns_id=None, addr_id=None, parent_id=None, response_id=None):
        pass

    def update_query_response(self, query_id, response_id):
        pass

    def get_record_id(self, record):
        pass

    def get_resource_header_id(self, resource):
        pass

    def create_record(self, record):
        pass

    def lookup_response(self, *args, **kwargs):
        pass

    def lookup_response_id(self, questions, ns_id=None, addr_id=None):
        pass

    def get_packet_questions(self, packet_id):
        pass

    def get_packet_records(self, packet_id):
        pass

    def get_packet(self, packet_id):
        pass

    def get_questionset_id(self, questions):
        pass

    def get_recordset_id(self, records):
        pass

    def create_packet_record(self, packet_id, record):
        pass

    def create_packet_question(self, packet_id, question):
        pass
