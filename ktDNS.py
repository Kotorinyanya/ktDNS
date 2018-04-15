"""
ktDNS server
created at 04/15/2018
by Kotorinyanya

Inspired by https://howcode.org
Refer to http://www.ietf.org/rfc/rfc1035.txt for more details about DNS portocol.
"""

import threading
import socketserver
import glob
import json


class Handler(socketserver.BaseRequestHandler):
    """
    The BaseRequestHandler class for the server.
    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    @staticmethod
    def build_flags(flags):
        """
        Build response flags.
        :param flags: the bytes data for flags (9-16 bits of DNS portocol
        :return: constructed response flags
        """

        byte1 = bytes(flags[:1])
        byte2 = bytes(flags[1:2])

        QR = '1'
        OPCODE = ''
        for bit in range(1, 5):
            OPCODE += str(ord(byte1) & (1 << bit))
        AA = '1'
        TC = '0'
        RD = '0'
        RA = '0'
        Z = '000'
        RCODE = '0000'

        Flags = int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1,
                                                                                                                  byteorder='big')
        return Flags

    @staticmethod
    def get_domain_and_QTYPE(data):
        """
        Get the query domain and QTYPE,
        to keep things simple, I assumed QTYPE to be 'a'
        :param data: data for this part start form 12th bytes in the contents of DNS portocol
        :return: a list of split domain, and binary representation of QTYPE
        """

        domain = []
        domain_string = ''
        char_count, QNAME_length = 0, 0
        is_appended, expected_length = 0, 0

        for byte in data:
            if is_appended == 1:
                if byte != 0:
                    domain_string += chr(byte)
                char_count += 1
                if char_count == expected_length:
                    domain.append(domain_string)
                    domain_string = ''
                    char_count = 0
                    is_appended = 0
                if byte == 0:
                    domain.append(domain_string)
                    break
            else:
                is_appended = 1
                expected_length = byte
            QNAME_length += 1

        QTYPE = data[QNAME_length:QNAME_length + 2]

        return domain, QTYPE

    @staticmethod
    def get_records(data, zones):
        """
        Get the records of the domain being queried
        :param data: data for this part start form 12th bytes in the contents of DNS portocol
        :param zones: where the records was stored
        :return: json list of records, string representation of QTYPE,
                list of domain, string representation of QCLASS
        """
        domain, QTYPE = Handler.get_domain_and_QTYPE(data)
        # To keep things simple, assume QCLASS to be 'IN'
        qclass, qtype = 'IN', ''
        if QTYPE == (1).to_bytes(2, byteorder='big'):
            # 'A' type query
            qtype = 'a'
        zone = Zone.get_zone_by_domain(zones, domain)

        return zone[qtype], qtype, domain, qclass

    @staticmethod
    def build_answers(records, qtype, qclass):
        """
        Build DNS answers.
        :param records: where the records was stored (form zone)
        :param qtype: string representation of QTYPE
        :param qclass: string representation of QCLASS
        :return: binary representation of DNS answers
        """
        Answers = b''

        for record in records:
            # A pointer point to domain name, to keep things simple,
            # assume there is only one domain to query.
            Answers += b'\xc0\x0c'

            # Type and Class
            if qtype == 'a':
                Answers += (1).to_bytes(2, byteorder='big')
            if qclass == 'IN':
                Answers += (1).to_bytes(2, byteorder='big')

            # Time to live
            Answers += int(record['ttl']).to_bytes(4, byteorder='big')

            if qtype == 'a':
                # Data length
                Answers += (4).to_bytes(2, byteorder='big')
                # Address
                for part in record['value'].split('.'):
                    Answers += int(part).to_bytes(1, byteorder='big')

        return Answers

    @staticmethod
    def build_queries(domain, qtype):
        """
        Build DNS queries
        :param domain: list representation of the domain being queried
        :param qtype: string representation of QTYPE
        :return: binary representation of DNS queries
        """
        Queries = b''

        # Name part
        for part in domain:
            Queries += len(part).to_bytes(1, byteorder='big')
            for char in part:
                Queries += ord(char).to_bytes(1, byteorder='big')

        # Type part
        if qtype == 'a':
            Queries += (1).to_bytes(2, byteorder='big')

        # Class part, assume Class to be 'IN'
        Queries += (1).to_bytes(2, byteorder='big')

        return Queries

    @staticmethod
    def build_header(data, records):
        """
        Build DNS header
        :param data: data received from client
        :param records: where the DNS records were stored
        :return: binary representation of DNS header
        """

        # Transaction ID
        Transaction_ID = data[:2]
        # Flags
        Flags = Handler.build_flags(data[2:4])
        # Question Count
        QDCOUNT = (1).to_bytes(2, byteorder='big')
        # Answer Count
        ANCOUNT = len(records).to_bytes(2, byteorder='big')
        # Name Server Count
        NSCOUNT = (0).to_bytes(2, byteorder='big')
        # Additional Count
        ARCOUNT = (0).to_bytes(2, byteorder='big')

        DNS_header = Transaction_ID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

        return DNS_header

    def build_response(self):
        """
        Build response data.
        :return: binary representation of constructed response
        """

        # TODO: Create a zone class
        global zones
        self.zones = zones
        records, qtype, domain, qclass = Handler.get_records(self.data[12:], self.zones)

        """
        Build DNS Header
        """
        DNS_header = self.build_header(self.data, records)

        """
        Build Queries
        """
        Queries = self.build_queries(domain, qtype)

        """
        Build Answers
        """
        Answers = self.build_answers(records, qtype, qclass)

        return DNS_header + Queries + Answers

    def handle(self):
        """
        override this method to implement communication to the client.
        """
        # receive form client socket
        self.data = self.request[0]
        # response to client socket
        response_data = self.build_response()
        client_socket = self.request[1]
        client_socket.sendto(response_data, self.client_address)


class Zone:
    """
    Zone is where DNS records stored.
    """

    @staticmethod
    def load_zone_data(zone_files):
        """
        Load DNS records from the zone files.
        :param zone_files: where the zone files located
        :return: json representation of DNS records data
        """
        # Load zone data into json zones
        json_zone = {}
        for zone in zone_files:
            with open(zone) as z:
                zone_data = json.load(z)
                zone_name = zone_data['$origin']
                json_zone[zone_name] = zone_data

        return json_zone

    @staticmethod
    def get_zone_by_domain(zones, domain):
        """
        Get the zone containing the DNS record for a specified domain
        :param zones: all of the zone data
        :param domain: domain being queried
        :return: json representation of the zone or empty
        """
        zone_name = '.'.join(domain)
        try:
            zone = zones[zone_name]
        except:
            zone = {}
        finally:
            return zone


# TODO: Git rid of this global variable
zones = Zone.load_zone_data(glob.glob('zones/*.zone'))


class Server(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """
    TODO: Explain what does this part exactly do.
    """
    pass


if __name__ == '__main__':
    server_ip, server_port = '127.0.0.1', 53
    server = Server((server_ip, server_port), Handler)
    with server:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print('ktDNS server running at ' + server_ip + '...')
        server_thread.join()
