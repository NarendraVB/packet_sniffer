from models.ipv4 import IPv4Packet
from utils.converters import ipv4_address

class IPv4Parser:

    def parse(self, packet: bytes) -> IPv4Packet:
        

        if len(packet) < 20:
            raise ValueError("Incomplete IPv4 packet.")
        
        first_byte = packet[0]

        version = first_byte >> 4

        ihl = first_byte & 0x0F

        header_length = ihl * 4

        if version != 4:
            raise ValueError("Not an IPv4 packet.")

        if ihl < 5:
            raise ValueError("Invalid IPv4 header length.")
        
        if len(packet) < header_length:
            raise ValueError("Incomplete IPv4 header.")

        ttl = packet[8]

        protocol = packet[9]


        source = ipv4_address(packet[12:16])

        destination = ipv4_address(packet[16:20])

        payload = packet[header_length:]

        return IPv4Packet(
            version=version,
            header_length=header_length,
            ttl=ttl,
            protocol=protocol,
            source=source,
            destination=destination,
            payload=payload
        )
