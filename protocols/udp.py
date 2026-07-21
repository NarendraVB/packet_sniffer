import struct

from models.udp import UDPPacket

class UDPParser:
    def parse(self, data: bytes) -> UDPPacket:
        if len(data) < 8:
            raise ValueError("UDP header too short")
        if length > len(data):
            raise ValueError("Incomplete UDP packet")
        source_port, destination_port, length, checksum = struct.unpack('!HHHH', data[:8]                                 )
        payload = data[8:]
        return UDPPacket(
            source_port=source_port,
            destination_port=destination_port,
            length=length,
            checksum=checksum,
            payload=payload
        )