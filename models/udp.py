from dataclasses import dataclass


@dataclass
class UDPPacket:
    source_port: int
    destination_port: int
    length: int
    checksum: int
    payload: bytes