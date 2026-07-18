from dataclasses import dataclass


@dataclass
class IPv4Packet:
    version: int
    header_length: int
    ttl: int
    protocol: int
    source: str
    destination: str
    payload: bytes