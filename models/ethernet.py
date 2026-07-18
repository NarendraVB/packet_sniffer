from dataclasses import dataclass


@dataclass
class EthernetFrame:
    destination: str
    source: str
    ethertype: int
    payload: bytes