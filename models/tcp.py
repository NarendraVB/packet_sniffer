from dataclasses import dataclass


@dataclass
class TCPPacket:
    source_port: int
    destination_port: int

    sequence_number: int
    acknowledgement_number: int

    header_length: int

    syn: bool
    ack: bool
    fin: bool
    rst: bool
    psh: bool
    urg: bool

    payload: bytes