from dataclasses import dataclass


@dataclass
class DNSAnswer:
    name: str
    record_type: int
    ttl: int
    data: str
@dataclass
class DNSPacket:
    transaction_id: int
    is_response: bool
    query_name: str
    query_type: int
    answer_count: int
    answers: list[DNSAnswer]

