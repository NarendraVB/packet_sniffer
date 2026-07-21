from dataclasses import dataclass


@dataclass
class DNSPacket:
    transaction_id: int
    is_response: bool
    query_name: str
    query_type: int
    answer_count: int