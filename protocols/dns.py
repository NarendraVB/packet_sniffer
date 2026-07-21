import struct

from models.dns import DNSPacket


class DNSParser:

    def _read_domain_name(self, data: bytes, offset: int):

        labels = []

        while True:

            length = data[offset]

            if length == 0:
                offset += 1
                break

            offset += 1

            label = data[offset:offset + length]

            labels.append(label.decode())

            offset += length

        return ".".join(labels), offset

    def parse(self, data: bytes) -> DNSPacket:

        if len(data) < 12:
            raise ValueError("DNS packet too short")

        transaction_id, flags, questions, answers, authority, additional = struct.unpack(
            "!HHHHHH",
            data[:12]
        )

        is_response = bool(flags & 0x8000)

        query_name, offset = self._read_domain_name(data, 12)

        query_type = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        return DNSPacket(
            transaction_id=transaction_id,
            is_response=is_response,
            query_name=query_name,
            query_type=query_type,
            answer_count=answers
        )