import struct
import socket
from models.dns import DNSAnswer, DNSPacket


class DNSParser:

    def _read_domain_name(self, data: bytes, offset: int):

        labels = []

        while True:

            length = data[offset]
            if (length & 0xC0) == 0xC0:
                pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
                pointed_name, _ = self._read_domain_name(data, pointer)
                labels.append(pointed_name)
                return ".".join(labels), offset + 2
                break
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

        transaction_id, flags, questions, answer_count, authority, additional = struct.unpack(
            "!HHHHHH",
            data[:12]
        )

        is_response = bool(flags & 0x8000)

        query_name, offset = self._read_domain_name(data, 12)

        query_type = struct.unpack(
            "!H",
            data[offset:offset + 2]
        )[0]

        offset += 2
        query_class = struct.unpack(
                "!H",
                data[offset:offset + 2]
            )[0]

        offset += 2
        answers = []
        for _ in range(answer_count):
            name, offset = self._read_domain_name(data, offset)
            record_type,record_class, ttl, data_length = struct.unpack(
                "!HHIH",
                data[offset:offset + 10]
            )
            offset += 10
            answer_data = data[offset:offset + data_length]
            offset += data_length

            if record_type == 1:  # A record
                decoded=socket.inet_ntoa(answer_data)
            elif record_type == 28:  # AAAA record
                decoded=socket.inet_ntop(socket.AF_INET6, answer_data)
            else:
                decoded=answer_data.hex()
                
            answers.append(DNSAnswer(
                name=name,
                record_type=record_type,
                ttl=ttl,
                data=decoded
                
            ))
        return DNSPacket(
            transaction_id=transaction_id,
            is_response=is_response,
            query_name=query_name,
            query_type=query_type,
            answer_count=len(answers),
            answers=answers
        )