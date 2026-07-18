from models.tcp import TCPPacket


class TCPParser:

    def parse(self, segment: bytes) -> TCPPacket:
        pass

        if len(segment) < 20:
            raise ValueError("Incomplete TCP segment.")
        
        source_port = int.from_bytes(
            segment[0:2],
            "big"
        )
        destination_port = int.from_bytes(
        segment[2:4],
        "big"
    )
        sequence_number = int.from_bytes(
        segment[4:8],
        "big"
    )
        acknowledgement_number = int.from_bytes(
        segment[8:12],
        "big"
    )
        data_offset = segment[12] >> 4
        header_length = data_offset * 4

        if data_offset < 5:
            raise ValueError("Invalid TCP header length.")
        if len(segment) < header_length:
            raise ValueError("Incomplete TCP header.")
        
        flag=segment[13]
        fin = bool(flag & 0x01)
        syn = bool(flag & 0x02)
        rst = bool(flag & 0x04)
        psh = bool(flag & 0x08)
        ack = bool(flag & 0x10)
        urg = bool(flag & 0x20)

        payload = segment[header_length:]


        return TCPPacket(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgement_number=acknowledgement_number,
            header_length=header_length,
            syn=syn,
            ack=ack,
            fin=fin,
            rst=rst,
            psh=psh,
            urg=urg,
            payload=payload
        )