from models.ethernet import EthernetFrame
from utils.converters import mac_address


class EthernetParser:

    def parse(self, frame: bytes) -> EthernetFrame:

        if len(frame) < 14:
            raise ValueError("Incomplete Ethernet frame.")

        destination = mac_address(frame[0:6])

        source = mac_address(frame[6:12])

        ethertype = int.from_bytes(
            frame[12:14],
            "big"
        )

        payload = frame[14:]

        return EthernetFrame(
            destination=destination,
            source=source,
            ethertype=ethertype,
            payload=payload,
        )