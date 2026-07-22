from scapy.all import rdpcap


class PcapReader:

    def __init__(self, filename):
        self.filename = filename

    def capture(self):
        packets = rdpcap(self.filename)

        for packet in packets:

            if packet.haslayer("Ether"):
                yield bytes(packet)