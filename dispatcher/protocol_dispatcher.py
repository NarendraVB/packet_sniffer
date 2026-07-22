from protocols.ethernet import EthernetParser
from protocols.ipv4 import IPv4Parser
from protocols.tcp import TCPParser
from protocols.udp import UDPParser
from protocols.dns import DNSParser


class ProtocolDispatcher:

    def __init__(self):
        self.ethernet = EthernetParser()
        self.ipv4 = IPv4Parser()
        self.tcp = TCPParser()
        self.udp = UDPParser()
        self.dns = DNSParser()

    def dispatch(self, raw_data):
        """
        Entry point.
        Takes raw bytes from the network or a PCAP file.
        """

        ethernet = self.ethernet.parse(raw_data)
        return self.dispatch_ethernet(ethernet)

    def dispatch_ethernet(self, ethernet):
        """
        Handle Ethernet frames.
        """

        # IPv4
        if ethernet.ethertype == 0x0800:
            ipv4 = self.ipv4.parse(ethernet.payload)
            return self.dispatch_ipv4(ipv4)

        # Unsupported EtherType
        return None

    def dispatch_ipv4(self, packet):
        """
        Handle IPv4 packets.
        """

        # TCP
        if packet.protocol == 6:
            return self.tcp.parse(packet.payload)

        # UDP
        elif packet.protocol == 17:
            udp = self.udp.parse(packet.payload)

            # DNS runs on UDP port 53
            if udp.source_port == 53 or udp.destination_port == 53:
                return self.dns.parse(udp.payload)

            return udp

        # Unsupported IPv4 protocol
        return None