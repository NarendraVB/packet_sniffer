from protocols.ipv4 import IPv4Parser
from protocols.ethernet import EthernetParser
from protocols.tcp import TCPParser
class ProtocolDispatcher:

    def __init__(self):
        self.ipv4= IPv4Parser()
        self.ethernet = EthernetParser()
        self.tcp = TCPParser()


    def dispatch_ethernet(self, ethernet): 
        if ethernet.ethertype == 0x0800:

            ipv4 = self.ipv4.parse(
                ethernet.payload
            )

            return self.dispatch_ipv4(ipv4)

        return None

    def dispatch_ipv4(self, packet):
        if packet.protocol == 6:

            return self.tcp.parse(
                packet.payload
            )

        return packet

        