from protocols.ipv4 import IPv4Parser
from protocols.ethernet import EthernetParser

class ProtocolDispatcher:

    def __init__(self):
        self.ipv4= IPv4Parser()
        self.ethernet = EthernetParser()

    def dispatch_ethernet(self, ethernet): 
        if ethernet.ethertype == 0x0800:
            return self.ipv4.parse(ethernet.payload)

        return None