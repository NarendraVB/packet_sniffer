from models.ipv4 import IPv4Packet
from models.tcp import TCPPacket
from models.udp import UDPPacket
from models.dns import DNSPacket
from utils.protocols import protocol_name, service_name


class PacketFormatter:

    def format(self, packet):

        if isinstance(packet, TCPPacket):
            return self._format_tcp(packet)

        if isinstance(packet, UDPPacket):
            return self._format_udp(packet)

        if isinstance(packet, IPv4Packet):
            return self._format_ipv4(packet)

        if isinstance(packet, DNSPacket):
            return self._format_dns(packet)

        return str(packet)

    def _format_ipv4(self, packet):

        return (
            f"[IPv4]\n"
            f"Source      : {packet.source}\n"
            f"Destination : {packet.destination}\n"
            f"TTL         : {packet.ttl}\n"
            f"Protocol    : {protocol_name(packet.protocol)}\n"
            f"Payload     : {len(packet.payload)} bytes\n"
        )
    
    def _format_udp(self, packet):

        source_service = service_name(packet.source_port)
        destination_service = service_name(packet.destination_port)

        return (
            f"[UDP]\n"
            f"Service  : {source_service} → {destination_service}\n"
            f"Ports    : {packet.source_port} → {packet.destination_port}\n"
            f"Length   : {packet.length} bytes\n"
            f"Checksum : 0x{packet.checksum:04X}\n"
            f"Payload  : {len(packet.payload)} bytes\n"
    )
    def _connection_state(self, packet):

        if packet.syn and not packet.ack:
            return "Connection Request"

        if packet.syn and packet.ack:
            return "Handshake Response"

        if packet.fin:
            return "Connection Closing"

        if packet.rst:
            return "Connection Reset"

        if packet.psh:
            return "Application Data"

        if packet.ack:
            return "Acknowledgement"

        return "Unknown"
    

    def _format_tcp(self, packet):

        flags = []
        source_service = service_name(packet.source_port)
        destination_service = service_name(packet.destination_port)
        state = self._connection_state(packet)


        if packet.syn:
            flags.append("SYN")

        if packet.ack:
            flags.append("ACK")

        if packet.fin:
            flags.append("FIN")

        if packet.rst:
            flags.append("RST")

        if packet.psh:
            flags.append("PSH")

        if packet.urg:
            flags.append("URG")

        return (
            f"[TCP]\n"
            f"Service  : {source_service} → {destination_service}\n"
            f"Ports    : {packet.source_port} → {packet.destination_port}\n"
            f"Flags    : {', '.join(flags)}\n"
            f"State    : {state}\n"
            f"Seq      : {packet.sequence_number}\n"
            f"Ack      : {packet.acknowledgement_number}\n"
            f"Payload  : {len(packet.payload)} bytes\n"
        )
    
   
          
    def _format_dns(self, packet):
        packet_type = (
        "Response"
        if packet.is_response
        else "Query"
    )

        return (
            f"[DNS {packet_type}]\n"
            f"Transaction ID : 0x{packet.transaction_id:04X}\n"
            f"Domain         : {packet.query_name}\n"
            f"Query Type     : {packet.query_type}\n"
            f"Answers        : {packet.answer_count}\n"
        )