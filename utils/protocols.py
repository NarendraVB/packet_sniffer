IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
}

def protocol_name(protocol_number):
    return IP_PROTOCOLS.get(protocol_number, "Unknown")

def service_name(port):
    return COMMON_PORTS.get(port, "Ephemeral")