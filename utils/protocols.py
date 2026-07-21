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
DNS_RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    65: "HTTPS",
}
def protocol_name(protocol_number):
    return IP_PROTOCOLS.get(protocol_number, "Unknown")

def service_name(port):
    return COMMON_PORTS.get(port, "Ephemeral")

def dns_record_name(record_type):
    return DNS_RECORD_TYPES.get(
        record_type,
        f"Unknown ({record_type})"
    )