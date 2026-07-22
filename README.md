# Packet Analyzer

> A lightweight packet analyzer built from scratch in Python to understand how network protocols work under the hood.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

## Overview

This project is a simplified Wireshark-inspired packet analyzer developed as part of my **CyberSpec** cybersecurity learning roadmap.

Instead of relying on existing packet analysis libraries to decode protocols, this project manually parses raw network packets using Python's `struct` module to understand how Ethernet, IPv4, TCP, UDP, and DNS operate internally.

The analyzer supports both:

- Live packet capture
- Offline PCAP analysis

making it useful for debugging, protocol learning, and security education.

---

# Features

- Ethernet Frame Parsing
- IPv4 Packet Parsing
- TCP Segment Parsing
- UDP Datagram Parsing
- DNS Query Parsing
- DNS Name Compression Support
- Protocol Dispatcher
- Human-readable Packet Formatter
- PCAP File Reader
- Live Packet Capture

---

# Supported Protocols

| Layer | Protocol | Status |
|--------|----------|--------|
| Layer 2 | Ethernet | ✅ |
| Layer 3 | IPv4 | ✅ |
| Layer 4 | TCP | ✅ |
| Layer 4 | UDP | ✅ |
| Layer 7 | DNS | ✅ |

---

# Architecture

```
                    +----------------------+
                    |   Raw Packet Bytes   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |   Ethernet Parser    |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |     IPv4 Parser      |
                    +----------+-----------+
                               |
                  +------------+-------------+
                  |                          |
                  v                          v
          +---------------+          +---------------+
          |   TCP Parser  |          |   UDP Parser  |
          +---------------+          +-------+-------+
                                             |
                                             v
                                     +---------------+
                                     |  DNS Parser   |
                                     +---------------+

                               |
                               v

                     +----------------------+
                     | Packet Formatter     |
                     +----------+-----------+
                                |
                                v
                         Human Readable Output
```

---

# Project Structure

```text
packet_sniffer/
│
├── capture/
│   ├── windows_capture.py
│   └── pcap_reader.py
│
├── dispatcher/
│   └── protocol_dispatcher.py
│
├── models/
│   ├── ethernet.py
│   ├── ipv4.py
│   ├── tcp.py
│   ├── udp.py
│   └── dns.py
│
├── output/
│   └── formatter.py
│
├── protocols/
│   ├── ethernet.py
│   ├── ipv4.py
│   ├── tcp.py
│   ├── udp.py
│   └── dns.py
│
├── utils/
│   ├── converters.py
│   └── protocols.py
│
├── test_pcaps/
│
├── tests/
│
└── main.py
```

---

# Example Output

### DNS Query

```text
[DNS Query]

Transaction ID : 0x1EC6

Domain         : ssl.gstatic.com

Query Type     : AAAA

Answers        : 0
```

---

### TCP Packet

```text
[TCP]

Service  : HTTPS → Ephemeral

Ports    : 443 → 59847

Flags    : ACK, PSH

State    : Application Data

Seq      : 1733756837

Ack      : 3285069927

Payload  : 252 bytes
```

---

# Technologies Used

- Python
- Scapy
- Struct Module
- Socket Module
- Dataclasses

---

# Concepts Learned

During this project I implemented:

- Binary protocol parsing
- Network byte order (Big Endian)
- Ethernet frame decoding
- IPv4 header decoding
- TCP flag analysis
- UDP parsing
- DNS packet parsing
- DNS compression pointers
- Protocol dispatching
- Packet formatting
- PCAP replay
- Live packet capture

---

# Future Improvements

- IPv6 Support
- ICMP Parser
- ARP Parser
- HTTP Parser
- TLS Handshake Parser
- DNS Response Records
- Packet Statistics
- CLI Arguments
- Export to JSON
- Flow Tracking

---

# Lessons Learned

Building this analyzer from scratch provided a deeper understanding of how packets travel through the network stack than using high-level libraries alone.

The project emphasized protocol specifications, binary parsing, layered architecture, and defensive parsing techniques commonly used in networking and cybersecurity tools.

---

# Inspiration

- Wireshark
- tcpdump
- Scapy
- RFC 791 (IPv4)
- RFC 793 (TCP)
- RFC 768 (UDP)
- RFC 1035 (DNS)

---

# Author

**Narendra VB**

This is part of my CyberSpec learnings.