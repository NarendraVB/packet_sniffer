import pytest

from protocols.ipv4 import IPv4Parser


def test_parse_valid_ipv4_packet():

    parser = IPv4Parser()

    packet = (
        b"\x45\x00\x00\x3c"
        b"\x1c\x46\x40\x00"
        b"\x40\x06\xa6\xec"
        b"\xc0\xa8\x01\x02"
        b"\xc0\xa8\x01\x01"
        b"Hello, World!"
    )

    ipv4 = parser.parse(packet)

    assert ipv4.version == 4
    assert ipv4.header_length == 20
    assert ipv4.ttl == 64
    assert ipv4.protocol == 6
    assert ipv4.source == "192.168.1.2"
    assert ipv4.destination == "192.168.1.1"
    assert ipv4.payload == b"Hello, World!"


def test_short_packet():

    parser = IPv4Parser()

    with pytest.raises(ValueError):
        parser.parse(b"\x45\x00\x00\x3c")


def test_invalid_version():

    parser = IPv4Parser()

    packet = (
        b"\x65\x00\x00\x3c"
        b"\x1c\x46\x40\x00"
        b"\x40\x06\xa6\xec"
        b"\xc0\xa8\x01\x02"
        b"\xc0\xa8\x01\x01"
    )

    with pytest.raises(ValueError):
        parser.parse(packet)


def test_invalid_header_length():

    parser = IPv4Parser()

    packet = (
        b"\x41\x00\x00\x3c"
        b"\x1c\x46\x40\x00"
        b"\x40\x06\xa6\xec"
        b"\xc0\xa8\x01\x02"
        b"\xc0\xa8\x01\x01"
    )

    with pytest.raises(ValueError):
        parser.parse(packet)


def test_incomplete_header():

    parser = IPv4Parser()

    packet = (
        b"\x45\x00\x00\x3c"
        b"\x1c\x46\x40\x00"
        b"\x40\x06\xa6\xec"
        b"\xc0\xa8\x01"
    )

    with pytest.raises(ValueError):
        parser.parse(packet)


def test_empty_payload():

    parser = IPv4Parser()

    packet = (
        b"\x45\x00\x00\x14"
        b"\x1c\x46\x40\x00"
        b"\x40\x06\xa6\xec"
        b"\xc0\xa8\x01\x02"
        b"\xc0\xa8\x01\x01"
    )

    ipv4 = parser.parse(packet)

    assert ipv4.payload == b""