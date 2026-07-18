import pytest

from protocols.tcp import TCPParser


def build_segment(flags=0x10, payload=b"Hello", data_offset=5):
    return (
        b"\x30\x39"
        b"\x01\xbb"
        b"\x00\x00\x03\xe8"
        b"\x00\x00\x07\xd0"
        + bytes([(data_offset << 4)])
        + bytes([flags])
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + payload
    )


def test_valid_tcp_segment():

    parser = TCPParser()

    tcp = parser.parse(build_segment())

    assert tcp.source_port == 12345
    assert tcp.destination_port == 443
    assert tcp.sequence_number == 1000
    assert tcp.acknowledgement_number == 2000
    assert tcp.header_length == 20
    assert tcp.ack
    assert not tcp.syn
    assert tcp.payload == b"Hello"


def test_short_segment():

    parser = TCPParser()

    with pytest.raises(ValueError):
        parser.parse(b"\x00\x01")


def test_invalid_header_length():

    parser = TCPParser()

    with pytest.raises(ValueError):
        parser.parse(build_segment(data_offset=4))


def test_incomplete_header():

    parser = TCPParser()

    with pytest.raises(ValueError):
        parser.parse(build_segment(data_offset=6, payload=b""))


def test_syn_packet():

    parser = TCPParser()

    tcp = parser.parse(build_segment(flags=0x02, payload=b""))

    assert tcp.syn
    assert not tcp.ack
    assert not tcp.fin
    assert not tcp.rst
    assert not tcp.psh
    assert not tcp.urg


def test_syn_ack_packet():

    parser = TCPParser()

    tcp = parser.parse(build_segment(flags=0x12, payload=b""))

    assert tcp.syn
    assert tcp.ack
    assert not tcp.fin


def test_empty_payload():

    parser = TCPParser()

    tcp = parser.parse(build_segment(payload=b""))

    assert tcp.payload == b""