import pytest

from protocols.ethernet import EthernetParser


def test_parse_valid_ethernet_frame():

    parser = EthernetParser()

    frame = (
        b"\xff\xff\xff\xff\xff\xff"
        b"\x00\x1a\x2b\x3c\x4d\x5e"
        b"\x08\x00"
        b"Hello"
    )

    ethernet = parser.parse(frame)

    assert ethernet.destination == "FF:FF:FF:FF:FF:FF"
    assert ethernet.source == "00:1A:2B:3C:4D:5E"
    assert ethernet.ethertype == 0x0800
    assert ethernet.payload == b"Hello"


def test_short_frame():

    parser = EthernetParser()

    with pytest.raises(ValueError):
        parser.parse(b"\x00\x01\x02")


def test_unknown_ethertype():

    parser = EthernetParser()

    frame = (
        b"\xff\xff\xff\xff\xff\xff"
        b"\x00\x1a\x2b\x3c\x4d\x5e"
        b"\x12\x34"
    )

    ethernet = parser.parse(frame)

    assert ethernet.ethertype == 0x1234


def test_empty_payload():

    parser = EthernetParser()

    frame = (
        b"\xff\xff\xff\xff\xff\xff"
        b"\x00\x1a\x2b\x3c\x4d\x5e"
        b"\x08\x00"
    )

    ethernet = parser.parse(frame)

    assert ethernet.payload == b""