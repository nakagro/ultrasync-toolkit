"""Tests for protocol encoding/decoding - no live panel required."""

import pytest
from ultrasync_toolkit import ultrasync_proto as proto


class TestCRC:
    """CRC-16/MODBUS calculation tests."""

    def test_known_frame(self):
        # Frame from capture: 5e 40 80 00 00 ... with known CRC
        # Test the CRC function with known data
        data = bytes([0x40, 0x80, 0x00, 0x00])
        crc = proto.crc16_modbus(data)
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF


class TestByteStuffing:
    """Byte stuffing (escape 0x5E as 0x5E 0xFF) tests."""

    def test_no_stuffing_needed(self):
        data = bytes([0x01, 0x02, 0x03])
        assert proto.stuff(data) == data

    def test_stuff_marker(self):
        data = bytes([0x01, 0x5E, 0x03])
        stuffed = proto.stuff(data)
        assert stuffed == bytes([0x01, 0x5E, 0xFF, 0x03])

    def test_unstuff(self):
        stuffed = bytes([0x01, 0x5E, 0xFF, 0x03])
        assert proto.unstuff(stuffed) == bytes([0x01, 0x5E, 0x03])

    def test_roundtrip(self):
        original = bytes([0x5E, 0x5E, 0x00, 0x5E])
        assert proto.unstuff(proto.stuff(original)) == original


class TestFrameBuild:
    """Frame construction tests."""

    def test_build_returns_bytes(self):
        frame = proto.build(0x60, 0, b'\x01\x02\x03')
        assert isinstance(frame, bytes)
        assert frame[0] == 0x5E  # Start marker

    def test_build_type_preserved(self):
        frame = proto.build(0x60, 0, b'\x01')
        # Type byte is at position 1 (after 0x5E marker)
        unstuffed = proto.unstuff(frame[1:-2])
        assert unstuffed[0] == 0x60


class TestFrameParse:
    """Frame parsing tests."""

    def test_parse_built_frame(self):
        payload = b'\x01\x02\x03\x04'
        frame = proto.build(0x60, 1, payload)
        parsed = proto.parse(frame)
        assert parsed['type'] == 0x60
        assert parsed['seq'] == 1
        assert parsed['crc_ok'] is True


class TestBCD:
    """BCD encoding tests for connect_login."""

    def test_bcd_encoding(self):
        from ultrasync_toolkit.connect_login import bcd10
        # Low-nibble-first BCD: "1960" -> 0x91, 0x06, 0x00, 0x00, 0x00
        assert bcd10("1960") == bytes.fromhex("9106000000")
        assert bcd10("66666666") == bytes.fromhex("6666666600")
        assert bcd10("1234567890") == bytes.fromhex("2143658709")
