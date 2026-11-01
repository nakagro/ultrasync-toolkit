"""Tests for record decoders using known capture data."""
import pytest
from ultrasync_toolkit.session import (
    _decode_events,
    _decode_names,
    _decode_users,
    User,
    Event,
)


# Known capture data (from ultrasync_download_capture.txt)
USER_RESPONSE = bytes.fromhex(
    "7d 58 1d 2b 01 00 01 00 0d 00 52 48 00 00 00 05 "
    "a6 07 19 02 00 00 1a 43 72 61 69 67 20 4c 55 44 "
    "45 4d 41 4e 00 00 00 00 00 00 00 00 00 00 00 02 "
    "00 01 00 0d 00 05 04 00 00 00 04 a6 07 1a 01 00 "
    "00 1a 46 52 41 4e 43 49 53 20 4c 55 44 45 4d 41 "
    "4e 00 00 00 00 00 00 00 00 00".replace(" ", "")
)

ZONE_NAMES_RESPONSE = bytes.fromhex(
    "98 80 30 01 00 0b 45 6e 74 72 79 20 44 6f 6f 72 "
    "20 02 00 0a 50 49 52 20 46 72 6f 6e 74 20 03 00 "
    "09 50 49 52 20 52 65 61 72 20".replace(" ", "")
)


class TestUserDecoder:
    def test_decode_users_basic(self):
        users = _decode_users(USER_RESPONSE)
        assert len(users) == 2

    def test_decode_users_names(self):
        users = _decode_users(USER_RESPONSE)
        names = [u.name for u in users]
        assert "Craig LUDEMAN" in names
        assert "FRANCIS LUDEMAN" in names

    def test_decode_users_numbers(self):
        users = _decode_users(USER_RESPONSE)
        nums = [u.num for u in users]
        assert 1 in nums
        assert 2 in nums

    def test_decode_users_returns_user_objects(self):
        users = _decode_users(USER_RESPONSE)
        assert all(isinstance(u, User) for u in users)

    def test_decode_users_empty(self):
        assert _decode_users(b"") == []
        assert _decode_users(b"\x00\x00\x00") == []


class TestNamesDecoder:
    def test_decode_names_basic(self):
        names = _decode_names(ZONE_NAMES_RESPONSE)
        assert len(names) == 3

    def test_decode_names_values(self):
        names = _decode_names(ZONE_NAMES_RESPONSE)
        name_dict = dict(names)
        assert name_dict[1] == "Entry Door"
        assert name_dict[2] == "PIR Front"
        assert name_dict[3] == "PIR Rear"

    def test_decode_names_empty(self):
        assert _decode_names(b"") == []


class TestEventDecoder:
    def test_decode_events_returns_event_objects(self):
        # Minimal event response with header + one 14-byte record
        event_data = bytes([0x7d, 0x80, 0x45, 0x01])  # header
        event_data += bytes([0x01, 0x00])  # rec num
        event_data += bytes([0x00, 0x00, 0x00, 0x00])  # timestamp
        event_data += bytes([0x0b])  # ARM code
        event_data += bytes([0x00, 0x00, 0x01])  # flags
        event_data += bytes([0x06, 0x00, 0x00, 0x00])  # user 6

        events = _decode_events(event_data)
        assert len(events) == 1
        assert isinstance(events[0], Event)
        assert events[0].code == "ARM"
        assert events[0].user == 6

    def test_decode_events_empty(self):
        assert _decode_events(b"") == []
