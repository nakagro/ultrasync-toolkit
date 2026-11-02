"""
UltraSync Session - Clean API for ChallengerPlus panel communication.

Usage:
    from ultrasync_toolkit import Session

    with Session(sid, passcode, user_number, user_pin) as panel:
        users = panel.get_users()
        events = panel.get_events(count=50)
        zones = panel.get_zones()
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import struct
import time

from . import ultrasync_proto as proto
from . import ultrasync_webauth as wa

try:
    import websocket
except ImportError:
    websocket = None


# ---------- Data Models ----------

@dataclass
class User:
    num: int
    name: str


@dataclass
class Zone:
    num: int
    name: str


@dataclass
class Area:
    num: int
    name: str
    exit_time: Optional[int] = None  # seconds
    entry_time: Optional[int] = None  # seconds


@dataclass
class Door:
    num: int
    name: str


@dataclass
class Device:
    num: int
    name: str


@dataclass
class Event:
    num: int
    time: str
    code: str
    user: Optional[int] = None


@dataclass
class PanelInfo:
    name: str
    ip: Optional[str] = None
    raw: bytes = field(default_factory=bytes, repr=False)


# ---------- Constants ----------

EVENT_CODES = {
    0x0b: "ARM",
    0x0c: "DISARM",
    0xd3: "AUTO-ARM",
    0x08: "ACCESS",
    0x01: "ZONE ALARM",
    0x02: "ZONE RESTORE",
    0x03: "ZONE TAMPER",
    0x04: "ZONE TROUBLE",
    0x05: "DOOR UNLOCK",
    0x06: "DOOR DENIED",
    0x07: "DOOR LOCK",
    0x10: "USER LOGIN",
    0x11: "USER LOGOUT",
}


# ---------- Exceptions ----------

class UltraSyncError(Exception):
    """Base exception for UltraSync errors."""
    pass


class AuthenticationError(UltraSyncError):
    """WebAuth or panel login failed."""
    pass


class ConnectionError(UltraSyncError):
    """Tunnel connection failed."""
    pass


class TimeoutError(UltraSyncError):
    """Operation timed out."""
    pass


# ---------- Decoders ----------

def _decode_timestamp(b4: bytes) -> str:
    """Decode 4-byte timestamp. Returns raw hex if epoch unknown."""
    val = struct.unpack("<I", b4)[0]
    try:
        from datetime import timedelta
        dt = datetime(2000, 1, 1) + timedelta(seconds=val)
        if 2020 <= dt.year <= 2030:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass
    return f"raw:{b4.hex()}"


def _decode_events(payload: bytes) -> list[Event]:
    """Parse event history response."""
    if len(payload) < 4:
        return []
    data = payload[4:]
    events = []
    for i in range(0, len(data), 14):
        if i + 14 > len(data):
            break
        rec = data[i:i+14]
        rec_num = struct.unpack("<H", rec[0:2])[0]
        ts = _decode_timestamp(rec[2:6])
        code = rec[6]
        code_name = EVENT_CODES.get(code, f"0x{code:02x}")
        user = rec[10] if rec[10] else None
        events.append(Event(num=rec_num, time=ts, code=code_name, user=user))
    return events


def _decode_names(payload: bytes) -> list[tuple[int, str]]:
    """Parse name record response. Returns list of (index, name)."""
    if len(payload) < 5:
        return []
    data = payload[3:] if payload[0] == 0x98 else payload[5:]
    names = []
    pos = 0
    while pos + 3 < len(data):
        idx = struct.unpack("<H", data[pos:pos+2])[0]
        length = data[pos+2]
        if length == 0 or pos + 3 + length > len(data):
            break
        name = data[pos+3:pos+3+length].decode('ascii', 'replace').strip()
        if name:
            names.append((idx, name))
        pos += 3 + length
    return names


def _decode_users(payload: bytes) -> list[User]:
    """Parse user record response."""
    if len(payload) < 6:
        return []
    start_index = struct.unpack("<H", payload[4:6])[0]
    data = payload[6:]
    users = []
    rec_size = 42
    rec_num = 0
    for i in range(0, len(data), rec_size):
        if i + rec_size > len(data):
            break
        rec = data[i:i+rec_size]
        user_num = start_index + rec_num
        rec_num += 1
        name = ""
        for name_start in range(15, 22):
            if name_start >= len(rec):
                break
            if rec[name_start] == 0x1a and name_start + 1 < len(rec):
                name_start += 1
            if 0x20 <= rec[name_start] <= 0x7e:
                name_bytes = rec[name_start:name_start+25]
                name = name_bytes.split(b'\x00')[0].decode('ascii', 'replace').strip()
                if len(name) >= 2:
                    break
        if name:
            users.append(User(num=user_num, name=name))
    return users


# ---------- Session Class ----------

class Session:
    """
    ChallengerPlus panel session via UltraSync cloud.

    Use as context manager:
        with Session(sid, passcode, user_number, user_pin) as panel:
            print(panel.get_info())
    """

    def __init__(
        self,
        sid: str,
        passcode: str,
        user_number: int,
        user_pin: str,
        timeout: float = 12.0,
    ):
        if websocket is None:
            raise ImportError("websocket-client required: pip install websocket-client")

        self.sid = sid
        self.passcode = passcode
        self.user_number = user_number
        self.user_pin = user_pin
        self.timeout = timeout

        self._ws = None
        self._session_handle = None
        self._seq = 0

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        """Connect to panel via UltraSync cloud relay."""
        # WebAuth
        try:
            resp = wa.webauth(self.sid, self.passcode)
        except Exception as e:
            raise AuthenticationError(f"WebAuth failed: {e}")

        if "error" in resp:
            raise AuthenticationError(f"WebAuth error: {resp['error']}")

        relay = resp.get("relay_server")
        if not relay:
            raise AuthenticationError("No relay_server in WebAuth response")

        # Open tunnel
        url = resp["_tunnel_url"]
        try:
            self._ws = websocket.create_connection(url, timeout=self.timeout)
        except Exception as e:
            raise ConnectionError(f"Tunnel connection failed: {e}")

        # Wait for relay ready
        self._recv_frame()  # Discard ready message

        # Login
        inner = self._build_login()
        login = proto.build(0x60, 0, self._tx_payload(b"\x00\x00\x00\x00", inner))
        self._ws.send(proto.wrap_ws(login))

        # Parse login reply
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            kind, data = self._recv_frame()
            if kind != "panel":
                continue
            p = proto.parse(data)
            if not p["crc_ok"]:
                continue
            if p["type"] == 0x40 and p["payload"][:1] == b"\x01":
                reply = self._parse_login_reply(p["payload"])
                if reply["ok"]:
                    self._session_handle = bytes(reply["session"])
                    self._seq = 1
                    return
                else:
                    raise AuthenticationError(
                        f"Login rejected: bit13={reply.get('bit13')} bit18={reply.get('bit18')}"
                    )

        raise TimeoutError("No login reply received")

    def close(self):
        """Close the tunnel connection."""
        if self._ws:
            try:
                self._ws.close()
            except:
                pass
            self._ws = None

    @property
    def connected(self) -> bool:
        return self._ws is not None and self._session_handle is not None

    # ---------- Query Methods ----------

    def get_info(self) -> PanelInfo:
        """Get panel identity (name, IP)."""
        resp = self._query(bytes([0x25, 0x02, 0x37, 0x01]))
        name = bytes(b for b in resp if 32 <= b < 127).decode('ascii', 'replace')
        return PanelInfo(name=name, raw=resp)

    def get_events(self, count: int = 50) -> list[Event]:
        """Get recent event history."""
        cmd = bytes([0x25, 0x05, 0x45, 0x01, 0x00, count & 0xFF, (count >> 8) & 0xFF])
        resp = self._query(cmd)
        return _decode_events(resp)

    def get_users(self, start: int = 1, end: int = 100) -> list[User]:
        """Get user records (paginated internally)."""
        all_users = []
        current = start
        while current <= end:
            cmd = bytes([
                0x25, 0x05, 0x1D,
                current & 0xFF, (current >> 8) & 0xFF,
                0xFF, 0xFF
            ])
            resp = self._query(cmd)
            users = _decode_users(resp)
            if not users:
                break
            all_users.extend(users)
            current = users[-1].num + 1
        return [u for u in all_users if start <= u.num <= end]

    def get_zones(self) -> list[Zone]:
        """Get zone/input names."""
        all_zones = []
        current = 1
        while current < 500:
            cmd = bytes([
                0x25, 0x06, 0x98, 0x30,
                current & 0xFF, (current >> 8) & 0xFF,
                0xFF, 0xFF
            ])
            resp = self._query(cmd)
            names = _decode_names(resp)
            if not names:
                break
            all_zones.extend([Zone(num=n, name=name) for n, name in names])
            current = names[-1][0] + 1
        return all_zones

    def get_areas(self) -> list[Area]:
        """Get area/category names."""
        all_areas = []
        current = 1
        while current < 100:
            cmd = bytes([
                0x25, 0x06, 0x98, 0x34,
                current & 0xFF, (current >> 8) & 0xFF,
                0xFF, 0xFF
            ])
            resp = self._query(cmd)
            names = _decode_names(resp)
            if not names:
                break
            all_areas.extend([Area(num=n, name=name) for n, name in names])
            current = names[-1][0] + 1
        return all_areas

    def get_doors(self) -> list[Door]:
        """Get door names."""
        cmd = bytes([0x25, 0x06, 0x98, 0x13, 0x01, 0x00, 0xFF, 0xFF])
        resp = self._query(cmd)
        names = _decode_names(resp)
        return [Door(num=n, name=name) for n, name in names]

    def get_devices(self) -> list[Device]:
        """Get device names (keypads, controllers)."""
        cmd = bytes([0x25, 0x06, 0x98, 0x28, 0x01, 0x00, 0xFF, 0xFF])
        resp = self._query(cmd)
        names = _decode_names(resp)
        return [Device(num=n, name=name) for n, name in names]

    def get_system_options(self) -> bytes:
        """Get raw system options (includes arm state)."""
        cmd = bytes([0x25, 0x01, 0x36, 0x01])
        return self._query(cmd)

    def get_area_config(self) -> list[Area]:
        """Get area configuration with exit/entry times."""
        cmd = bytes([0x25, 0x03, 0x32, 0x01, 0x50])
        resp = self._query(cmd)
        areas = []
        if len(resp) > 4:
            data = resp[4:]
            # Parse area records (~27 bytes each)
            for i in range(0, len(data), 27):
                if i + 27 > len(data):
                    break
                rec = data[i:i+27]
                area_no = rec[0]
                exit_time = rec[25] if len(rec) > 25 else None
                entry_time = rec[26] if len(rec) > 26 else None
                areas.append(Area(num=area_no, name=f"Area {area_no}",
                                  exit_time=exit_time, entry_time=entry_time))
        return areas

    def is_armed(self) -> bool:
        """Check if the panel is armed.

        Queries record 0x46 and checks byte 5:
        - Bit 1 set (0x02) = armed
        - Bit 2 set (0x04) = disarmed
        """
        cmd = bytes([0x25, 0x01, 0x46])
        resp = self._query(cmd)
        if len(resp) >= 6:
            status_byte = resp[5]
            # Bit 1 = armed, Bit 2 = disarmed
            return (status_byte & 0x02) != 0
        return False

    def get_arm_status(self) -> dict:
        """Get detailed arm status including raw bytes."""
        cmd = bytes([0x25, 0x01, 0x46])
        resp = self._query(cmd)
        armed = False
        if len(resp) >= 6:
            status_byte = resp[5]
            armed = (status_byte & 0x02) != 0
        return {
            "armed": armed,
            "raw": resp.hex(" ") if resp else ""
        }

    # ---------- Internal Methods ----------

    def _query(self, inner_cmd: bytes) -> bytes:
        """Send a command and return the response payload."""
        if not self.connected:
            raise ConnectionError("Not connected")

        seq = self._seq
        self._seq += 1

        frame = proto.build(0x60, seq, self._tx_payload(self._session_handle, inner_cmd))
        self._ws.send(proto.wrap_ws(frame))

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            kind, data = self._recv_frame()
            if kind != "panel":
                continue
            p = proto.parse(data)
            if p["seq"] == seq and p["crc_ok"]:
                return p["payload"]

        raise TimeoutError(f"No response for seq={seq}")

    def _recv_frame(self) -> tuple[str, bytes]:
        """Receive a frame from the tunnel."""
        self._ws.settimeout(self.timeout)
        msg = self._ws.recv()
        if isinstance(msg, bytes):
            msg = msg.decode("latin-1")
        if msg.startswith("ws:"):
            import base64, re
            m = re.match(r"ws:\d+\{([A-Za-z0-9+/=]+)\}", msg)
            if m:
                return "panel", base64.b64decode(m.group(1))
        return "control", msg.encode() if isinstance(msg, str) else msg

    def _tx_payload(self, session: bytes, inner: bytes) -> bytes:
        """Build transport wrapper."""
        return bytes([0xB0, 4 + len(inner)]) + session + inner

    def _build_login(self) -> bytes:
        """Build login command."""
        pin_digits = "".join(ch for ch in self.user_pin if ch.isdigit())
        return (
            bytes([0x01, 0x10, 0x09])
            + self._bcd10(self.passcode)
            + struct.pack("<I", self.user_number)
            + bytes([len(pin_digits)])
            + self._bcd10(pin_digits)
        )

    @staticmethod
    def _bcd10(digits: str) -> bytes:
        """Encode digits as BCD (low-nibble-first, 10-digit field)."""
        d = "".join(ch for ch in digits if ch.isdigit())
        d = (d + "0" * 10)[:10]
        return bytes(int(d[i]) | (int(d[i + 1]) << 4) for i in range(0, 10, 2))

    @staticmethod
    def _parse_login_reply(payload: bytes) -> dict:
        """Parse login response."""
        if len(payload) < 24 or payload[0] != 0x01 or payload[2] != 0x09:
            return {"ok": False, "reason": "unexpected header"}
        session = payload[3:7]
        mask = struct.unpack("<I", payload[20:24])[0]
        bit13 = (mask >> 0x0D) & 1
        bit18 = (mask >> 0x12) & 1
        return {"ok": bool(bit13 and bit18), "session": session, "mask": mask,
                "bit13": bit13, "bit18": bit18}
