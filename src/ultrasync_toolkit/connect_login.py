#!/usr/bin/env python3
"""
Standalone UltraSync -> ChallengerPlus live connect + login probe.

What it does (all read-only on the panel):
  1. WebAuth POST  -> relay_server + webkey        (ultrasync_webauth.py)
  2. open wss tunnel: wss://<relay_server>/xtun/panel?id=..&webkey=..&port=80&multi=true
  3. wait for the relay's `{}` ready message
  4. send the seq-0 panel LOGIN (opcode 01 10 09 + BCD creds)   [ultrasync_proto.py]
  5. parse the 0x40 reply: session handle + permission mask (bits 13 & 18)
  6. optional --info: send the read-only identity query 25 02 37 01
                      (what CTPlus itself sends first; returns panel name + LAN)

Credentials are read from a .env file; they are NEVER printed. The script
reports lengths/masks only. It sends NO arm/disarm/door/programming commands.

Config (.env, same dir by default, or pass --env PATH):
  ULTRASYNC_SID=...
  ULTRASYNC_PASSCODE=...
  ULTRASYNC_SECURITY_PASSWORD=...
  ULTRASYNC_USER_NUMBER=...
  ULTRASYNC_USER_PIN=...

Requires: pip install websocket-client
"""
import argparse, json, os, struct, sys, time
from datetime import datetime
from pathlib import Path

from . import ultrasync_proto as proto
from . import ultrasync_webauth as wa


# ---------- record decoders ----------
# Event codes observed in CTPlus capture. Many still unmapped.
# Format: code byte at offset 6 in 14-byte event record
EVENT_CODES = {
    0x0b: "ARM",
    0x0c: "DISARM",
    0xd3: "AUTO-ARM",      # 0xd3 02 00 01 pattern - likely automatic arm
    0x08: "ACCESS",        # 0x08 10 01 00 pattern - door access
    0x01: "ZONE ALARM",
    0x02: "ZONE RESTORE",
    0x03: "ZONE TAMPER",
    0x04: "ZONE TROUBLE",
    0x05: "DOOR UNLOCK",
    0x06: "DOOR DENIED",
    0x07: "DOOR LOCK",
    0x10: "USER LOGIN",
    0x11: "USER LOGOUT",
    # TODO: More codes to map from CTPlus capture analysis
}


def decode_timestamp(b4: bytes) -> str:
    """Decode 4-byte ChallengerPlus timestamp. Format TBD - showing raw for now."""
    # Timestamps appear to be seconds since a panel-specific epoch
    # Need more data points to determine exact epoch
    val = struct.unpack("<I", b4)[0]
    # Try epoch of 2000-01-01 (common in embedded systems)
    try:
        dt = datetime(2000, 1, 1) + __import__('datetime').timedelta(seconds=val)
        if 2020 <= dt.year <= 2030:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        pass
    return f"raw:{b4.hex()}"


def decode_events(payload: bytes) -> list:
    """Parse event history response into list of event dicts."""
    if len(payload) < 4:
        return []
    # Header: 4 bytes (7d 80 45 <count>), then 14-byte records
    data = payload[4:]
    events = []
    # Each event is 14 bytes: 2-byte rec#, 4-byte timestamp, 1-byte code, 3-byte flags, 4-byte user/extra
    for i in range(0, len(data), 14):
        if i + 14 > len(data):
            break
        rec = data[i:i+14]
        rec_num = struct.unpack("<H", rec[0:2])[0]
        ts = decode_timestamp(rec[2:6])
        code = rec[6]
        code_name = EVENT_CODES.get(code, f"0x{code:02x}")
        user = rec[10]  # User number at offset 10
        events.append({"num": rec_num, "time": ts, "code": code_name, "user": user})
    return events


def decode_names(payload: bytes) -> list:
    """Parse name record response (25 06 98 XX).

    Format: 3-byte header (98 80 type), then variable records:
    <index_lo> <index_hi> <length> <name bytes>
    """
    if len(payload) < 5:
        return []
    # Header: 98 80 <type> or similar
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
            names.append({"num": idx, "name": name})
        pos += 3 + length
    return names


def decode_users(payload: bytes) -> list:
    """Parse user record response into list of user dicts.

    Format: 6-byte header (7d 58 1d 2b start_lo start_hi), then 42-byte records.
    User number = start_index + record_position (NOT from record bytes).
    Name field is ~25 bytes, usually starting at offset 17 in the record,
    possibly preceded by 0x1a marker at offset 16.
    """
    if len(payload) < 6:
        return []
    # Header: 7d 58 1d 2b <start_lo> <start_hi>
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

        # Find name: look for printable ASCII starting around offset 15-20
        name = ""
        for name_start in range(15, 22):
            if name_start >= len(rec):
                break
            # Skip 0x1a marker if present
            if rec[name_start] == 0x1a and name_start + 1 < len(rec):
                name_start += 1
            # Check if this looks like a name (starts with printable char)
            if 0x20 <= rec[name_start] <= 0x7e:
                name_bytes = rec[name_start:name_start+25]
                name = name_bytes.split(b'\x00')[0].decode('ascii', 'replace').strip()
                if len(name) >= 2:  # valid name has at least 2 chars
                    break

        if name:
            users.append({"num": user_num, "name": name})

    return users

try:
    import websocket  # websocket-client
except ImportError:
    sys.exit("Missing dependency: pip install websocket-client")


# ---------- config ----------
def load_env(path: Path) -> dict:
    env = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    # environment overrides file
    for k in ("ULTRASYNC_SID", "ULTRASYNC_PASSCODE", "ULTRASYNC_SECURITY_PASSWORD",
              "ULTRASYNC_USER_NUMBER", "ULTRASYNC_USER_PIN"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


# ---------- BCD (high-nibble-first, 10-digit / 5-byte field, right zero-padded) ----------
def bcd10(digits: str) -> bytes:
    d = "".join(ch for ch in digits if ch.isdigit())
    d = (d + "0" * 10)[:10]
    return bytes(int(d[i]) | (int(d[i + 1]) << 4) for i in range(0, 10, 2))


def build_login_inner(security_pwd: str, user_number: int, user_pin: str) -> bytes:
    pin_digits = "".join(ch for ch in user_pin if ch.isdigit())
    return (bytes([0x01, 0x10, 0x09])
            + bcd10(security_pwd)                       # 5 bytes
            + struct.pack("<I", user_number)            # 4 bytes LE
            + bytes([len(pin_digits)])                  # 1 byte: PIN digit count
            + bcd10(pin_digits))                        # 5 bytes


def latest_ctplus_login_inner(log_glob=r"C:\Users\Administrator\AppData\Local\Temp\2\CTPlus\**\*.log"):
    """Lift the exact 18-byte login command (01 10 09 ...) from CTPlus's own
    most-recent login frame. Ground-truth known-good creds; never printed."""
    import glob, os, re, base64
    rx = re.compile(r'ws:\d+\{([A-Za-z0-9+/=]+)\}')
    found = None
    for fn in sorted(glob.glob(log_glob, recursive=True), key=os.path.getmtime):
        for line in open(fn, errors="ignore"):
            m = rx.search(line)
            if not m:
                continue
            try:
                raw = base64.b64decode(m.group(1))
            except Exception:
                continue
            if len(raw) < 7:
                continue
            p = proto.parse(raw)
            inn = p["payload"]
            if p["type"] == 0x60 and len(inn) >= 24 and inn[0] == 0xB0:
                x = inn[6:]  # skip B0, len, session4
                if len(x) >= 18 and x[0] == 0x01 and x[1] == 0x10 and x[2] == 0x09:
                    found = x[:18]
    return found


def tx_payload(session4: bytes, inner: bytes) -> bytes:
    """Transport wrapper that sits between the seq and the inner command:
    B0 | len | <session4> | <inner>    (len = 4 + len(inner))."""
    return bytes([0xB0, 4 + len(inner)]) + session4 + inner


# ---------- reply parsing ----------
def parse_login_reply(payload: bytes) -> dict:
    # payload == unstuff(frame)[5:-2]; layout: 01 <len> 09 <session4> <usernum4> ... <mask4@20>
    if len(payload) < 24 or payload[0] != 0x01 or payload[2] != 0x09:
        return {"ok": False, "reason": "unexpected reply header", "raw_len": len(payload)}
    session = payload[3:7]
    usernum = struct.unpack("<I", payload[7:11])[0]
    mask = struct.unpack("<I", payload[20:24])[0]
    bit13 = (mask >> 0x0D) & 1
    bit18 = (mask >> 0x12) & 1
    return {"ok": bool(bit13 and bit18), "session": session, "usernum": usernum,
            "mask": mask, "bit13": bit13, "bit18": bit18}


# ---------- websocket helpers ----------
DEBUG = False
VERBOSE = False

def recv_frame(ws, timeout=10.0):
    """Return ('control', text) for relay JSON or ('panel', bytes) for a ws:N{b64} frame."""
    ws.settimeout(timeout)
    msg = ws.recv()
    if isinstance(msg, bytes):
        msg = msg.decode("latin-1")
    if DEBUG:
        print(f"    [raw recv] {msg!r}")
    if msg.startswith("ws:"):
        import base64, re
        m = re.match(r"ws:\d+\{([A-Za-z0-9+/=]+)\}", msg)
        if m:
            raw = base64.b64decode(m.group(1))
            if DEBUG:
                print(f"    [raw frame] {raw.hex(' ')}  crc_ok={proto.verify(raw)}")
            return "panel", raw
    return "control", msg


def main():
    ap = argparse.ArgumentParser()
    here = Path(__file__).resolve().parent
    ap.add_argument("--env", default=str(here / ".env"))
    ap.add_argument("--info", action="store_true",
                    help="after login, send the read-only identity query (25 02 37 01)")
    ap.add_argument("--read-system", action="store_true",
                    help="read System Options record (0x36) — contains arm state bits")
    ap.add_argument("--history", nargs="?", const="50", metavar="COUNT",
                    help="read event history (default 50 events, or specify count)")
    ap.add_argument("--users", nargs="?", const="1-100", metavar="RANGE",
                    help="read user records (default 1-100, or specify N or N-M)")
    ap.add_argument("--zones", action="store_true",
                    help="read zone/input names")
    ap.add_argument("--areas", action="store_true",
                    help="read area names")
    ap.add_argument("--area-state", action="store_true",
                    help="read raw area state bytes (0x32) to find arm bits")
    ap.add_argument("--doors", action="store_true",
                    help="read door names")
    ap.add_argument("--devices", action="store_true",
                    help="read device names (keypads, card readers)")
    ap.add_argument("--dump-all", action="store_true",
                    help="dump all configuration (zones, areas, doors, devices, users)")
    ap.add_argument("--json", action="store_true",
                    help="output in JSON format")
    ap.add_argument("--area-config", action="store_true",
                    help="read raw area configuration (includes exit/entry delays)")
    ap.add_argument("--raw-query", metavar="HEX",
                    help="send raw query bytes (hex, e.g. '25 01 44')")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="verbose output with connection steps and raw data (for debugging/LLM)")
    ap.add_argument("--debug", action="store_true", help="print raw frames (no credentials)")
    ap.add_argument("--replay-ctplus-login", action="store_true",
                    help="use the exact login CTPlus last sent (known-good proof; stop CTPlus first)")
    ap.add_argument("--security-password-auth", action="store_true",
                    help="legacy auth type: use ULTRASYNC_SECURITY_PASSWORD for the "
                         "security field instead of the passcode")
    args = ap.parse_args()
    global DEBUG, VERBOSE
    DEBUG = args.debug
    VERBOSE = args.verbose or args.debug  # debug implies verbose

    env = load_env(Path(args.env))
    # In "Authentication" auth mode (TS-CHPLUS default) the panel-login security
    # field is the UltraSync passcode, NOT the UI "Security password". So that
    # UI field is not required here. ULTRASYNC_SECURITY_PASSWORD is only used for
    # the legacy "Security password" auth type (--security-password-auth).
    required = ["ULTRASYNC_SID", "ULTRASYNC_PASSCODE",
                "ULTRASYNC_USER_NUMBER", "ULTRASYNC_USER_PIN"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        sys.exit(f"Missing in {args.env}: {', '.join(missing)}")

    sid = env["ULTRASYNC_SID"]
    passcode = env["ULTRASYNC_PASSCODE"]
    try:
        user_number = int(env["ULTRASYNC_USER_NUMBER"])
    except ValueError:
        sys.exit("ULTRASYNC_USER_NUMBER must be an integer")

    if VERBOSE:
        print(f"[1] WebAuth as id={sid[:4]}...({len(sid)} chars) -> {wa.DEFAULT_WEBAUTH_HOST}")
    try:
        resp = wa.webauth(sid, passcode)
    except Exception as e:
        sys.exit(f"WebAuth failed: {e}")
    if "error" in resp:
        sys.exit(f"WebAuth returned error: {resp['error']}")
    relay = resp.get("relay_server")
    webkey = resp.get("webkey")
    if not relay or not webkey:
        sys.exit(f"WebAuth response missing relay_server/webkey. Keys: {list(resp)}")
    if VERBOSE:
        print(f"    relay_server={relay}  webkey={'*' * len(webkey)} ({len(webkey)} chars)")

    url = resp["_tunnel_url"]
    if VERBOSE:
        print(f"[2] Open tunnel: wss://{relay}/xtun/panel?id=...&webkey=***&port=80&multi=true")
    ws = websocket.create_connection(url, timeout=args.timeout)
    try:
        # [3] relay ready message
        kind, data = recv_frame(ws, args.timeout)
        if VERBOSE:
            print(f"[3] relay ready message: {kind} {data!r}")

        # [4] send login. Authentication mode: security field = passcode.
        if args.replay_ctplus_login:
            inner = latest_ctplus_login_inner()
            if not inner:
                if VERBOSE:
                    print("    could not find a CTPlus login frame to replay; using .env")
                inner = build_login_inner(passcode, user_number, env["ULTRASYNC_USER_PIN"])
            elif VERBOSE:
                print("    (replaying CTPlus's own last login — known-good creds)")
        else:
            sec_field = (env.get("ULTRASYNC_SECURITY_PASSWORD", "")
                         if args.security_password_auth else passcode)
            inner = build_login_inner(sec_field, user_number, env["ULTRASYNC_USER_PIN"])
        login = proto.build(0x60, 0, tx_payload(b"\x00\x00\x00\x00", inner))
        if VERBOSE:
            print(f"[4] send login seq=0 ({len(login)} wire bytes, inner={len(inner)} bytes) ...")
        if DEBUG:
            # mask the credential bytes (inner offsets 3..17) in the printed hex
            masked = bytearray(login)
            print(f"    [login wire] {login[:11].hex(' ')} <inner redacted> {login[-2:].hex(' ')}")
            print(f"    [ws text]    {proto.wrap_ws(login)[:14]}...(len field)")
        ws.send(proto.wrap_ws(login))

        # [5] read login reply (skip any further control frames)
        session = None
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            kind, data = recv_frame(ws, args.timeout)
            if kind != "panel":
                if VERBOSE:
                    print(f"    (control: {data!r})")
                continue
            p = proto.parse(data)
            if not p["crc_ok"]:
                print(f"CRC FAILED: {data.hex(' ')}")
                continue
            if p["type"] == 0x40 and p["payload"][:1] == b"\x01":
                r = parse_login_reply(p["payload"])
                if VERBOSE:
                    print(f"[5] LOGIN REPLY: {r}")
                if r.get("ok"):
                    session = bytes(r["session"])
                    if VERBOSE:
                        print(f"    >>> CONNECTED. session={session.hex()} mask=0x{r['mask']:08x}")
                else:
                    print(f"Login rejected (bit13={r.get('bit13')} bit18={r.get('bit18')})")
                break
            elif VERBOSE:
                print(f"    other panel frame type=0x{p['type']:02x} "
                      f"payload={p['payload'].hex(' ')}")

        if session is None:
            print("No valid login reply received.")
            return

        # Collect results for JSON output
        results = {}

        # [6] optional read-only identity query
        if args.info:
            q = proto.build(0x60, 1, tx_payload(session, bytes([0x25, 0x02, 0x37, 0x01])))
            if VERBOSE:
                print("[6] send read-only identity query 25 02 37 01 (seq=1) ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["seq"] == 1 and p["crc_ok"]:
                    pl = p["payload"]
                    # panel name is the printable CH-... run in the payload
                    name = bytes(b for b in pl if 32 <= b < 127).decode('ascii', 'replace')
                    if VERBOSE:
                        print(f"    identity reply ({len(pl)} bytes): {pl.hex(' ')}")
                    print(f"Panel: {name}")
                    break

        # [7] optional System Options record read (0x36)
        if args.read_system:
            q = proto.build(0x60, 2, tx_payload(session, bytes([0x25, 0x01, 0x36, 0x01])))
            if VERBOSE:
                print("[7] send System Options read 25 01 36 01 (seq=2) ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["seq"] == 2 and p["crc_ok"]:
                    pl = p["payload"]
                    # TODO: decode system options once arm state bits are known
                    print(f"System Options ({len(pl)} bytes): {pl.hex(' ')}")
                    break

        # [8] optional event history read
        if args.history:
            # 25 05 45 <start_lo> <start_hi> <count_lo> <count_hi>
            event_count = int(args.history)
            q = proto.build(0x60, 3, tx_payload(session, bytes([
                0x25, 0x05, 0x45,
                0x01, 0x00,  # start at record 1
                event_count & 0xFF, (event_count >> 8) & 0xFF
            ])))
            if VERBOSE:
                print(f"[8] send event history read 25 05 45 (seq=3, up to {event_count} events) ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["seq"] == 3 and p["crc_ok"]:
                    pl = p["payload"]
                    if VERBOSE:
                        print(f"    raw ({len(pl)} bytes): {pl.hex(' ')}")
                    events = decode_events(pl)
                    results["events"] = events
                    if not args.json:
                        if VERBOSE:
                            print(f"    Event history ({len(events)} events):")
                        if events:
                            print("Events:")
                            for ev in events:
                                user_str = f"  user {ev['user']}" if ev['user'] else ""
                                print(f"  {ev['time']}  {ev['code']:12}{user_str}")
                        else:
                            print("Events: (none found)")
                    break

        # [9] optional user record read (paginated - panel returns 2 users per response)
        if args.users:
            # Parse range: "50" -> user 50, "1-10" -> users 1-10
            user_range = args.users
            if "-" in user_range:
                start, end = user_range.split("-", 1)
                start, end = int(start), int(end)
            else:
                start = int(user_range)
                end = start + 99  # default to 100 users if single number given

            all_users = []
            seq = 4
            current_start = start

            while current_start <= end:
                # 25 05 1D <start_lo> <start_hi> <count_lo> <count_hi>
                # Request 0xFFFF to get max available, panel will return 2 at a time
                q = proto.build(0x60, seq, tx_payload(session, bytes([
                    0x25, 0x05, 0x1D,
                    current_start & 0xFF, (current_start >> 8) & 0xFF,
                    0xFF, 0xFF  # request max, panel returns 2
                ])))
                if VERBOSE:
                    print(f"[9] fetch users starting at {current_start} (seq={seq}) ...")
                ws.send(proto.wrap_ws(q))

                # Wait for response
                got_response = False
                deadline = time.time() + args.timeout
                while time.time() < deadline:
                    kind, data = recv_frame(ws, args.timeout)
                    if kind != "panel":
                        continue
                    p = proto.parse(data)
                    if p["seq"] == seq and p["crc_ok"]:
                        pl = p["payload"]
                        if VERBOSE:
                            print(f"    raw ({len(pl)} bytes): {pl.hex(' ')}")
                        users = decode_users(pl)
                        if users:
                            all_users.extend(users)
                            current_start = users[-1]["num"] + 1
                        else:
                            current_start = end + 1  # no more users, stop
                        got_response = True
                        break

                if not got_response:
                    break
                seq += 1
                if seq > 250:  # safety limit
                    break

            # Filter to requested range
            all_users = [u for u in all_users if start <= u["num"] <= end]
            results["users"] = all_users
            if not args.json:
                if VERBOSE:
                    print(f"    Users ({len(all_users)} found):")
                if all_users:
                    print("Users:")
                    for u in all_users:
                        print(f"  #{u['num']:3d}  {u['name']}")
                else:
                    print("Users: (none found)")

        # [10] optional zone names read
        if args.zones or args.dump_all:
            # 25 06 98 30 <start_lo> <start_hi> <count_lo> <count_hi>
            seq = 10
            all_names = []
            current_start = 1
            while current_start < 500:
                q = proto.build(0x60, seq, tx_payload(session, bytes([
                    0x25, 0x06, 0x98, 0x30,
                    current_start & 0xFF, (current_start >> 8) & 0xFF,
                    0xFF, 0xFF
                ])))
                if VERBOSE:
                    print(f"[10] fetch zone names starting at {current_start} (seq={seq}) ...")
                ws.send(proto.wrap_ws(q))
                deadline = time.time() + args.timeout
                got_any = False
                while time.time() < deadline:
                    kind, data = recv_frame(ws, args.timeout)
                    if kind != "panel":
                        continue
                    p = proto.parse(data)
                    if p["seq"] == seq and p["crc_ok"]:
                        names = decode_names(p["payload"])
                        if names:
                            all_names.extend(names)
                            current_start = names[-1]["num"] + 1
                            got_any = True
                        break
                if not got_any:
                    break
                seq += 1
            results["zones"] = all_names
            if not args.json:
                if all_names:
                    print("Zones:")
                    for z in all_names:
                        print(f"  #{z['num']:3d}  {z['name']}")
                else:
                    print("Zones: (none found)")

        # [11] optional area/user-category names read (type 0x34)
        if args.areas or args.dump_all:
            seq = 20
            all_names = []
            current_start = 1
            while current_start < 100:
                q = proto.build(0x60, seq, tx_payload(session, bytes([
                    0x25, 0x06, 0x98, 0x34,
                    current_start & 0xFF, (current_start >> 8) & 0xFF,
                    0xFF, 0xFF
                ])))
                if VERBOSE:
                    print(f"[11] fetch area names starting at {current_start} (seq={seq}) ...")
                ws.send(proto.wrap_ws(q))
                deadline = time.time() + args.timeout
                got_any = False
                while time.time() < deadline:
                    kind, data = recv_frame(ws, args.timeout)
                    if kind != "panel":
                        continue
                    p = proto.parse(data)
                    if p["seq"] == seq and p["crc_ok"]:
                        names = decode_names(p["payload"])
                        if names:
                            all_names.extend(names)
                            current_start = names[-1]["num"] + 1
                            got_any = True
                        break
                if not got_any:
                    break
                seq += 1
            results["areas"] = all_names
            if not args.json:
                if all_names:
                    print("Areas/Categories:")
                    for a in all_names:
                        print(f"  #{a['num']:3d}  {a['name']}")
                else:
                    print("Areas: (none found)")

        # [11b] optional area state read (record type 0x32)
        if args.area_state:
            # Query area state records - exact format from CTPlus capture
            q = proto.build(0x60, 25, tx_payload(session, bytes([
                0x25, 0x03, 0x32, 0x01, 0x50
            ])))
            if VERBOSE:
                print("[11b] fetch area state (0x32) ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["crc_ok"]:
                    pl = p["payload"]
                    print(f"Area State ({len(pl)} bytes): {pl.hex(' ')}")
                    break

        # [11c] optional raw query
        if args.raw_query:
            query_bytes = bytes.fromhex(args.raw_query.replace(" ", ""))
            q = proto.build(0x60, 26, tx_payload(session, query_bytes))
            print(f"[raw] sending: {query_bytes.hex(' ')}")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["crc_ok"]:
                    pl = p["payload"]
                    print(f"[raw] response ({len(pl)} bytes): {pl.hex(' ')}")
                    break

        # [12] optional door names read
        if args.doors or args.dump_all:
            q = proto.build(0x60, 30, tx_payload(session, bytes([
                0x25, 0x06, 0x98, 0x13, 0x01, 0x00, 0xFF, 0xFF
            ])))
            if VERBOSE:
                print("[12] fetch door names ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["seq"] == 30 and p["crc_ok"]:
                    names = decode_names(p["payload"])
                    results["doors"] = names
                    if not args.json:
                        if names:
                            print("Doors:")
                            for d in names:
                                print(f"  #{d['num']:3d}  {d['name']}")
                        else:
                            print("Doors: (none found)")
                    break

        # [13] optional device names read
        if args.devices or args.dump_all:
            q = proto.build(0x60, 40, tx_payload(session, bytes([
                0x25, 0x06, 0x98, 0x28, 0x01, 0x00, 0xFF, 0xFF
            ])))
            if VERBOSE:
                print("[13] fetch device names ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["seq"] == 40 and p["crc_ok"]:
                    names = decode_names(p["payload"])
                    results["devices"] = names
                    if not args.json:
                        if names:
                            print("Devices:")
                            for d in names:
                                print(f"  #{d['num']:3d}  {d['name']}")
                        else:
                            print("Devices: (none found)")
                    break

        # [14] optional raw area configuration read
        if args.area_config:
            # 25 03 32 <start> <count> - raw area records with timers/config
            q = proto.build(0x60, 50, tx_payload(session, bytes([
                0x25, 0x03, 0x32, 0x01, 0x50  # start=1, count=80
            ])))
            if VERBOSE:
                print("[14] fetch raw area configuration ...")
            ws.send(proto.wrap_ws(q))
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                kind, data = recv_frame(ws, args.timeout)
                if kind != "panel":
                    continue
                p = proto.parse(data)
                if p["seq"] == 50 and p["crc_ok"]:
                    pl = p["payload"]
                    if VERBOSE:
                        print(f"Area config raw ({len(pl)} bytes): {pl.hex(' ')}")
                    # Parse area records - header is 4 bytes (7d 38 32 1b)
                    # Each area is ~27 bytes based on capture
                    # Fields: areano, textword, exittime, entrytime, events...
                    data = pl[4:] if len(pl) > 4 else pl
                    # Area 1 data starts at offset 0
                    # Looking at DLL: areano(1), textword(2), exittime(2), entrytime(2)
                    if len(data) >= 27:
                        area1 = data[0:27]
                        area_no = area1[0]
                        # exittime appears to be at offset ~25-26 based on capture pattern
                        # The 26 4e bytes suggest exit=38 (0x26) entry=78 (0x4e) seconds
                        exit_time = area1[25] if len(area1) > 25 else 0
                        entry_time = area1[26] if len(area1) > 26 else 0
                        print(f"Area {area_no}: exit_time={exit_time}s, entry_time={entry_time}s")
                        print(f"  (raw bytes for analysis: {area1.hex(' ')})")
                    if len(data) >= 54:
                        area2 = data[27:54]
                        area_no = area2[0] if area2[0] != 0 else 2
                        exit_time = area2[25] if len(area2) > 25 else 0
                        entry_time = area2[26] if len(area2) > 26 else 0
                        print(f"Area {area_no}: exit_time={exit_time}s, entry_time={entry_time}s")
                    break

        # Output JSON if requested
        if args.json and results:
            print(json.dumps(results, indent=2))
    finally:
        ws.close()
        if VERBOSE:
            print("[*] tunnel closed.")


if __name__ == "__main__":
    main()
