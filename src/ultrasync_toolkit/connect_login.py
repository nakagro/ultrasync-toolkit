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
import argparse, os, struct, sys, time
from pathlib import Path

from . import ultrasync_proto as proto
from . import ultrasync_webauth as wa

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
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--debug", action="store_true", help="print raw frames (no credentials)")
    ap.add_argument("--replay-ctplus-login", action="store_true",
                    help="use the exact login CTPlus last sent (known-good proof; stop CTPlus first)")
    ap.add_argument("--security-password-auth", action="store_true",
                    help="legacy auth type: use ULTRASYNC_SECURITY_PASSWORD for the "
                         "security field instead of the passcode")
    args = ap.parse_args()
    global DEBUG
    DEBUG = args.debug

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

    print(f"[1] WebAuth as id={sid[:4]}...({len(sid)} chars) -> {wa.DEFAULT_WEBAUTH_HOST}")
    try:
        resp = wa.webauth(sid, passcode)
    except Exception as e:
        sys.exit(f"    WebAuth failed: {e}")
    if "error" in resp:
        sys.exit(f"    WebAuth returned error: {resp['error']}")
    relay = resp.get("relay_server")
    webkey = resp.get("webkey")
    if not relay or not webkey:
        sys.exit(f"    WebAuth response missing relay_server/webkey. Keys: {list(resp)}")
    print(f"    relay_server={relay}  webkey={'*' * len(webkey)} ({len(webkey)} chars)")

    url = resp["_tunnel_url"]
    print(f"[2] Open tunnel: wss://{relay}/xtun/panel?id=...&webkey=***&port=80&multi=true")
    ws = websocket.create_connection(url, timeout=args.timeout)
    try:
        # [3] relay ready message
        kind, data = recv_frame(ws, args.timeout)
        print(f"[3] relay ready message: {kind} {data!r}")

        # [4] send login. Authentication mode: security field = passcode.
        if args.replay_ctplus_login:
            inner = latest_ctplus_login_inner()
            if not inner:
                print("    could not find a CTPlus login frame to replay; using .env")
                inner = build_login_inner(passcode, user_number, env["ULTRASYNC_USER_PIN"])
            else:
                print("    (replaying CTPlus's own last login — known-good creds)")
        else:
            sec_field = (env.get("ULTRASYNC_SECURITY_PASSWORD", "")
                         if args.security_password_auth else passcode)
            inner = build_login_inner(sec_field, user_number, env["ULTRASYNC_USER_PIN"])
        login = proto.build(0x60, 0, tx_payload(b"\x00\x00\x00\x00", inner))
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
                print(f"    (control: {data!r})")
                continue
            p = proto.parse(data)
            if not p["crc_ok"]:
                print(f"    frame CRC FAILED: {data.hex(' ')}")
                continue
            if p["type"] == 0x40 and p["payload"][:1] == b"\x01":
                r = parse_login_reply(p["payload"])
                print(f"[5] LOGIN REPLY: {r}")
                if r.get("ok"):
                    session = bytes(r["session"])
                    print(f"    >>> CONNECTED. Authenticated to the panel. "
                          f"session={session.hex()} mask=0x{r['mask']:08x}")
                else:
                    print(f"    >>> login rejected / insufficient permission "
                          f"(bit13={r.get('bit13')} bit18={r.get('bit18')})")
                break
            else:
                print(f"    other panel frame type=0x{p['type']:02x} "
                      f"payload={p['payload'].hex(' ')}")

        if session is None:
            print("    No valid login reply received.")
            return

        # [6] optional read-only identity query
        if args.info:
            q = proto.build(0x60, 1, tx_payload(session, bytes([0x25, 0x02, 0x37, 0x01])))
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
                    name = bytes(b for b in pl if 32 <= b < 127)
                    print(f"    identity reply ({len(pl)} bytes): {pl.hex(' ')}")
                    print(f"    printable: {name.decode('ascii', 'replace')}")
                    break
    finally:
        ws.close()
        print("[*] tunnel closed.")


if __name__ == "__main__":
    main()
