"""
CTPlus <-> UltraSync Xtun tunnel frame codec.  (v2 — adds 0x5E byte-stuffing)

Transport: Xtun WebSocket text frames of form  ws:<len>{<base64>}   (len = len(base64)+2)
On the wire (after base64 decode) a frame is BYTE-STUFFED:
    wire = 0x5E (marker) + stuff(  TYPE 80 SEQ(2 BE) PAYLOAD CRC(2 LE)  )
    stuffing: every data byte 0x5E (i.e. not the leading marker) is followed by 0xFF.
    On receive: strip marker handling, collapse 0x5E 0xFF -> 0x5E, THEN check CRC/parse.
    CRC = CRC-16/MODBUS over the UN-stuffed body (everything after the 0x5E marker, minus CRC).
Unstuffed frame layout:
    5E | TYPE | 80 | SEQ(2 BE) | PAYLOAD... | CRC(2 LE)
TYPE: 0x60 = TX command, 0x40 = RX data reply, 0x41 = RX short ack.
Verified: unstuffing takes the captured corpus from 1876/1901 to 1901/1901 CRC-valid.
"""
import re, base64

def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF

def unstuff(frame: bytes) -> bytes:
    """Collapse 0x5E 0xFF -> 0x5E in the body (leading marker preserved)."""
    out = bytearray(frame[:1])
    i = 1
    while i < len(frame):
        out.append(frame[i])
        if frame[i] == 0x5E and i + 1 < len(frame) and frame[i+1] == 0xFF:
            i += 2
        else:
            i += 1
    return bytes(out)

def stuff(frame: bytes) -> bytes:
    """Escape every data 0x5E as 0x5E 0xFF (leading marker untouched)."""
    out = bytearray(frame[:1])
    for b in frame[1:]:
        out.append(b)
        if b == 0x5E:
            out.append(0xFF)
    return bytes(out)

def verify(frame: bytes) -> bool:
    f = unstuff(frame)
    if len(f) < 7:
        return False
    return crc16_modbus(f[1:-2]) == (f[-2] | (f[-1] << 8))   # CRC little-endian

def build(type_byte: int, seq: int, payload: bytes) -> bytes:
    """Return the STUFFED on-wire frame ready for wrap_ws()."""
    body = bytes([type_byte, 0x80, (seq >> 8) & 0xFF, seq & 0xFF]) + payload
    crc = crc16_modbus(body)
    unstuffed = bytes([0x5E]) + body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    return stuff(unstuffed)

def wrap_ws(frame: bytes) -> str:
    b64 = base64.b64encode(frame).decode()
    return f"ws:{len(b64) + 2}{{{b64}}}"   # length counts the base64 + the two braces

def parse(frame: bytes) -> dict:
    f = unstuff(frame)
    return {
        "type": f[1], "flag": f[2],
        "seq": (f[3] << 8) | f[4],
        "payload": f[5:-2],            # == reply fields; opcode at [0], subtype at [2]
        "crc_ok": verify(frame),
    }

if __name__ == "__main__":
    import glob
    rx = re.compile(r'(?:sendData|onDrvSocketReadyRead)\(\): ws:\d+\{([A-Za-z0-9+/=]+)\}')
    frames, ok = [], 0
    for fn in glob.glob(r"C:\Users\Administrator\AppData\Local\Temp\2\CTPlus\**\*.log", recursive=True):
        with open(fn, errors="ignore") as fh:
            for line in fh:
                m = rx.search(line)
                if not m: continue
                try: b = base64.b64decode(m.group(1))
                except Exception: continue
                if len(b) >= 7:
                    frames.append(b); ok += verify(b)
    print(f"verified {ok}/{len(frames)} frames (with unstuffing)")
    # round-trip: rebuild from parsed parts, compare to the on-wire (stuffed) frame
    rebuilt = sum(build(parse(f)["type"], parse(f)["seq"], parse(f)["payload"]) == f for f in frames)
    print(f"round-trip rebuilt identical: {rebuilt}/{len(frames)}")
