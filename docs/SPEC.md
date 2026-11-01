# CTPlus ↔ UltraSync ↔ ChallengerPlus — Protocol Spec

Reverse-engineered from `servermodule.dll` (CTPlus 3.x, Ghidra 12.1.4) and live
plaintext capture of a running CTPlus session. Target panel: TS-CHPLUS (ChallengerPlus)
reached via the UltraSync cloud (Communication Type = UltraSync).

All values below are verified: the signature against 13 captured vectors, the frame
CRC against 634/646 captured frames (round-trip wire-exact).

---

## 1. Endpoints

| Purpose | Host | Notes |
|---|---|---|
| WebAuth | `webauth-a.ultraconnect.com:443` | config key `ultrasync/WebAuthServer` |
| Tunnel (Xtun) | `xtun-au7a.ultraconnect.com:443` | returned as `relay_server` from WebAuth |
| Notify | `notifym.ultraconnect.com` | returned as `notify_server` (push/events) |

Identity: **SID** (UltraSync serial, 12 digits) + **passcode** (panel UltraSync passcode).

---

## 2. WebAuth handshake

`POST https://webauth-a.ultraconnect.com/xquery/1.0/relay.json`
Content-Type: `application/json`  (body is actually form-urlencoded)

```
id=<SID>&passcode=<PASSCODE>&apptype=titan&date=<UTC>&signature=<SIG>
```

- `date` = UTC now, Qt format `yyyyMMddThhmmssZ` → e.g. `20261031T120454Z`
- `signature` = SigV4-style chained HMAC-SHA256, hex:
  ```
  secret = <48-byte key below>
  k1  = HMAC_SHA256(secret, date)
  k2  = HMAC_SHA256(k1, "/xquery/1.0/relay.json")
  k3  = HMAC_SHA256(k2, SID)
  signature = hex(k3)
  ```
  The passcode is **not** part of the signature (sent cleartext, checked server-side).

**App secret** (from `servermodule.dll` .rdata @ `0x1801c40b8`, 48 bytes):
```
b1f9c077465f895ce9b9984abe9cc5cc81eda90c4d68df65a133161342d227a1327ae9cd98ce34953af7daaa21486b37
```

Response (JSON):
```json
{ "relay_server":"xtun-au7a.ultraconnect.com",
  "notify_server":"notifym.ultraconnect.com",
  "webkey":"GMOSlxL7xu12gK6n4sUcOg", "product":"65", "features":[...] }
```

---

## 3. Tunnel

Open a WebSocket:
```
wss://<relay_server>/xtun/panel?id=<SID>&webkey=<webkey>&port=80&multi=true
```
The `webkey` is ephemeral (per session) — redo WebAuth each connect.
Panel protocol frames travel as WebSocket **text** messages of the form:
```
ws:<N>{<base64>}          where N = len(base64) + 2
```
`base64` decodes to one inner frame (section 4).

---

## 4. Inner frame (ChallengerPlus over Xtun)

```
5E | TYPE | 80 | SEQ(2, big-endian) | PAYLOAD... | CRC(2, little-endian)
```
- `5E` start marker
- `TYPE`: `0x60` = TX command, `0x40` = RX data reply, `0x41` = RX short ack
- `0x80` flag
- `SEQ` 16-bit, big-endian, increments per transaction; TX and its RX share SEQ
- `CRC` = **CRC-16/MODBUS** (poly 0x8005, init 0xFFFF, reflected, xorout 0) computed over
  everything **after** the `5E` marker up to (not incl.) the CRC, stored little-endian.

### Transport wrapper (TX, type 0x60)
```
B0 | LEN | <session-token 4 bytes> | <inner command...>
```
- `LEN` = 4 + len(inner) (covers the session token + inner bytes).
- session-token = **zeros (`00 00 00 00`) on the login frame**; the panel's login
  reply returns the real 4-byte session handle, which you put in every later frame.

### Login handshake (SOLVED — do this first, seq=0)
Inner command, opcode `01 10 09`, 18 bytes total:
```
01 10 09 | <5B BCD security-field> | <u32 LE user#> | <1B pin-len> | <5B BCD pin>
```
- **BCD** = high-nibble-first, 10-digit / 5-byte field, right zero-padded.
  "66666666" → `66 66 66 66 00`; "9106" → `91 06 00 00 00`.
- **security-field** depends on the panel's *Authentication type* (CTPlus → Communication tab):
  - **"Authentication"** (TS-CHPLUS default): security-field = the **UltraSync passcode** (BCD).
    The UI "Security password" field is greyed/unused (`0000000000`) in this mode.
  - **"Security password"** (legacy): security-field = that UI Security-password field.
- user# = the CTPlus user number (e.g. 50) as u32 LE.
- pin = that user's PIN; pin-len = number of PIN digits.

Login reply (RX type 0x40, payload = `unstuff(frame)[5:-2]`):
```
01 <len> 09 | <session4> | <usernum4 echo> | ... | <u32 LE permission mask @ offset 20>
```
- session handle = payload[3:7]; success requires mask **bit 13 (0x2000) AND bit 18 (0x40000)** set.
  Observed success mask = `0xFFFFFF00`. A `0x49` reply type = reject/NAK (bad creds → disconnect).

### Record reads (TX, after login)
```
25 | TYPE | INDEX | ...
```
- `0x25` = read-record opcode; `TYPE`/`INDEX` select the record.
- First read CTPlus issues: `25 02 37 01` = panel identity/network (name + LAN IP/gw/mask).
- Other reads seen in a full programming download: `25 04 40`, `25 05 1d`, `25 06 98`,
  `25 05 45/47` (event history), `25 03 37/34/76/70/13/31/32`, ... (catalog TBD).

### Observed decoded data
- panel IP config: 4-byte IP, 4-byte gateway, 4-byte mask
- panel firmware version string
- device names, area/group names, event flags, user table

---

## 5. Client assembly (what a standalone client does) — PROVEN LIVE
1. `webauth(SID, passcode)` → webkey + relay_server   (`ultrasync_webauth.py`)
2. open `wss://…/xtun/panel?…&port=80&multi=true`       (`websocket-client`)
3. wait for the relay `{}` ready message
4. send login (seq=0, session token = zeros) → parse reply for session handle + mask
5. read/write frames with `ultrasync_proto.py`, putting the session handle in each
6. map `0x25 TYPE INDEX` record types → structured fields (next task; do from capture logs)

Steps 1–5 are implemented and verified against a live panel in `connect_login.py`
(`--info` runs the read-only `25 02 37 01` identity read).

## 6. TODO / open items (for the Linux side)
- Record-type catalog: map each `25 TYPE INDEX` to its meaning (users/doors/areas/…),
  using `ultrasync_download_capture.txt` as the worked example.
- Read-only status reads next: area arm/disarm state, zone seal states.
- Write/control opcodes (arm/disarm/door) — LAST, and only if wanted; capture one
  known action to isolate. Keep everything read-only until then.

## 7. Files
- `src/connect_login.py`     — live connect + login + optional read-only identity read
- `src/ultrasync_webauth.py` — WebAuth signer + client (stdlib only)
- `src/ultrasync_proto.py`   — frame build/parse/verify + byte-stuffing (CRC-16/MODBUS)
