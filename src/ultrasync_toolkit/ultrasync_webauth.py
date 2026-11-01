"""
CTPlus / UltraSync WebAuth client.

Reproduces the auth handshake CTPlus uses to obtain an Xtun tunnel webkey.
Cross-platform (stdlib only). Verified against CTPlus-captured signature vectors.

Flow:
  1. sign(id, date) -> SigV4-style chained HMAC-SHA256, hex
  2. POST form body to https://<webauth_host>/xquery/1.0/relay.json
        id=<SID>&passcode=<PASSCODE>&apptype=titan&date=<UTC>&signature=<sig>
     (Content-Type: application/json)
  3. response JSON -> {"relay_server": "...", "webkey": "...", ...}
  4. tunnel = wss://<relay_server>/xtun/panel?id=<SID>&webkey=<webkey>&port=80&multi=true
"""
import hmac, hashlib, json, time, urllib.request, urllib.parse

# 48-byte app secret recovered from servermodule.dll (.rdata @ 0x1801c40b8)
APP_SECRET = bytes.fromhex(
    "b1f9c077465f895ce9b9984abe9cc5cc81eda90c4d68df65a133161342d227a1"
    "327ae9cd98ce34953af7daaa21486b37"
)
RELAY_PATH = b"/xquery/1.0/relay.json"
DEFAULT_WEBAUTH_HOST = "webauth-a.ultraconnect.com"   # config key ultrasync/WebAuthServer

def utc_date() -> str:
    # Qt format "yyyyMMddThhmmssZ" (24-hour, UTC)
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

def sign(sid: str, date: str) -> str:
    k = hmac.new(APP_SECRET, date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, RELAY_PATH, hashlib.sha256).digest()
    return hmac.new(k, sid.encode(), hashlib.sha256).hexdigest()

def webauth(sid: str, passcode: str, host: str = DEFAULT_WEBAUTH_HOST, date: str | None = None) -> dict:
    date = date or utc_date()
    body = urllib.parse.urlencode({
        "id": sid, "passcode": passcode, "apptype": "titan",
        "date": date, "signature": sign(sid, date),
    }).encode()
    url = f"https://{host}{RELAY_PATH.decode()}"
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        resp = json.loads(r.read().decode())
    resp["_tunnel_url"] = (
        f"wss://{resp.get('relay_server')}/xtun/panel"
        f"?id={sid}&webkey={resp.get('webkey')}&port=80&multi=true"
    )
    return resp

if __name__ == "__main__":
    import sys
    # self-test: reproduce a known captured vector (no network)
    vec_date = "20261031T024201Z"
    vec_sig  = "266c14c04a6c833b00199ef19e0f4fb512b6488ab8d19ff9beecebeb7841ee45"
    ok = sign("257143070042", vec_date) == vec_sig
    print("signature self-test:", "PASS" if ok else "FAIL")
    if len(sys.argv) == 3:                     # live: python ultrasync_webauth.py <SID> <passcode>
        print(json.dumps(webauth(sys.argv[1], sys.argv[2]), indent=2))
