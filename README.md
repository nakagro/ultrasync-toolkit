# UltraSync Toolkit

> **Unofficial, reverse-engineered** - This project is not affiliated with Tecom or Carrier.

A Python toolkit for communicating with Tecom ChallengerPlus alarm panels via the UltraSync cloud relay.

**Status:** Read-only operations working (connect, login, identity read). Control operations (arm/disarm) not yet implemented.

## What it does

- Authenticates with the UltraSync WebAuth API
- Opens a WebSocket tunnel to the panel through the cloud relay
- Logs in with user credentials
- Reads panel data (identity, zones, areas, users, etc.)

**This toolkit requires network access to the UltraSync cloud service.**

## Supported hardware

Tested with:
- Tecom ChallengerPlus (TS-CHPLUS) with UltraSync communication enabled

May work with other Challenger panels that support UltraSync, but not verified.

## Requirements

- Python 3.8+
- A Tecom ChallengerPlus panel with UltraSync enabled
- Valid UltraSync credentials (SID, passcode, user PIN)

## Installation

```bash
git clone https://github.com/youruser/ultrasync-toolkit.git
cd ultrasync-toolkit
pip install -e .
```

Or install dependencies manually:
```bash
pip install websocket-client
```

## Configuration

Copy the example config and fill in your credentials:

```bash
cp examples/.env.example .env
# Edit .env with your real values
```

Required credentials:
- `ULTRASYNC_SID` - Your 12-digit UltraSync serial (from panel or app)
- `ULTRASYNC_PASSCODE` - Your UltraSync passcode
- `ULTRASYNC_USER_NUMBER` - Panel user number
- `ULTRASYNC_USER_PIN` - That user's PIN

## Usage

After installation:

```bash
# Run as installed command
ultrasync --env .env --info

# Or run directly
python -m ultrasync_toolkit.connect_login --env .env --info
```

Expected output:
```
[1] WebAuth as id=XXXX...(12 chars) -> webauth-a.ultraconnect.com
    relay_server=xtun-XXX.ultraconnect.com  webkey=**** (22 chars)
[2] Open tunnel: wss://...
[3] relay ready message: control '{}\n'
[4] send login seq=0 ...
[5] LOGIN REPLY: {'ok': True, 'session': ..., 'mask': ...}
    >>> CONNECTED. Authenticated to the panel.
[6] send read-only identity query ...
    identity reply (45 bytes): ...
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Documentation

- [docs/SPEC.md](docs/SPEC.md) - Protocol specification
- [docs/RECORD_CATALOG.md](docs/RECORD_CATALOG.md) - Record type mappings
- [SECURITY.md](SECURITY.md) - Security policy and credential handling

## Security

- **Never commit credentials** - `.env` files are gitignored
- **Never post credentials in issues** - see [SECURITY.md](SECURITY.md)
- This toolkit only performs read operations
- Test only against panels you own or have authorization to access

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

Protocol reverse-engineered from CTPlus (Tecom's official software) for interoperability purposes.
