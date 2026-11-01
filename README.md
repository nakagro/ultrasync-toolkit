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

### Python API (recommended)

```python
from ultrasync_toolkit import Session

# Connect and query
with Session(sid="123456789012", passcode="1234", 
             user_number=1, user_pin="1234") as panel:
    
    # Get panel info
    info = panel.get_info()
    print(f"Connected to: {info.name}")
    
    # Get users
    for user in panel.get_users():
        print(f"  #{user.num}: {user.name}")
    
    # Get zones
    for zone in panel.get_zones():
        print(f"  Zone {zone.num}: {zone.name}")
    
    # Get events
    for event in panel.get_events(count=10):
        print(f"  {event.time} {event.code} user={event.user}")
    
    # Get area config (exit/entry delays)
    for area in panel.get_area_config():
        print(f"  Area {area.num}: exit={area.exit_time}s entry={area.entry_time}s")
```

### CLI

```bash
# Basic info
ultrasync --env .env --info

# List users, zones, areas, doors, devices
ultrasync --env .env --users
ultrasync --env .env --zones
ultrasync --env .env --areas
ultrasync --env .env --doors
ultrasync --env .env --devices

# Dump all config
ultrasync --env .env --dump-all

# JSON output (for scripts)
ultrasync --env .env --zones --json

# Event history
ultrasync --env .env --history 50

# Area timers
ultrasync --env .env --area-config

# Verbose mode (for debugging)
ultrasync --env .env --info -v
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
