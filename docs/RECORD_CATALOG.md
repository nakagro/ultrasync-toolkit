# ChallengerPlus 0x25 Record Catalog

Derived from `servermodule.dll` (CTPlus) + `ultrasync_download_capture.txt`.

## Command structure

```
25 | OP | TYPE | INDEX | [params...]
```

- `25` = read-record opcode ("Request Database Record Upload")
- `OP` = sub-operation: `01`/`02`/`03` = read data, `05` = read range, `06 98` = read names
- `TYPE` = record type (see table below)
- `INDEX` = starting record number

## Message types (from servermodule.dll strings)

| TYPE | Official Name | Notes |
|------|---------------|-------|
| `0x1D` | User Record with PIN & Name | |
| `0x25` | Request Database Record Upload | The read opcode itself |
| `0x30` | V10-Input Record | **Zones/inputs** |
| `0x36` | System Options Record | **Panel status/config** |
| `0x37` | V10-Communication Records | Panel identity, IP config |
| `0x38` | UltraSync Settings | |
| `0x40` | Communications path setup record | |
| `0x98` | Entity Name Record | **Name reading sub-op** |
| `0xA2` | Extended Door Options Record | |
| `0xA3` | V10 Access Controller Options | |
| `0xAC` | Controller Diagnostics | |
| `0xB0` | Session Identification Prefix | Transport wrapper |

## Record type names (from DLL string table)

These are the database record types (the TYPE byte after 0x25):

| Record Name | Observed TYPE | Notes |
|-------------|---------------|-------|
| Input Record | `0x30` | Zone/input config |
| Area Record | `0x32` | Area config/state |
| User Record | `0x1D` | User with PIN |
| User Category Record | `0x34` | User groups |
| Door Group Record | | |
| RAS Record | | Remote Arming Station |
| DGP Record | | Data Gathering Panel |
| Relay Record | | |
| Alarm Group Record | | |
| Area Group Record | `0x70` | |
| System Options Record | `0x36` | |
| Communications Record | `0x37` | |
| UltraSync Settings Record | `0x38` | |
| Alarm Buffer Record | | Event history |
| Access Buffer Record | | Access events |
| Automation Zone Record | | |

## Observed TYPE mappings (from capture)

| TYPE | Description | Name read | Notes |
|------|-------------|-----------|-------|
| `30` | **Zones** | `25 06 98 30 ...` | Entry Door, PIR Front, etc. |
| `31` | **Satellites** | `25 06 98 31 ...` | "Satellite" |
| `32` | **Areas** | `25 03 32 ...` | Area config/state (binary) |
| `33` | **CH modules** | `25 06 98 33 ...` | "CH 1" |
| `34` | **User groups** | `25 06 98 34 ...` | High Level User Master, etc. |
| `37` | **Panel identity** | `25 02 37 01` | Panel name, IP config |
| `13` | **Doors** | `25 06 98 13 ...` | "Front Door" |
| `28` | **Devices** | `25 06 98 28 ...` | Keypad, Front Door Controller |
| `70` | **Area groups** | `25 06 98 70 ...` | "Area Group 1" |
| `4b` | **Zone groups** | `25 03 4b ...` | Zone group config (binary) |
| `99` | **Event flags** | `25 06 98 99 ...` | Event flag 1 siren, etc. |

## Event history

| OP TYPE | Description |
|---------|-------------|
| `25 05 45` | Event history records (timestamps, event codes) |
| `25 05 47` | Event history continuation |
| `25 05 1d` | Another event/log type (38 occurrences) |

## Other records

| OP TYPE | Count | Notes |
|---------|-------|-------|
| `25 04 40` | 51 | Most frequent - likely zone state or config blocks |
| `25 04 a8` | 4 | Unknown |
| `25 03 76` | 3 | Unknown |
| `25 03 70` | 3 | Area group data |
| `25 05 37` | 5 | Panel/system config |
| `25 05 3b` | 2 | Unknown |

## Next: status reads

For live status (arm/disarm, zone state), likely candidates:
- `25 03 32` or `25 05 32` — area arm state
- `25 03 30` or `25 05 30` — zone seal state
- Need to compare responses when panel is armed vs disarmed to identify status bits

## Tested (live reads confirmed)

| Command | Response | Notes |
|---------|----------|-------|
| `25 02 37 01` | 45 bytes | Panel identity (name + IP config) |
| `25 03 32 01 50` | 58 bytes | Area config (2 areas, membership bitmasks) |
| `25 05 30 01 00 f0 03` | 114 bytes | Zone data (8 zones, 22 bytes each) |
| `25 01 36` | 63 bytes | Status/config - likely contains arm state |
| `25 01 92` | 53 bytes | System info: firmware V10-07.69389, serial |
| `25 04 40 00 06` | 58 bytes | Module info: UltraSync-Eth |

## Next: decode status bits

To map arm/disarm state and zone seal bits:
1. Read `25 01 36` when panel is **disarmed**
2. Arm the panel (manually via keypad)
3. Read `25 01 36` again and diff the bytes
4. Same for zone states — open/close a zone and compare `25 05 30` responses
