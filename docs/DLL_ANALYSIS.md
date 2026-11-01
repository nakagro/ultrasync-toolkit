# servermodule.dll Analysis

Extracted from CTPlus `servermodule.dll` via string analysis.

## Database Tables (92 found)

Key tables relevant to the protocol:

| Table | Purpose |
|-------|---------|
| `tc_area` | Area configuration (zones, timers) |
| `tc_alarmgroup` | Alarm group settings (arm permissions) |
| `tc_door` | Door controller config |
| `tc_input` | Zone/input configuration |
| `tc_user` | User records |
| `tc_automation` | Automation/macro settings |
| `tc_macrologic` | Macro logic rules |
| `tc_systemoption` | System-wide options |
| `tc_chtimes` | Panel timing settings |

## Area Record Fields (tc_area)

```
areaunit, chunit, areano, textword, exittime, entrytime,
accessevent, unsealedevent, isolateevent, securealarmevent,
accessalarmevent, entryevent, exitevent, localalarmevent,
warningevent, cameraevent, prealarmevent, outofhourstz,
accesstime, sirenevent, preferredcamera, cidareacode, perimeterarea
```

- `exittime` - Exit delay in seconds (countdown before arming)
- `entrytime` - Entry delay in seconds (grace period to disarm)

## Alarm Group Fields (tc_alarmgroup)

```
almgrpno, almgrpdesc, areatype, areano, remoteaccess, alarmcontrol,
agreset, agarm, resetsysalarms, useralarmgroup, prompt, duress,
autoarm, autoisolate, forcearming, preventforcedisarm, agdisarm,
preventarm, disableautodeisolate, agtime, deadman, timezone
```

Key fields:
- `autoarm` - Auto-arm enabled
- `forcearming` - Allow force arm with unsealed zones
- `preventforcedisarm` - Prevent force disarm
- `agtime` - Alarm group timing

## UltraSync Option Bits

```
BIT 0 - UltraSync Enabled
BIT 1 - Monitor secondary SIM link
BIT 2 - Siren beep on ARM
BIT 3 - Web interface
```

## Reporting Option Bits

```
BIT 0 - Report Alarm Events
BIT 1 - Report Connection Event
BIT 2 - System Alarms Report
BIT 3 - Send Events Outside of TZ
BIT 4 - Common open/close
BIT 5 - Report communication event
```

## Access Option Bits

```
BIT 0 - Report Access Events
BIT 1 - Remove unsent events
BIT 2 - Multi-break alarms
BIT 3 - Multi-break restores
BIT 4 - Report open/close
BIT 5 - Disarm clears pending alarms
```

## Door Record Subtypes

| Subtype | Description |
|---------|-------------|
| 1 | Door access options |
| 2 | Door shunt / egress / Passback |
| 3 | Hardware options |
| 4 | Assigned readers |
| 5 | User Defined Door Override Timezone |
| 6 | Alarm control |
| 7 | Alarm control levels (deprecated) |
| 9 | User Defined Low Security Timezone |

## Lift Record Subtypes

| Subtype | Description |
|---------|-------------|
| 1 | Lift options |
| 2 | Floor output mapping |
| 3 | Floor input mapping |
| 4 | High level lift options |

## Panel Timing Fields (tc_chtimes)

```sql
accesstest=15, warning=5, suspicion=15, dooraccess=5,
externalsiren=8, rascardandpintimeout=8, securetest=15,
delayholdup=60, service=30, individualtest=5, testerevent=15
```

## System Options (tc_systemoption)

```
testmode, outputcontroller, textword, alarmprefixdigits,
cardoffseta, cardoffsetb, timebeforerotate, lcdrotatespeed,
filmlow, filmout, autodeisolate, usernamefile, tampermonitoring,
displayoneinput, useroffset
```

## Door Fields (tc_door)

```
accesstime, extendedaccesstime, shunttime, extendedshunttime,
warningtime, antipassbacktime, lockrelay, doorinput, doorinput2,
egressinput, dotlrelay, warningrelay, forcedrelay, faultedrelay,
localinterlocks, externalinterlockinput1-3, alarmoption,
modetime, dualcustodytime, cardpintime
```

## Automation Tables

- `tc_automation` - Automation zone records
- `tc_macrologic` - Macro logic records (up to 48 per panel)
- `tc_dgpmacrologic` - DGP macro logic

## Notes

- Field order in database schema may not match wire protocol byte order
- Some fields may be packed/encoded differently on the wire
- Cross-reference with packet captures to map exact byte offsets
