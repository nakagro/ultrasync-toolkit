# Security Policy

## Important notice

This toolkit communicates with alarm panels. Misuse could compromise physical security.

**Only use this toolkit with panels you own or have explicit authorization to access.**

## Reporting vulnerabilities

If you discover a security vulnerability in this toolkit, please report it privately:

1. **Do not** open a public GitHub issue
2. Email the maintainer directly (see repository contact info)
3. Include steps to reproduce and potential impact

## Credential handling

- **Never commit credentials** — `.env` files are gitignored for a reason
- **Never post credentials in issues** — even partial ones
- **Never share raw panel captures** — they contain identifying information

## What to avoid in issues and PRs

- Panel serial numbers (SID)
- UltraSync passcodes or PINs
- Zone/area names from your installation
- IP addresses or hostnames
- Raw protocol captures from live panels
- Screenshots showing panel identifiers

## Safe examples

When reporting issues, use sanitized examples:
- Replace real SIDs with `123456789012`
- Replace real IPs with `192.168.1.100`
- Replace zone names with generic labels like `Zone 1`, `Front Door`
- Redact any authentication payloads

## Panel security

This toolkit currently only performs read operations. If control operations (arm/disarm) are added in the future, they will be clearly documented and require explicit user action.
