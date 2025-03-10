# AutoBAKED
This script automates pentesting tasks:
   1. Bloodhound AD enumeration
   2. Kerberoasting with impacket-GetUserSPNs
   3. SMB shares enumeration with netexec

 Usage:
   ./AutoBAKED.sh -u <username> -p <password> -d <domain> -t <targets_file> [-i <dc_ip>]
