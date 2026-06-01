# Internal_scanner
Scan SMB files for interesting data, run AD scans and attacks

# Tools
impacket and SMBConnection

# Installation
pip install impacket --break-system-packages

# Usage
 # Anonymous only
  python internal_scanner.py 192.168.1.10

  # Authenticated (domain optional)
  python internal_scanner.py 192.168.1.10 -u admin -p 'P@ssw0rd' -d CORP

  # Scan specific shares only
  python internal_scanner.py 192.168.1.10 -u admin -p 'P@ssw0rd' -s Finance HR

