# Internal_scanner
Scan SMB files for interesting data, run AD scans and attacks

# Installation
pip install impacket --break-system-packages

# Usage
 # Anonymous only
  python smb_scanner.py 192.168.1.10

  # Authenticated (domain optional)
  python smb_scanner.py 192.168.1.10 -u admin -p 'P@ssw0rd' -d CORP

  # Scan specific shares only
  python smb_scanner.py 192.168.1.10 -u admin -p 'P@ssw0rd' -s Finance HR

