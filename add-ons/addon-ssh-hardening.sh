#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — SSH Hardening (extended)
#  Checks: weak ciphers, algorithms, key exchange advertised by the server
#  Supplements the built-in SSH audit with network-level banner analysis
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="ssh-hardening"
ADDON_DIR="${INSTALL_DIR}/backend/scanner/addons"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

[[ $EUID -eq 0 ]] || { echo -e "${RED}Run as root.${NC}"; exit 1; }
[[ -d "${INSTALL_DIR}" ]] || { echo -e "${RED}HomelabGuard not found at ${INSTALL_DIR}. Run install.sh first.${NC}"; exit 1; }
command -v nmap &>/dev/null || { echo -e "${RED}nmap is required: apt install nmap${NC}"; exit 1; }

echo -e "${CYAN}${BOLD}[HomelabGuard] Installing add-on: ${ADDON_NAME}${NC}"

install_loader() {
  mkdir -p "${ADDON_DIR}"
  if [[ -f "${ADDON_DIR}/__init__.py" ]]; then return; fi
  echo -e "  ${BOLD}→ Installing add-on loader...${NC}"
  cat > "${ADDON_DIR}/__init__.py" << 'PYEOF'
import os, importlib

def run_addons(ip: str) -> list:
    findings = []
    addon_dir = os.path.dirname(__file__)
    for fname in sorted(os.listdir(addon_dir)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        module_name = fname[:-3]
        try:
            mod = importlib.import_module(f"scanner.addons.{module_name}")
            if hasattr(mod, "scan"):
                findings += mod.scan(ip) or []
        except Exception:
            pass
    return findings
PYEOF
  if ! grep -q "from scanner.addons import run_addons" "${INSTALL_DIR}/backend/main.py"; then
    sed -i '/^from notifications/a from scanner.addons import run_addons' "${INSTALL_DIR}/backend/main.py"
  fi
  if ! grep -q "run_addons(node.ip)" "${INSTALL_DIR}/backend/main.py"; then
    sed -i '/findings += cve_check()/a\        if node.ip:\n            findings += run_addons(node.ip)' "${INSTALL_DIR}/backend/main.py"
  fi
  echo -e "  ${GREEN}✓ Loader installed${NC}"
}

write_scanner() {
  cat > "${ADDON_DIR}/ssh_hardening_scan.py" << 'PYEOF'
import socket, subprocess, re

WEAK_CIPHERS = {
    "arcfour", "arcfour128", "arcfour256",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
}

WEAK_KEXALGS = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "gss-group1-sha1-*",
}

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-32@openssh.com", "umac-64@openssh.com",
}

def _port_open(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def _get_ssh_banner(ip: str, port: int = 22) -> str:
    try:
        with socket.create_connection((ip, port), timeout=5) as s:
            return s.recv(256).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

def _nmap_ssh_audit(ip: str) -> dict:
    """Run nmap ssh2-enum-algos script and parse output."""
    try:
        result = subprocess.run(
            ["nmap", "-p", "22", "--script", "ssh2-enum-algos", "-oN", "-", ip],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception:
        return ""

def scan(ip: str) -> list:
    findings = []

    if not _port_open(ip):
        return findings

    # Banner / version
    banner = _get_ssh_banner(ip)
    if banner:
        m = re.search(r"SSH-[\d.]+-OpenSSH_([\d.]+)", banner)
        if m:
            version = tuple(int(x) for x in m.group(1).split(".")[:2])
            if version < (8, 0):
                findings.append({
                    "type": "ssh_outdated_version",
                    "severity": "medium",
                    "message": f"OpenSSH version {m.group(1)} is outdated — upgrade to 8.x+ recommended",
                    "penalty": 7,
                })

    # nmap algorithm audit
    nmap_out = _nmap_ssh_audit(ip)
    if nmap_out:
        # Weak ciphers
        cipher_match = re.search(r"encryption_algorithms.*?\n(.*?)(?:\n\s*\n|\|_)", nmap_out, re.S)
        if cipher_match:
            ciphers = set(re.findall(r"\|\s+(\S+)", cipher_match.group(1)))
            weak = ciphers & WEAK_CIPHERS
            if weak:
                findings.append({
                    "type": "ssh_weak_ciphers",
                    "severity": "medium",
                    "message": f"SSH server advertises weak ciphers: {', '.join(sorted(weak))}",
                    "penalty": 8,
                })

        # Weak KEX
        kex_match = re.search(r"kex_algorithms.*?\n(.*?)(?:\n\s*\n|\|_)", nmap_out, re.S)
        if kex_match:
            kexes = set(re.findall(r"\|\s+(\S+)", kex_match.group(1)))
            weak = kexes & WEAK_KEXALGS
            if weak:
                findings.append({
                    "type": "ssh_weak_kex",
                    "severity": "medium",
                    "message": f"SSH server supports weak key exchange algorithms: {', '.join(sorted(weak))}",
                    "penalty": 8,
                })

        # Weak MACs
        mac_match = re.search(r"mac_algorithms.*?\n(.*?)(?:\n\s*\n|\|_)", nmap_out, re.S)
        if mac_match:
            macs = set(re.findall(r"\|\s+(\S+)", mac_match.group(1)))
            weak = macs & WEAK_MACS
            if weak:
                findings.append({
                    "type": "ssh_weak_macs",
                    "severity": "low",
                    "message": f"SSH server supports weak MAC algorithms: {', '.join(sorted(weak))}",
                    "penalty": 5,
                })

    return findings
PYEOF
  echo -e "  ${GREEN}✓ SSH hardening scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
echo -e "    Checks: OpenSSH version, weak ciphers, weak KEX algorithms, weak MACs"
