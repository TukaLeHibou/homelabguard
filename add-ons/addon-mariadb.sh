#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — MariaDB / MySQL / PostgreSQL
#  Checks: exposed database ports, unauthenticated access
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="mariadb"
ADDON_DIR="${INSTALL_DIR}/backend/scanner/addons"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

[[ $EUID -eq 0 ]] || { echo -e "${RED}Run as root.${NC}"; exit 1; }
[[ -d "${INSTALL_DIR}" ]] || { echo -e "${RED}HomelabGuard not found at ${INSTALL_DIR}. Run install.sh first.${NC}"; exit 1; }

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
  cat > "${ADDON_DIR}/mariadb_scan.py" << 'PYEOF'
import socket

DB_PORTS = {
    3306: ("mysql_exposed",      "critical", "MySQL/MariaDB port 3306 exposed — database should never be reachable from the network", 20),
    5432: ("postgres_exposed",   "critical", "PostgreSQL port 5432 exposed — database should never be reachable from the network", 20),
    1433: ("mssql_exposed",      "critical", "MSSQL port 1433 exposed — database should never be reachable from the network", 20),
    27017:("mongodb_exposed",    "critical", "MongoDB port 27017 exposed — often runs without authentication by default", 20),
    6379: ("redis_exposed",      "critical", "Redis port 6379 exposed — default config has no authentication", 20),
    5984: ("couchdb_exposed",    "high",     "CouchDB port 5984 exposed — check authentication is enabled", 15),
    9042: ("cassandra_exposed",  "high",     "Cassandra port 9042 exposed — verify access controls", 15),
}

def _port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def scan(ip: str) -> list:
    findings = []
    for port, (ftype, severity, msg, penalty) in DB_PORTS.items():
        if _port_open(ip, port):
            findings.append({
                "type": ftype,
                "severity": severity,
                "message": msg,
                "penalty": penalty,
            })
    return findings
PYEOF
  echo -e "  ${GREEN}✓ MariaDB/DB scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
echo -e "    Covers: MySQL/MariaDB, PostgreSQL, MSSQL, MongoDB, Redis, CouchDB, Cassandra"
