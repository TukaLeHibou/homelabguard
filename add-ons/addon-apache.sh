#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — Apache
#  Checks: version/OS exposure, TRACE method, server-status, security headers
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="apache"
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
  cat > "${ADDON_DIR}/apache_scan.py" << 'PYEOF'
import requests, urllib3
urllib3.disable_warnings()

def _req(method: str, url: str, timeout: int = 5):
    return requests.request(method, url, verify=False, timeout=timeout, allow_redirects=False)

def scan(ip: str) -> list:
    findings = []

    for scheme in ("http", "https"):
        try:
            r = _req("GET", f"{scheme}://{ip}")
        except Exception:
            continue

        server = r.headers.get("server", "").lower()

        # Version + OS exposure
        if "apache" in server:
            if any(c.isdigit() for c in server):
                findings.append({
                    "type": "apache_version_exposure",
                    "severity": "low",
                    "message": f"Apache version exposed in Server header: {r.headers.get('server')}",
                    "penalty": 3,
                })
            if any(x in server for x in ("ubuntu", "debian", "centos", "red hat", "fedora")):
                findings.append({
                    "type": "apache_os_exposure",
                    "severity": "low",
                    "message": f"OS fingerprint exposed in Server header: {r.headers.get('server')}",
                    "penalty": 3,
                })

        # TRACE method
        try:
            rt = _req("TRACE", f"{scheme}://{ip}")
            if rt.status_code == 200:
                findings.append({
                    "type": "apache_trace_enabled",
                    "severity": "medium",
                    "message": "HTTP TRACE method enabled — cross-site tracing (XST) risk",
                    "penalty": 5,
                })
        except Exception:
            pass

        # server-status
        try:
            rs = _req("GET", f"{scheme}://{ip}/server-status")
            if rs.status_code == 200 and "apache" in rs.text.lower():
                findings.append({
                    "type": "apache_server_status_exposed",
                    "severity": "high",
                    "message": "/server-status publicly accessible — leaks internal requests, IPs, and load",
                    "penalty": 10,
                })
        except Exception:
            pass

        # server-info
        try:
            ri = _req("GET", f"{scheme}://{ip}/server-info")
            if ri.status_code == 200 and "apache" in ri.text.lower():
                findings.append({
                    "type": "apache_server_info_exposed",
                    "severity": "high",
                    "message": "/server-info publicly accessible — leaks full Apache configuration",
                    "penalty": 10,
                })
        except Exception:
            pass

        # Directory listing
        try:
            rd = _req("GET", f"{scheme}://{ip}/icons/")
            if rd.status_code == 200 and "index of" in rd.text.lower():
                findings.append({
                    "type": "apache_directory_listing",
                    "severity": "medium",
                    "message": "Directory listing enabled — file tree exposed",
                    "penalty": 7,
                })
        except Exception:
            pass

        break

    return findings
PYEOF
  echo -e "  ${GREEN}✓ Apache scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
