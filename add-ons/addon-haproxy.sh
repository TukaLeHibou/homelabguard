#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — HAProxy
#  Checks: stats page exposure, unauthenticated access, version in headers
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="haproxy"
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
  cat > "${ADDON_DIR}/haproxy_scan.py" << 'PYEOF'
import requests, urllib3
urllib3.disable_warnings()

STATS_PORTS  = [1936, 8080, 8404, 9000]
STATS_PATHS  = ["/haproxy?stats", "/stats", "/admin?stats"]

def _get(url: str, timeout: int = 4):
    return requests.get(url, verify=False, timeout=timeout, allow_redirects=True)

def scan(ip: str) -> list:
    findings = []

    for port in STATS_PORTS:
        for path in STATS_PATHS:
            for scheme in ("http", "https"):
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    r = _get(url)
                    if r.status_code == 200 and (
                        "haproxy" in r.text.lower() or "statistics report" in r.text.lower()
                    ):
                        # Check if auth is required
                        auth_required = r.status_code == 401 or "www-authenticate" in {
                            k.lower() for k in r.headers
                        }
                        if not auth_required:
                            findings.append({
                                "type": "haproxy_stats_exposed",
                                "severity": "high",
                                "message": f"HAProxy stats page unauthenticated at {url} — exposes backend topology and traffic",
                                "penalty": 10,
                            })
                        return findings  # found it, stop scanning ports
                except Exception:
                    pass

    # Check version in headers on standard ports
    for scheme in ("http", "https"):
        for port in (80, 443, 8080):
            try:
                r = _get(f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}")
                server = r.headers.get("server", "").lower()
                via = r.headers.get("via", "").lower()
                if "haproxy" in server or "haproxy" in via:
                    if any(c.isdigit() for c in (server + via)):
                        findings.append({
                            "type": "haproxy_version_exposure",
                            "severity": "low",
                            "message": f"HAProxy version exposed in response headers",
                            "penalty": 3,
                        })
                    break
            except Exception:
                pass

    return findings
PYEOF
  echo -e "  ${GREEN}✓ HAProxy scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
