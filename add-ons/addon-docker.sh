#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — Docker
#  Checks: unauthenticated Docker API, Portainer exposure, registry exposure
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="docker"
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
  cat > "${ADDON_DIR}/docker_scan.py" << 'PYEOF'
import requests, urllib3
urllib3.disable_warnings()

def _get(url: str, timeout: int = 4):
    return requests.get(url, verify=False, timeout=timeout)

def scan(ip: str) -> list:
    findings = []

    # Docker API — unauthenticated (port 2375)
    try:
        r = _get(f"http://{ip}:2375/version")
        if r.status_code == 200 and "ApiVersion" in r.text:
            findings.append({
                "type": "docker_api_exposed",
                "severity": "critical",
                "message": "Docker API exposed unauthenticated on port 2375 — full host takeover possible",
                "penalty": 25,
            })
    except Exception:
        pass

    # Docker API — TLS (port 2376), check if accessible without client cert
    try:
        r = _get(f"https://{ip}:2376/version")
        if r.status_code == 200 and "ApiVersion" in r.text:
            findings.append({
                "type": "docker_api_tls_no_mtls",
                "severity": "high",
                "message": "Docker TLS API on port 2376 responds without client certificate — mTLS not enforced",
                "penalty": 15,
            })
    except Exception:
        pass

    # Portainer — port 9000 / 9443
    for port, scheme in [(9000, "http"), (9443, "https")]:
        try:
            r = _get(f"{scheme}://{ip}:{port}/api/status")
            if r.status_code == 200 and "portainer" in r.text.lower():
                findings.append({
                    "type": "portainer_exposed",
                    "severity": "high",
                    "message": f"Portainer accessible on port {port} — verify authentication is enabled",
                    "penalty": 10,
                })
                break
        except Exception:
            pass

    # Docker registry — port 5000
    try:
        r = _get(f"http://{ip}:5000/v2/")
        if r.status_code in (200, 401):
            if r.status_code == 200:
                findings.append({
                    "type": "docker_registry_unauthenticated",
                    "severity": "critical",
                    "message": "Docker registry on port 5000 is unauthenticated — anyone can push/pull images",
                    "penalty": 20,
                })
            else:
                findings.append({
                    "type": "docker_registry_exposed",
                    "severity": "medium",
                    "message": "Docker registry exposed on port 5000 — ensure access is restricted to trusted networks",
                    "penalty": 5,
                })
    except Exception:
        pass

    return findings
PYEOF
  echo -e "  ${GREEN}✓ Docker scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
