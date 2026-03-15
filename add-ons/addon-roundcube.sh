#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — Roundcube
#  Checks: version exposure, temp/logs dirs, installer left behind, default paths
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="roundcube"
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
  cat > "${ADDON_DIR}/roundcube_scan.py" << 'PYEOF'
import re, requests, urllib3
urllib3.disable_warnings()

RC_PATHS      = ["/roundcube", "/webmail", "/mail", "/rc"]
EXPOSED_PATHS = [
    "/roundcube/installer",  "/webmail/installer",
    "/roundcube/logs",       "/webmail/logs",
    "/roundcube/temp",       "/webmail/temp",
    "/roundcube/config/config.inc.php",
]

def _get(url: str, timeout: int = 5):
    return requests.get(url, verify=False, timeout=timeout, allow_redirects=True)

def _is_roundcube(text: str) -> bool:
    return any(x in text.lower() for x in ("roundcube", "roundcubemail", "rcmloginuser"))

def scan(ip: str) -> list:
    findings = []
    rc_base = None

    for scheme in ("http", "https"):
        for path in RC_PATHS:
            try:
                r = _get(f"{scheme}://{ip}{path}")
                if r.status_code == 200 and _is_roundcube(r.text):
                    rc_base = f"{scheme}://{ip}{path}"

                    # Version from HTML
                    m = re.search(r'roundcube[\s/\-_]?(?:webmail[\s/\-_]?)?(\d+\.\d+[\.\d]*)', r.text, re.I)
                    if m:
                        findings.append({
                            "type": "roundcube_version_exposure",
                            "severity": "low",
                            "message": f"Roundcube version exposed in HTML source: {m.group(1)}",
                            "penalty": 3,
                        })
                    break
            except Exception:
                pass
        if rc_base:
            break

    if not rc_base:
        return findings

    # Installer left accessible
    for path in ["/roundcube/installer", "/webmail/installer", "/installer"]:
        for scheme in ("http", "https"):
            try:
                r = _get(f"{scheme}://{ip}{path}", timeout=3)
                if r.status_code == 200 and "roundcube" in r.text.lower():
                    findings.append({
                        "type": "roundcube_installer_exposed",
                        "severity": "critical",
                        "message": f"Roundcube installer accessible at {path} — allows full reconfiguration",
                        "penalty": 20,
                    })
            except Exception:
                pass

    # Log and temp directories
    for path in ["/roundcube/logs", "/roundcube/temp", "/webmail/logs", "/webmail/temp"]:
        for scheme in ("http", "https"):
            try:
                r = _get(f"{scheme}://{ip}{path}", timeout=3)
                if r.status_code == 200 and "index of" in r.text.lower():
                    findings.append({
                        "type": "roundcube_dir_exposed",
                        "severity": "high",
                        "message": f"Roundcube directory listing accessible: {path} — may expose session data",
                        "penalty": 10,
                    })
            except Exception:
                pass

    return findings
PYEOF
  echo -e "  ${GREEN}✓ Roundcube scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
