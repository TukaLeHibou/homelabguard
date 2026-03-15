#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — PHP
#  Checks: version exposure, phpinfo() pages, exposed composer/config files
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="php"
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
  cat > "${ADDON_DIR}/php_scan.py" << 'PYEOF'
import requests, urllib3
urllib3.disable_warnings()

PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/php.php", "/php_info.php",
    "/test.php", "/phptest.php", "/i.php",
]

SENSITIVE_PATHS = [
    "/composer.json", "/composer.lock", "/.env",
    "/config.php", "/configuration.php", "/wp-config.php.bak",
]

def _get(url: str, timeout: int = 5):
    return requests.get(url, verify=False, timeout=timeout, allow_redirects=True)

def scan(ip: str) -> list:
    findings = []
    found_php = False

    for scheme in ("http", "https"):
        try:
            r = _get(f"{scheme}://{ip}")
        except Exception:
            continue

        powered = r.headers.get("x-powered-by", "").lower()
        if "php" in powered:
            found_php = True
            if any(c.isdigit() for c in powered):
                findings.append({
                    "type": "php_version_exposure",
                    "severity": "medium",
                    "message": f"PHP version exposed in X-Powered-By header: {r.headers.get('x-powered-by')}",
                    "penalty": 7,
                })

        # phpinfo() pages
        for path in PHPINFO_PATHS:
            try:
                rp = _get(f"{scheme}://{ip}{path}", timeout=3)
                if rp.status_code == 200 and "phpinfo()" in rp.text:
                    findings.append({
                        "type": "phpinfo_exposed",
                        "severity": "high",
                        "message": f"phpinfo() page accessible at {path} — full server configuration leaked",
                        "penalty": 15,
                    })
                    found_php = True
            except Exception:
                pass

        # Sensitive files
        for path in SENSITIVE_PATHS:
            try:
                rp = _get(f"{scheme}://{ip}{path}", timeout=3)
                if rp.status_code == 200 and len(rp.text) > 10:
                    findings.append({
                        "type": "sensitive_file_exposed",
                        "severity": "critical",
                        "message": f"Sensitive file publicly accessible: {path}",
                        "penalty": 20,
                    })
            except Exception:
                pass

        break

    return findings
PYEOF
  echo -e "  ${GREEN}✓ PHP scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
