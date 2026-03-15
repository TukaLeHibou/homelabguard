#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — WordPress
#  Checks: xmlrpc, wp-login exposure, version leaks, uploads dir, debug mode
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="wordpress"
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
  cat > "${ADDON_DIR}/wordpress_scan.py" << 'PYEOF'
import re, requests, urllib3
urllib3.disable_warnings()

def _get(url: str, timeout: int = 5):
    return requests.get(url, verify=False, timeout=timeout, allow_redirects=True)

def _is_wordpress(text: str) -> bool:
    return any(x in text.lower() for x in ("wp-content", "wp-includes", "wordpress"))

def scan(ip: str) -> list:
    findings = []
    is_wp = False

    for scheme in ("http", "https"):
        try:
            r = _get(f"{scheme}://{ip}")
            if _is_wordpress(r.text):
                is_wp = True

                # Version from meta generator
                m = re.search(r'<meta[^>]+generator[^>]+WordPress\s+([\d.]+)', r.text, re.I)
                if m:
                    findings.append({
                        "type": "wordpress_version_exposure",
                        "severity": "medium",
                        "message": f"WordPress version exposed in meta generator: {m.group(1)}",
                        "penalty": 5,
                    })
                break
        except Exception:
            pass

    # Check common paths regardless (WP might redirect index)
    for scheme in ("http", "https"):
        # xmlrpc.php — brute-force amplification vector
        try:
            r = _get(f"{scheme}://{ip}/xmlrpc.php", timeout=3)
            if r.status_code == 200 and "xml" in r.text.lower():
                findings.append({
                    "type": "wordpress_xmlrpc_exposed",
                    "severity": "high",
                    "message": "WordPress xmlrpc.php is accessible — enables brute-force amplification attacks",
                    "penalty": 10,
                })
                is_wp = True
        except Exception:
            pass

        if not is_wp:
            break

        # wp-login.php without lockout
        try:
            r = _get(f"{scheme}://{ip}/wp-login.php", timeout=3)
            if r.status_code == 200 and "user_login" in r.text:
                findings.append({
                    "type": "wordpress_login_exposed",
                    "severity": "medium",
                    "message": "WordPress wp-login.php accessible — ensure brute-force protection is in place",
                    "penalty": 5,
                })
        except Exception:
            pass

        # readme.html / license.txt — version disclosure
        for path in ("/readme.html", "/license.txt", "/wp-admin/readme.html"):
            try:
                r = _get(f"{scheme}://{ip}{path}", timeout=3)
                if r.status_code == 200 and "wordpress" in r.text.lower():
                    findings.append({
                        "type": "wordpress_readme_exposed",
                        "severity": "low",
                        "message": f"{path} is publicly accessible — leaks WordPress version",
                        "penalty": 3,
                    })
                    break
            except Exception:
                pass

        # wp-content/uploads directory listing
        try:
            r = _get(f"{scheme}://{ip}/wp-content/uploads/", timeout=3)
            if r.status_code == 200 and "index of" in r.text.lower():
                findings.append({
                    "type": "wordpress_uploads_listing",
                    "severity": "medium",
                    "message": "WordPress uploads directory listing is enabled",
                    "penalty": 7,
                })
        except Exception:
            pass

        # debug.log
        try:
            r = _get(f"{scheme}://{ip}/wp-content/debug.log", timeout=3)
            if r.status_code == 200 and len(r.text) > 50:
                findings.append({
                    "type": "wordpress_debug_log_exposed",
                    "severity": "high",
                    "message": "WordPress debug.log is publicly accessible — may contain credentials and stack traces",
                    "penalty": 12,
                })
        except Exception:
            pass

        break

    return findings
PYEOF
  echo -e "  ${GREEN}✓ WordPress scanner module written${NC}"
}

install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
