#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard Add-on — nginx
#  Checks: version exposure, security headers, default page, status endpoint
#  Run inside the HomelabGuard LXC as root
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/homelabguard"
ADDON_NAME="nginx"
ADDON_DIR="${INSTALL_DIR}/backend/scanner/addons"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

[[ $EUID -eq 0 ]] || { echo -e "${RED}Run as root.${NC}"; exit 1; }
[[ -d "${INSTALL_DIR}" ]] || { echo -e "${RED}HomelabGuard not found at ${INSTALL_DIR}. Run install.sh first.${NC}"; exit 1; }

echo -e "${CYAN}${BOLD}[HomelabGuard] Installing add-on: ${ADDON_NAME}${NC}"

# ── 1. Bootstrap the addon loader (idempotent) ────────────────────────────────
install_loader() {
  mkdir -p "${ADDON_DIR}"

  if [[ -f "${ADDON_DIR}/__init__.py" ]]; then
    return
  fi

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

  # Patch main.py — add import
  if ! grep -q "from scanner.addons import run_addons" "${INSTALL_DIR}/backend/main.py"; then
    sed -i '/^from notifications/a from scanner.addons import run_addons' \
      "${INSTALL_DIR}/backend/main.py"
  fi

  # Patch main.py — add call inside _do_scan after cve_check()
  if ! grep -q "run_addons(node.ip)" "${INSTALL_DIR}/backend/main.py"; then
    sed -i '/findings += cve_check()/a\        if node.ip:\n            findings += run_addons(node.ip)' \
      "${INSTALL_DIR}/backend/main.py"
  fi

  echo -e "  ${GREEN}✓ Loader installed${NC}"
}

# ── 2. Write the nginx scanner module ─────────────────────────────────────────
write_scanner() {
  cat > "${ADDON_DIR}/nginx_scan.py" << 'PYEOF'
import requests, urllib3
urllib3.disable_warnings()

SECURITY_HEADERS = {
    "x-frame-options":           ("clickjacking_missing_xfo",   "medium", "Missing X-Frame-Options header — clickjacking risk", 5),
    "x-content-type-options":    ("missing_xcto",               "low",    "Missing X-Content-Type-Options header", 3),
    "strict-transport-security": ("missing_hsts",               "medium", "Missing Strict-Transport-Security (HSTS) header", 5),
    "content-security-policy":   ("missing_csp",                "medium", "Missing Content-Security-Policy header", 5),
    "x-xss-protection":          ("missing_xxss",               "low",    "Missing X-XSS-Protection header", 2),
}

def _get(url: str, timeout: int = 5):
    return requests.get(url, verify=False, timeout=timeout, allow_redirects=True)

def scan(ip: str) -> list:
    findings = []

    for scheme in ("http", "https"):
        try:
            r = _get(f"{scheme}://{ip}")
        except Exception:
            continue

        server = r.headers.get("server", "").lower()

        # Version exposure
        if "nginx" in server and any(c.isdigit() for c in server):
            findings.append({
                "type": "nginx_version_exposure",
                "severity": "low",
                "message": f"nginx version exposed in Server header: {r.headers.get('server')}",
                "penalty": 3,
            })

        # Default page
        if "welcome to nginx" in r.text.lower():
            findings.append({
                "type": "nginx_default_page",
                "severity": "low",
                "message": "nginx default test page is publicly accessible",
                "penalty": 3,
            })

        # Security headers
        for header, (ftype, severity, msg, penalty) in SECURITY_HEADERS.items():
            if header not in {k.lower() for k in r.headers}:
                findings.append({"type": ftype, "severity": severity, "message": msg, "penalty": penalty})

        break  # stop after first successful scheme

    # nginx status endpoint
    for scheme in ("http", "https"):
        try:
            r = _get(f"{scheme}://{ip}/nginx_status", timeout=3)
            if r.status_code == 200 and "active connections" in r.text.lower():
                findings.append({
                    "type": "nginx_status_exposed",
                    "severity": "medium",
                    "message": "/nginx_status endpoint publicly accessible — leaks connection metrics",
                    "penalty": 5,
                })
                break
        except Exception:
            pass

    return findings
PYEOF

  echo -e "  ${GREEN}✓ nginx scanner module written${NC}"
}

# ── Run ───────────────────────────────────────────────────────────────────────
install_loader
write_scanner

systemctl restart homelabguard
echo -e "${GREEN}${BOLD}[✓] Add-on '${ADDON_NAME}' installed and service restarted.${NC}"
echo -e "    Scans will now include nginx security checks on nodes with HTTP/HTTPS services."
