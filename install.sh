#!/usr/bin/env bash
# =============================================================================
#  HomelabGuard — Security Scanner for Proxmox Homelabs
#  Usage: bash install.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="/opt/homelabguard"

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ██╗  ██╗ ██████╗ ███╗   ███╗███████╗██╗      █████╗ ██████╗ "
  echo "  ██║  ██║██╔═══██╗████╗ ████║██╔════╝██║     ██╔══██╗██╔══██╗"
  echo "  ███████║██║   ██║██╔████╔██║█████╗  ██║     ███████║██████╔╝"
  echo "  ██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██╔══██║██╔══██╗"
  echo "  ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗███████╗██║  ██║██████╔╝"
  echo "  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝ "
  echo -e "${NC}${BOLD}         G U A R D  —  Proxmox Security Scanner${NC}"
  echo ""
}

# ── Guards ────────────────────────────────────────────────────────────────────
check_root() {
  [[ $EUID -eq 0 ]] || { echo -e "${RED}Run as root.${NC}"; exit 1; }
}

check_os() {
  command -v apt-get &>/dev/null || { echo -e "${RED}Requires Debian/Ubuntu.${NC}"; exit 1; }
}

# ── Config prompts ────────────────────────────────────────────────────────────
prompt_config() {
  echo -e "${BOLD}=== Configuration ===${NC}\n"

  read -rp "  Proxmox host URL (ex: https://192.168.1.10:8006) : " PROXMOX_HOST
  read -rp "  Proxmox node name                 [default: pve] : " PROXMOX_NODE
  PROXMOX_NODE="${PROXMOX_NODE:-pve}"
  read -rp "  API Token ID   (ex: root@pam!homelabguard)       : " PROXMOX_TOKEN_ID
  read -rsp "  API Token Secret                                 : " PROXMOX_TOKEN_SECRET
  echo ""
  read -rp "  Discord Webhook URL          [leave empty to skip]: " DISCORD_WEBHOOK
  read -rp "  Scan interval in hours              [default: 24] : " SCAN_INTERVAL
  SCAN_INTERVAL="${SCAN_INTERVAL:-24}"
  read -rp "  Web UI port                       [default: 8765] : " WEB_PORT
  WEB_PORT="${WEB_PORT:-8765}"

  echo -e "\n${GREEN}  Configuration saved.${NC}\n"
}

# ── Step 1: Packages ──────────────────────────────────────────────────────────
install_packages() {
  echo -e "${BOLD}[1/6] Installing system packages...${NC}"
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip python3-venv nmap curl wget 2>/dev/null
  echo -e "${GREEN}  ✓ Done${NC}"
}

# ── Step 2: Directories ───────────────────────────────────────────────────────
setup_dirs() {
  echo -e "${BOLD}[2/6] Creating directory structure...${NC}"
  mkdir -p "${INSTALL_DIR}"/{backend/scanner,frontend,data}
  echo -e "${GREEN}  ✓ Done${NC}"
}

# ── Step 3: Write all source files ────────────────────────────────────────────
write_files() {
  echo -e "${BOLD}[3/6] Writing application files...${NC}"

  # .env
  cat > "${INSTALL_DIR}/.env" << EOF
PROXMOX_HOST=${PROXMOX_HOST}
PROXMOX_NODE=${PROXMOX_NODE}
PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
SCAN_INTERVAL_HOURS=${SCAN_INTERVAL}
PORT=${WEB_PORT}
EOF
  chmod 600 "${INSTALL_DIR}/.env"

  # ── requirements.txt ──────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/requirements.txt" << 'PYEOF'
fastapi==0.115.5
uvicorn[standard]==0.32.1
sqlalchemy==2.0.36
python-dotenv==1.0.1
requests==2.32.3
python-nmap==0.7.1
apscheduler==3.10.4
pydantic==2.10.3
PYEOF

  # ── database.py ───────────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/database.py" << 'PYEOF'
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:////opt/homelabguard/data/homelabguard.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
PYEOF

  # ── models.py ─────────────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/models.py" << 'PYEOF'
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.sql import func
from database import Base

class Node(Base):
    __tablename__ = "nodes"
    id           = Column(Integer, primary_key=True)
    vmid         = Column(String, unique=True, index=True)
    name         = Column(String)
    type         = Column(String)   # lxc | qemu
    status       = Column(String)
    ip           = Column(String, nullable=True)
    last_score   = Column(Float, nullable=True)
    last_scan    = Column(DateTime, nullable=True)
    created_at   = Column(DateTime, server_default=func.now())

class Scan(Base):
    __tablename__ = "scans"
    id            = Column(Integer, primary_key=True)
    vmid          = Column(String, index=True)
    score         = Column(Float)
    grade         = Column(String)
    findings_json = Column(Text)
    scan_type     = Column(String)   # manual | scheduled
    created_at    = Column(DateTime, server_default=func.now())
PYEOF

  # ── notifications.py ──────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/notifications.py" << 'PYEOF'
import os, requests
from datetime import datetime, timezone

WEBHOOK = os.getenv("DISCORD_WEBHOOK", "")

def _send(title: str, description: str, color: int = 0x3b82f6):
    if not WEBHOOK:
        return
    try:
        requests.post(WEBHOOK, json={"embeds": [{
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "HomelabGuard"}
        }]}, timeout=5)
    except Exception:
        pass

def notify_scan_complete(name: str, score: float, grade: str, findings: list):
    color = 0x22c55e if grade in ("A", "B") else 0xeab308 if grade == "C" else 0xef4444
    critical = [f for f in findings if f.get("severity") == "critical"]
    desc = f"**Score:** `{score:.0f}/100`  •  Grade **{grade}**\n"
    if critical:
        desc += "\n**Critical findings:**\n"
        for f in critical[:5]:
            desc += f"• {f['message']}\n"
    _send(f"Scan complete — {name}", desc, color)

def notify_critical(node_name: str, message: str):
    _send(f"⚠️ Critical — {node_name}", message, 0xef4444)
PYEOF

  # ── scanner/__init__.py ───────────────────────────────────────────────────
  touch "${INSTALL_DIR}/backend/scanner/__init__.py"

  # ── scanner/proxmox.py ────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/scanner/proxmox.py" << 'PYEOF'
import os, requests, urllib3
urllib3.disable_warnings()

class ProxmoxClient:
    def __init__(self):
        self.host   = os.getenv("PROXMOX_HOST", "").rstrip("/")
        self.tok_id = os.getenv("PROXMOX_TOKEN_ID", "")
        self.tok_sec= os.getenv("PROXMOX_TOKEN_SECRET", "")
        self.node   = os.getenv("PROXMOX_NODE", "pve")
        self.hdrs   = {"Authorization": f"PVEAPIToken={self.tok_id}={self.tok_sec}"}

    def _get(self, path: str):
        r = requests.get(f"{self.host}/api2/json{path}",
                         headers=self.hdrs, verify=False, timeout=10)
        r.raise_for_status()
        return r.json().get("data") or []

    def get_all_guests(self):
        guests = []
        try:
            for g in self._get(f"/nodes/{self.node}/lxc"):
                g["type"] = "lxc"; guests.append(g)
        except Exception:
            pass
        try:
            for g in self._get(f"/nodes/{self.node}/qemu"):
                g["type"] = "qemu"; guests.append(g)
        except Exception:
            pass
        return guests

    def get_lxc_interfaces(self, vmid: str):
        try:
            return self._get(f"/nodes/{self.node}/lxc/{vmid}/interfaces")
        except Exception:
            return []

    def get_lxc_config(self, vmid: str):
        try:
            return self._get(f"/nodes/{self.node}/lxc/{vmid}/config")
        except Exception:
            return {}

    def check_lxc_security(self, vmid: str) -> list:
        findings = []
        cfg = self.get_lxc_config(vmid)
        if isinstance(cfg, dict):
            if cfg.get("unprivileged") == 0 or not cfg.get("unprivileged"):
                findings.append({
                    "type": "privileged_container",
                    "severity": "high",
                    "message": "Container runs in privileged mode — full host access possible",
                    "penalty": 15
                })
            nesting = cfg.get("features", "")
            if "nesting=1" in str(nesting):
                findings.append({
                    "type": "nesting_enabled",
                    "severity": "medium",
                    "message": "Docker/nesting enabled — increases attack surface",
                    "penalty": 5
                })
        return findings
PYEOF

  # ── scanner/nmap_scan.py ──────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/scanner/nmap_scan.py" << 'PYEOF'
import nmap

RISKY_PORTS = {
    21:    "FTP (clear-text credentials)",
    23:    "Telnet (clear-text protocol)",
    445:   "SMB (ransomware target)",
    3389:  "RDP (brute-force target)",
    5900:  "VNC (often unauthenticated)",
    6379:  "Redis (default: no auth)",
    9200:  "Elasticsearch (default: no auth)",
    27017: "MongoDB (default: no auth)",
    2375:  "Docker daemon (unauthenticated)",
    5432:  "PostgreSQL (exposed externally?)",
}

def scan_host(ip: str) -> dict:
    nm = nmap.PortScanner()
    findings = []
    open_ports = []
    try:
        nm.scan(ip, arguments="-sV -T4 --top-ports 1000 --open -Pn", timeout=90)
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port, data in nm[ip][proto].items():
                    if data["state"] == "open":
                        service = data.get("name", "unknown")
                        version = data.get("version", "")
                        open_ports.append({"port": port, "service": service, "version": version})
                        if port in RISKY_PORTS:
                            findings.append({
                                "type": "risky_port",
                                "severity": "critical",
                                "message": f"Port {port} open — {RISKY_PORTS[port]}",
                                "penalty": 15
                            })
        if len(open_ports) > 15:
            findings.append({
                "type": "too_many_open_ports",
                "severity": "medium",
                "message": f"{len(open_ports)} ports open — reduce attack surface",
                "penalty": 10
            })
    except Exception as e:
        findings.append({
            "type": "scan_error", "severity": "info",
            "message": f"Nmap scan failed: {e}", "penalty": 0
        })
    return {"open_ports": open_ports, "findings": findings}
PYEOF

  # ── scanner/cve_check.py ──────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/scanner/cve_check.py" << 'PYEOF'
import subprocess, requests

OSV_API = "https://api.osv.dev/v1/query"

def get_upgradable() -> list:
    try:
        r = subprocess.run(["apt", "list", "--upgradable"],
                           capture_output=True, text=True, timeout=30)
        pkgs = []
        for line in r.stdout.splitlines():
            if "/" in line and "upgradable" in line:
                pkgs.append(line.split("/")[0])
        return pkgs
    except Exception:
        return []

def run_check() -> list:
    pkgs = get_upgradable()
    findings = []

    for pkg in pkgs[:15]:   # cap to avoid OSV rate limits
        try:
            resp = requests.post(OSV_API,
                json={"package": {"name": pkg, "ecosystem": "Debian"}},
                timeout=5)
            if resp.status_code == 200:
                vulns = resp.json().get("vulns", [])
                if vulns:
                    sev = "high" if len(vulns) >= 3 else "medium"
                    findings.append({
                        "type": "vulnerable_package",
                        "severity": sev,
                        "package": pkg,
                        "message": f"Package '{pkg}' has {len(vulns)} known CVE(s) — update required",
                        "penalty": min(5 * len(vulns), 20)
                    })
        except Exception:
            continue

    if len(pkgs) > 0:
        findings.append({
            "type": "outdated_packages",
            "severity": "low" if len(pkgs) < 10 else "medium",
            "message": f"{len(pkgs)} package(s) have available updates",
            "penalty": min(len(pkgs), 10)
        })
    return findings
PYEOF

  # ── scanner/config_audit.py ───────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/scanner/config_audit.py" << 'PYEOF'
import subprocess, os

def check_ssh() -> list:
    findings = []
    path = "/etc/ssh/sshd_config"
    if not os.path.exists(path):
        return findings
    try:
        content = open(path).read().lower()
        if "permitrootlogin yes" in content:
            findings.append({
                "type": "ssh_root_login", "severity": "critical",
                "message": "SSH: PermitRootLogin yes — direct root login allowed",
                "penalty": 20
            })
        if "passwordauthentication yes" in content:
            findings.append({
                "type": "ssh_password_auth", "severity": "high",
                "message": "SSH: PasswordAuthentication yes — brute-force risk",
                "penalty": 15
            })
        if "permitemptypasswords yes" in content:
            findings.append({
                "type": "ssh_empty_pwd", "severity": "critical",
                "message": "SSH: PermitEmptyPasswords yes — extremely dangerous",
                "penalty": 30
            })
    except Exception:
        pass
    return findings

def check_firewall() -> list:
    findings = []
    ufw_active = False
    try:
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
        ufw_active = "active" in r.stdout.lower()
    except FileNotFoundError:
        pass

    ipt_rules = 0
    try:
        r = subprocess.run(["iptables", "-L", "--line-numbers"],
                           capture_output=True, text=True, timeout=5)
        ipt_rules = sum(1 for l in r.stdout.splitlines()
                        if l.strip() and not l.startswith(("Chain", "target", "pkts")))
    except Exception:
        pass

    if not ufw_active and ipt_rules < 3:
        findings.append({
            "type": "no_firewall", "severity": "high",
            "message": "No active firewall detected (UFW inactive, iptables empty)",
            "penalty": 20
        })
    return findings

def check_listening_services() -> list:
    findings = []
    try:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        exposed = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            addr = parts[3]
            if addr.startswith(("0.0.0.0:", ":::")):
                port = int(addr.rsplit(":", 1)[-1])
                if port not in (22, 80, 443, 8080, 8443, 8765):
                    exposed.append(port)
        if exposed:
            findings.append({
                "type": "wide_open_services", "severity": "medium",
                "message": f"Services listening on all interfaces: ports {exposed[:10]}",
                "penalty": min(5 * len(exposed), 20)
            })
    except Exception:
        pass
    return findings

def run_audit() -> list:
    return check_ssh() + check_firewall() + check_listening_services()
PYEOF

  # ── scanner/scoring.py ────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/scanner/scoring.py" << 'PYEOF'
def score_to_grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

def calculate(findings: list) -> tuple:
    penalty = sum(f.get("penalty", 0) for f in findings)
    score   = max(0.0, 100.0 - float(penalty))
    return score, score_to_grade(score)
PYEOF

  # ── main.py ───────────────────────────────────────────────────────────────
  cat > "${INSTALL_DIR}/backend/main.py" << 'PYEOF'
import json, os
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv("/opt/homelabguard/.env")

from database import engine, get_db, SessionLocal
import models
from scanner.proxmox    import ProxmoxClient
from scanner.nmap_scan  import scan_host
from scanner.cve_check  import run_check as cve_check
from scanner.config_audit import run_audit
from scanner.scoring    import calculate
from notifications      import notify_scan_complete

# ── Scheduler ──────────────────────────────────────────────────────────────
from apscheduler.schedulers.background import BackgroundScheduler

def _scheduled_scan_all():
    db = SessionLocal()
    try:
        nodes = db.query(models.Node).filter(models.Node.status == "running").all()
        for node in nodes:
            _do_scan(node.vmid, "scheduled")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    interval = int(os.getenv("SCAN_INTERVAL_HOURS", "24"))
    if interval > 0:
        scheduler = BackgroundScheduler()
        scheduler.add_job(_scheduled_scan_all, "interval", hours=interval)
        scheduler.start()
    yield

app = FastAPI(title="HomelabGuard", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# Serve frontend
FRONTEND = "/opt/homelabguard/frontend"
app.mount("/assets", StaticFiles(directory=FRONTEND + "/assets"), name="assets")

@app.get("/")
def serve_index():
    return FileResponse(FRONTEND + "/index.html")

# ── API ────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "1.0.0"}

@app.get("/api/nodes")
def get_nodes(db: Session = Depends(get_db)):
    return db.query(models.Node).all()

@app.post("/api/sync")
def sync_nodes(db: Session = Depends(get_db)):
    client = ProxmoxClient()
    guests = client.get_all_guests()
    synced = 0
    for g in guests:
        vmid = str(g["vmid"])
        ip   = None
        if g["type"] == "lxc":
            for iface in client.get_lxc_interfaces(vmid):
                if iface.get("name") != "lo" and iface.get("inet"):
                    ip = iface["inet"].split("/")[0]
                    break
        node = db.query(models.Node).filter(models.Node.vmid == vmid).first()
        if not node:
            db.add(models.Node(
                vmid=vmid, name=g.get("name", f"vm-{vmid}"),
                type=g["type"], status=g.get("status", "unknown"), ip=ip
            ))
        else:
            node.status = g.get("status", "unknown")
            node.ip = ip or node.ip
        synced += 1
    db.commit()
    return {"synced": synced}

def _do_scan(vmid: str, scan_type: str = "manual"):
    db = SessionLocal()
    try:
        node = db.query(models.Node).filter(models.Node.vmid == vmid).first()
        if not node:
            return
        findings = []

        # Proxmox config checks (privileged container, etc.)
        if node.type == "lxc":
            client = ProxmoxClient()
            findings += client.check_lxc_security(vmid)

        # Remote port scan
        if node.ip:
            nmap_result = scan_host(node.ip)
            findings += nmap_result["findings"]

        # Local audits (SSH config, firewall, CVEs — run on this host)
        findings += run_audit()
        findings += cve_check()

        score, grade = calculate(findings)

        db.add(models.Scan(
            vmid=vmid, score=score, grade=grade,
            findings_json=json.dumps(findings), scan_type=scan_type
        ))
        node.last_score = score
        node.last_scan  = datetime.now(timezone.utc)
        db.commit()
        notify_scan_complete(node.name, score, grade, findings)
    finally:
        db.close()

@app.post("/api/scan/{vmid}")
def trigger_scan(vmid: str, bg: BackgroundTasks, db: Session = Depends(get_db)):
    if not db.query(models.Node).filter(models.Node.vmid == vmid).first():
        raise HTTPException(404, "Node not found")
    bg.add_task(_do_scan, vmid, "manual")
    return {"status": "started", "vmid": vmid}

@app.post("/api/scan-all")
def scan_all(bg: BackgroundTasks, db: Session = Depends(get_db)):
    nodes = db.query(models.Node).filter(models.Node.status == "running").all()
    for n in nodes:
        bg.add_task(_do_scan, n.vmid, "manual")
    return {"status": "started", "count": len(nodes)}

@app.get("/api/scans/{vmid}")
def get_scans(vmid: str, limit: int = 10, db: Session = Depends(get_db)):
    rows = (db.query(models.Scan)
              .filter(models.Scan.vmid == vmid)
              .order_by(models.Scan.created_at.desc())
              .limit(limit).all())
    return [{
        "id": s.id, "vmid": s.vmid, "score": s.score, "grade": s.grade,
        "findings": json.loads(s.findings_json),
        "scan_type": s.scan_type, "created_at": str(s.created_at)
    } for s in rows]

@app.get("/api/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    nodes  = db.query(models.Node).all()
    scores = [n.last_score for n in nodes if n.last_score is not None]
    dist   = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0, "-": 0}
    critical = []
    for n in nodes:
        if n.last_score is None:
            dist["-"] += 1
        else:
            g = ("A" if n.last_score >= 90 else "B" if n.last_score >= 75
                 else "C" if n.last_score >= 60 else "D" if n.last_score >= 40 else "F")
            dist[g] += 1
            if g in ("D", "F"):
                critical.append({"vmid": n.vmid, "name": n.name,
                                  "score": n.last_score, "grade": g})
    return {
        "total_nodes": len(nodes),
        "scanned_nodes": len(scores),
        "average_score": round(sum(scores) / len(scores), 1) if scores else None,
        "grade_distribution": dist,
        "critical_nodes": critical
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8765")))
PYEOF

  # ── frontend/index.html ───────────────────────────────────────────────────
  mkdir -p "${INSTALL_DIR}/frontend/assets"

  cat > "${INSTALL_DIR}/frontend/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>HomelabGuard</title>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; min-height: 100vh; }
    ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #1e293b; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
    button { cursor: pointer; font-family: inherit; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const { useState, useEffect, useCallback, useRef } = React;

const GRADE_COLOR = { A:'#22c55e', B:'#84cc16', C:'#eab308', D:'#f97316', F:'#ef4444', '-':'#475569' };

function grade(score) {
  if (score === null || score === undefined) return '-';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function ScoreBadge({ score }) {
  const g = grade(score);
  const c = GRADE_COLOR[g];
  return (
    <div style={{
      display:'flex', flexDirection:'column', alignItems:'center',
      background: c + '18', border: `2px solid ${c}`,
      borderRadius: 10, padding: '8px 14px', minWidth: 58
    }}>
      <span style={{ fontSize: 22, fontWeight: 800, color: c, lineHeight: 1 }}>{g}</span>
      {score !== null && score !== undefined &&
        <span style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{Math.round(score)}/100</span>}
    </div>
  );
}

function StatusBadge({ status }) {
  const ok = status === 'running';
  return (
    <span style={{
      fontSize: 11, padding: '2px 8px', borderRadius: 4,
      background: ok ? '#22c55e18' : '#ef444418',
      color: ok ? '#22c55e' : '#ef4444',
      border: `1px solid ${ok ? '#22c55e40' : '#ef444440'}`
    }}>{status}</span>
  );
}

function Spinner() {
  return <span style={{
    display:'inline-block', width:14, height:14,
    border:'2px solid #334155', borderTopColor:'#3b82f6',
    borderRadius:'50%', animation:'spin .7s linear infinite'
  }} />;
}

function NodeCard({ node, onScan, onClick, scanning }) {
  const g   = grade(node.last_score);
  const col = GRADE_COLOR[g];
  const [hov, setHov] = useState(false);

  return (
    <div onClick={() => onClick(node)}
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        background: '#1e293b', border: `1px solid ${hov ? col : '#334155'}`,
        borderRadius: 14, padding: 20, cursor: 'pointer',
        transition: 'border-color .2s, transform .1s',
        transform: hov ? 'translateY(-2px)' : 'none'
      }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12 }}>
        <div style={{ flex:1, minWidth:0 }}>
          <h3 style={{ color:'#f1f5f9', fontSize:15, fontWeight:600, marginBottom:4,
            whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
            {node.name}
          </h3>
          <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
            <span style={{ fontSize:11, color:'#64748b' }}>
              {node.type.toUpperCase()} · VMID {node.vmid}
            </span>
            <StatusBadge status={node.status} />
          </div>
          {node.ip && <div style={{ fontSize:11, color:'#475569', marginTop:4 }}>📡 {node.ip}</div>}
        </div>
        <ScoreBadge score={node.last_score} />
      </div>

      <div style={{ marginTop:14, display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ fontSize:11, color:'#475569' }}>
          {node.last_scan
            ? `Scanned ${new Date(node.last_scan + (node.last_scan.endsWith('Z') ? '' : 'Z')).toLocaleDateString()}`
            : 'Never scanned'}
        </span>
        <button onClick={e => { e.stopPropagation(); onScan(node.vmid); }}
          disabled={scanning === node.vmid}
          style={{
            background:'#1d4ed8', color:'white', border:'none',
            borderRadius:7, padding:'5px 14px', fontSize:12, fontWeight:500,
            display:'flex', alignItems:'center', gap:6
          }}>
          {scanning === node.vmid ? <><Spinner /> Scanning…</> : '⚡ Scan'}
        </button>
      </div>
    </div>
  );
}

const SEV_COLOR = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#3b82f6' };

function FindingRow({ f }) {
  const c = SEV_COLOR[f.severity] || '#6b7280';
  return (
    <div style={{
      padding:'10px 14px', background:'#0f172a',
      borderLeft:`3px solid ${c}`, borderRadius:6, marginBottom:8
    }}>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
        <span style={{ fontSize:10, textTransform:'uppercase', color:c, fontWeight:700 }}>{f.severity}</span>
        {f.penalty > 0 && <span style={{ fontSize:11, color:'#ef4444' }}>−{f.penalty} pts</span>}
      </div>
      <p style={{ color:'#cbd5e1', fontSize:13 }}>{f.message}</p>
    </div>
  );
}

function Modal({ node, onClose }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/scans/${node.vmid}`)
      .then(r => r.json()).then(d => { setScans(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [node.vmid]);

  const latest = scans[0];

  return (
    <div onClick={onClose} style={{
      position:'fixed', inset:0, background:'rgba(0,0,0,.75)',
      display:'flex', alignItems:'center', justifyContent:'center',
      zIndex:1000, padding:20
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background:'#1e293b', border:'1px solid #334155', borderRadius:18,
        padding:28, maxWidth:600, width:'100%', maxHeight:'85vh', overflow:'auto'
      }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
          <div>
            <h2 style={{ color:'#f1f5f9', fontSize:18, fontWeight:700 }}>{node.name}</h2>
            <span style={{ fontSize:12, color:'#64748b' }}>VMID {node.vmid} · {node.type.toUpperCase()}</span>
          </div>
          <button onClick={onClose} style={{
            background:'#334155', border:'none', color:'#94a3b8',
            borderRadius:8, padding:'6px 12px', fontSize:18, lineHeight:1
          }}>×</button>
        </div>

        {loading && <div style={{ textAlign:'center', padding:40, color:'#64748b' }}><Spinner /></div>}
        {!loading && !latest && <p style={{ color:'#64748b' }}>No scans yet. Run a scan first.</p>}

        {latest && (
          <>
            <div style={{
              display:'flex', alignItems:'center', gap:16,
              padding:'12px 16px', background:'#0f172a', borderRadius:10, marginBottom:18
            }}>
              <ScoreBadge score={latest.score} />
              <div>
                <div style={{ color:'#94a3b8', fontSize:12 }}>Latest scan</div>
                <div style={{ color:'#64748b', fontSize:12 }}>
                  {new Date(latest.created_at + (latest.created_at.endsWith('Z')?'':'Z')).toLocaleString()}
                </div>
                <div style={{ color:'#64748b', fontSize:12 }}>
                  {latest.findings.length} finding(s) · {latest.scan_type}
                </div>
              </div>
            </div>

            <h3 style={{ color:'#475569', fontSize:12, textTransform:'uppercase',
              letterSpacing:1, marginBottom:12 }}>Findings</h3>
            {latest.findings.length === 0
              ? <p style={{ color:'#22c55e' }}>✓ No issues found — great job!</p>
              : latest.findings
                  .sort((a,b) => {
                    const o = {critical:0,high:1,medium:2,low:3,info:4};
                    return (o[a.severity]??5)-(o[b.severity]??5);
                  })
                  .map((f,i) => <FindingRow key={i} f={f} />)
            }
          </>
        )}

        {scans.length > 1 && (
          <>
            <h3 style={{ color:'#475569', fontSize:12, textTransform:'uppercase',
              letterSpacing:1, margin:'20px 0 12px' }}>History</h3>
            {scans.slice(1).map(s => (
              <div key={s.id} style={{
                display:'flex', justifyContent:'space-between', alignItems:'center',
                padding:'8px 12px', background:'#0f172a', borderRadius:7, marginBottom:6
              }}>
                <span style={{ fontSize:12, color:'#64748b' }}>
                  {new Date(s.created_at + (s.created_at.endsWith('Z')?'':'Z')).toLocaleString()}
                </span>
                <span style={{ fontWeight:700, color: GRADE_COLOR[s.grade] }}>
                  {s.grade} · {Math.round(s.score)}/100
                </span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color, icon }) {
  return (
    <div style={{
      background:'#1e293b', border:`1px solid ${color}30`,
      borderRadius:14, padding:'20px 24px', textAlign:'center'
    }}>
      <div style={{ fontSize:13, color:'#475569', marginBottom:8 }}>{icon} {label}</div>
      <div style={{ fontSize:32, fontWeight:800, color }}>{value ?? '—'}</div>
    </div>
  );
}

function App() {
  const [nodes, setNodes]         = useState([]);
  const [dashboard, setDashboard] = useState(null);
  const [selected, setSelected]   = useState(null);
  const [loading, setLoading]     = useState(false);
  const [scanning, setScanning]   = useState(null);
  const [toast, setToast]         = useState('');
  const [filter, setFilter]       = useState('all');
  const toastRef = useRef(null);

  const showToast = (msg) => {
    setToast(msg);
    clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToast(''), 6000);
  };

  const fetchAll = useCallback(async () => {
    try {
      const [nr, dr] = await Promise.all([fetch('/api/nodes'), fetch('/api/dashboard')]);
      setNodes(await nr.json());
      setDashboard(await dr.json());
    } catch (e) { console.error(e); }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, 20000);
    return () => clearInterval(id);
  }, [fetchAll]);

  const handleSync = async () => {
    setLoading(true);
    showToast('Syncing with Proxmox…');
    try {
      const r = await fetch('/api/sync', { method:'POST' });
      const d = await r.json();
      showToast(`✓ Synced ${d.synced} node(s)`);
      await fetchAll();
    } catch { showToast('✗ Sync failed — check Proxmox credentials'); }
    setLoading(false);
  };

  const handleScanAll = async () => {
    setLoading(true);
    showToast('Launching scans on all running nodes…');
    try {
      const r = await fetch('/api/scan-all', { method:'POST' });
      const d = await r.json();
      showToast(`✓ ${d.count} scan(s) started — results in ~1 min`);
      setTimeout(fetchAll, 30000);
    } catch { showToast('✗ Failed to start scans'); }
    setLoading(false);
  };

  const handleScan = async (vmid) => {
    setScanning(vmid);
    try {
      await fetch(`/api/scan/${vmid}`, { method:'POST' });
      showToast(`⚡ Scan started for VMID ${vmid}`);
      setTimeout(() => { setScanning(null); fetchAll(); }, 8000);
    } catch { setScanning(null); }
  };

  const filtered = nodes.filter(n => {
    if (filter === 'all')      return true;
    if (filter === 'running')  return n.status === 'running';
    if (filter === 'critical') return ['D','F'].includes(grade(n.last_score));
    if (filter === 'unscanned')return n.last_score === null;
    return true;
  });

  return (
    <div style={{ minHeight:'100vh', background:'#0f172a' }}>

      {/* Header */}
      <header style={{
        background:'#1e293b', borderBottom:'1px solid #334155',
        padding:'14px 28px', display:'flex',
        justifyContent:'space-between', alignItems:'center',
        position:'sticky', top:0, zIndex:100
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <span style={{ fontSize:26 }}>🛡️</span>
          <div>
            <div style={{ fontSize:17, fontWeight:700, color:'#f1f5f9', lineHeight:1 }}>HomelabGuard</div>
            <div style={{ fontSize:11, color:'#475569' }}>Proxmox Security Scanner</div>
          </div>
        </div>
        <div style={{ display:'flex', gap:10, alignItems:'center' }}>
          {toast && (
            <span style={{ fontSize:12, color:'#94a3b8', maxWidth:340,
              background:'#0f172a', padding:'6px 12px', borderRadius:8,
              border:'1px solid #334155' }}>{toast}</span>
          )}
          <button onClick={handleSync} disabled={loading} style={{
            background:'#334155', color:'#e2e8f0', border:'none',
            borderRadius:8, padding:'8px 18px', fontSize:13, fontWeight:500,
            display:'flex', alignItems:'center', gap:6
          }}>
            {loading ? <Spinner /> : '🔄'} Sync Nodes
          </button>
          <button onClick={handleScanAll} disabled={loading} style={{
            background:'#1d4ed8', color:'white', border:'none',
            borderRadius:8, padding:'8px 18px', fontSize:13, fontWeight:500,
            display:'flex', alignItems:'center', gap:6
          }}>
            ⚡ Scan All
          </button>
        </div>
      </header>

      <div style={{ padding:'24px 28px', maxWidth:1400, margin:'0 auto' }}>

        {/* Stats */}
        {dashboard && (
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16, marginBottom:28 }}>
            <StatCard label="Total Nodes"  value={dashboard.total_nodes}   color="#3b82f6" icon="🖥️" />
            <StatCard label="Scanned"      value={dashboard.scanned_nodes} color="#22c55e" icon="✅" />
            <StatCard label="Avg Score"    value={dashboard.average_score ? dashboard.average_score + '/100' : null} color="#a78bfa" icon="📊" />
            <StatCard label="Critical"     value={dashboard.critical_nodes.length} color="#ef4444" icon="🚨" />
          </div>
        )}

        {/* Grade bar */}
        {dashboard && dashboard.scanned_nodes > 0 && (
          <div style={{
            display:'flex', gap:10, marginBottom:24,
            background:'#1e293b', padding:'14px 20px', borderRadius:12
          }}>
            {Object.entries(dashboard.grade_distribution).map(([g, count]) =>
              count > 0 && (
                <div key={g} style={{ display:'flex', alignItems:'center', gap:6 }}>
                  <span style={{
                    width:28, height:28, borderRadius:6, background: GRADE_COLOR[g] + '25',
                    border:`2px solid ${GRADE_COLOR[g]}`, display:'flex',
                    alignItems:'center', justifyContent:'center',
                    fontSize:13, fontWeight:700, color: GRADE_COLOR[g]
                  }}>{g}</span>
                  <span style={{ color:'#64748b', fontSize:13 }}>{count}</span>
                </div>
              )
            )}
            <span style={{ marginLeft:'auto', fontSize:12, color:'#475569', alignSelf:'center' }}>
              Grade distribution
            </span>
          </div>
        )}

        {/* Filter tabs */}
        {nodes.length > 0 && (
          <div style={{ display:'flex', gap:8, marginBottom:20 }}>
            {[
              { key:'all',      label:`All (${nodes.length})` },
              { key:'running',  label:`Running (${nodes.filter(n=>n.status==='running').length})` },
              { key:'critical', label:`Critical (${nodes.filter(n=>['D','F'].includes(grade(n.last_score))).length})` },
              { key:'unscanned',label:`Unscanned (${nodes.filter(n=>n.last_score===null).length})` },
            ].map(tab => (
              <button key={tab.key} onClick={() => setFilter(tab.key)} style={{
                background: filter===tab.key ? '#1d4ed8' : '#1e293b',
                color: filter===tab.key ? 'white' : '#64748b',
                border: `1px solid ${filter===tab.key ? '#1d4ed8' : '#334155'}`,
                borderRadius:8, padding:'6px 14px', fontSize:12, fontWeight:500
              }}>{tab.label}</button>
            ))}
          </div>
        )}

        {/* Node grid */}
        {nodes.length === 0 ? (
          <div style={{
            textAlign:'center', padding:'80px 20px', color:'#334155',
            background:'#1e293b', borderRadius:16, border:'1px dashed #334155'
          }}>
            <div style={{ fontSize:56, marginBottom:16 }}>🖥️</div>
            <p style={{ fontSize:18, color:'#475569', marginBottom:8 }}>No nodes discovered yet</p>
            <p style={{ fontSize:13, color:'#334155' }}>
              Click <strong style={{color:'#94a3b8'}}>Sync Nodes</strong> to discover your Proxmox VMs and LXC containers
            </p>
          </div>
        ) : (
          <div style={{
            display:'grid',
            gridTemplateColumns:'repeat(auto-fill, minmax(290px, 1fr))',
            gap:16
          }}>
            {filtered.map(n => (
              <NodeCard key={n.vmid} node={n}
                onScan={handleScan} onClick={setSelected} scanning={scanning} />
            ))}
            {filtered.length === 0 && (
              <p style={{ color:'#475569', gridColumn:'1/-1', textAlign:'center', padding:40 }}>
                No nodes match this filter.
              </p>
            )}
          </div>
        )}
      </div>

      {selected && (
        <Modal node={selected} onClose={() => { setSelected(null); fetchAll(); }} />
      )}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
</script>
</body>
</html>
HTMLEOF

  echo -e "${GREEN}  ✓ All files written${NC}"
}

# ── Step 4: Python venv ───────────────────────────────────────────────────────
setup_venv() {
  echo -e "${BOLD}[4/6] Installing Python dependencies (this may take a minute)...${NC}"
  python3 -m venv "${INSTALL_DIR}/venv"
  "${INSTALL_DIR}/venv/bin/pip" install -q --upgrade pip
  "${INSTALL_DIR}/venv/bin/pip" install -q -r "${INSTALL_DIR}/backend/requirements.txt"
  echo -e "${GREEN}  ✓ Done${NC}"
}

# ── Step 5: Systemd service ───────────────────────────────────────────────────
setup_systemd() {
  echo -e "${BOLD}[5/6] Creating systemd service...${NC}"
  cat > /etc/systemd/system/homelabguard.service << EOF
[Unit]
Description=HomelabGuard Security Scanner
After=network.target

[Service]
Type=exec
User=root
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn main:app --host 0.0.0.0 --port ${WEB_PORT} --workers 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable homelabguard --quiet
  echo -e "${GREEN}  ✓ Service registered${NC}"
}

# ── Step 6: Start ─────────────────────────────────────────────────────────────
start_service() {
  echo -e "${BOLD}[6/6] Starting HomelabGuard...${NC}"
  systemctl restart homelabguard
  sleep 3
  if systemctl is-active --quiet homelabguard; then
    echo -e "${GREEN}  ✓ Service is running${NC}"
  else
    echo -e "${RED}  ✗ Service failed to start. Check logs:${NC}"
    echo -e "    journalctl -u homelabguard -n 30"
    exit 1
  fi
}

# ── Done ──────────────────────────────────────────────────────────────────────
print_done() {
  IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_LXC_IP")
  echo ""
  echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║     HomelabGuard installed successfully!     ║${NC}"
  echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${BOLD}Dashboard :${NC} ${CYAN}http://${IP}:${WEB_PORT}${NC}"
  echo -e "  ${BOLD}API docs  :${NC} ${CYAN}http://${IP}:${WEB_PORT}/docs${NC}"
  echo ""
  echo -e "  ${BOLD}Next steps:${NC}"
  echo -e "  1. Open the dashboard in your browser"
  echo -e "  2. Click ${YELLOW}Sync Nodes${NC} to discover your Proxmox VMs/LXC"
  echo -e "  3. Click ${YELLOW}Scan All${NC} to run your first security scan"
  echo ""
  echo -e "  ${BOLD}Useful commands:${NC}"
  echo -e "  ${YELLOW}systemctl status homelabguard${NC}   — service status"
  echo -e "  ${YELLOW}journalctl -u homelabguard -f${NC}   — live logs"
  echo -e "  ${YELLOW}systemctl restart homelabguard${NC}  — restart"
  echo -e "  ${YELLOW}cat ${INSTALL_DIR}/.env${NC}          — view config"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
print_banner
check_root
check_os
prompt_config
install_packages
setup_dirs
write_files
setup_venv
setup_systemd
start_service
print_done
