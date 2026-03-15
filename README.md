<div align="center">

```
  ██╗  ██╗ ██████╗ ███╗   ███╗███████╗██╗      █████╗ ██████╗
  ██║  ██║██╔═══██╗████╗ ████║██╔════╝██║     ██╔══██╗██╔══██╗
  ███████║██║   ██║██╔████╔██║█████╗  ██║     ███████║██████╔╝
  ██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██╔══██║██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗███████╗██║  ██║██████╔╝
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝
```

**Security scanner for Proxmox homelabs — self-hosted, zero telemetry.**

[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Proxmox%20VE-E57000?style=flat-square&logo=proxmox&logoColor=white)](https://www.proxmox.com)
[![Python](https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Self-hosted](https://img.shields.io/badge/self--hosted-100%25-22c55e?style=flat-square)](#)

[🇫🇷 Version française](README.fr.md)

</div>

---

<!-- Replace with an actual screenshot: docs/screenshot.png -->
<!-- ![HomelabGuard dashboard](docs/screenshot.png) -->

## What is this?

HomelabGuard is a one-command security scanner that lives inside a Proxmox LXC container and continuously audits your entire homelab infrastructure.

It connects to the Proxmox API, discovers every LXC and VM on your node, runs security checks against each one (port scans, config audits, CVE detection), computes a security score, and surfaces everything in a clean web dashboard. Alerts go straight to Discord when something critical is found.

No cloud. No accounts. No agents to install on guests. Just a single bash script.

---

## Features

| | |
|---|---|
| **Auto-discovery** | Syncs all LXC containers and QEMU VMs from Proxmox API |
| **Port scanning** | nmap-based scan, flags risky services (FTP, Telnet, RDP, Redis...) |
| **Config audits** | Detects privileged containers, nesting, missing firewall rules |
| **CVE detection** | Checks installed packages against known vulnerability databases |
| **Security scoring** | 0–100 score with A/B/C/D/F grade per node |
| **Dashboard** | Real-time web UI, grade distribution, critical node alerts |
| **Scheduled scans** | Automatic re-scan at a configurable interval |
| **Discord alerts** | Webhook notifications for critical findings and scan results |

---

## Stack

```
┌─────────────────────────────────────────┐
│              Web UI (React 18)          │  ← served at :8765
├─────────────────────────────────────────┤
│           FastAPI + APScheduler         │  ← REST API + cron
├──────────────┬──────────────────────────┤
│  SQLite DB   │   Scanner modules        │
│  (SQLAlchemy)│   proxmox · nmap · audit │
└──────────────┴──────────┬───────────────┘
                          │  Proxmox API (HTTPS)
                    ┌─────▼──────┐
                    │ Proxmox VE │
                    │  node(s)   │
                    └────────────┘
```

- **Backend** — Python 3.11, FastAPI, SQLAlchemy, APScheduler
- **Scanner** — python-nmap, Proxmox API v2, custom audit modules
- **Frontend** — React 18 (no build step), dark UI
- **Storage** — SQLite, single file at `/opt/homelabguard/data/`
- **Deploy** — systemd service, runs inside a Debian LXC

---

## Quick start

> **Requirements:** a Debian/Ubuntu LXC on Proxmox, and a Proxmox API token.

### 1 — Create a Proxmox API token

On your Proxmox host:

```bash
pveum user token add root@pam homelabguard --privsep=0
```

Copy the token ID (`root@pam!homelabguard`) and the generated secret.

### 2 — Run the installer inside your LXC

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/youruser/homelabguard/main/install.sh)
```

The installer will ask for:

```
Proxmox host URL   →  https://192.168.1.10:8006
Proxmox node name  →  pve
API Token ID       →  root@pam!homelabguard
API Token Secret   →  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Discord Webhook    →  (optional)
Scan interval (h)  →  24
Web UI port        →  8765
```

### 3 — Open the dashboard

```
http://<lxc-ip>:8765
```

Click **Sync Nodes** → all your LXCs and VMs appear. Click **Scan All** to run the first audit.

---

## API

The backend exposes a REST API consumed by the UI — you can also call it directly.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Service health check |
| `GET` | `/api/nodes` | List all discovered nodes |
| `POST` | `/api/sync` | Sync nodes from Proxmox |
| `POST` | `/api/scan/{vmid}` | Trigger scan on a specific node |
| `POST` | `/api/scan-all` | Trigger scan on all running nodes |
| `GET` | `/api/scans/{vmid}` | Get scan history for a node |
| `GET` | `/api/dashboard` | Aggregated stats and grade distribution |

Example:

```bash
curl http://localhost:8765/api/dashboard | jq
```

```json
{
  "total_nodes": 13,
  "scanned_nodes": 13,
  "average_score": 74.3,
  "grade_distribution": { "A": 3, "B": 5, "C": 3, "D": 1, "F": 1, "-": 0 },
  "critical_nodes": [
    { "vmid": "108", "name": "old-minecraft", "score": 38.0, "grade": "F" }
  ]
}
```

---

## Security scoring

Each scan starts at **100** and deductions are applied per finding:

| Finding | Severity | Penalty |
|---------|----------|---------|
| Privileged LXC container | `high` | −15 |
| Risky open port (Telnet, RDP…) | `high` | −10 |
| Nesting / Docker enabled | `medium` | −5 |
| No firewall detected | `medium` | −5 |
| SSH root login allowed | `medium` | −5 |
| Known CVE in installed package | `critical` | −20 |

Final grade: **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 40 · **F** < 40

---

## Add-ons

Once HomelabGuard is installed, you can extend scan coverage by running add-on scripts from inside the LXC. Each add-on installs a new scanner module and plugs into the existing pipeline automatically — no manual wiring required.

### How it works

The first add-on you install sets up a dynamic plugin loader inside the backend. Every subsequent add-on just drops a Python module into `scanner/addons/` and it gets picked up automatically on the next scan.

### Installing an add-on

```bash
# From inside the HomelabGuard LXC, as root:
bash <(curl -fsSL https://raw.githubusercontent.com/youruser/homelabguard/main/add-ons/addon-nginx.sh)
```

Or copy the script and run it locally:

```bash
bash add-ons/addon-nginx.sh
```

### Available add-ons

| Add-on | Script | What it checks |
|--------|--------|----------------|
| **nginx** | `addon-nginx.sh` | Version exposure, security headers (CSP, HSTS, X-Frame…), default page, `/nginx_status` |
| **Apache** | `addon-apache.sh` | Version/OS exposure, TRACE method, `/server-status`, `/server-info`, directory listing |
| **PHP** | `addon-php.sh` | Version in headers, `phpinfo()` pages, exposed `composer.json` / `.env` |
| **HAProxy** | `addon-haproxy.sh` | Unauthenticated stats page, version in headers |
| **Roundcube** | `addon-roundcube.sh` | Version exposure, installer left accessible, logs/temp directory listing |
| **WordPress** | `addon-wordpress.sh` | `xmlrpc.php`, `wp-login.php`, version in meta, uploads listing, `debug.log` |
| **Docker** | `addon-docker.sh` | Unauthenticated Docker API (2375), Portainer (9000/9443), registry (5000) |
| **MariaDB / DBs** | `addon-mariadb.sh` | Exposed ports: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, CouchDB, Cassandra |
| **SSH Hardening** | `addon-ssh-hardening.sh` | OpenSSH version, weak ciphers, weak KEX algorithms, weak MACs |

### Stacking add-ons

Add-ons are fully composable — install as many as you want:

```bash
bash add-ons/addon-nginx.sh
bash add-ons/addon-php.sh
bash add-ons/addon-wordpress.sh
bash add-ons/addon-docker.sh
```

Each one is idempotent: running it twice has no side effect.

---

## Discord notifications

Set `DISCORD_WEBHOOK` in `/opt/homelabguard/.env` to receive:

- Scan completion summary with score and grade
- Immediate alert when a critical finding is detected

---

## File layout

```
/opt/homelabguard/
├── .env                        ← credentials (chmod 600)
├── data/
│   └── homelabguard.db         ← SQLite database
├── backend/
│   ├── main.py                 ← FastAPI app + API routes
│   ├── models.py               ← SQLAlchemy models
│   ├── database.py             ← DB engine + session
│   ├── notifications.py        ← Discord webhook
│   ├── requirements.txt
│   └── scanner/
│       ├── proxmox.py          ← Proxmox API client
│       ├── nmap_scan.py        ← Port scanner
│       ├── config_audit.py     ← SSH/firewall audit
│       ├── cve_check.py        ← CVE detection
│       └── scoring.py          ← Score calculation
└── frontend/
    └── index.html              ← React single-page UI
```

---

## Service management

```bash
systemctl status homelabguard     # check status
systemctl restart homelabguard    # restart after config change
journalctl -u homelabguard -f     # live logs
```

To update config, edit `/opt/homelabguard/.env` then restart the service.

---

## Troubleshooting

**Sync returns 0 nodes**
- Verify the token format: must be `user@realm!tokenname` (e.g. `root@pam!homelabguard`)
- Verify the node name matches exactly — run `pvesh get /nodes` on the Proxmox host
- Test the API directly from the LXC:
  ```bash
  source /opt/homelabguard/.env
  curl -sk -H "Authorization: PVEAPIToken=${PROXMOX_TOKEN_ID}=${PROXMOX_TOKEN_SECRET}" \
    "${PROXMOX_HOST}/api2/json/nodes/${PROXMOX_NODE}/lxc"
  ```

**Scan shows no IP for a node**
- Stopped containers have no interfaces — start the container first, then re-sync.

**Port scan fails**
- Make sure `nmap` is installed: `apt install nmap`
- The LXC needs network access to the guest IPs being scanned.

---

## License

MIT — do whatever you want with it.

---

<div align="center">

Built for homelabs. Runs on Proxmox. Stays on your hardware.

</div>
