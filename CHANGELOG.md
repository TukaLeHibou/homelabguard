# Changelog

All notable changes to HomelabGuard are documented here.

---

## [1.0.0] — 2026-03-15

### Added

- One-command installer (`install.sh`) for Debian/Ubuntu LXC
- Proxmox API integration — auto-discovery of LXC containers and QEMU VMs
- nmap-based port scanner with risky port detection (FTP, Telnet, RDP, Redis, MongoDB, Elasticsearch…)
- LXC configuration audit — privileged container and nesting detection
- SSH configuration audit — root login, password auth checks
- Firewall detection audit
- CVE check against installed packages
- Security scoring engine — 0–100 score with A/B/C/D/F grade
- FastAPI REST backend with SQLite persistence
- APScheduler integration for automatic scheduled scans
- React 18 web dashboard — node list, grade distribution, critical alerts
- Discord webhook notifications for scan results and critical findings
- systemd service with automatic restart
- English and French documentation

### Fixed

- `ProxmoxClient._get()` returning `None` instead of `[]` when Proxmox API responds with `{"data": null}` (stopped containers with no interfaces)
