# Security Policy

## Scope

HomelabGuard is a self-hosted tool designed to run inside a private network. It interacts with the Proxmox API, stores credentials locally, and exposes a web UI with no authentication by default.

If you find a vulnerability in HomelabGuard itself — not in your homelab — please report it responsibly.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via one of these channels:

- GitHub: use [Security Advisories](../../security/advisories/new) (preferred)
- Email: open an issue asking for a private contact if advisories are unavailable

Please include:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

You can expect an acknowledgement within **48 hours** and a patch within **7 days** for critical issues.

## Known Design Limitations

These are intentional trade-offs for a homelab tool, not bugs:

| Limitation | Reason |
|------------|--------|
| No authentication on the web UI | Designed for private LAN use only — put it behind a VPN or reverse proxy with auth if exposed |
| Self-signed TLS ignored (`verify=False`) | Proxmox uses self-signed certs by default; pin the cert if you need strict validation |
| Credentials stored in plaintext `.env` | File is `chmod 600` and only readable by root inside the LXC |
| nmap runs as root | Required for SYN scan; the LXC itself is the trust boundary |

## Recommendations for Production Use

- Run HomelabGuard in a **dedicated, unprivileged LXC**
- Do **not** expose port 8765 to the internet — use a VPN (WireGuard, Tailscale) or a reverse proxy with authentication
- Use a **dedicated Proxmox API token** with minimal permissions (`VM.Audit` on `/nodes` is sufficient for read-only sync)
- Rotate the API token secret periodically
