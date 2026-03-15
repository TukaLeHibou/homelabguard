<div align="center">

```
  ██╗  ██╗ ██████╗ ███╗   ███╗███████╗██╗      █████╗ ██████╗
  ██║  ██║██╔═══██╗████╗ ████║██╔════╝██║     ██╔══██╗██╔══██╗
  ███████║██║   ██║██╔████╔██║█████╗  ██║     ███████║██████╔╝
  ██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██╔══██║██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗███████╗██║  ██║██████╔╝
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝
```

**Scanner de sécurité pour homelabs Proxmox — auto-hébergé, zéro télémétrie.**

[![License](https://img.shields.io/badge/licence-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/plateforme-Proxmox%20VE-E57000?style=flat-square&logo=proxmox&logoColor=white)](https://www.proxmox.com)
[![Python](https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Self-hosted](https://img.shields.io/badge/auto--hébergé-100%25-22c55e?style=flat-square)](#)

[🇬🇧 English version](README.md)

</div>

---

## C'est quoi ?

HomelabGuard est un scanner de sécurité en une seule commande, qui s'installe dans un conteneur LXC Proxmox et audite en continu toute l'infrastructure de ton homelab.

Il se connecte à l'API Proxmox, découvre tous tes LXC et VM, lance des vérifications de sécurité sur chacun (scan de ports, audit de config, détection de CVE), calcule un score de sécurité, et affiche tout dans un dashboard web. Les alertes critiques partent directement sur Discord.

Pas de cloud. Pas de compte. Pas d'agent à installer sur les guests. Juste un script bash.

---

## Fonctionnalités

| | |
|---|---|
| **Découverte automatique** | Synchronise tous les LXC et VMs QEMU depuis l'API Proxmox |
| **Scan de ports** | Scan nmap, détecte les services dangereux (FTP, Telnet, RDP, Redis...) |
| **Audit de configuration** | Détecte les conteneurs privilégiés, le nesting, les règles firewall manquantes |
| **Détection de CVE** | Vérifie les paquets installés contre les bases de vulnérabilités connues |
| **Score de sécurité** | Score 0–100 avec note A/B/C/D/F par node |
| **Dashboard** | Interface web temps réel, distribution des notes, alertes critiques |
| **Scans planifiés** | Re-scan automatique à intervalle configurable |
| **Alertes Discord** | Notifications webhook pour les findings critiques et résultats de scan |

---

## Stack technique

```
┌─────────────────────────────────────────┐
│              Web UI (React 18)          │  ← accessible sur :8765
├─────────────────────────────────────────┤
│           FastAPI + APScheduler         │  ← API REST + cron
├──────────────┬──────────────────────────┤
│  SQLite DB   │   Modules scanner        │
│  (SQLAlchemy)│   proxmox · nmap · audit │
└──────────────┴──────────┬───────────────┘
                          │  API Proxmox (HTTPS)
                    ┌─────▼──────┐
                    │ Proxmox VE │
                    │  node(s)   │
                    └────────────┘
```

- **Backend** — Python 3.11, FastAPI, SQLAlchemy, APScheduler
- **Scanner** — python-nmap, Proxmox API v2, modules d'audit custom
- **Frontend** — React 18 (sans build), interface dark
- **Stockage** — SQLite, fichier unique dans `/opt/homelabguard/data/`
- **Déploiement** — service systemd, tourne dans un LXC Debian

---

## Démarrage rapide

> **Prérequis :** un LXC Debian/Ubuntu sur Proxmox, et un token API Proxmox.

### 1 — Créer un token API Proxmox

Sur le host Proxmox :

```bash
pveum user token add root@pam homelabguard --privsep=0
```

Note le token ID (`root@pam!homelabguard`) et le secret généré.

### 2 — Lancer l'installeur dans le LXC

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/youruser/homelabguard/main/install.sh)
```

L'installeur va demander :

```
URL du host Proxmox    →  https://192.168.1.10:8006
Nom du nœud Proxmox   →  pve
Token ID               →  root@pam!homelabguard
Token Secret           →  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Discord Webhook        →  (optionnel)
Intervalle de scan (h) →  24
Port Web UI            →  8765
```

### 3 — Ouvrir le dashboard

```
http://<ip-du-lxc>:8765
```

Clique sur **Sync Nodes** → tous tes LXC et VMs apparaissent. Clique sur **Scan All** pour lancer le premier audit.

---

## API

Le backend expose une API REST consommée par l'UI — tu peux aussi l'appeler directement.

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/api/health` | Vérification de l'état du service |
| `GET` | `/api/nodes` | Liste tous les nodes découverts |
| `POST` | `/api/sync` | Synchronise les nodes depuis Proxmox |
| `POST` | `/api/scan/{vmid}` | Déclenche un scan sur un node précis |
| `POST` | `/api/scan-all` | Déclenche un scan sur tous les nodes actifs |
| `GET` | `/api/scans/{vmid}` | Historique des scans d'un node |
| `GET` | `/api/dashboard` | Stats agrégées et distribution des notes |

Exemple :

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

## Score de sécurité

Chaque scan démarre à **100** et des pénalités sont appliquées par finding :

| Finding | Sévérité | Pénalité |
|---------|----------|----------|
| Conteneur LXC privilégié | `high` | −15 |
| Port risqué ouvert (Telnet, RDP…) | `high` | −10 |
| Nesting / Docker activé | `medium` | −5 |
| Aucun firewall détecté | `medium` | −5 |
| Login SSH root autorisé | `medium` | −5 |
| CVE connue dans un paquet installé | `critical` | −20 |

Note finale : **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 40 · **F** < 40

---

## Notifications Discord

Renseigne `DISCORD_WEBHOOK` dans `/opt/homelabguard/.env` pour recevoir :

- Un résumé de scan avec le score et la note
- Une alerte immédiate dès qu'un finding critique est détecté

---

## Structure des fichiers

```
/opt/homelabguard/
├── .env                        ← identifiants (chmod 600)
├── data/
│   └── homelabguard.db         ← base de données SQLite
├── backend/
│   ├── main.py                 ← app FastAPI + routes API
│   ├── models.py               ← modèles SQLAlchemy
│   ├── database.py             ← moteur DB + session
│   ├── notifications.py        ← webhook Discord
│   ├── requirements.txt
│   └── scanner/
│       ├── proxmox.py          ← client API Proxmox
│       ├── nmap_scan.py        ← scanner de ports
│       ├── config_audit.py     ← audit SSH/firewall
│       ├── cve_check.py        ← détection CVE
│       └── scoring.py          ← calcul du score
└── frontend/
    └── index.html              ← UI React single-page
```

---

## Gestion du service

```bash
systemctl status homelabguard     # vérifier l'état
systemctl restart homelabguard    # redémarrer après un changement de config
journalctl -u homelabguard -f     # logs en temps réel
```

Pour modifier la config, édite `/opt/homelabguard/.env` puis redémarre le service.

---

## Dépannage

**Sync retourne 0 nodes**
- Vérifie le format du token : doit être `user@realm!tokenname` (ex : `root@pam!homelabguard`)
- Vérifie que le nom du nœud correspond exactement — lance `pvesh get /nodes` sur le host Proxmox
- Teste l'API directement depuis le LXC :
  ```bash
  source /opt/homelabguard/.env
  curl -sk -H "Authorization: PVEAPIToken=${PROXMOX_TOKEN_ID}=${PROXMOX_TOKEN_SECRET}" \
    "${PROXMOX_HOST}/api2/json/nodes/${PROXMOX_NODE}/lxc"
  ```

**Pas d'IP affichée pour un node**
- Les conteneurs arrêtés n'ont pas d'interfaces — démarre le conteneur, puis re-synchronise.

**Le scan de ports échoue**
- Vérifie que `nmap` est installé : `apt install nmap`
- Le LXC doit avoir accès réseau aux IPs des guests scannés.

---

## Licence

MIT — fais-en ce que tu veux.

---

<div align="center">

Fait pour les homelabs. Tourne sur Proxmox. Reste sur ton matériel.

</div>
