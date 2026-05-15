<div align="center">

<img src="assets/logo.svg" alt="KQLab" width="540">

**The self-hosted KQL query management platform for SOC teams**

_Passphrase authentication · AES-256-GCM encryption · MITRE ATT&CK mapping · Investigation tracking_

[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.x-000000?style=flat-square&logo=express&logoColor=white)](https://expressjs.com/)
[![SQLite](https://img.shields.io/badge/SQLite-better--sqlite3-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Auth](https://img.shields.io/badge/Auth-Passphrase%2Bscrypt-4A90D9?style=flat-square&logo=shield&logoColor=white)](https://nodejs.org/api/crypto.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.1-blue?style=flat-square)](CHANGELOG.md)

</div>

---

## Why KQLab?

SOC analysts accumulate hundreds of KQL queries across Microsoft Defender and Azure Sentinel. They live in Notepad, Notion, shared drives — undocumented, unsearchable, scattered across teams.

KQLab centralizes them in a **self-hosted, encrypted platform**: team-based sharing, MITRE ATT&CK mapping, investigation tracking, and passphrase authentication — with zero cloud dependency and zero vendor lock-in.

Deploy it on your infrastructure. Own your data.

---

## Features

| Feature | Description |
|---|---|
| **Passphrase authentication** | Login + scrypt-hashed passphrase — no plain-text passwords ever stored or transmitted |
| **Encrypted database** | AES-256-GCM with scrypt KDF, unique salt per stored value |
| **Multi-language queries** | Write queries in KQL (Defender/Sentinel), DSL (Elastic/ELK), or SPL (Splunk) |
| **Team scoping** | Queries and folders isolated per team |
| **MITRE ATT&CK mapping** | Tag queries by tactic and technique |
| **SANS IR Cycle mapping** | Map queries to PICERL incident response phases |
| **Variable resolver** | Fill `{{variables}}` before copying a query to the clipboard |
| **Environment compatibility** | Check query compatibility against your Defender/Sentinel tables |
| **Investigations** | Track active incidents — IoCs, timeline, findings, reports |
| **Report export** | Generate PDF, DOCX, and HTML investigation reports |
| **Report templates** | Customizable section-based report templates (admin-managed) |
| **Cyber watch** | Built-in threat feed reader (RSS + CISA JSON) with query auto-matching |
| **GitHub repo sync** | Pull KQL queries directly from public GitHub repositories (YAML, MD, KQL, auto) |
| **Import / Export** | Bulk JSON import and export |
| **Bilingual UI** | Full English and French interface, switchable per user |
| **Keyboard shortcuts** | `/` search · `n` new query · `e` edit · `f` favorites · `?` shortcut panel |
| **Admin portal** | User, team, audit log, and settings management |
| **Audit log** | Full trace of auth and CRUD events with IP and timestamp |
| **Rate limiting** | 30 auth req/15 min · 120 API req/min |

---

## Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js ≥ 18 |
| Framework | Express 4 |
| Database | SQLite via `better-sqlite3` (synchronous, no server required) |
| Encryption | AES-256-GCM · scrypt KDF (N=16384) · HMAC-SHA256 session tokens |
| Authentication | Passphrase + scrypt (N=16384) · timing-safe verify · account lockout |
| Frontend | Vanilla JS SPA — no framework, no bundler |
| Code editor | Monaco Editor (VS Code engine, via CDN) — KQL, DSL, SPL syntax |
| Internationalisation | Custom i18n engine (EN/FR, switchable per user) |
| Charts | Chart.js (admin dashboard) |
| Reports | pdfkit · docx |

---

## Quick Start

### Prerequisites

- [Node.js LTS](https://nodejs.org/en/download) ≥ 18
- npm (bundled with Node.js)

```bash
node --version   # v18.x or higher
npm --version
```

### 1. Clone

```bash
git clone https://github.com/vinsk0h/kqlab.git
cd kqlab
```

### 2. Install dependencies

```bash
npm install
```

> **Windows — build error on `better-sqlite3`?**
> Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) then retry `npm install`.

### 3. Configure environment

```bash
cp .env.example .env
```

Generate secret keys (run twice — you need two different keys):

```bash
npm run keygen   # → paste as DB_ENCRYPTION_KEY
npm run keygen   # → paste as SESSION_SECRET
```

Minimal `.env` for local development:

```env
PORT=3000
DB_ENCRYPTION_KEY=<64-char hex key>
SESSION_SECRET=<64-char hex key>
```

> `RP_ID`, `RP_NAME`, and `ORIGIN` are legacy fields kept for compatibility — they are not required for passphrase-based auth.

### 4. Start

```bash
npm start
```

Open `http://localhost:3000` — the demo account `john.doe` is pre-seeded (read-only access). Create your own account via the registration form.

---

## Docker

Docker is the recommended deployment method for production — no Node.js install required on the host.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24
- [Docker Compose](https://docs.docker.com/compose/install/) v2 (`docker compose`, not `docker-compose`)

### 1. Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your values. At minimum, set the three required fields:

```env
DB_ENCRYPTION_KEY=<64-char hex>
SESSION_SECRET=<64-char hex>
```

> No Node.js locally? Generate keys with Docker:
> ```bash
> docker run --rm node:20-alpine node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```
> Run twice — one value per key.

### 2. Build and start

```bash
docker compose up -d --build
```

Open `http://localhost:3000` — demo account `john.doe` is pre-seeded.

### Useful commands

```bash
docker compose logs -f kqlab            # stream logs
docker compose ps                       # check health status
docker compose restart kqlab           # restart container
docker compose down                     # stop (data preserved in volume)
docker compose down -v                  # stop + delete database volume
docker exec -it kqlab sh               # open shell inside container
docker exec kqlab npm run sync-repos   # trigger GitHub repo sync
```

### Backup and restore

The database lives in a named Docker volume (`kqlab-db`). Back it up with:

```bash
# Backup
docker run --rm \
  -v kqlab-db:/data \
  -v "$(pwd)":/backup \
  alpine tar czf /backup/kqlab-$(date +%Y%m%d).tar.gz -C /data .

# Restore (container must be stopped first)
docker compose down
docker run --rm \
  -v kqlab-db:/data \
  -v "$(pwd)":/backup \
  alpine tar xzf /backup/kqlab-<date>.tar.gz -C /data
docker compose up -d
```

---

## Production Deployment

KQLab is designed for self-hosted enterprise deployments behind a reverse proxy (nginx, Caddy, Traefik).

### Environment

```env
NODE_ENV=production
```

> `NODE_ENV=production` enables secure (HTTPS-only) session cookies and stricter CSP. HTTPS is strongly recommended in production to protect credentials in transit.

### Recommended setup

```
Internet → HTTPS reverse proxy → KQLab (127.0.0.1:3000)
```

**Docker (recommended):** set the env vars above in `.env`, then `docker compose up -d --build`. Place a TLS-terminating reverse proxy in front. Example Caddy config:

```
kqlab.yourdomain.com {
    reverse_proxy kqlab:3000
}
```

**Bare metal:** bind KQLab to `127.0.0.1` only and let the reverse proxy handle TLS. The SQLite database is at `backend/db/kqlab.db` — back it up regularly.

### Optional integrations

```env
# GitHub token — raises repo sync rate limit from 60 to 5000 req/h
GITHUB_TOKEN=<personal access token, scope: public_repo>

# VirusTotal — IoC enrichment (free: 4 req/min, 500 req/day)
VT_API_KEY=<your VT api key>
```

---

## Security

| Layer | Protection |
|---|---|
| Credentials | AES-256-GCM · unique salt per value · scrypt KDF (N=16384) |
| Passphrase | scrypt hash stored · timing-safe compare · complexity enforced (upper + lower + digit, min 8 chars) |
| Sessions | HMAC-SHA256 hash in DB · httpOnly cookie · configurable TTL (default 24h) · max 5 concurrent |
| Account lockout | Configurable threshold (default 5 failed attempts → 15 min lock) |
| Rate limiting | 30 auth req/15 min · 120 API req/min |
| Database file | `chmod 600` · `secure_delete` · `auto_vacuum` |
| HTTP headers | Helmet · strict CSP · `X-Powered-By` removed |
| Input | Sanitized on all endpoints · enum validation |
| Audit log | All auth and CRUD events: timestamp, user, IP |

To report a vulnerability, open a [GitHub Security Advisory](../../security/advisories/new) — do not use public issues.

---

## Role Model

| Role | Permissions |
|---|---|
| `admin` | Full access — user, team, settings, and audit management |
| `analyst` | Read + write queries, folders, and investigations within their team |
| `viewer` | Read-only access to team queries |

Users belong to exactly one team. Queries, folders, and investigations are scoped to teams.

---

## Available Commands

```bash
npm start              # Production server (port 3000)
npm run dev            # Dev server with file watch (auto-restart)
npm run keygen         # Generate a 64-char hex secret key
npm run sync-repos     # Sync queries from configured GitHub repositories
npm run release:patch  # Bump patch version + git tag (2.1.1 → 2.1.2)
npm run release:minor  # Bump minor version + git tag (2.1.1 → 2.2.0)
npm run release:major  # Bump major version + git tag (2.1.1 → 3.0.0)
```

---

## API

KQLab exposes a full REST API. All endpoints require authentication (`/api/auth/*` excepted) and return JSON.

| Prefix | Description |
|---|---|
| `/api/auth/*` | Registration, login, session management |
| `/api/queries/*` | KQL query CRUD, star, bulk import/export |
| `/api/folders/*` | Folder management (team + personal) |
| `/api/investigations/*` | Investigation tracking, IoCs, findings, reports |
| `/api/templates/*` | Report template management (admin) |
| `/api/settings/*` | Report branding and system settings (admin) |
| `/api/comments/*` | Per-query comments |
| `/api/env/*` | Environment profiles and query compatibility |
| `/api/repos/*` | GitHub repository sources and sync |
| `/api/watch/*` | Threat feed sources and articles |
| `/api/admin/*` | User, team, and audit management (admin only) |
| `/health` | Health check (no auth) |

See [`docs/API.md`](docs/API.md) for the full endpoint reference.

---

## Project Structure

```
kqlab/
├── frontend/
│   ├── index.html              # Main SPA
│   ├── admin.html              # Admin portal
│   ├── investigations.html     # Investigations view
│   └── js/
│       ├── app.js              # UI state + render loop
│       ├── admin.js            # Admin portal UI
│       ├── admin-templates.js  # Report template editor UI
│       ├── api.js              # REST fetch wrapper (GET/POST/PUT/DELETE)
│       ├── auth.js             # Auth client helpers
│       ├── data.js             # MITRE/SANS IR Cycle constants, query variable templates, enums
│       ├── i18n.js             # Internationalisation (FR/EN)
│       ├── investigations.js   # Investigation UI
│       ├── kql-monaco.js       # Monaco editor integration
│       ├── rich-editor.js      # Rich text editor (findings)
│       └── chart.umd.min.js    # Chart.js (bundled, admin dashboard)
├── backend/
│   ├── server.js               # Express entry point + rate limiting
│   ├── db/database.js          # SQLite init · AES-256-GCM · seed data
│   ├── lib/
│   │   ├── sanitize.js         # Input sanitization helpers
│   │   ├── reportGenerator.js  # PDF / DOCX / HTML report generation
│   │   ├── repo-parser.js      # GitHub repo sync engine
│   │   └── watch-engine.js     # Threat feed fetcher
│   ├── middleware/
│   │   ├── auth.js             # requireAuth()
│   │   ├── roles.js            # requireWriter(), requireAdmin()
│   │   └── utils.js            # Re-exports from lib/sanitize + roles
│   └── routes/
│       ├── auth.js             # Register · login · session · lockout
│       ├── queries.js          # KQL CRUD · star · import · export
│       ├── folders.js          # Folder CRUD
│       ├── comments.js         # Per-query comments
│       ├── investigations.js   # Investigations · IoCs · findings · reports
│       ├── templates.js        # Report templates (admin)
│       ├── settings.js         # System + report settings (admin)
│       ├── fingerprint.js      # Environment profiles + compatibility
│       ├── repos.js            # GitHub repo sources + sync
│       ├── watch.js            # Threat feeds + articles
│       └── admin.js            # User/team/audit management
├── scripts/
│   └── sync-repos.js           # Standalone repo sync runner
├── docs/
│   └── API.md                  # Full REST API reference
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── CHANGELOG.md
├── LICENSE
└── package.json
```

---

## Troubleshooting

**`better-sqlite3` fails to compile (Windows)**
Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) then `npm install`.

**Port 3000 already in use**
```powershell
netstat -ano | findstr :3000
taskkill /PID <pid> /F
```
Or set a different `PORT=` in `.env`.

**Login fails in production (cookie not sent)**
Session cookies use the `Secure` flag when `NODE_ENV=production`. Ensure you're serving over HTTPS — cookies won't be sent over plain HTTP in production mode.

**Reset the database**
```bash
rm backend/db/kqlab.db
npm start   # re-seeds with demo data automatically
```

**Docker: container exits immediately**
Check logs: `docker compose logs kqlab`. Most common cause: `DB_ENCRYPTION_KEY` missing or too short (min 32 chars).

**Docker: port already in use**
Set `PORT=8080` in `.env`, then `docker compose up -d`.

**Docker: healthcheck stuck in "starting"**
Normal for the first 15 seconds while Node initializes. Check with `docker compose ps` after startup.

**Docker: volume permission error**
```bash
docker compose down -v && docker compose up -d --build
```

---

## Contributing

Contributions are welcome. Please:

1. Fork the repo and create a branch from `main`
2. Follow the commit convention: `feat:` `fix:` `docs:` `security:` `chore:`
3. Open a pull request with a clear description of the change

For significant changes, open an issue first to discuss the approach.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## License

MIT — see [LICENSE](LICENSE) for details.
