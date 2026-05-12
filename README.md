<div align="center">

<img src="assets/logo.svg" alt="KQLab" width="540">

**The self-hosted KQL query management platform for SOC teams**

_Passkey authentication · AES-256-GCM encryption · MITRE ATT&CK mapping · Investigation tracking_

[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.x-000000?style=flat-square&logo=express&logoColor=white)](https://expressjs.com/)
[![SQLite](https://img.shields.io/badge/SQLite-better--sqlite3-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![WebAuthn](https://img.shields.io/badge/Auth-WebAuthn%2FPasskeys-4A90D9?style=flat-square&logo=webauthn&logoColor=white)](https://webauthn.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.1-blue?style=flat-square)](CHANGELOG.md)

</div>

---

## Why KQLab?

SOC analysts accumulate hundreds of KQL queries across Microsoft Defender and Azure Sentinel. They live in Notepad, Notion, shared drives — undocumented, unsearchable, scattered across teams.

KQLab centralizes them in a **self-hosted, encrypted platform**: team-based sharing, MITRE ATT&CK mapping, investigation tracking, and passkey authentication — with zero cloud dependency, zero passwords, and zero vendor lock-in.

Deploy it on your infrastructure. Own your data.

---

## Features

| Feature | Description |
|---|---|
| **Passkey authentication** | WebAuthn/FIDO2 — hardware-backed credentials, no passwords |
| **Encrypted database** | AES-256-GCM with scrypt KDF, unique salt per stored value |
| **Team scoping** | Queries and folders isolated per team |
| **MITRE ATT&CK mapping** | Tag queries by tactic and technique |
| **PICERL mapping** | Map queries to incident response phases |
| **Variable resolver** | Fill `{{variables}}` before copying a query to the clipboard |
| **Environment compatibility** | Check query compatibility against your Defender/Sentinel tables |
| **Investigations** | Track active incidents — IoCs, timeline, findings, reports |
| **Report export** | Generate PDF, DOCX, and HTML investigation reports |
| **Report templates** | Customizable section-based report templates (admin-managed) |
| **Cyber watch** | Built-in threat feed reader with query auto-matching |
| **GitHub repo sync** | Pull KQL queries directly from public GitHub repositories |
| **Import / Export** | Bulk JSON import and export |
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
| Encryption | AES-256-GCM · scrypt KDF (N=16384) |
| Authentication | WebAuthn / Passkeys (FIDO2) |
| Frontend | Vanilla JS SPA — no framework, no bundler |
| Code editor | Monaco Editor (VS Code engine, via CDN) |
| Syntax highlighting | PrismJS (KQL, PowerShell, Python, JSON, YAML) |
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
git clone https://github.com/YOURUSERNAME/kqlab.git
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
RP_ID=localhost
RP_NAME=KQLab
ORIGIN=http://localhost:3000
```

### 4. Start

```bash
npm start
```

Open `http://localhost:3000` — use demo account `john.doe` to explore.

---

## Production Deployment

KQLab is designed for self-hosted enterprise deployments behind a reverse proxy (nginx, Caddy, Traefik).

### Environment

```env
NODE_ENV=production
RP_ID=kqlab.yourdomain.com
RP_NAME=KQLab
ORIGIN=https://kqlab.yourdomain.com
```

> WebAuthn requires HTTPS for any non-localhost hostname. `NODE_ENV=production` enables secure cookies and stricter CSP.

### Recommended setup

```
Internet → HTTPS reverse proxy → KQLab (127.0.0.1:3000)
```

Bind KQLab to `127.0.0.1` only and let the reverse proxy handle TLS. The SQLite database is at `backend/db/kqlvault.db` — back it up regularly.

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
| Credentials | AES-256-GCM · unique salt per value · scrypt KDF |
| Sessions | HMAC-SHA256 hash in DB · httpOnly cookie · 24h TTL · max 5 concurrent |
| WebAuthn | `userVerification: required` · origin check · counter replay prevention |
| Account lockout | 5 failed attempts → 15 min lock |
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
│       ├── data.js             # MITRE/PICERL constants + enums
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
│       ├── auth.js             # Register · login · passkey · lockout
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

**Passkey not working**
WebAuthn works on `localhost` without HTTPS (Chrome, Edge). Any other hostname requires HTTPS.

**Reset the database**
```bash
rm backend/db/kqlvault.db
npm start   # re-seeds with demo data automatically
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
