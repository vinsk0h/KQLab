# Changelog

All notable changes to KQLab are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.0] - 2026-05-15

Initial public release.

### Added

**Core**
- KQL query manager for SOC teams (Microsoft Defender / Azure Sentinel)
- MITRE ATT&CK tactic + technique mapping per query
- PICERL phase tagging (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned)
- Severity and environment tagging
- Variable resolver — fill `{{variables}}` before copying to clipboard
- Import / export queries as JSON
- 12 community KQL queries seeded from Bert-JanP

**Authentication**
- WebAuthn / Passkey login — no passwords
- Demo mode with pre-seeded data
- Account lockout after 5 failed attempts (15-minute cooldown)
- Admin unlock for locked accounts
- Passkey reset (admin)

**Backend**
- Node.js + Express REST API
- SQLite via `better-sqlite3` (synchronous API)
- AES-256-GCM encryption for all sensitive fields (unique salt per value)
- HMAC-SHA256 session token hashing
- Session TTL: 24 hours, max 5 concurrent sessions per user
- Background worker prunes expired sessions every 15 minutes
- Rate limiting: 30 auth requests / 15 min, 120 API requests / min
- Helmet + compression middleware
- Request logging

**Frontend**
- Vanilla JS SPA — no framework, no bundler
- Monaco Editor with KQL syntax highlighting
- i18n support (English / French)

**Folders & Teams**
- Personal folders (user-scoped)
- Team folders (team-scoped)
- Folder rename and delete
- Move query between folders (drag or modal)

**Admin Portal** (`/admin.html`)
- User management: create, edit, delete
- Team management: create, rename, delete, add/remove members
- Audit log viewer
- Dashboard stats

**Security**
- Origin validation on WebAuthn
- Authenticator counter verification (replay prevention)
- Expired session cleanup
- DB file permissions: `chmod 600`
- Secure cookie flag in production (`NODE_ENV=production`)
- XSS sanitization on all user-supplied content
- URL protocol validation (http/https only)
- Dotenv loaded as a runtime dependency

**Infrastructure**
- Docker support: multi-stage `Dockerfile` (builder → production)
- `docker-compose.yml` for local dev
- `.dockerignore`
- MIT license

---

[Unreleased]: https://github.com/vinsk0h/KQLab/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vinsk0h/KQLab/releases/tag/v1.0.0
