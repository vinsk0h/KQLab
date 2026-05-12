# Changelog

All notable changes to KQL Vault are documented here.

## [2.1.1] - 2026-03-30

### Security
- Comments: add `sanitize()` on content field (POST + PUT) — prevents XSS via stored comment body
- Comments: add URL protocol validation — rejects non-http/https URLs
- Comments: raise max comment length from 1000 to 5000 chars
- Auth: add password complexity requirement (uppercase + lowercase + digit) on register and change-password
- Rate limiting: add general API limiter (120 req/min on all /api/ routes)
- Rate limiting: reduce auth limiter from 100 to 30 req per 15 min

### Changed
- Extract sanitization helpers to `backend/lib/sanitize.js`
- Extract role middleware to `backend/middleware/roles.js` (`requireWriter`, `requireAdmin`)
- `backend/middleware/utils.js` now re-exports from both — all existing imports unchanged
- Add `LICENSE` (MIT)
- Add `"license": "MIT"` to `package.json`
- Update project structure in README

## [2.1.0] - 2026-03-20

### Added
- Admin portal (`/admin.html`) with user/team/audit management
- Folder rename and delete (personal folders)
- Move query to folder (drag or via detail modal)
- Team management: create, rename, delete, add members
- Passkey reset for users (admin)
- Account unlock (admin)
- Audit log viewer in admin portal
- `.gitignore` file
- `CHANGELOG.md`
- Git branching strategy in README
- Windows deployment guide

### Changed
- Folders API now supports PUT (rename) and DELETE
- Queries API now supports PUT /:id/move
- Session duration reduced to 24h
- Max 5 concurrent sessions per user

### Security
- VULN-01 FIX: unique random salt per encrypted value
- VULN-02 FIX: origin validation on WebAuthn
- VULN-03 FIX: counter verification (replay prevention)
- VULN-04 FIX: session tokens hashed with HMAC-SHA256
- VULN-05 FIX: expired session cleanup
- VULN-06 FIX: DB file permissions chmod 600
- VULN-07 FIX: secure cookie flag in production
- VULN-08 FIX: dotenv in dependencies

## [2.0.0] - 2026-03-19

### Added
- Full Node.js/Express backend
- SQLite database with AES-256-GCM encryption
- WebAuthn passkey authentication
- REST API for queries, folders, auth
- 12 community KQL queries (Bert-JanP)
- Import/Export JSON
- Variable resolver (fill before copy)
- MITRE ATT&CK + PICERL mapping

## [1.0.0] - 2026-03-18

### Added
- Initial HTML standalone version
- Client-side rendering
- Demo mode
