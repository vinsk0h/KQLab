# KQLab — REST API Reference

All endpoints (except `/health` and `/api/auth/*`) require an authenticated session cookie.  
All responses are JSON. Rate limits: **30 req/15 min** on `/api/auth/*`, **120 req/min** on all other `/api/*`.

---

## Auth — `/api/auth`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/register` | Start passkey/user registration |
| POST | `/login` | User login |
| POST | `/demo` | Login as demo account (read-only) |
| GET | `/me` | Get current user info |
| POST | `/change-password` | Change current user password |
| PUT | `/profile` | Update user avatar |
| POST | `/leave-team` | Leave current team |
| POST | `/logout` | End session |

---

## Queries — `/api/queries`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List queries — supports `?search`, `?severity`, `?language`, `?environment`, `?folder_id`, `?limit`, `?offset` |
| POST | `/` | Create query |
| PUT | `/:id` | Update query |
| PUT | `/:id/move` | Move query to a folder |
| DELETE | `/:id` | Delete query (owner or admin) |
| POST | `/:id/star` | Toggle star/favourite |
| POST | `/bulk` | Bulk operation — `action=delete\|move\|severity` |
| POST | `/import` | Import queries from JSON array |
| GET | `/:id/export` | Export query as PDF (`?format=pdf`) |

---

## Folders — `/api/folders`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List personal + team folders |
| POST | `/` | Create folder |
| PUT | `/:id` | Rename or change icon/color |
| DELETE | `/:id` | Delete folder |

---

## Comments — `/api/comments`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/:queryId` | List comments for a query |
| POST | `/:queryId` | Add comment |
| PUT | `/:id` | Edit own comment |
| DELETE | `/:id` | Delete own comment (or admin) |

---

## Investigations — `/api/investigations`

### Investigations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List team investigations |
| POST | `/` | Create investigation (optional `template_id`) |
| GET | `/:id` | Get investigation with IoCs + findings |
| PUT | `/:id` | Update title, status, severity, description, conclusion |
| DELETE | `/:id` | Delete investigation |
| POST | `/:id/unlock` | Unlock closed report (admin only) |
| GET | `/:id/completeness` | Get report completeness percentage |

### Branding

| Method | Path | Description |
|--------|------|-------------|
| PUT | `/:id/branding` | Update client name, logo, color, mission type, CVSS |

### IoCs

| Method | Path | Description |
|--------|------|-------------|
| POST | `/:id/iocs` | Add single IoC |
| POST | `/:id/iocs/bulk` | Add multiple IoCs |
| PUT | `/:id/iocs/:iocId` | Edit IoC |
| DELETE | `/:id/iocs/:iocId` | Delete IoC |
| DELETE | `/:id/iocs/bulk` | Bulk delete IoCs |
| POST | `/:id/iocs/:iocId/enrich` | Enrich via VirusTotal / MalwareBazaar / ThreatFox |

### Findings

| Method | Path | Description |
|--------|------|-------------|
| POST | `/:id/findings` | Add finding |
| PUT | `/:id/findings/:findingId` | Edit finding |
| DELETE | `/:id/findings/:findingId` | Delete finding |
| PUT | `/:id/findings/reorder` | Reorder findings |

### Template Sections

| Method | Path | Description |
|--------|------|-------------|
| GET | `/:id/sections` | Get report sections content |
| PUT | `/:id/sections/:sid` | Update section content |

### Report Export

| Method | Path | Description |
|--------|------|-------------|
| GET | `/:id/report` | Generate report — `?format=pdf\|docx\|html` |

---

## Report Templates — `/api/templates`

> Admin-only for write operations.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List report templates |
| POST | `/` | Create template |
| PUT | `/:id` | Update template |
| DELETE | `/:id` | Delete template (fails if in use) |
| POST | `/:id/duplicate` | Duplicate template |
| GET | `/:id/sections` | Get template sections |
| POST | `/:id/sections` | Add section |
| PUT | `/:id/sections/reorder` | Reorder sections |
| PUT | `/:id/sections/:sid` | Edit section |
| DELETE | `/:id/sections/:sid` | Delete section |

---

## Settings — `/api/settings`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/report` | Get report branding settings |
| PUT | `/report` | Update branding (admin only) — `company_name`, `company_subtitle`, `report_header_color`, `report_lang` |
| DELETE | `/report/logo` | Delete company logo (admin only) |

---

## Environment Profiles — `/api/env`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List user's environment profiles |
| POST | `/` | Create profile (platform + config) |
| PUT | `/:id` | Update profile |
| DELETE | `/:id` | Delete profile |
| POST | `/:id/activate` | Activate profile and recalculate compatibility |
| GET | `/compatibility` | Compatibility status for all team queries |
| GET | `/compatibility/:queryId` | Detailed compatibility for one query |
| POST | `/recheck` | Recalculate compatibility for all user queries |

---

## GitHub Repo Sync — `/api/repos`

> Most operations are admin-only.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/last-sync` | Recent sync status (all users) |
| GET | `/` | List repo sources (admin) |
| POST | `/` | Add repo source (admin) |
| PUT | `/:id` | Update repo source (admin) |
| DELETE | `/:id` | Delete repo source (admin) |
| POST | `/:id/sync` | Manual sync of one repo (admin) |
| POST | `/sync-all` | Sync all enabled repos (admin) |
| POST | `/reparse` | Force re-parse all repos (admin) |
| POST | `/purge/:id` | Delete all queries from a repo (admin) |
| POST | `/purge-imported` | Delete all repo-imported queries (admin) |
| GET | `/:id/files` | List files tracked in repo (admin) |
| POST | `/:id/reset-file` | Reset locally modified query to upstream (admin) |

---

## Cyber Watch — `/api/watch`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/summary` | Unread/critical counts + matched queries (last 48h) |
| GET | `/feed` | Articles — `?days=7`, `?source=`, `?severity=`, `?unread=1`, `?matched_only=1` |
| GET | `/feed/:articleId` | Article detail + matching queries |
| POST | `/feed/:articleId/read` | Mark article as read |
| POST | `/feed/:articleId/dismiss` | Dismiss article |
| GET | `/sources` | List watch sources |
| POST | `/sources` | Add source (admin) |
| PUT | `/sources/:id` | Update source (admin) |
| DELETE | `/sources/:id` | Delete source (admin) |
| POST | `/refresh` | Manual feed refresh (admin) |
| POST | `/test-feed` | Test-parse a feed URL (admin) |

---

## Admin — `/api/admin`

> All routes require `admin` role.

### Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Full stats, analytics, recent activity |
| GET | `/features` | Check which optional features are enabled |

### Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/users` | List all users |
| GET | `/users/:id/detail` | User detail (sessions, audit, query count) |
| POST | `/users` | Create user |
| PUT | `/users/:id` | Update user (role, team, display_name) |
| DELETE | `/users/:id` | Delete user |
| POST | `/users/:id/unlock` | Unlock locked account |
| POST | `/users/:id/reset-password` | Reset password |
| POST | `/users/:id/force-change-pw` | Force password change on next login |
| POST | `/users/:id/kill-sessions` | Terminate all sessions |
| POST | `/users/:id/kill-session/:hash` | Terminate specific session |

### Teams

| Method | Path | Description |
|--------|------|-------------|
| GET | `/teams` | List teams with member counts |
| POST | `/teams` | Create team |
| PUT | `/teams/:id` | Update team (name, description, color, avatar) |
| DELETE | `/teams/:id` | Delete team (must be empty) |
| POST | `/teams/:id/add-member` | Add user to team |
| POST | `/teams/:id/remove-member` | Remove user from team |

### Queries & Folders (Admin view)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/queries` | All queries across teams |
| POST | `/queries/bulk` | Bulk delete/move/severity |
| GET | `/folders` | All folders with query counts |
| DELETE | `/folders/:id` | Delete folder (`?unlink=1` to preserve queries) |

### Investigations (Admin view)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/investigations` | All investigations with stats |

### Audit Log

| Method | Path | Description |
|--------|------|-------------|
| GET | `/audit` | Query logs — `?limit=50`, `?offset=0`, filters |
| GET | `/audit/export` | Export audit logs as CSV |

### Settings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/settings` | All system settings |
| PUT | `/settings` | Update settings (instance_name, session_ttl_hours, lockout params) |
| GET | `/watch-settings` | Watch sync interval |
| PUT | `/watch-settings` | Update sync interval |

### Maintenance

| Method | Path | Description |
|--------|------|-------------|
| POST | `/maintenance/purge-sessions` | Delete expired sessions |
| POST | `/maintenance/purge-audit` | Delete audit logs older than N days |
| POST | `/maintenance/purge-watch` | Clear watch articles |
| POST | `/maintenance/vacuum` | VACUUM database |
| POST | `/maintenance/backup` | Download database backup |

---

## Health Check

| Method | Path | Auth required | Description |
|--------|------|---------------|-------------|
| GET | `/health` | No | Returns `{ status: "ok" }` |
