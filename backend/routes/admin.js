const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");
const { getDb, hashPassword, auditLog, getSetting, setSetting } = require("../db/database");
const { requireAuth }   = require("../middleware/auth");
const { sanitize, requireAdmin, validateAvatarDataUri } = require("../middleware/utils");

const router = express.Router();
const DB_FILE = path.join(__dirname, "../db/kqlab.db");

router.use(requireAuth);
router.use(requireAdmin);

// ── HELPERS ───────────────────────────────────────────────────────────────────

function formatBytes(b) {
  if (!b) return "0 B";
  if (b < 1024) return b + " B";
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
  return (b / (1024 * 1024)).toFixed(1) + " MB";
}

// ── FEATURES ─────────────────────────────────────────────────────────────────

router.get("/features", function(req, res) {
  var db = getDb();
  var features = {};
  var tables = { repos: "repo_sources", watch: "watch_sources", threats: "threat_feeds", fingerprint: "environment_profiles", translations: "query_translations" };
  Object.keys(tables).forEach(function(k) {
    try { db.prepare("SELECT 1 FROM " + tables[k] + " LIMIT 1").get(); features[k] = true; }
    catch(e) { features[k] = false; }
  });
  res.json(features);
});

// ── DASHBOARD ────────────────────────────────────────────────────────────────

router.get("/dashboard", function(req, res) {
  var db = getDb();

  var baseCounts = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM users)                                                  AS users,
      (SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now'))             AS active_sessions,
      (SELECT COUNT(*) FROM queries)                                                 AS queries,
      (SELECT COUNT(*) FROM folders)                                                 AS folders,
      (SELECT COUNT(*) FROM audit_log WHERE created_at > datetime('now','-7 days')) AS audit_7d
  `).get();

  var stats = {
    users:               baseCounts.users,
    active_sessions:     baseCounts.active_sessions,
    queries:             baseCounts.queries,
    folders:             baseCounts.folders,
    teams:               0,
    watch_articles:      0,
    repo_sources:        0,
    investigations_open: 0,
    audit_7d:            baseCounts.audit_7d
  };
  try { stats.investigations_open = db.prepare("SELECT COUNT(*) AS c FROM investigations WHERE status != 'closed'").get().c; } catch(e) {}
  try { stats.teams         = db.prepare("SELECT COUNT(*) AS c FROM teams").get().c; } catch(e) {}
  try { stats.watch_articles= db.prepare("SELECT COUNT(*) AS c FROM watch_articles").get().c; } catch(e) {}
  try { stats.repo_sources  = db.prepare("SELECT COUNT(*) AS c FROM repo_sources").get().c; } catch(e) {}

  var recentActivity = db.prepare(`
    SELECT a.id, a.user_id, a.action, a.target_type, a.target_id, a.details, a.ip_address, a.created_at,
           u.login AS user_login, u.avatar AS user_avatar
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC LIMIT 15
  `).all();

  var sessionStats = db.prepare(`
    SELECT
      COUNT(CASE WHEN expires_at > datetime('now') THEN 1 END) AS active,
      COUNT(CASE WHEN expires_at <= datetime('now') THEN 1 END) AS expired
    FROM sessions
  `).get();

  var systemHealth = {
    db_size: 0, db_size_human: "N/A",
    sessions_active: sessionStats.active,
    sessions_expired: sessionStats.expired,
    node_version: process.version,
    uptime: Math.floor(process.uptime()),
    last_repo_sync: null,
    last_watch_fetch: null
  };

  try { var st = fs.statSync(DB_FILE); systemHealth.db_size = st.size; systemHealth.db_size_human = formatBytes(st.size); } catch(e) {}
  try { systemHealth.last_repo_sync = db.prepare("SELECT MAX(last_sync_at) AS t FROM repo_sources").get().t; } catch(e) {}
  try { systemHealth.last_watch_fetch = db.prepare("SELECT MAX(last_fetch_at) AS t FROM watch_sources").get().t; } catch(e) {}

  // ── Analytics ──────────────────────────────────────────────────────────────

  // Activity over last 30 days
  var activity30d = [];
  try {
    var actRows = db.prepare(
      "SELECT date(created_at) AS day, COUNT(*) AS cnt FROM audit_log " +
      "WHERE created_at > datetime('now','-30 days') GROUP BY day ORDER BY day ASC"
    ).all();
    var actMap = {};
    actRows.forEach(function(r) { actMap[r.day] = r.cnt; });
    for (var i = 29; i >= 0; i--) {
      var d = new Date(); d.setDate(d.getDate() - i);
      var key = d.toISOString().slice(0, 10);
      activity30d.push({ date: key, count: actMap[key] || 0 });
    }
  } catch(e) {}

  // Queries by severity
  var bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  try {
    db.prepare("SELECT severity, COUNT(*) AS cnt FROM queries GROUP BY severity").all()
      .forEach(function(r) { if (r.severity && bySeverity.hasOwnProperty(r.severity)) bySeverity[r.severity] = r.cnt; });
  } catch(e) {}

  // Queries by environment
  var byEnvironment = { Defender: 0, Sentinel: 0, Both: 0 };
  try {
    db.prepare("SELECT environment, COUNT(*) AS cnt FROM queries GROUP BY environment").all()
      .forEach(function(r) { if (r.environment && byEnvironment.hasOwnProperty(r.environment)) byEnvironment[r.environment] = r.cnt; });
  } catch(e) {}

  // Queries by team (top 8)
  var byTeam = [];
  try {
    byTeam = db.prepare(
      "SELECT u.team AS team, COUNT(q.id) AS count FROM queries q " +
      "JOIN users u ON q.author_id = u.id WHERE u.team IS NOT NULL AND u.team != '' " +
      "GROUP BY u.team ORDER BY count DESC LIMIT 8"
    ).all();
  } catch(e) {}

  // Queries by language
  var byLanguage = {};
  try {
    db.prepare("SELECT UPPER(COALESCE(language,'KQL')) AS lang, COUNT(*) AS cnt FROM queries GROUP BY lang").all()
      .forEach(function(r) { byLanguage[r.lang] = r.cnt; });
  } catch(e) {}

  // Top 10 tags — json_each() évite de rapatrier tout le JSON en Node.js
  var topTags = [];
  try {
    topTags = db.prepare(`
      SELECT je.value AS tag, COUNT(*) AS count
      FROM queries q, json_each(q.tags) je
      WHERE q.tags IS NOT NULL AND q.tags != '[]' AND q.tags != ''
        AND je.value IS NOT NULL AND je.value != ''
      GROUP BY je.value
      ORDER BY count DESC
      LIMIT 10
    `).all();
  } catch(e) {
    // Fallback JS si json_each n'est pas disponible
    var tagMap = {};
    db.prepare("SELECT tags FROM queries WHERE tags IS NOT NULL AND tags NOT IN ('','[]')").all()
      .forEach(function(row) {
        var arr = []; try { arr = JSON.parse(row.tags); } catch(_) {}
        if (!Array.isArray(arr)) return;
        arr.forEach(function(t) { if (typeof t === "string" && t) tagMap[t] = (tagMap[t] || 0) + 1; });
      });
    topTags = Object.keys(tagMap)
      .map(function(t) { return { tag: t, count: tagMap[t] }; })
      .sort(function(a, b) { return b.count - a.count; })
      .slice(0, 10);
  }

  // Watch activity last 14 days
  var watchActivity14d = [];
  try {
    var waRows = db.prepare(
      "SELECT date(published_at) AS day, COUNT(*) AS articles, " +
      "COUNT(CASE WHEN severity='critical' THEN 1 END) AS critical " +
      "FROM watch_articles WHERE published_at > datetime('now','-14 days') " +
      "GROUP BY day ORDER BY day ASC"
    ).all();
    var waMap = {};
    waRows.forEach(function(r) { waMap[r.day] = { articles: r.articles, critical: r.critical }; });
    for (var j = 13; j >= 0; j--) {
      var wd = new Date(); wd.setDate(wd.getDate() - j);
      var wkey = wd.toISOString().slice(0, 10);
      var we = waMap[wkey] || { articles: 0, critical: 0 };
      watchActivity14d.push({ date: wkey, articles: we.articles, critical: we.critical });
    }
  } catch(e) {}

  // Extended system info
  var failedLogins24h = 0;
  try { failedLogins24h = db.prepare("SELECT COUNT(*) AS c FROM audit_log WHERE action='LOGIN_FAIL' AND created_at > datetime('now','-24 hours')").get().c; } catch(e) {}
  var auditEntries = 0;
  try { auditEntries = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get().c; } catch(e) {}

  var system = {
    db_size_mb:          systemHealth.db_size ? parseFloat((systemHealth.db_size / (1024 * 1024)).toFixed(2)) : 0,
    db_size_human:       systemHealth.db_size_human,
    active_sessions:     sessionStats.active,
    last_repo_sync:      systemHealth.last_repo_sync,
    last_watch_fetch:    systemHealth.last_watch_fetch,
    failed_logins_24h:   failedLogins24h,
    audit_entries:       auditEntries
  };

  // MITRE tactic coverage — count queries per tactic (from JSON mitre field)
  var mitreCoverage = {};
  try {
    var mitreRows = db.prepare("SELECT mitre FROM queries WHERE mitre IS NOT NULL AND mitre != '[]' AND mitre != ''").all();
    mitreRows.forEach(function(row) {
      var ids = []; try { ids = JSON.parse(row.mitre); } catch(e) {}
      if (!Array.isArray(ids)) return;
      ids.forEach(function(id) {
        // Tactic IDs start with TA, technique IDs start with T followed by digits
        var tacticId = null;
        if (/^TA\d{4}$/.test(id)) {
          tacticId = id;
        } else if (/^T\d{4}/.test(id)) {
          // Derive tactic from technique prefix (handled on client; store raw for client-side mapping)
          tacticId = null;
        }
        // Store raw ID counts — client derives tactics
        if (id) mitreCoverage[id] = (mitreCoverage[id] || 0) + 1;
      });
    });
  } catch(e) {}

  // Top 10 queries by stars
  var topQueries = [];
  try {
    topQueries = db.prepare(
      "SELECT id, title, severity, stars, language, team FROM queries ORDER BY stars DESC, updated_at DESC LIMIT 10"
    ).all();
  } catch(e) {}

  res.json({
    stats, recentActivity, systemHealth,
    activity_30d: activity30d,
    by_severity: bySeverity,
    by_environment: byEnvironment,
    by_team: byTeam,
    by_language: byLanguage,
    top_tags: topTags,
    watch_activity_14d: watchActivity14d,
    system: system,
    mitre_coverage: mitreCoverage,
    top_queries: topQueries
  });
});

// ── USERS ─────────────────────────────────────────────────────────────────────

// GET /api/admin/users
router.get("/users", function(req, res) {
  var db = getDb();
  var users = db.prepare(`
    SELECT u.id, u.login, u.display_name, u.role, u.team, u.failed_attempts, u.locked_until,
           u.must_change_password, u.avatar, u.created_at, u.updated_at,
           COUNT(s.token_hash) AS session_count
    FROM users u
    LEFT JOIN sessions s ON s.user_id = u.id AND s.expires_at > datetime('now')
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all();
  res.json(users);
});

// GET /api/admin/users/:id/detail
router.get("/users/:id/detail", function(req, res) {
  var db = getDb();
  var user = db.prepare("SELECT id, login, display_name, role, team, failed_attempts, locked_until, must_change_password, avatar, created_at, updated_at FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  var sessions = db.prepare("SELECT token_hash, ip_address, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC").all(req.params.id);
  var query_count = db.prepare("SELECT COUNT(*) AS c FROM queries WHERE author_id = ?").get(req.params.id).c;
  var comment_count = 0;
  try { comment_count = db.prepare("SELECT COUNT(*) AS c FROM comments WHERE user_id = ?").get(req.params.id).c; } catch(e) {}
  var investigation_count = 0;
  try { investigation_count = db.prepare("SELECT COUNT(*) AS c FROM investigations WHERE team = (SELECT team FROM users WHERE id = ?)").get(req.params.id).c; } catch(e) {}
  var recent_audit = db.prepare("SELECT id, action, target_type, target_id, details, ip_address, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 10").all(req.params.id);

  res.json({ user, sessions, query_count, comment_count, investigation_count, recent_audit });
});

// POST /api/admin/users
router.post("/users", function(req, res) {
  var db = getDb();
  var login = sanitize(req.body.login || "", 50);
  var displayName = sanitize(req.body.display_name || login, 100);
  var password = req.body.password || crypto.randomBytes(8).toString("hex");
  var role = ["admin", "analyst", "viewer"].includes(req.body.role) ? req.body.role : "analyst";
  var team = sanitize(req.body.team || "none", 50);
  var forceChange = req.body.force_change !== false;

  if (!login || !/^[a-zA-Z0-9_.\-]+$/.test(login)) return res.status(400).json({ error: "Invalid login" });
  if (db.prepare("SELECT id FROM users WHERE login = ?").get(login)) return res.status(409).json({ error: "Login already exists" });

  var userId = "u_" + crypto.randomBytes(6).toString("hex");
  db.prepare(
    "INSERT INTO users (id, login, display_name, password_hash, role, team, must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))"
  ).run(userId, login, displayName, hashPassword(password), role, team, forceChange ? 1 : 0);

  auditLog(req.user.id, "ADMIN_USER_CREATE", "user", userId, { login, role, team }, req.ip);
  res.json({ ok: true, id: userId, login, password });
});

// PUT /api/admin/users/:id
router.put("/users/:id", function(req, res) {
  var db   = getDb();
  var user = db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  var updates = [], params = [];
  if (req.body.role && ["admin", "analyst", "viewer"].includes(req.body.role)) { updates.push("role = ?"); params.push(req.body.role); }
  if (req.body.team !== undefined) { updates.push("team = ?"); params.push(sanitize(req.body.team, 50)); }
  if (req.body.display_name) { updates.push("display_name = ?"); params.push(sanitize(req.body.display_name, 100)); }

  if (updates.length === 0) return res.status(400).json({ error: "Nothing to update" });
  updates.push("updated_at = datetime('now')");
  params.push(req.params.id);
  db.prepare("UPDATE users SET " + updates.join(", ") + " WHERE id = ?").run(...params);

  auditLog(req.user.id, "ADMIN_USER_UPDATE", "user", req.params.id, { role: req.body.role, team: req.body.team, display_name: req.body.display_name }, req.ip);
  res.json({ ok: true });
});

// DELETE /api/admin/users/:id
router.delete("/users/:id", function(req, res) {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "Cannot delete yourself" });
  var db   = getDb();
  var user = db.prepare("SELECT login FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  db.transaction(function() {
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(req.params.id);
    db.prepare("DELETE FROM stars    WHERE user_id = ?").run(req.params.id);
    db.prepare("DELETE FROM users    WHERE id = ?").run(req.params.id);
  })();

  auditLog(req.user.id, "ADMIN_USER_DELETE", "user", req.params.id, { login: user.login }, req.ip);
  res.json({ ok: true });
});

// POST /api/admin/users/:id/unlock
router.post("/users/:id/unlock", function(req, res) {
  var db = getDb();
  if (!db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id)) return res.status(404).json({ error: "User not found" });
  db.prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "ADMIN_UNLOCK", "user", req.params.id, null, req.ip);
  res.json({ ok: true });
});

// POST /api/admin/users/:id/reset-password
router.post("/users/:id/reset-password", function(req, res) {
  var db   = getDb();
  var user = db.prepare("SELECT login FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  var tempPw = crypto.randomBytes(8).toString("hex");
  db.prepare("UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = datetime('now') WHERE id = ?").run(hashPassword(tempPw), req.params.id);
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(req.params.id);
  auditLog(req.user.id, "ADMIN_PASSWORD_RESET", "user", req.params.id, { login: user.login }, req.ip);
  res.json({ ok: true, temp_password: tempPw });
});

// POST /api/admin/users/:id/force-change-pw
router.post("/users/:id/force-change-pw", function(req, res) {
  var db = getDb();
  if (!db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id)) return res.status(404).json({ error: "User not found" });
  db.prepare("UPDATE users SET must_change_password = 1, updated_at = datetime('now') WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "ADMIN_FORCE_CHANGE_PW", "user", req.params.id, null, req.ip);
  res.json({ ok: true });
});

// POST /api/admin/users/:id/kill-sessions
router.post("/users/:id/kill-sessions", function(req, res) {
  var db = getDb();
  if (!db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id)) return res.status(404).json({ error: "User not found" });
  var n = db.prepare("DELETE FROM sessions WHERE user_id = ?").run(req.params.id).changes;
  auditLog(req.user.id, "ADMIN_KILL_SESSIONS", "user", req.params.id, { killed: n }, req.ip);
  res.json({ ok: true, killed: n });
});

// POST /api/admin/users/:id/kill-session/:hash  (kill single session)
router.post("/users/:id/kill-session/:hash", function(req, res) {
  var db = getDb();
  db.prepare("DELETE FROM sessions WHERE token_hash = ? AND user_id = ?").run(req.params.hash, req.params.id);
  res.json({ ok: true });
});

// PUT /api/admin/users/:id/team (legacy, keep for admin.html compat)
router.put("/users/:id/team", function(req, res) {
  var db   = getDb();
  var user = db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  var teamId = req.body.team_id;
  if (teamId && teamId !== "none") {
    if (!db.prepare("SELECT id FROM teams WHERE id = ?").get(teamId)) return res.status(404).json({ error: "Team not found" });
  }
  db.prepare("UPDATE users SET team = ?, updated_at = datetime('now') WHERE id = ?").run(teamId || "none", req.params.id);
  auditLog(req.user.id, "ADMIN_USER_TEAM_CHANGE", "user", req.params.id, { team: teamId }, req.ip);
  res.json({ ok: true });
});

// ── TEAMS ─────────────────────────────────────────────────────────────────────

// GET /api/admin/teams  (with counts)
router.get("/teams", function(req, res) {
  var db    = getDb();
  var teams = db.prepare("SELECT * FROM teams ORDER BY name").all();

  var memberRows = db.prepare("SELECT id, login, display_name, role, team, avatar FROM users").all();
  var byTeam = {};
  memberRows.forEach(function(u) {
    if (!byTeam[u.team]) byTeam[u.team] = [];
    byTeam[u.team].push({ id: u.id, login: u.login, display_name: u.display_name, role: u.role, avatar: u.avatar });
  });

  var queryCounts = {};
  db.prepare("SELECT team, COUNT(*) AS c FROM queries GROUP BY team").all().forEach(function(r) { queryCounts[r.team] = r.c; });

  var folderCounts = {};
  db.prepare("SELECT team_id, COUNT(*) AS c FROM folders GROUP BY team_id").all().forEach(function(r) { folderCounts[r.team_id] = r.c; });

  var invCounts = {};
  try { db.prepare("SELECT team, COUNT(*) AS c FROM investigations GROUP BY team").all().forEach(function(r) { invCounts[r.team] = r.c; }); } catch(e) {}

  res.json(teams.map(function(t) {
    return {
      id: t.id, name: t.name,
      description: t.description || '',
      color: t.color || '#6366f1',
      avatar_url: t.avatar_url || null,
      members: byTeam[t.id] || [],
      member_count: (byTeam[t.id] || []).length,
      query_count: queryCounts[t.id] || 0,
      folder_count: folderCounts[t.id] || 0,
      investigation_count: invCounts[t.id] || 0
    };
  }));
});

// POST /api/admin/teams
router.post("/teams", function(req, res) {
  var name        = sanitize(req.body.name || "", 100);
  var description = sanitize(req.body.description || "", 500);
  var color       = /^#[0-9a-fA-F]{3,8}$/.test(req.body.color || '') ? req.body.color : '#6366f1';
  var avatarRes = validateAvatarDataUri(req.body.avatar_url || "", 360000);
  if (!avatarRes.ok) return res.status(400).json({ error: avatarRes.error });
  var avatar_url = avatarRes.value;
  if (name.length < 2) return res.status(400).json({ error: "Name must be at least 2 characters" });
  var db     = getDb();
  var teamId = "t_" + crypto.randomBytes(4).toString("hex");
  db.prepare("INSERT INTO teams (id, name, description, color, avatar_url) VALUES (?, ?, ?, ?, ?)").run(teamId, name, description, color, avatar_url || null);
  auditLog(req.user.id, "ADMIN_TEAM_CREATE", "team", teamId, { name }, req.ip);
  res.json({ id: teamId, name, description, color, avatar_url: avatar_url || null, members: [], member_count: 0, query_count: 0, folder_count: 0, investigation_count: 0 });
});

// PUT /api/admin/teams/:id
router.put("/teams/:id", function(req, res) {
  var db   = getDb();
  var team = db.prepare("SELECT id FROM teams WHERE id = ?").get(req.params.id);
  if (!team) return res.status(404).json({ error: "Team not found" });
  var newName     = sanitize(req.body.name || "", 100);
  var description = sanitize(req.body.description || "", 500);
  var color       = /^#[0-9a-fA-F]{3,8}$/.test(req.body.color || '') ? req.body.color : '#6366f1';
  var avatar_url = null;
  if (req.body.avatar_url === undefined) {
    var existing = db.prepare("SELECT avatar_url FROM teams WHERE id = ?").get(req.params.id);
    avatar_url = existing ? existing.avatar_url : null;
  } else {
    var avatarRes = validateAvatarDataUri(req.body.avatar_url, 360000);
    if (!avatarRes.ok) return res.status(400).json({ error: avatarRes.error });
    avatar_url = avatarRes.value;
  }
  if (newName.length < 2) return res.status(400).json({ error: "Name must be at least 2 characters" });
  db.prepare("UPDATE teams SET name = ?, description = ?, color = ?, avatar_url = ? WHERE id = ?").run(newName, description, color, avatar_url, req.params.id);
  auditLog(req.user.id, "ADMIN_TEAM_UPDATE", "team", req.params.id, { newName }, req.ip);
  res.json({ ok: true });
});

// DELETE /api/admin/teams/:id
router.delete("/teams/:id", function(req, res) {
  var db   = getDb();
  var team = db.prepare("SELECT name FROM teams WHERE id = ?").get(req.params.id);
  if (!team) return res.status(404).json({ error: "Team not found" });
  var memberCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE team = ?").get(req.params.id).c;
  if (memberCount > 0) return res.status(400).json({ error: `Team has ${memberCount} member(s). Reassign them first.` });
  db.prepare("DELETE FROM folders WHERE team_id = ?").run(req.params.id);
  db.prepare("DELETE FROM teams   WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "ADMIN_TEAM_DELETE", "team", req.params.id, { name: team.name }, req.ip);
  res.json({ ok: true });
});

// POST /api/admin/teams/:id/add-member
router.post("/teams/:id/add-member", function(req, res) {
  var db   = getDb();
  if (!db.prepare("SELECT id FROM teams WHERE id = ?").get(req.params.id)) return res.status(404).json({ error: "Team not found" });
  var user = db.prepare("SELECT id, login FROM users WHERE id = ?").get(req.body.user_id);
  if (!user) return res.status(404).json({ error: "User not found" });
  db.prepare("UPDATE users SET team = ?, updated_at = datetime('now') WHERE id = ?").run(req.params.id, user.id);
  auditLog(req.user.id, "ADMIN_TEAM_ADD_MEMBER", "team", req.params.id, { user_id: user.id, login: user.login }, req.ip);
  res.json({ ok: true });
});

// POST /api/admin/teams/:id/remove-member
router.post("/teams/:id/remove-member", function(req, res) {
  var db   = getDb();
  var user = db.prepare("SELECT id, login FROM users WHERE id = ? AND team = ?").get(req.body.user_id, req.params.id);
  if (!user) return res.status(404).json({ error: "User not in team" });
  db.prepare("UPDATE users SET team = 'none', updated_at = datetime('now') WHERE id = ?").run(user.id);
  auditLog(req.user.id, "ADMIN_TEAM_REMOVE_MEMBER", "team", req.params.id, { user_id: user.id, login: user.login }, req.ip);
  res.json({ ok: true });
});

// ── QUERIES (admin - all teams) ───────────────────────────────────────────────

// GET /api/admin/queries
router.get("/queries", function(req, res) {
  var db = getDb();
  var queries = db.prepare(`
    SELECT q.id, q.title, q.language, q.environment, q.severity, q.folder_id, q.author_id, q.author_name,
           q.team, q.stars, q.created_at, q.updated_at,
           f.name AS folder_name, f.icon AS folder_icon,
           (SELECT COUNT(*) FROM repo_query_map rqm WHERE rqm.query_id = q.id) > 0 AS is_repo_query
    FROM queries q
    LEFT JOIN folders f ON f.id = q.folder_id
    ORDER BY q.updated_at DESC
  `).all();
  // Wrap is_repo_query in try/catch in case repo_query_map doesn't exist
  var result;
  try { result = queries; }
  catch(e) {
    result = db.prepare(`
      SELECT q.id, q.title, q.language, q.environment, q.severity, q.folder_id, q.author_id, q.author_name,
             q.team, q.stars, q.created_at, q.updated_at,
             f.name AS folder_name, f.icon AS folder_icon, 0 AS is_repo_query
      FROM queries q LEFT JOIN folders f ON f.id = q.folder_id
      ORDER BY q.updated_at DESC
    `).all();
  }
  res.json(result);
});

// POST /api/admin/queries/bulk
router.post("/queries/bulk", function(req, res) {
  var db     = getDb();
  var action = req.body.action;
  var ids    = Array.isArray(req.body.ids)
    ? req.body.ids.filter(function(id) { return typeof id === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(id); }).slice(0, 500)
    : [];
  var value  = req.body.value;
  if (!ids.length) return res.status(400).json({ error: "No ids" });

  var placeholders = ids.map(function() { return "?"; }).join(",");

  if (action === "delete") {
    db.prepare("DELETE FROM queries WHERE id IN (" + placeholders + ")").run(...ids);
    auditLog(req.user.id, "ADMIN_QUERY_BULK_DELETE", "query", null, { count: ids.length }, req.ip);
    return res.json({ ok: true, affected: ids.length });
  }
  if (action === "move") {
    var folderId = value || null;
    db.prepare("UPDATE queries SET folder_id = ?, updated_at = datetime('now') WHERE id IN (" + placeholders + ")").run(folderId, ...ids);
    auditLog(req.user.id, "ADMIN_QUERY_BULK_MOVE", "query", null, { count: ids.length, folder_id: folderId }, req.ip);
    return res.json({ ok: true, affected: ids.length });
  }
  if (action === "severity") {
    var sev = ["critical","high","medium","low","info"].includes(value) ? value : null;
    if (!sev) return res.status(400).json({ error: "Invalid severity" });
    db.prepare("UPDATE queries SET severity = ?, updated_at = datetime('now') WHERE id IN (" + placeholders + ")").run(sev, ...ids);
    auditLog(req.user.id, "ADMIN_QUERY_BULK_SEVERITY", "query", null, { count: ids.length, severity: sev }, req.ip);
    return res.json({ ok: true, affected: ids.length });
  }
  return res.status(400).json({ error: "Unknown action" });
});

// ── FOLDERS (admin - all teams) ───────────────────────────────────────────────

router.get("/folders", function(req, res) {
  var db = getDb();
  var folders = db.prepare(`
    SELECT f.id, f.name, f.icon, f.scope, f.color, f.owner_id, f.team_id,
           u.login AS owner_login,
           t.name AS team_name,
           COUNT(q.id) AS query_count
    FROM folders f
    LEFT JOIN users u ON u.id = f.owner_id
    LEFT JOIN teams t ON t.id = f.team_id
    LEFT JOIN queries q ON q.folder_id = f.id
    GROUP BY f.id
    ORDER BY f.scope, f.name
  `).all();
  res.json(folders);
});

// DELETE /api/admin/folders/:id  (with optional unlink)
router.delete("/folders/:id", function(req, res) {
  var db     = getDb();
  var folder = db.prepare("SELECT name FROM folders WHERE id = ?").get(req.params.id);
  if (!folder) return res.status(404).json({ error: "Folder not found" });
  var unlink = req.query.unlink === "1";
  if (unlink) db.prepare("UPDATE queries SET folder_id = NULL WHERE folder_id = ?").run(req.params.id);
  else {
    var cnt = db.prepare("SELECT COUNT(*) AS c FROM queries WHERE folder_id = ?").get(req.params.id).c;
    if (cnt > 0) return res.status(400).json({ error: `Folder has ${cnt} queries. Use ?unlink=1 to unlink them.` });
  }
  db.prepare("DELETE FROM folders WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "ADMIN_FOLDER_DELETE", "folder", req.params.id, { name: folder.name, unlink }, req.ip);
  res.json({ ok: true });
});

// ── INVESTIGATIONS ────────────────────────────────────────────────────────────

router.get("/investigations", function(req, res) {
  var db = getDb();
  var invs;
  try {
    invs = db.prepare(`
      SELECT i.id, i.title, i.status, i.severity, i.team, i.created_at,
             COUNT(DISTINCT ioc.id) AS ioc_count,
             COUNT(DISTINCT f.id) AS finding_count
      FROM investigations i
      LEFT JOIN investigation_iocs ioc ON ioc.investigation_id = i.id
      LEFT JOIN investigation_findings f ON f.investigation_id = i.id
      GROUP BY i.id
      ORDER BY i.created_at DESC
    `).all();
  } catch(e) { invs = []; }
  res.json(invs);
});

// PUT /api/admin/investigations/:id — admin status update (bypasses team check)
router.put("/investigations/:id", function(req, res) {
  var db = getDb();
  var STATUSES = ['open', 'in-progress', 'closed'];
  var inv;
  try { inv = db.prepare("SELECT * FROM investigations WHERE id = ?").get(req.params.id); } catch(e) {}
  if (!inv) return res.status(404).json({ error: "Investigation not found" });

  var newStatus = (STATUSES.indexOf(req.body.status) !== -1) ? req.body.status : inv.status;
  var report_locked = inv.report_locked || 0;
  var locked_at = inv.locked_at || null;
  var locked_by = inv.locked_by || null;

  if (newStatus === 'closed' && inv.status !== 'closed') {
    report_locked = 1; locked_at = Date.now(); locked_by = req.user.id;
  }
  if (newStatus !== 'closed' && inv.status === 'closed') {
    report_locked = 0; locked_at = null; locked_by = null;
  }

  db.prepare(
    "UPDATE investigations SET status=?,report_locked=?,locked_at=?,locked_by=?,updated_at=datetime('now') WHERE id=?"
  ).run(newStatus, report_locked, locked_at, locked_by, req.params.id);

  auditLog(req.user.id, "ADMIN_INV_STATUS", "investigation", req.params.id, { status: newStatus }, req.ip);
  res.json({ ok: true });
});

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────

// GET /api/admin/audit?limit=50&offset=0&user_id=&action=&from=&to=&q=
router.get("/audit", function(req, res) {
  var db     = getDb();
  var limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  var offset = Math.max(parseInt(req.query.offset) || 0,  0);

  var where  = [];
  var params = [];

  if (req.query.user_id) { where.push("a.user_id = ?"); params.push(req.query.user_id); }
  if (req.query.action)  { where.push("a.action = ?");  params.push(req.query.action); }
  if (req.query.from)    { where.push("a.created_at >= ?"); params.push(req.query.from); }
  if (req.query.to)      { where.push("a.created_at <= ?"); params.push(req.query.to); }
  if (req.query.q)       { where.push("(a.details LIKE ? ESCAPE '\\' OR a.action LIKE ? ESCAPE '\\' OR u.login LIKE ? ESCAPE '\\')");
    var rawQ = (req.query.q || "").slice(0, 200).replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
    var qp = "%" + rawQ + "%"; params.push(qp, qp, qp); }

  var whereClause = where.length ? "WHERE " + where.join(" AND ") : "";

  var logs = db.prepare(`
    SELECT a.id, a.user_id, a.action, a.target_type, a.target_id, a.details, a.ip_address, a.created_at,
           u.login AS user_login, u.avatar AS user_avatar
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ${whereClause}
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  var totalRow = db.prepare(`
    SELECT COUNT(*) AS c FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ${whereClause}
  `).get(...params);

  // Distinct action types for the filter dropdown
  var actionTypes = db.prepare("SELECT DISTINCT action FROM audit_log ORDER BY action").all().map(function(r) { return r.action; });

  res.json({ logs, total: totalRow.c, limit, offset, actionTypes });
});

// GET /api/admin/audit/export?format=csv&from=&to=&user_id=&action=
router.get("/audit/export", function(req, res) {
  var db = getDb();
  var where = [], params = [];
  if (req.query.user_id) { where.push("a.user_id = ?"); params.push(req.query.user_id); }
  if (req.query.action)  { where.push("a.action = ?");  params.push(req.query.action); }
  if (req.query.from)    { where.push("a.created_at >= ?"); params.push(req.query.from); }
  if (req.query.to)      { where.push("a.created_at <= ?"); params.push(req.query.to); }
  var whereClause = where.length ? "WHERE " + where.join(" AND ") : "";

  var rows = db.prepare(`
    SELECT a.created_at, u.login AS user_login, a.action, a.target_type, a.target_id, a.details, a.ip_address
    FROM audit_log a LEFT JOIN users u ON a.user_id = u.id
    ${whereClause}
    ORDER BY a.created_at DESC LIMIT 10000
  `).all(...params);

  function csvEscape(v) {
    if (v === null || v === undefined) return "";
    var s = String(v);
    if (s.includes(",") || s.includes('"') || s.includes("\n")) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  var lines = ["timestamp,user,action,target_type,target_id,details,ip"];
  rows.forEach(function(r) {
    lines.push([r.created_at, r.user_login || "system", r.action, r.target_type, r.target_id, r.details, r.ip_address].map(csvEscape).join(","));
  });

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=\"audit-log.csv\"");
  res.send(lines.join("\n"));
});

// ── STATS (legacy endpoint kept) ─────────────────────────────────────────────

router.get("/stats", function(req, res) {
  var db = getDb();
  var row = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM users)                                         AS users,
      (SELECT COUNT(*) FROM queries)                                       AS queries,
      (SELECT COUNT(*) FROM folders)                                       AS folders,
      (SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now'))  AS sessions,
      (SELECT COUNT(*) FROM audit_log)                                     AS auditEntries
  `).get();
  res.json(row);
});

// ── WATCH SETTINGS ────────────────────────────────────────────────────────────

router.get("/watch-settings", function(req, res) {
  var mins = parseInt(getSetting("watch_sync_interval_minutes", "15")) || 15;
  res.json({ sync_interval_minutes: mins });
});

router.put("/watch-settings", function(req, res) {
  var mins = parseInt(req.body.sync_interval_minutes);
  if (!mins || mins < 1 || mins > 1440) return res.status(400).json({ error: "sync_interval_minutes must be between 1 and 1440" });
  setSetting("watch_sync_interval_minutes", mins);
  auditLog(req.user.id, "ADMIN_WATCH_SETTINGS", "system", null, { sync_interval_minutes: mins }, req.ip);
  // Apply new interval immediately
  try { require("../lib/watch-scheduler").schedule(); } catch(e) {}
  res.json({ ok: true, sync_interval_minutes: mins });
});

// ── SETTINGS ─────────────────────────────────────────────────────────────────

router.get("/settings", function(req, res) {
  var db = getDb();
  var dbSize = 0, dbSizeHuman = "N/A";
  try { var st = fs.statSync(DB_FILE); dbSize = st.size; dbSizeHuman = formatBytes(st.size); } catch(e) {}

  var encryptionActive = !!(process.env.DB_ENCRYPTION_KEY && process.env.DB_ENCRYPTION_KEY.length >= 32 && process.env.DB_ENCRYPTION_KEY !== "CHANGE_ME_TO_A_STRONG_RANDOM_STRING_64_CHARS");

  res.json({
    instance: {
      name: getSetting("instance_name", process.env.INSTANCE_NAME || "KQLab"),
      node_version: process.version,
      uptime: Math.floor(process.uptime()),
      uptime_human: formatUptime(Math.floor(process.uptime())),
      db_size: dbSize,
      db_size_human: dbSizeHuman,
      encryption_active: encryptionActive,
      env: process.env.NODE_ENV || "development"
    },
    security: {
      session_ttl_hours:       parseInt(getSetting("session_ttl_hours", "24")) || 24,
      max_sessions_per_user:   parseInt(getSetting("max_sessions_per_user", "5")) || 5,
      login_lockout_attempts:  parseInt(getSetting("login_lockout_attempts", "5")) || 5,
      login_lockout_minutes:   parseInt(getSetting("login_lockout_minutes", "15")) || 15,
      audit_retention_days:    parseInt(getSetting("audit_retention_days", "365")) || 365,
      auth_rate_limit: "30 req / 15 min"
    },
    counts: db.prepare(`
      SELECT
        (SELECT COUNT(*) FROM users)                                        AS users,
        (SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')) AS sessions,
        (SELECT COUNT(*) FROM sessions WHERE expires_at <= datetime('now')) AS expired,
        (SELECT COUNT(*) FROM audit_log)                                    AS audit
    `).get()
  });
});

// PUT /api/admin/settings
router.put("/settings", function(req, res) {
  var allowed = {
    instance_name:          { type: "string",  max: 100 },
    session_ttl_hours:      { type: "int",     min: 1,  max: 168 },
    max_sessions_per_user:  { type: "int",     min: 1,  max: 50  },
    login_lockout_attempts: { type: "int",     min: 1,  max: 100 },
    login_lockout_minutes:  { type: "int",     min: 1,  max: 1440 },
    audit_retention_days:   { type: "int",     min: 7,  max: 3650 }
  };
  var saved = {};
  var errors = [];
  Object.keys(allowed).forEach(function(key) {
    if (req.body[key] === undefined) return;
    var spec = allowed[key];
    if (spec.type === "int") {
      var v = parseInt(req.body[key]);
      if (isNaN(v) || v < spec.min || v > spec.max) { errors.push(key + " must be between " + spec.min + " and " + spec.max); return; }
      setSetting(key, String(v));
      saved[key] = v;
    } else {
      var s = sanitize(String(req.body[key] || ""), spec.max);
      setSetting(key, s);
      saved[key] = s;
    }
  });
  if (errors.length) return res.status(400).json({ error: errors.join("; ") });
  if (Object.keys(saved).length === 0) return res.status(400).json({ error: "No valid fields provided" });
  auditLog(req.user.id, "ADMIN_SETTINGS_UPDATE", "system", null, saved, req.ip);
  res.json({ ok: true, saved });
});

function formatUptime(s) {
  var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + "d " + h + "h " + m + "m";
  if (h > 0) return h + "h " + m + "m";
  return m + "m " + (s % 60) + "s";
}

// ── MAINTENANCE ───────────────────────────────────────────────────────────────

router.post("/maintenance/:action", function(req, res) {
  var db = getDb();
  var action = req.params.action;

  if (action === "purge-sessions") {
    var n = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run().changes;
    auditLog(req.user.id, "ADMIN_MAINTENANCE", "system", null, { action: "purge-sessions", purged: n }, req.ip);
    return res.json({ ok: true, purged: n });
  }

  if (action === "purge-audit") {
    var days = parseInt(req.body.days);
    if (isNaN(days) || days < 1 || days > 3650)
      return res.status(400).json({ error: "days doit être compris entre 1 et 3650" });
    var cutoff = new Date(Date.now() - days * 86400000).toISOString();
    var n2 = db.prepare("DELETE FROM audit_log WHERE created_at < ?").run(cutoff).changes;
    auditLog(req.user.id, "ADMIN_MAINTENANCE", "system", null, { action: "purge-audit", purged: n2, days }, req.ip);
    return res.json({ ok: true, purged: n2 });
  }

  if (action === "purge-watch") {
    var nArt = db.prepare("DELETE FROM watch_articles").run().changes;
    // Reset last_fetch_at so the next refresh re-ingests everything
    db.prepare("UPDATE watch_sources SET last_fetch_at = NULL, last_fetch_status = 'never', fetch_count = 0").run();
    auditLog(req.user.id, "ADMIN_MAINTENANCE", "system", null, { action: "purge-watch", purged: nArt }, req.ip);
    return res.json({ ok: true, purged: nArt });
  }

  if (action === "vacuum") {
    db.pragma("vacuum");
    auditLog(req.user.id, "ADMIN_MAINTENANCE", "system", null, { action: "vacuum" }, req.ip);
    return res.json({ ok: true });
  }

  if (action === "backup") {
    try {
      var backupPath = DB_FILE + ".backup-" + Date.now() + ".tmp";
      fs.copyFileSync(DB_FILE, backupPath);
      var backupStat = fs.statSync(backupPath);
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", "attachment; filename=\"kqlab-backup-" + new Date().toISOString().slice(0,10) + ".db\"");
      res.setHeader("Content-Length", backupStat.size);
      var stream = fs.createReadStream(backupPath);
      stream.pipe(res);
      stream.on("close", function() { try { fs.unlinkSync(backupPath); } catch(e) {} });
      auditLog(req.user.id, "ADMIN_MAINTENANCE", "system", null, { action: "backup" }, req.ip);
    } catch(e) {
      res.status(500).json({ error: "Backup failed: " + e.message });
    }
    return;
  }

  res.status(400).json({ error: "Unknown action" });
});

// POST /api/admin/reparse-queries
// Re-extracts CVEs from KQL comments of all repo-imported queries and merges them into tags.
router.post("/reparse-queries", function(req, res) {
  var db = getDb();
  try {
    var queries = db.prepare(
      "SELECT q.id, q.kql, q.tags FROM queries q " +
      "JOIN repo_query_map rm ON rm.query_id = q.id"
    ).all();

    var cveRe = /CVE-\d{4}-\d{4,7}/gi;
    var updated = 0;

    for (var i = 0; i < queries.length; i++) {
      var q = queries[i];
      var kql = q.kql || "";
      var cveMatches = kql.match(cveRe) || [];
      if (!cveMatches.length) continue;

      var cves = [];
      var seen = {};
      cveMatches.forEach(function(c) { var u = c.toUpperCase(); if (!seen[u]) { seen[u] = true; cves.push(u); } });

      var existingTags = [];
      try { existingTags = JSON.parse(q.tags || "[]"); } catch(e) {}
      var merged = existingTags.slice();
      cves.forEach(function(cve) { if (merged.indexOf(cve) < 0) merged.push(cve); });

      if (merged.length !== existingTags.length) {
        db.prepare("UPDATE queries SET tags = ? WHERE id = ?").run(JSON.stringify(merged), q.id);
        updated++;
      }
    }

    auditLog(req.user.id, "ADMIN_REPARSE_QUERIES", "system", null, { updated, total: queries.length }, req.ip);
    res.json({ ok: true, updated, total: queries.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/fix-watch-urls
// One-shot: normalizes any malformed watch_sources URLs via new URL().href
router.post("/fix-watch-urls", function(req, res) {
  var db = getDb();
  try {
    var sources = db.prepare("SELECT id, url FROM watch_sources").all();
    var fixed = 0;
    var errors = [];
    sources.forEach(function(s) {
      try {
        var correct = new URL(s.url).href;
        if (correct !== s.url) {
          db.prepare("UPDATE watch_sources SET url=?, last_error=NULL WHERE id=?").run(correct, s.id);
          console.log("[Admin] fix-watch-urls: corrected", s.url, "→", correct);
          fixed++;
        }
      } catch(e) {
        errors.push(s.url);
        console.error("[Admin] fix-watch-urls: invalid URL in DB:", s.url);
      }
    });
    auditLog(req.user.id, "ADMIN_FIX_WATCH_URLS", "system", null, { fixed, total: sources.length }, req.ip);
    res.json({ ok: true, fixed, total: sources.length, errors });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
