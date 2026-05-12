const express = require("express");
const crypto  = require("crypto");
const { getDb, auditLog } = require("../db/database");
const { requireAuth }     = require("../middleware/auth");
const { sanitize }        = require("../middleware/utils");
const { checkCompatibility } = require("../lib/env-matcher");

const router = express.Router();
router.use(requireAuth);

const VALID_PLATFORMS = ["defender_xdr", "sentinel"];

function parseConfig(raw) {
  if (!raw) return {};
  if (typeof raw === "object") return raw;
  try { return JSON.parse(raw); } catch(e) { return {}; }
}

function serializeConfig(config) {
  if (typeof config === "string") {
    try { JSON.parse(config); return config; } catch(e) { return "{}"; }
  }
  return JSON.stringify(config || {});
}

function parseProfile(p) {
  return Object.assign({}, p, { config: parseConfig(p.config) });
}

// ─────────────────────────────────────────────
// Recalculate compatibility for ALL queries of a user's team
// ─────────────────────────────────────────────
function recalculateCompatibility(userId, db) {
  var env = db.prepare("SELECT * FROM user_environments WHERE user_id = ? AND is_active = 1").get(userId);
  if (!env) {
    db.prepare("DELETE FROM query_compatibility WHERE user_id = ?").run(userId);
    return { checked: 0, compatible: 0, partial: 0, incompatible: 0, unknown: 0 };
  }

  var user = db.prepare("SELECT team FROM users WHERE id = ?").get(userId);
  if (!user) return { checked: 0, compatible: 0, partial: 0, incompatible: 0, unknown: 0 };

  var queries = db.prepare("SELECT id, kql, language FROM queries WHERE team = ?").all(user.team);
  var insertStmt = db.prepare("INSERT OR REPLACE INTO query_compatibility (query_id, user_id, status, tables_found, tables_ok, tables_missing) VALUES (?, ?, ?, ?, ?, ?)");
  var deleteStmt = db.prepare("DELETE FROM query_compatibility WHERE user_id = ?");
  var stats = { checked: 0, compatible: 0, partial: 0, incompatible: 0, unknown: 0 };

  db.transaction(function() {
    deleteStmt.run(userId);
    queries.forEach(function(q) {
      var result = checkCompatibility(q.kql, q.language, env.config, env.platform);
      insertStmt.run(q.id, userId, result.status,
        JSON.stringify(result.tables_found),
        JSON.stringify(result.tables_ok.map(function(t) { return t.table; })),
        JSON.stringify(result.tables_missing));
      if (stats[result.status] !== undefined) stats[result.status]++;
      else stats.unknown++;
      stats.checked++;
    });
  })();

  return stats;
}

// ─────────────────────────────────────────────
// Recheck a single query for all users in its team
// ─────────────────────────────────────────────
function recheckSingleQuery(queryId, db) {
  try {
    var query = db.prepare("SELECT id, kql, language, team FROM queries WHERE id = ?").get(queryId);
    if (!query) return;

    var users = db.prepare(
      "SELECT ue.user_id, ue.config, ue.platform FROM user_environments ue JOIN users u ON ue.user_id = u.id WHERE u.team = ? AND ue.is_active = 1"
    ).all(query.team);

    var insertStmt = db.prepare("INSERT OR REPLACE INTO query_compatibility (query_id, user_id, status, tables_found, tables_ok, tables_missing) VALUES (?, ?, ?, ?, ?, ?)");

    users.forEach(function(ue) {
      var result = checkCompatibility(query.kql, query.language, ue.config, ue.platform);
      insertStmt.run(queryId, ue.user_id, result.status,
        JSON.stringify(result.tables_found),
        JSON.stringify(result.tables_ok.map(function(t) { return t.table; })),
        JSON.stringify(result.tables_missing));
    });
  } catch(e) {
    console.error("[recheckSingleQuery] Error:", e.message);
  }
}

// ─────────────────────────────────────────────
// GET /api/env — list user's profiles
// ─────────────────────────────────────────────
router.get("/", function(req, res) {
  var db = getDb();
  var rows = db.prepare("SELECT * FROM user_environments WHERE user_id = ? ORDER BY is_active DESC, created_at DESC").all(req.user.id);
  res.json(rows.map(parseProfile));
});

// ─────────────────────────────────────────────
// GET /api/env/compatibility — all compat results for the user
// MUST come before /:id routes
// ─────────────────────────────────────────────
router.get("/compatibility", function(req, res) {
  var db = getDb();
  var rows = db.prepare("SELECT query_id, status FROM query_compatibility WHERE user_id = ?").all(req.user.id);
  var result = {};
  rows.forEach(function(r) { result[r.query_id] = r.status; });
  res.json(result);
});

// ─────────────────────────────────────────────
// GET /api/env/compatibility/:queryId — detailed compat for one query
// ─────────────────────────────────────────────
router.get("/compatibility/:queryId", function(req, res) {
  var db = getDb();
  var row = db.prepare("SELECT * FROM query_compatibility WHERE query_id = ? AND user_id = ?").get(req.params.queryId, req.user.id);
  if (!row) {
    // Not checked yet — run on demand
    var query = db.prepare("SELECT id, kql, language FROM queries WHERE id = ? AND team = ?").get(req.params.queryId, req.user.team);
    if (!query) return res.status(404).json({ error: "Not found" });
    var env = db.prepare("SELECT * FROM user_environments WHERE user_id = ? AND is_active = 1").get(req.user.id);
    if (!env) return res.json({ status: "unknown", tables_found: [], tables_ok: [], tables_missing: [] });
    var result = checkCompatibility(query.kql, query.language, env.config, env.platform);
    return res.json({ status: result.status, tables_found: result.tables_found, tables_ok: result.tables_ok, tables_missing: result.tables_missing });
  }
  res.json({
    status: row.status,
    tables_found: JSON.parse(row.tables_found || "[]"),
    tables_ok: JSON.parse(row.tables_ok || "[]"),
    tables_missing: JSON.parse(row.tables_missing || "[]")
  });
});

// ─────────────────────────────────────────────
// POST /api/env/recheck — force recalculate for the user
// MUST come before /:id routes
// ─────────────────────────────────────────────
router.post("/recheck", function(req, res) {
  var db = getDb();
  var stats = recalculateCompatibility(req.user.id, db);
  res.json(stats);
});

// ─────────────────────────────────────────────
// POST /api/env — create a profile
// ─────────────────────────────────────────────
router.post("/", function(req, res) {
  var db = getDb();
  var name     = sanitize(req.body.name || "", 100).trim();
  var platform = req.body.platform;
  var config   = req.body.config;

  if (!name) return res.status(400).json({ error: "Name is required" });
  if (!VALID_PLATFORMS.includes(platform)) return res.status(400).json({ error: "Invalid platform (defender_xdr or sentinel)" });

  var configStr = serializeConfig(config);

  var id = "env_" + crypto.randomBytes(8).toString("hex");
  var existing = db.prepare("SELECT COUNT(*) as c FROM user_environments WHERE user_id = ?").get(req.user.id);
  var is_active = existing.c === 0 ? 1 : 0;

  db.prepare("INSERT INTO user_environments (id, user_id, name, platform, config, is_active) VALUES (?, ?, ?, ?, ?, ?)").run(
    id, req.user.id, name, platform, configStr, is_active
  );

  auditLog(req.user.id, "ENV_CREATE", "environment", id, { name: name, platform: platform }, req.ip);

  var stats = recalculateCompatibility(req.user.id, db);
  var profile = parseProfile(db.prepare("SELECT * FROM user_environments WHERE id = ?").get(id));
  res.json({ profile: profile, stats: stats });
});

// ─────────────────────────────────────────────
// PUT /api/env/:id — update a profile
// ─────────────────────────────────────────────
router.put("/:id", function(req, res) {
  var db  = getDb();
  var row = db.prepare("SELECT * FROM user_environments WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Profile not found" });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: "Not authorized" });

  var name   = sanitize(req.body.name || "", 100).trim();
  var config = req.body.config;
  if (!name) return res.status(400).json({ error: "Name is required" });

  var configStr = serializeConfig(config);

  db.prepare("UPDATE user_environments SET name = ?, config = ?, updated_at = datetime('now') WHERE id = ?").run(name, configStr, req.params.id);
  auditLog(req.user.id, "ENV_UPDATE", "environment", req.params.id, { name: name }, req.ip);

  var stats = recalculateCompatibility(req.user.id, db);
  var profile = parseProfile(db.prepare("SELECT * FROM user_environments WHERE id = ?").get(req.params.id));
  res.json({ profile: profile, stats: stats });
});

// ─────────────────────────────────────────────
// DELETE /api/env/:id — delete a profile
// ─────────────────────────────────────────────
router.delete("/:id", function(req, res) {
  var db  = getDb();
  var row = db.prepare("SELECT * FROM user_environments WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Profile not found" });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: "Not authorized" });

  db.prepare("DELETE FROM user_environments WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "ENV_DELETE", "environment", req.params.id, null, req.ip);

  // Si c'était le profil actif, activer le suivant
  if (row.is_active) {
    var next = db.prepare("SELECT id FROM user_environments WHERE user_id = ? ORDER BY created_at ASC LIMIT 1").get(req.user.id);
    if (next) db.prepare("UPDATE user_environments SET is_active = 1 WHERE id = ?").run(next.id);
  }

  // Recalculer ou vider les résultats
  var hasActive = db.prepare("SELECT COUNT(*) as c FROM user_environments WHERE user_id = ? AND is_active = 1").get(req.user.id);
  if (hasActive.c === 0) {
    db.prepare("DELETE FROM query_compatibility WHERE user_id = ?").run(req.user.id);
  } else {
    recalculateCompatibility(req.user.id, db);
  }

  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// POST /api/env/:id/activate — activate a profile
// ─────────────────────────────────────────────
router.post("/:id/activate", function(req, res) {
  var db  = getDb();
  var row = db.prepare("SELECT * FROM user_environments WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Profile not found" });
  if (row.user_id !== req.user.id) return res.status(403).json({ error: "Not authorized" });

  db.transaction(function() {
    db.prepare("UPDATE user_environments SET is_active = 0 WHERE user_id = ?").run(req.user.id);
    db.prepare("UPDATE user_environments SET is_active = 1 WHERE id = ?").run(req.params.id);
  })();

  auditLog(req.user.id, "ENV_ACTIVATE", "environment", req.params.id, null, req.ip);

  var stats = recalculateCompatibility(req.user.id, db);
  res.json({ ok: true, stats: stats });
});

module.exports = { router, recheckSingleQuery, recalculateCompatibility };
