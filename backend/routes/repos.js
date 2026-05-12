const express    = require("express");
const crypto     = require("crypto");
const { getDb, auditLog } = require("../db/database");
const { requireAuth }     = require("../middleware/auth");
const { sanitize }        = require("../middleware/utils");
const { syncRepo }        = require("../lib/repo-parser");
const { recalculateCompatibility } = require("./fingerprint");

const router = express.Router();
router.use(requireAuth);

const VALID_FORMATS = ["yaml", "md", "kql", "auto"];

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

function recalcTeamEnvs(db, teamId) {
  var users = db.prepare(
    "SELECT ue.user_id FROM user_environments ue JOIN users u ON ue.user_id = u.id WHERE ue.is_active = 1 AND u.team = ?"
  ).all(teamId);
  users.forEach(function(u) { recalculateCompatibility(u.user_id, db); });
}

function parseSource(row) {
  return Object.assign({}, row, { enabled: row.enabled === 1 });
}

// GET /api/repos/last-sync — analyst + admin
router.get("/last-sync", function(req, res) {
  var db = getDb();
  var sources = db.prepare("SELECT id,name,github_owner,last_sync_at,last_sync_status,last_sync_new,last_sync_updated,last_sync_errors,target_folder_id FROM repo_sources WHERE enabled=1 ORDER BY last_sync_at DESC").all();
  var total = db.prepare("SELECT COUNT(*) as c FROM repo_query_map").get().c;
  res.json({ sources: sources, total_queries: total });
});

// GET /api/repos
router.get("/", requireAdmin, function(req, res) {
  var db = getDb();
  var rows = db.prepare(
    "SELECT rs.*, COUNT(rqm.query_id) as query_count FROM repo_sources rs LEFT JOIN repo_query_map rqm ON rqm.repo_id=rs.id GROUP BY rs.id ORDER BY rs.created_at ASC"
  ).all();
  res.json(rows.map(parseSource));
});

// POST /api/repos
router.post("/", requireAdmin, function(req, res) {
  var b  = req.body;
  var name   = sanitize(b.name || "", 100);
  var owner  = sanitize(b.github_owner || "", 100);
  var repo   = sanitize(b.github_repo  || "", 100);
  var branch = sanitize(b.branch || "main", 100);
  var pf     = sanitize(b.path_filter  || "", 200);
  var fmt    = VALID_FORMATS.includes(b.file_format) ? b.file_format : "auto";

  if (!name || !owner || !repo) return res.status(400).json({ error: "name, github_owner and github_repo are required" });

  var db     = getDb();
  var id     = "rs_" + crypto.randomBytes(6).toString("hex");
  var teamRow = db.prepare("SELECT id FROM teams LIMIT 1").get();
  var teamId  = teamRow ? teamRow.id : "t1";

  // Auto-create a dedicated folder for this repo if no target_folder_id provided
  var folderId = b.target_folder_id || null;
  if (!folderId) {
    folderId = "f_" + id;
    var ini  = ((owner[0] || "?") + (repo[0] || "?")).toUpperCase();
    db.prepare("INSERT OR IGNORE INTO folders (id,name,icon,scope,team_id,color,owner_id) VALUES (?,?,?,?,?,?,?)").run(
      folderId, name, ini, "team", teamId, "#6e40c9", req.user.id
    );
  }

  db.prepare(
    "INSERT INTO repo_sources (id,name,github_owner,github_repo,branch,path_filter,file_format,target_folder_id,added_by) VALUES(?,?,?,?,?,?,?,?,?)"
  ).run(id, name, owner, repo, branch, pf, fmt, folderId, req.user.id);

  auditLog(req.user.id, "REPO_ADD", "repo_source", id, { name }, req.ip);
  res.json(parseSource(db.prepare("SELECT * FROM repo_sources WHERE id=?").get(id)));
});

// PUT /api/repos/:id
router.put("/:id", requireAdmin, function(req, res) {
  var db  = getDb();
  var row = db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Not found" });

  var b      = req.body;
  var name   = sanitize(b.name   || row.name, 100);
  var branch = sanitize(b.branch || row.branch, 100);
  var pf     = sanitize(b.path_filter !== undefined ? b.path_filter : row.path_filter, 200);
  var fmt    = VALID_FORMATS.includes(b.file_format) ? b.file_format : row.file_format;
  var enabled = b.enabled !== undefined ? (b.enabled ? 1 : 0) : row.enabled;

  db.prepare(
    "UPDATE repo_sources SET name=?,branch=?,path_filter=?,file_format=?,target_folder_id=?,enabled=? WHERE id=?"
  ).run(name, branch, pf, fmt, b.target_folder_id !== undefined ? (b.target_folder_id || null) : row.target_folder_id, enabled, req.params.id);

  res.json(parseSource(db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id)));
});

// DELETE /api/repos/:id
router.delete("/:id", requireAdmin, function(req, res) {
  var db  = getDb();
  var row = db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Not found" });
  // queries remain in vault; only tracking is removed (CASCADE on repo_query_map)
  db.prepare("DELETE FROM repo_sources WHERE id=?").run(req.params.id);
  auditLog(req.user.id, "REPO_DELETE", "repo_source", req.params.id, { name: row.name }, req.ip);
  res.json({ ok: true });
});

// POST /api/repos/purge/:id — delete all queries imported from a specific repo source
router.post("/purge/:id", requireAdmin, function(req, res) {
  try {
    var db  = getDb();
    var src = db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id);
    if (!src) return res.status(404).json({ error: "Not found" });

    var mappings = db.prepare("SELECT query_id FROM repo_query_map WHERE repo_id=?").all(req.params.id);
    var queryIds = mappings.map(function(r) { return r.query_id; });

    var deleted = 0;
    if (queryIds.length > 0) {
      var batchSize = 500;
      for (var i = 0; i < queryIds.length; i += batchSize) {
        var batch = queryIds.slice(i, i + batchSize);
        var placeholders = batch.map(function() { return "?"; }).join(",");
        db.prepare("DELETE FROM queries WHERE id IN (" + placeholders + ")").run(...batch);
        deleted += batch.length;
      }
    }

    db.prepare("DELETE FROM repo_query_map WHERE repo_id=?").run(req.params.id);
    db.prepare("UPDATE repo_sources SET last_sync_at=NULL, last_sync_status='never', last_sync_new=0, last_sync_updated=0, last_sync_errors=0 WHERE id=?").run(req.params.id);

    auditLog(req.user.id, "REPO_PURGE", "repo_source", req.params.id, { name: src.name, deleted: deleted }, req.ip);
    res.json({ ok: true, deleted: deleted });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/repos/purge-imported — delete all repo-imported queries and reset sync state
router.post("/purge-imported", requireAdmin, function(req, res) {
  try {
    var db = getDb();

    var mappings = db.prepare("SELECT query_id FROM repo_query_map").all();
    var queryIds = mappings.map(function(r) { return r.query_id; });

    var deleted = 0;
    if (queryIds.length > 0) {
      var batchSize = 500;
      for (var i = 0; i < queryIds.length; i += batchSize) {
        var batch = queryIds.slice(i, i + batchSize);
        var placeholders = batch.map(function() { return "?"; }).join(",");
        db.prepare("DELETE FROM queries WHERE id IN (" + placeholders + ")").run(...batch);
        deleted += batch.length;
      }
    }

    db.prepare("DELETE FROM repo_query_map").run();
    db.prepare("UPDATE repo_sources SET last_sync_at=NULL, last_sync_status='never', last_sync_new=0, last_sync_updated=0, last_sync_errors=0").run();

    auditLog(req.user.id, "REPO_PURGE_IMPORTED", "queries", null, { deleted: deleted }, req.ip);
    res.json({ ok: true, deleted: deleted });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/repos/reparse — force re-parse all non-locally-modified files by clearing SHAs
router.post("/reparse", requireAdmin, async function(req, res) {
  var db = getDb();
  // Clear SHAs for non-locally-modified entries so syncRepo will re-fetch them
  var cleared = db.prepare("UPDATE repo_query_map SET file_sha='' WHERE local_modified=0").run().changes;
  var sources  = db.prepare("SELECT * FROM repo_sources WHERE enabled=1").all();
  var results  = [];
  for (var i = 0; i < sources.length; i++) {
    var src    = sources[i];
    var team   = db.prepare("SELECT id FROM teams LIMIT 1").get();
    var teamId = team ? team.id : "t1";
    var t0     = Date.now();
    try {
      var stats = await syncRepo(src, db, teamId);
      var dur   = Date.now() - t0;
      db.prepare(
        "UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status='ok',last_sync_new=?,last_sync_updated=?,last_sync_errors=? WHERE id=?"
      ).run(stats.new, stats.updated, stats.errors, src.id);
      auditLog(req.user.id, "REPO_REPARSE", "repo_source", src.id, { new: stats.new, updated: stats.updated, errors: stats.errors }, req.clientIp || req.ip);
      if (stats.new > 0 || stats.updated > 0) recalcTeamEnvs(db, teamId);
      results.push(Object.assign({ id: src.id, name: src.name, duration_ms: dur }, stats));
    } catch(e) {
      db.prepare("UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status=? WHERE id=?").run("error: " + e.message.slice(0, 100), src.id);
      results.push({ id: src.id, name: src.name, error: e.message });
    }
  }
  res.json({ cleared_entries: cleared, results });
});

// POST /api/repos/sync-all
router.post("/sync-all", requireAdmin, async function(req, res) {
  var db      = getDb();
  var sources = db.prepare("SELECT * FROM repo_sources WHERE enabled=1").all();
  var results = [];
  for (var i = 0; i < sources.length; i++) {
    var src    = sources[i];
    var team   = db.prepare("SELECT id FROM teams LIMIT 1").get();
    var teamId = team ? team.id : "t1";
    var t0     = Date.now();
    try {
      var stats = await syncRepo(src, db, teamId);
      var dur   = Date.now() - t0;
      db.prepare(
        "UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status='ok',last_sync_new=?,last_sync_updated=?,last_sync_errors=? WHERE id=?"
      ).run(stats.new, stats.updated, stats.errors, src.id);
      auditLog(null, "REPO_SYNC", "repo_source", src.id, { new: stats.new, updated: stats.updated, errors: stats.errors }, "");
      if (stats.new > 0 || stats.updated > 0) recalcTeamEnvs(db, teamId);
      results.push(Object.assign({ id: src.id, name: src.name, duration_ms: dur }, stats));
    } catch(e) {
      db.prepare("UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status=? WHERE id=?").run("error: " + e.message.slice(0, 100), src.id);
      results.push({ id: src.id, name: src.name, error: e.message });
    }
  }
  res.json({ results });
});

// POST /api/repos/:id/sync
router.post("/:id/sync", requireAdmin, async function(req, res) {
  var db  = getDb();
  var src = db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id);
  if (!src) return res.status(404).json({ error: "Not found" });

  var team   = db.prepare("SELECT id FROM teams LIMIT 1").get();
  var teamId = team ? team.id : "t1";
  var t0     = Date.now();
  try {
    var stats = await syncRepo(src, db, teamId);
    var dur   = Date.now() - t0;
    db.prepare(
      "UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status='ok',last_sync_new=?,last_sync_updated=?,last_sync_errors=? WHERE id=?"
    ).run(stats.new, stats.updated, stats.errors, src.id);
    auditLog(req.user.id, "REPO_SYNC", "repo_source", src.id, { new: stats.new, updated: stats.updated }, req.ip);
    if (stats.new > 0 || stats.updated > 0) recalcTeamEnvs(db, teamId);
    res.json(Object.assign({ duration_ms: dur }, stats));
  } catch(e) {
    db.prepare("UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status=? WHERE id=?").run("error: " + e.message.slice(0, 100), src.id);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/repos/:id/files
router.get("/:id/files", requireAdmin, function(req, res) {
  var db = getDb();
  var row = db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "Not found" });
  var files = db.prepare(
    "SELECT rqm.file_path, rqm.file_sha, rqm.local_modified, rqm.last_synced_at, q.title FROM repo_query_map rqm LEFT JOIN queries q ON q.id=rqm.query_id WHERE rqm.repo_id=? ORDER BY rqm.file_path ASC"
  ).all(req.params.id);
  res.json(files);
});

// POST /api/repos/:id/reset-file — reset a locally-modified query to upstream
router.post("/:id/reset-file", requireAdmin, async function(req, res) {
  var db      = getDb();
  var src     = db.prepare("SELECT * FROM repo_sources WHERE id=?").get(req.params.id);
  if (!src) return res.status(404).json({ error: "Not found" });
  var filePath = req.body.file_path;
  if (!filePath) return res.status(400).json({ error: "file_path required" });
  var mapping = db.prepare("SELECT * FROM repo_query_map WHERE repo_id=? AND file_path=?").get(src.id, filePath);
  if (!mapping) return res.status(404).json({ error: "File not tracked" });

  try {
    var { fetchFileContent, parseFile } = require("../lib/repo-parser");
    var content = await fetchFileContent(src.github_owner, src.github_repo, filePath, src.branch);
    // parseFile returns an array; use first block for reset-to-upstream
    var parsedArr = parseFile(content, filePath);
    var parsed = parsedArr && parsedArr.length ? parsedArr[0] : null;
    if (!parsed) return res.status(422).json({ error: "Could not parse file" });

    var now = new Date().toISOString().slice(0, 10);
    var currentVersions = JSON.parse(db.prepare("SELECT versions FROM queries WHERE id=?").get(mapping.query_id).versions || "[]");
    var nextV = (currentVersions.length > 0 ? currentVersions[currentVersions.length - 1].v : 0) + 1;
    currentVersions.push({ v: nextV, date: now, author: src.github_owner + "/" + src.github_repo, note: "Reset to upstream" });

    db.prepare(
      "UPDATE queries SET title=?,description=?,kql=?,environment=?,severity=?,mitre=?,tags=?,versions=?,updated_at=datetime('now') WHERE id=?"
    ).run(parsed.title, parsed.description, parsed.kql, parsed.environment, parsed.severity,
          JSON.stringify(parsed.mitre), JSON.stringify(parsed.tags), JSON.stringify(currentVersions), mapping.query_id);
    db.prepare("UPDATE repo_query_map SET local_modified=0,last_synced_at=datetime('now') WHERE repo_id=? AND file_path=?").run(src.id, filePath);
    auditLog(req.user.id, "REPO_RESET_FILE", "query", mapping.query_id, { file_path: filePath }, req.ip);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
