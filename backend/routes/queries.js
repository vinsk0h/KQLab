const express = require("express");
const crypto  = require("crypto");
const { getDb, auditLog, getSetting } = require("../db/database");
const { requireAuth }     = require("../middleware/auth");
const { sanitize, requireWriter, validateEnum, VALID_ENVIRONMENTS, VALID_SEVERITIES, VALID_LANGUAGES } = require("../middleware/utils");
const { detectEnvironment, buildExtrasFromDb } = require("../lib/env-detector");
const { recheckSingleQuery } = require("./fingerprint");
const { generateQueryPDF, safeFilename } = require("../lib/reportGenerator");

const router = express.Router();
router.use(requireAuth);

function extractUrlsFromKql(kql) {
  var refs = [], seen = {};
  (kql || "").split("\n").forEach(function(line) {
    var t = line.trim();
    if (!t.startsWith("//")) return;
    var m = t.match(/https?:\/\/[^\s,;)'"<>]+/);
    if (!m) return;
    var url = m[0].replace(/[.,;!?)+]+$/, "");
    if (seen[url]) return;
    seen[url] = true;
    var note = t.replace(/^\/\/\s*/, "").replace(m[0], "").replace(/^[:\-–\s]+/, "").trim();
    refs.push({ url: url, note: note });
  });
  return refs;
}

// GET /api/queries
// Without ?limit: returns plain array (backward compat).
// With ?limit=N&offset=M: returns { queries, total, limit, offset, hasMore }.
// Optional filters: search, severity, language, environment, folder_id
router.get("/", function (req, res) {
  const db = getDb();

  // Build WHERE clause
  const where  = ["team = ?"];
  const params = [req.user.team];

  if (req.query.search) {
    where.push("(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR kql LIKE ? ESCAPE '\\')");
    const raw = req.query.search.slice(0, 200).replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
    const s = "%" + raw + "%";
    params.push(s, s, s);
  }
  if (req.query.severity && VALID_SEVERITIES.includes(req.query.severity)) {
    where.push("severity = ?"); params.push(req.query.severity);
  }
  if (req.query.language && VALID_LANGUAGES.includes(req.query.language)) {
    where.push("language = ?"); params.push(req.query.language);
  }
  if (req.query.environment && VALID_ENVIRONMENTS.includes(req.query.environment)) {
    where.push("environment = ?"); params.push(req.query.environment);
  }
  if (req.query.folder_id) {
    if (req.query.folder_id === "null") where.push("folder_id IS NULL");
    else { where.push("folder_id = ?"); params.push(req.query.folder_id); }
  }

  const whereSQL = "WHERE " + where.join(" AND ");

  // Stars lookup (user-specific)
  const stars = {};
  db.prepare("SELECT query_id FROM stars WHERE user_id = ?").all(req.user.id)
    .forEach(function (s) { stars[s.query_id] = true; });

  function mapQuery(q) {
    return Object.assign({}, q, {
      mitre:    JSON.parse(q.mitre    || "[]"),
      picerl:   JSON.parse(q.picerl   || "[]"),
      tags:     JSON.parse(q.tags     || "[]"),
      versions: JSON.parse(q.versions || "[]"),
      starred:  !!stars[q.id],
    });
  }

  // Paginated mode
  if (req.query.limit !== undefined) {
    const limit  = Math.min(parseInt(req.query.limit)  || 50, 500);
    const offset = Math.max(parseInt(req.query.offset) || 0,  0);
    const total  = db.prepare(`SELECT COUNT(*) AS c FROM queries ${whereSQL}`).get(...params).c;
    const queries = db.prepare(`SELECT * FROM queries ${whereSQL} ORDER BY updated_at DESC LIMIT ? OFFSET ?`)
      .all(...params, limit, offset).map(mapQuery);
    return res.json({ queries, total, limit, offset, hasMore: offset + limit < total });
  }

  // Full load (default — backward compat)
  const queries = db.prepare(`SELECT * FROM queries ${whereSQL} ORDER BY updated_at DESC`)
    .all(...params).map(mapQuery);
  res.json(queries);
});

// POST /api/queries
router.post("/", requireWriter, function (req, res) {
  const db = getDb();
  const b  = req.body;

  const title = sanitize(b.title || "", 200);
  if (!title) return res.status(400).json({ error: "Title is required" });

  const extras = buildExtrasFromDb(db);
  const id = "q_" + crypto.randomBytes(8).toString("hex");
  const kqlBody = (b.kql || "").slice(0, 100000);
  const kqlRefs = JSON.stringify(extractUrlsFromKql(kqlBody));
  db.prepare(
    "INSERT INTO queries (id,title,description,kql,language,environment,severity,mitre,picerl,playbook,folder_id,tags,author_id,author_name,team,versions,parsed_references) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
  ).run(
    id,
    title,
    sanitize(b.description || "", 500),
    kqlBody,
    validateEnum(b.language,    VALID_LANGUAGES,    "KQL"),
    detectEnvironment(b.kql, extras) || validateEnum(b.environment, VALID_ENVIRONMENTS, "Defender"),
    validateEnum(b.severity,    VALID_SEVERITIES,   "medium"),
    JSON.stringify(Array.isArray(b.mitre)  ? b.mitre  : []),
    JSON.stringify(Array.isArray(b.picerl) ? b.picerl : []),
    sanitize(b.playbook || "Uncategorized", 100),
    b.folder_id || null,
    JSON.stringify((Array.isArray(b.tags) ? b.tags : []).map(function (t) { return sanitize(t, 50); })),
    req.user.id,
    req.user.display_name,
    req.user.team,
    JSON.stringify([{
      v: 1,
      date: new Date().toISOString().slice(0, 10),
      author: req.user.display_name,
      note: "Initial version",
    }]),
    kqlRefs
  );

  auditLog(req.user.id, "QUERY_CREATE", "query", id, { title: title }, req.ip);
  recheckSingleQuery(id, db);
  const q = db.prepare("SELECT * FROM queries WHERE id = ?").get(id);
  res.json(Object.assign({}, q, {
    mitre:    JSON.parse(q.mitre),
    picerl:   JSON.parse(q.picerl),
    tags:     JSON.parse(q.tags),
    versions: JSON.parse(q.versions),
    starred:  false,
  }));
});

// PUT /api/queries/:id
router.put("/:id", requireWriter, function (req, res) {
  const db       = getDb();
  const existing = db.prepare("SELECT * FROM queries WHERE id = ? AND team = ?").get(req.params.id, req.user.team);
  if (!existing) return res.status(404).json({ error: "Not found" });

  const b = req.body;

  // Append a new version entry (server-controlled — client cannot overwrite history)
  const currentVersions = JSON.parse(existing.versions || "[]");
  const nextV = (currentVersions.length > 0 ? currentVersions[currentVersions.length - 1].v : 0) + 1;
  const updatedVersions = currentVersions.concat([{
    v:      nextV,
    date:   new Date().toISOString().slice(0, 10),
    author: req.user.display_name,
    note:   sanitize(b.version_note || "Updated", 200),
  }]);

  const updatedKql = (b.kql !== undefined ? b.kql : existing.kql).slice(0, 100000);
  const updatedRefs = JSON.stringify(extractUrlsFromKql(updatedKql));

  db.prepare(
    "UPDATE queries SET title=?,description=?,kql=?,language=?,environment=?,severity=?,mitre=?,picerl=?,playbook=?,folder_id=?,tags=?,versions=?,parsed_references=?,updated_at=datetime('now') WHERE id=?"
  ).run(
    sanitize(b.title       || existing.title,       200),
    sanitize(b.description || existing.description, 500),
    updatedKql,
    validateEnum(b.language,    VALID_LANGUAGES,    existing.language    || "KQL"),
    validateEnum(b.environment, VALID_ENVIRONMENTS, existing.environment),
    validateEnum(b.severity,    VALID_SEVERITIES,   existing.severity),
    JSON.stringify(Array.isArray(b.mitre)  ? b.mitre  : JSON.parse(existing.mitre)),
    JSON.stringify(Array.isArray(b.picerl) ? b.picerl : JSON.parse(existing.picerl)),
    sanitize(b.playbook || existing.playbook, 100),
    b.folder_id !== undefined ? b.folder_id : existing.folder_id,
    JSON.stringify((Array.isArray(b.tags) ? b.tags : JSON.parse(existing.tags)).map(function (t) { return sanitize(t, 50); })),
    JSON.stringify(updatedVersions),
    updatedRefs,
    req.params.id
  );

  // Mark as locally modified so auto-sync won't overwrite
  db.prepare("UPDATE repo_query_map SET local_modified = 1 WHERE query_id = ?").run(req.params.id);
  auditLog(req.user.id, "QUERY_UPDATE", "query", req.params.id, { title: b.title }, req.ip);
  recheckSingleQuery(req.params.id, db);
  res.json({ ok: true });
});

// PUT /api/queries/:id/move
router.put("/:id/move", requireWriter, function (req, res) {
  const db       = getDb();
  const existing = db.prepare("SELECT id FROM queries WHERE id = ? AND team = ?").get(req.params.id, req.user.team);
  if (!existing) return res.status(404).json({ error: "Not found" });

  const folderId = req.body.folder_id || null;
  if (folderId) {
    // IDOR fix: ensure target folder belongs to user's team or is the user's personal folder
    const folder = db.prepare(
      "SELECT id FROM folders WHERE id = ? AND (team_id = ? OR (scope = 'personal' AND owner_id = ?))"
    ).get(folderId, req.user.team, req.user.id);
    if (!folder) return res.status(404).json({ error: "Folder not found" });
  }

  db.prepare("UPDATE queries SET folder_id = ?, updated_at = datetime('now') WHERE id = ?").run(folderId, req.params.id);
  auditLog(req.user.id, "QUERY_MOVE", "query", req.params.id, { folder_id: folderId }, req.ip);
  res.json({ ok: true });
});

// DELETE /api/queries/:id
router.delete("/:id", requireWriter, function (req, res) {
  const db       = getDb();
  const existing = db.prepare("SELECT * FROM queries WHERE id = ? AND team = ?").get(req.params.id, req.user.team);
  if (!existing) return res.status(404).json({ error: "Not found" });
  if (existing.author_id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  db.prepare("DELETE FROM queries WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "QUERY_DELETE", "query", req.params.id, { title: existing.title }, req.ip);
  res.json({ ok: true });
});

// POST /api/queries/:id/star
router.post("/:id/star", function (req, res) {
  const db  = getDb();
  const qid = req.params.id;

  // Verify the query belongs to the user's team before starring
  const query = db.prepare("SELECT id FROM queries WHERE id = ? AND team = ?").get(qid, req.user.team);
  if (!query) return res.status(404).json({ error: "Not found" });

  const starOps = db.transaction(function () {
    const ex = db.prepare("SELECT 1 FROM stars WHERE user_id = ? AND query_id = ?").get(req.user.id, qid);
    if (ex) {
      db.prepare("DELETE FROM stars WHERE user_id = ? AND query_id = ?").run(req.user.id, qid);
      db.prepare("UPDATE queries SET stars = MAX(stars - 1, 0) WHERE id = ?").run(qid);
      return false;
    } else {
      db.prepare("INSERT INTO stars (user_id, query_id) VALUES (?, ?)").run(req.user.id, qid);
      db.prepare("UPDATE queries SET stars = stars + 1 WHERE id = ?").run(qid);
      return true;
    }
  });

  res.json({ starred: starOps() });
});

// POST /api/queries/bulk
router.post("/bulk", requireWriter, function (req, res) {
  var db     = getDb();
  var action = req.body.action;
  var ids    = Array.isArray(req.body.ids) ? req.body.ids.filter(function(id) { return typeof id === "string" && /^q_[a-z0-9]+$/.test(id); }).slice(0, 200) : [];
  var value  = req.body.value !== undefined ? req.body.value : null;
  if (!ids.length) return res.status(400).json({ error: "No ids provided" });

  var placeholders = ids.map(function () { return "?"; }).join(",");
  var owned = db.prepare("SELECT id, author_id FROM queries WHERE id IN (" + placeholders + ") AND team = ?").all(...ids, req.user.team);
  if (owned.length !== ids.length) return res.status(403).json({ error: "Some queries not found in your team" });

  if (action === "delete") {
    if (req.user.role !== "admin") {
      var notOwned = owned.filter(function (q) { return q.author_id !== req.user.id; });
      if (notOwned.length) return res.status(403).json({ error: "You can only delete your own queries" });
    }
    db.prepare("DELETE FROM queries WHERE id IN (" + placeholders + ")").run(...ids);
    auditLog(req.user.id, "QUERY_BULK_DELETE", "query", null, { count: ids.length }, req.ip);
    return res.json({ ok: true, affected: ids.length });
  }

  if (action === "move") {
    var folderId = value || null;
    if (folderId) {
      var folder = db.prepare("SELECT id FROM folders WHERE id = ? AND (team_id = ? OR (scope = 'personal' AND owner_id = ?))").get(folderId, req.user.team, req.user.id);
      if (!folder) return res.status(404).json({ error: "Folder not found" });
    }
    db.prepare("UPDATE queries SET folder_id = ?, updated_at = datetime('now') WHERE id IN (" + placeholders + ")").run(folderId, ...ids);
    auditLog(req.user.id, "QUERY_BULK_MOVE", "query", null, { count: ids.length, folder_id: folderId }, req.ip);
    return res.json({ ok: true, affected: ids.length });
  }

  if (action === "severity") {
    var sev = VALID_SEVERITIES.includes(value) ? value : null;
    if (!sev) return res.status(400).json({ error: "Invalid severity" });
    db.prepare("UPDATE queries SET severity = ?, updated_at = datetime('now') WHERE id IN (" + placeholders + ")").run(sev, ...ids);
    auditLog(req.user.id, "QUERY_BULK_SEVERITY", "query", null, { count: ids.length, severity: sev }, req.ip);
    return res.json({ ok: true, affected: ids.length });
  }

  return res.status(400).json({ error: "Unknown action" });
});

// POST /api/queries/import
router.post("/import", requireWriter, function (req, res) {
  const db = getDb();
  const qs = req.body.queries;
  if (!Array.isArray(qs)) return res.status(400).json({ error: "Expected queries array" });

  const ins = db.prepare(
    "INSERT INTO queries (id,title,description,kql,language,environment,severity,mitre,picerl,playbook,folder_id,tags,author_id,author_name,team,versions) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
  );
  let count = 0;
  const today = new Date().toISOString().slice(0, 10);
  const extras = buildExtrasFromDb(db);

  db.transaction(function (items) {
    items.slice(0, 500).forEach(function (q) {
      const title = sanitize(q.title || "Imported query", 200);
      ins.run(
        "q_" + crypto.randomBytes(8).toString("hex"),
        title,
        sanitize(q.description || q.desc || "", 500),
        (q.kql || "").slice(0, 100000),
        validateEnum(q.language,    VALID_LANGUAGES,    "KQL"),
        detectEnvironment(q.kql, extras) || validateEnum(q.environment || q.env, VALID_ENVIRONMENTS, "Defender"),
        validateEnum(q.severity,    VALID_SEVERITIES,   "medium"),
        JSON.stringify(Array.isArray(q.mitre)  ? q.mitre  : []),
        JSON.stringify(Array.isArray(q.picerl) ? q.picerl : []),
        sanitize(q.playbook || "Imported", 100),
        null,
        JSON.stringify((Array.isArray(q.tags) ? q.tags : []).map(function (t) { return sanitize(t, 50); })),
        req.user.id,
        req.user.display_name,
        req.user.team,
        JSON.stringify([{ v: 1, date: today, author: req.user.display_name, note: "Imported" }])
      );
      count++;
    });
  })(qs);

  auditLog(req.user.id, "QUERY_IMPORT", "query", null, { count: count }, req.ip);
  // Recheck all newly imported queries
  var newIds = db.prepare("SELECT id FROM queries WHERE team = ? ORDER BY created_at DESC LIMIT ?").all(req.user.team, count);
  newIds.forEach(function(r) { recheckSingleQuery(r.id, db); });
  res.json({ imported: count });
});

// GET /api/queries/:id/export?format=pdf
router.get("/:id/export", async function(req, res) {
  const format = (req.query.format || "pdf").toLowerCase();
  if (format !== "pdf") return res.status(400).json({ error: "Only format=pdf is supported" });

  const db    = getDb();
  const query = db.prepare("SELECT * FROM queries WHERE id = ? AND team = ?").get(req.params.id, req.user.team);
  if (!query) return res.status(404).json({ error: "Query not found" });

  const settings = {
    company_name:        getSetting("company_name",        "KQL Vault"),
    company_subtitle:    getSetting("company_subtitle",    "Security Operations Center"),
    company_logo:        getSetting("company_logo",        ""),
    report_header_color: getSetting("report_header_color", "#e63946"),
  };
  const lang = getSetting("report_lang", "fr");

  try {
    const buffer   = await generateQueryPDF(query, settings, lang);
    const filename = `query_${safeFilename(query.title)}.pdf`;
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Length", buffer.length);
    auditLog(req.user.id, "QUERY_EXPORT_PDF", "query", query.id, { title: query.title }, req.ip);
    res.end(buffer);
  } catch(e) {
    console.error("Query PDF error:", e);
    res.status(500).json({ error: "PDF generation failed" });
  }
});

module.exports = router;
