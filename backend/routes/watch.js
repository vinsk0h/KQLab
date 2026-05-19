// KQLab — Cyber Watch routes
var express = require("express");
var crypto  = require("crypto");
var { getDb, auditLog } = require("../db/database");
var { requireAuth }     = require("../middleware/auth");
var { sanitize, sanitizeUrl, requireAdmin } = require("../middleware/utils");

var rateLimit = require("express-rate-limit");

var router = express.Router();
router.use(requireAuth);

var feedOpsLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: "Too many requests, please wait." } });

var VALID_FEED_TYPES = ["rss", "atom", "rss_auto", "msrc", "json_cisa", "cisa_kev"];

// ─── GET /api/watch/summary ───────────────────────────────────────────────
// P13 — 5 sequential queries collapsed into 2 (scalar subqueries + match rows)
router.get("/summary", function(req, res) {
  var db = getDb();
  try {
    var scalars = db.prepare(`
      SELECT
        (SELECT COUNT(DISTINCT wa.id) FROM watch_articles wa
         JOIN watch_article_matches wam ON wam.article_id = wa.id
         WHERE wa.is_read = 0 AND wa.is_dismissed = 0 AND wa.fetched_at > datetime('now','-48 hours')) AS unread,
        (SELECT COUNT(*) FROM watch_articles
         WHERE severity = 'critical' AND is_dismissed = 0 AND fetched_at > datetime('now','-48 hours'))  AS critical,
        (SELECT COUNT(*) FROM watch_article_matches wam
         JOIN watch_articles wa ON wa.id = wam.article_id
         WHERE wa.is_dismissed = 0 AND wa.fetched_at > datetime('now','-7 days'))                        AS total_matches,
        (SELECT MAX(last_fetch_at) FROM watch_sources)                                                   AS last_fetch_at
    `).get();

    var matchRows = db.prepare(
      "SELECT wam.query_id, wa.title FROM watch_article_matches wam " +
      "JOIN watch_articles wa ON wa.id = wam.article_id " +
      "WHERE wa.is_read = 0 AND wa.is_dismissed = 0 AND wa.fetched_at > datetime('now', '-48 hours')"
    ).all();

    var matched_queries = {};
    matchRows.forEach(function(row) {
      if (!matched_queries[row.query_id]) matched_queries[row.query_id] = [];
      if (matched_queries[row.query_id].length < 3) {
        matched_queries[row.query_id].push(row.title.slice(0, 60));
      }
    });

    res.json({
      unread_count:    scalars.unread,
      critical_count:  scalars.critical,
      total_matches:   scalars.total_matches,
      last_fetch_at:   scalars.last_fetch_at || null,
      matched_queries: matched_queries
    });
  } catch(e) {
    console.error('[Watch] GET /summary error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── GET /api/watch/feed ─────────────────────────────────────────────────
router.get("/feed", function(req, res) {
  var db     = getDb();
  var days   = Math.min(parseInt(req.query.days) || 7, 90);
  var source = req.query.source || "all";
  var sev    = req.query.severity || "all";
  var unread = req.query.unread === "1";
  var matched_only = req.query.matched_only === "1";

  try {
    var cutoff = new Date(Date.now() - days * 86400000).toISOString();
    var where  = ["wa.is_dismissed = 0", "wa.fetched_at > ?"];
    var params = [cutoff];

    if (source !== "all") { where.push("wa.source_id = ?"); params.push(source); }
    if (sev    !== "all") { where.push("wa.severity = ?");  params.push(sev);    }
    if (unread)           { where.push("wa.is_read = 0"); }

    var havingClause = matched_only ? "HAVING match_count > 0" : "";
    var sql =
      "SELECT wa.*, COUNT(wam.query_id) as match_count " +
      "FROM watch_articles wa " +
      "LEFT JOIN watch_article_matches wam ON wam.article_id = wa.id " +
      "WHERE " + where.join(" AND ") + " " +
      "GROUP BY wa.id " +
      havingClause + " " +
      "ORDER BY wa.published_at DESC " +
      "LIMIT 100";

    var rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch(e) {
    console.error('[Watch] GET /feed error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── GET /api/watch/feed/:articleId ──────────────────────────────────────
router.get("/feed/:articleId", function(req, res) {
  var db = getDb();
  try {
    var article = db.prepare("SELECT * FROM watch_articles WHERE id = ?").get(req.params.articleId);
    if (!article) return res.status(404).json({ error: "Not found" });

    var matches = db.prepare(
      "SELECT q.id, q.title, q.severity, q.language, q.environment, wam.match_score, wam.match_reasons " +
      "FROM watch_article_matches wam " +
      "JOIN queries q ON wam.query_id = q.id " +
      "WHERE wam.article_id = ? " +
      "ORDER BY wam.match_score DESC"
    ).all(req.params.articleId);

    res.json(Object.assign({}, article, { matches: matches }));
  } catch(e) {
    console.error('[Watch] GET /feed/:id error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /api/watch/feed/:articleId/read ────────────────────────────────
router.post("/feed/:articleId/read", function(req, res) {
  var db = getDb();
  try {
    db.prepare("UPDATE watch_articles SET is_read = 1 WHERE id = ?").run(req.params.articleId);
    res.json({ ok: true });
  } catch(e) {
    console.error('[Watch] POST /feed/:id/read error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /api/watch/feed/:articleId/dismiss ─────────────────────────────
router.post("/feed/:articleId/dismiss", function(req, res) {
  var db = getDb();
  try {
    db.prepare("UPDATE watch_articles SET is_dismissed = 1, is_read = 1 WHERE id = ?").run(req.params.articleId);
    res.json({ ok: true });
  } catch(e) {
    console.error('[Watch] POST /feed/:id/dismiss error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /api/watch/refresh (admin) ─────────────────────────────────────
router.post("/refresh", requireAdmin, feedOpsLimiter, async function(req, res) {
  var db = getDb();
  try {
    var { runWatchCycle } = require("../lib/watch-engine");
    var result = await runWatchCycle(db);
    auditLog(req.user.id, "WATCH_MANUAL_REFRESH", "watch", null, { new_articles: result.new_articles, matched: result.matched, fetched: result.fetched }, req.clientIp);
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/watch/test-feed (admin) ───────────────────────────────────
// Body: { url: string }
// Returns: { ok, format, count, feedTitle, finalUrl, sample: [3 articles], error?, hint? }
router.post("/test-feed", requireAdmin, feedOpsLimiter, async function(req, res) {
  var url = (req.body && req.body.url) ? String(req.body.url).trim() : "";
  if (!url) return res.status(400).json({ error: "url is required" });

  // Basic URL validation
  try { new URL(url); } catch(e) { return res.status(400).json({ error: "Invalid URL", hint: "L'URL doit commencer par http:// ou https://" }); }

  try {
    var engine = require("../lib/watch-engine");
    var result = await engine.fetchFeed({ url: url, name: "" });

    if (result.error) {
      return res.json({ ok: false, error: result.error, hint: result.hint || engine.getErrorHint(result.error), format: result.format || "unknown", count: 0, sample: [] });
    }

    var sample = (result.articles || []).slice(0, 3).map(function(a) {
      return { title: a.title, url: a.url, published_at: a.published_at };
    });

    res.json({
      ok:        true,
      format:    result.format || "unknown",
      count:     result.articles.length,
      feedTitle: result.feedTitle || "",
      finalUrl:  result.finalUrl || url,
      sample:    sample
    });
  } catch(e) {
    var { getErrorHint } = require("../lib/watch-engine");
    res.json({ ok: false, error: e.message, hint: getErrorHint(e.message), format: "unknown", count: 0, sample: [] });
  }
});

// ─── GET /api/watch/sources ──────────────────────────────────────────────
router.get("/sources", function(req, res) {
  var db = getDb();
  try {
    var rows = db.prepare("SELECT * FROM watch_sources ORDER BY created_at ASC").all();
    res.json(rows.map(function(r) { return Object.assign({}, r, { enabled: r.enabled === 1 }); }));
  } catch(e) {
    console.error('[Watch] GET /sources error:', e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── POST /api/watch/sources (admin) ─────────────────────────────────────
router.post("/sources", requireAdmin, function(req, res) {
  var db   = getDb();
  var b    = req.body || {};
  var name = sanitize(b.name || "", 100);
  var url  = sanitizeUrl(b.url || "");
  var ft   = VALID_FEED_TYPES.includes(b.feed_type) ? b.feed_type : "rss";

  if (!name) return res.status(400).json({ error: "name is required" });
  if (!url)  return res.status(400).json({ error: "URL invalide — doit commencer par http:// ou https://" });

  // Normalize feed_type aliases
  if (ft === "cisa_kev") ft = "json_cisa";

  try {
    var id = "ws_" + crypto.randomBytes(6).toString("hex");
    // Insert — feed_type may fail the CHECK constraint on older DBs; if so, use 'rss'
    try {
      db.prepare(
        "INSERT INTO watch_sources (id, name, url, feed_type, enabled) VALUES (?,?,?,?,1)"
      ).run(id, name, url, ft);
    } catch(e2) {
      if (e2.message && e2.message.includes("CHECK")) {
        db.prepare(
          "INSERT INTO watch_sources (id, name, url, feed_type, enabled) VALUES (?,?,?,?,1)"
        ).run(id, name, url, "rss");
      } else throw e2;
    }
    var row = db.prepare("SELECT * FROM watch_sources WHERE id = ?").get(id);
    auditLog(req.user.id, "WATCH_SOURCE_ADD", "watch_source", id, { name, url }, req.clientIp);
    res.status(201).json(Object.assign({}, row, { enabled: row.enabled === 1 }));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── PUT /api/watch/sources/:id (admin) ──────────────────────────────────
router.put("/sources/:id", requireAdmin, function(req, res) {
  var db  = getDb();
  var b   = req.body;
  var src = db.prepare("SELECT * FROM watch_sources WHERE id = ?").get(req.params.id);
  if (!src) return res.status(404).json({ error: "Not found" });

  try {
    var enabled  = b.enabled !== undefined ? (b.enabled ? 1 : 0) : src.enabled;
    var url      = b.url  ? (sanitizeUrl(b.url) || src.url) : src.url;
    var name     = b.name ? sanitize(b.name, 100) : src.name;
    var ft       = b.feed_type && VALID_FEED_TYPES.includes(b.feed_type) ? b.feed_type : src.feed_type;
    if (ft === "cisa_kev") ft = "json_cisa";
    try {
      db.prepare("UPDATE watch_sources SET enabled = ?, url = ?, name = ?, feed_type = ? WHERE id = ?").run(enabled, url, name, ft, req.params.id);
    } catch(e2) {
      if (e2.message && e2.message.includes("CHECK")) {
        db.prepare("UPDATE watch_sources SET enabled = ?, url = ?, name = ? WHERE id = ?").run(enabled, url, name, req.params.id);
      } else throw e2;
    }
    var updated = db.prepare("SELECT * FROM watch_sources WHERE id = ?").get(req.params.id);
    res.json(Object.assign({}, updated, { enabled: updated.enabled === 1 }));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── DELETE /api/watch/sources/:id (admin) ────────────────────────────────
router.delete("/sources/:id", requireAdmin, function(req, res) {
  var db = getDb();
  try {
    var src = db.prepare("SELECT * FROM watch_sources WHERE id = ?").get(req.params.id);
    if (!src) return res.status(404).json({ error: "Not found" });
    db.prepare("DELETE FROM watch_sources WHERE id = ?").run(req.params.id);
    auditLog(req.user.id, "WATCH_SOURCE_DEL", "watch_source", req.params.id, { name: src.name }, req.clientIp);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
