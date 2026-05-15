const express = require("express");
const crypto  = require("crypto");
const { getDb, auditLog } = require("../db/database");
const { requireAuth }     = require("../middleware/auth");
const { sanitize, sanitizeUrl } = require("../middleware/utils");

const router = express.Router();
router.use(requireAuth);

// GET /api/comments/:queryId
// Verifies the query belongs to the user's team to prevent cross-team IDOR.
router.get("/:queryId", function (req, res) {
  const db    = getDb();
  const query = db.prepare("SELECT id FROM queries WHERE id = ? AND team = ?").get(req.params.queryId, req.user.team);
  if (!query) return res.status(404).json({ error: "Query not found" });

  const comments = db.prepare(
    "SELECT c.*, u.avatar AS author_avatar FROM comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.query_id = ? ORDER BY c.created_at ASC"
  ).all(req.params.queryId);
  res.json(comments);
});

// POST /api/comments/:queryId
router.post("/:queryId", function (req, res) {
  if (req.user.role === "viewer") return res.status(403).json({ error: "Read-only access" });

  const rawContent = (req.body.content || "").trim();
  if (!rawContent) return res.status(400).json({ error: "Comment cannot be empty" });
  if (rawContent.length > 5000) return res.status(400).json({ error: "Comment too long (max 5000 chars)" });
  const content = sanitize(rawContent, 5000);

  const rawUrl = (req.body.url || "").trim();
  if (rawUrl && rawUrl.length > 2048) return res.status(400).json({ error: "URL too long (max 2048 chars)" });
  const url = rawUrl ? sanitizeUrl(rawUrl) : null;
  if (rawUrl && !url) return res.status(400).json({ error: "URL must be a valid http:// or https:// address" });

  const db    = getDb();
  const query = db.prepare("SELECT id FROM queries WHERE id = ? AND team = ?").get(req.params.queryId, req.user.team);
  if (!query) return res.status(404).json({ error: "Query not found" });

  const id = "cmt_" + crypto.randomBytes(8).toString("hex");
  db.prepare(
    "INSERT INTO comments (id, query_id, user_id, author_name, content, url) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(id, req.params.queryId, req.user.id, req.user.display_name, content, url);

  auditLog(req.user.id, "COMMENT_ADD", "comment", id, { query_id: req.params.queryId }, req.ip);
  res.json(db.prepare("SELECT * FROM comments WHERE id = ?").get(id));
});

// PUT /api/comments/:id
router.put("/:id", function (req, res) {
  if (req.user.role === "viewer") return res.status(403).json({ error: "Read-only access" });

  const db      = getDb();
  const comment = db.prepare("SELECT * FROM comments WHERE id = ?").get(req.params.id);
  if (!comment) return res.status(404).json({ error: "Comment not found" });
  if (comment.user_id !== req.user.id) return res.status(403).json({ error: "Not authorized" });

  const rawContent = (req.body.content || "").trim();
  if (!rawContent) return res.status(400).json({ error: "Comment cannot be empty" });
  if (rawContent.length > 5000) return res.status(400).json({ error: "Comment too long (max 5000 chars)" });
  const content = sanitize(rawContent, 5000);

  const rawUrl2 = (req.body.url || "").trim();
  if (rawUrl2 && rawUrl2.length > 2048) return res.status(400).json({ error: "URL too long (max 2048 chars)" });
  const url = rawUrl2 ? sanitizeUrl(rawUrl2) : null;
  if (rawUrl2 && !url) return res.status(400).json({ error: "URL must be a valid http:// or https:// address" });

  db.prepare("UPDATE comments SET content=?, url=? WHERE id=?").run(content, url, req.params.id);
  auditLog(req.user.id, "COMMENT_EDIT", "comment", req.params.id, null, req.ip);
  res.json({ ok: true });
});

// DELETE /api/comments/:id
router.delete("/:id", function (req, res) {
  const db      = getDb();
  const comment = db.prepare("SELECT * FROM comments WHERE id = ?").get(req.params.id);
  if (!comment) return res.status(404).json({ error: "Comment not found" });
  if (comment.user_id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  db.prepare("DELETE FROM comments WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "COMMENT_DELETE", "comment", req.params.id, null, req.ip);
  res.json({ ok: true });
});

module.exports = router;
