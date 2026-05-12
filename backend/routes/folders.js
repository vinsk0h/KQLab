const express = require("express");
const crypto  = require("crypto");
const { getDb, auditLog } = require("../db/database");
const { requireAuth }     = require("../middleware/auth");
const { sanitize, requireWriter, isValidHexColor } = require("../middleware/utils");

const router = express.Router();
router.use(requireAuth);

// GET /api/folders
router.get("/", function (req, res) {
  const db      = getDb();
  const folders = db.prepare(
    "SELECT f.*, t.name AS team_name FROM folders f LEFT JOIN teams t ON f.team_id = t.id WHERE f.team_id = ? OR (f.scope = 'personal' AND f.owner_id = ?) ORDER BY f.name"
  ).all(req.user.team, req.user.id);
  res.json(folders);
});

// POST /api/folders
router.post("/", requireWriter, function (req, res) {
  const db = getDb();
  const b  = req.body;

  const name = sanitize(b.name || "", 100);
  if (!name) return res.status(400).json({ error: "Folder name is required" });

  const color = isValidHexColor(b.color) ? b.color : "#dc2626";
  const id    = "f_" + crypto.randomBytes(6).toString("hex");

  db.prepare(
    "INSERT INTO folders (id, name, icon, scope, team_id, color, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(
    id,
    name,
    sanitize(b.icon || "FD", 10).slice(0, 2).toUpperCase(),
    b.scope === "team" ? "team" : "personal",
    b.scope === "team" ? req.user.team : null,
    color,
    req.user.id
  );

  auditLog(req.user.id, "FOLDER_CREATE", "folder", id, { name: name }, req.ip);
  res.json(db.prepare("SELECT * FROM folders WHERE id = ?").get(id));
});

// PUT /api/folders/:id
router.put("/:id", requireWriter, function (req, res) {
  const db     = getDb();
  // IDOR fix: scope lookup to user's team or their own personal folders
  const folder = db.prepare(
    "SELECT * FROM folders WHERE id = ? AND (team_id = ? OR owner_id = ?)"
  ).get(req.params.id, req.user.team, req.user.id);
  if (!folder) return res.status(404).json({ error: "Not found" });

  if (folder.scope === "personal" && folder.owner_id !== req.user.id) {
    return res.status(403).json({ error: "Not your folder" });
  }
  if (folder.scope === "team" && folder.owner_id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  const updates = [];
  const params  = [];

  if (req.body.name) {
    updates.push("name = ?");
    params.push(sanitize(req.body.name, 100));
  }
  if (req.body.icon) {
    updates.push("icon = ?");
    params.push(sanitize(req.body.icon, 10).slice(0, 2).toUpperCase());
  }
  if (req.body.color !== undefined) {
    if (!isValidHexColor(req.body.color)) {
      return res.status(400).json({ error: "Invalid color format (expected #rgb or #rrggbb)" });
    }
    updates.push("color = ?");
    params.push(req.body.color);
  }

  if (updates.length === 0) return res.status(400).json({ error: "Nothing to update" });

  params.push(req.params.id);
  db.prepare("UPDATE folders SET " + updates.join(", ") + " WHERE id = ?").run(...params);

  auditLog(req.user.id, "FOLDER_UPDATE", "folder", req.params.id, req.body, req.ip);
  res.json(db.prepare("SELECT * FROM folders WHERE id = ?").get(req.params.id));
});

// DELETE /api/folders/:id
router.delete("/:id", requireWriter, function (req, res) {
  const db     = getDb();
  // IDOR fix: scope lookup to user's team or their own personal folders
  const folder = db.prepare(
    "SELECT * FROM folders WHERE id = ? AND (team_id = ? OR owner_id = ?)"
  ).get(req.params.id, req.user.team, req.user.id);
  if (!folder) return res.status(404).json({ error: "Not found" });
  if (folder.owner_id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  // Unlink queries rather than deleting them
  db.prepare("UPDATE queries SET folder_id = NULL WHERE folder_id = ?").run(req.params.id);
  db.prepare("DELETE FROM folders WHERE id = ?").run(req.params.id);

  auditLog(req.user.id, "FOLDER_DELETE", "folder", req.params.id, { name: folder.name }, req.ip);
  res.json({ ok: true });
});

module.exports = router;
