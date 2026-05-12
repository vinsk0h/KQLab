/**
 * roles.js — Role-based access control middleware.
 * Attach after requireAuth to enforce minimum role requirements on routes.
 */

/**
 * Block viewer-role users from write operations.
 * Use on any route that mutates data.
 */
function requireWriter(req, res, next) {
  if (req.user.role === "viewer") return res.status(403).json({ error: "Read-only access" });
  next();
}

/**
 * Restrict route to admin-role users only.
 * Use on all /api/admin/ routes.
 */
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

module.exports = { requireWriter, requireAdmin };
