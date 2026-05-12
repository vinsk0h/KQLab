const { getDb, hashToken } = require("../db/database");

// Avatar is excluded here — it can be up to 200 KB of base64 and is
// only needed on the /api/auth/me endpoint, not on every single request.
const USER_COLS = "id, login, display_name, role, team, failed_attempts, locked_until, must_change_password";

function requireAuth(req, res, next) {
  const token = req.cookies.kqlvault_session;
  if (!token) return res.status(401).json({ error: "Not authenticated" });

  const db = getDb();
  const tokenHash = hashToken(token);
  const session = db.prepare(
    "SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > datetime('now')"
  ).get(tokenHash);

  if (!session) {
    res.clearCookie("kqlvault_session");
    return res.status(401).json({ error: "Session expired" });
  }

  const user = db.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).get(session.user_id);
  if (!user) return res.status(401).json({ error: "User not found" });
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(423).json({ error: "Account locked" });
  }

  req.user     = user;
  req.clientIp = req.ip || "";
  next();
}

module.exports = { requireAuth };
