const express = require("express");
const crypto  = require("crypto");
const { getDb, hashPassword, verifyPassword, hashToken, encrypt, auditLog, getSetting } = require("../db/database");
const { requireAuth } = require("../middleware/auth");
const { sanitize, validateAvatarDataUri } = require("../middleware/utils");

const router = express.Router();

function createSession(userId, req) {
  var token = crypto.randomBytes(48).toString("hex");
  var tokenHash = hashToken(token);
  var ttlHours = parseInt(getSetting("session_ttl_hours", "24")) || 24;
  var expires = new Date(Date.now() + ttlHours * 60 * 60 * 1000).toISOString();
  var db = getDb();
  var maxSessions = parseInt(getSetting("max_sessions_per_user", "5")) || 5;
  var count = db.prepare("SELECT COUNT(*) as c FROM sessions WHERE user_id = ? AND expires_at > datetime('now')").get(userId).c;
  if (count >= maxSessions) {
    db.prepare("DELETE FROM sessions WHERE user_id = ? AND expires_at = (SELECT MIN(expires_at) FROM sessions WHERE user_id = ?)").run(userId, userId);
  }
  db.prepare("INSERT INTO sessions (token_hash, user_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)").run(
    tokenHash, userId,
    req.ip || "unknown",
    (req.headers["user-agent"] || "").slice(0, 200),
    expires
  );
  return { token, ttlHours };
}

// Bug fix: maxAge doit correspondre au TTL configuré en base (session_ttl_hours)
function setCookie(res, token, ttlHours) {
  res.cookie("kqlab_session", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: ttlHours * 60 * 60 * 1000,
    path: "/",
  });
}

// POST /api/auth/register
router.post("/register", function (req, res) {
  var login = sanitize(req.body.login);
  var displayName = sanitize(req.body.displayName) || login;
  var password = req.body.password;

  if (!login || login.length < 2) return res.status(400).json({ error: "Login minimum 2 caractères" });
  if (!/^[a-zA-Z0-9_.-]+$/.test(login)) return res.status(400).json({ error: "Login : lettres, chiffres, _ . - uniquement" });
  if (!password || typeof password !== "string") return res.status(400).json({ error: "Passphrase requise" });
  if (password.length < 8) return res.status(400).json({ error: "Passphrase minimum 8 caractères" });
  if (password.length > 200) return res.status(400).json({ error: "Passphrase trop longue (max 200)" });
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
    return res.status(400).json({ error: "Passphrase must contain at least one uppercase letter, one lowercase letter, and one digit" });
  }

  var db = getDb();
  if (db.prepare("SELECT id FROM users WHERE login = ?").get(login)) {
    return res.status(409).json({ error: "Login déjà utilisé" });
  }

  var userId = "u_" + crypto.randomBytes(12).toString("hex");
  var pwHash = hashPassword(password);

  db.prepare("INSERT INTO users (id, login, display_name, password_hash, role, team) VALUES (?, ?, ?, ?, ?, ?)").run(
    userId, login, displayName, pwHash, "analyst", "t1"
  );

  var sess = createSession(userId, req);
  setCookie(res, sess.token, sess.ttlHours);
  auditLog(userId, "REGISTER", "user", userId, { login: login }, req.ip);
  res.json({ user: { id: userId, login: login, name: displayName, role: "analyst" } });
});

// POST /api/auth/login
router.post("/login", function (req, res) {
  var login = sanitize(req.body.login);
  var password = req.body.password;
  var db = getDb();
  var user = db.prepare("SELECT * FROM users WHERE login = ?").get(login);

  // Timing-safe: même délai si user inexistant
  if (!user) {
    try { verifyPassword(password || "", "aaaaaaaaaaaaaaaa:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"); } catch(e) {}
    auditLog(null, "LOGIN_FAIL_NOTFOUND", "user", null, { login: login }, req.ip);
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(423).json({ error: "Compte verrouillé. Réessayez dans 15 minutes." });
  }

  if (!verifyPassword(password || "", user.password_hash || "")) {
    db.prepare("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?").run(user.id);
    var fa = db.prepare("SELECT failed_attempts FROM users WHERE id = ?").get(user.id).failed_attempts;
    // Bug fix: lire les seuils depuis les settings admin au lieu des valeurs hardcodées
    var maxAttempts = parseInt(getSetting("login_lockout_attempts", "5")) || 5;
    var lockoutMin  = parseInt(getSetting("login_lockout_minutes",  "15")) || 15;
    if (fa >= maxAttempts) {
      db.prepare("UPDATE users SET locked_until = ? WHERE id = ?").run(
        new Date(Date.now() + lockoutMin * 60 * 1000).toISOString(), user.id
      );
    }
    auditLog(user.id, "LOGIN_FAIL", "user", user.id, null, req.ip);
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  db.prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?").run(user.id);
  var sess = createSession(user.id, req);
  setCookie(res, sess.token, sess.ttlHours);
  auditLog(user.id, "LOGIN", "user", user.id, null, req.ip);
  res.json({
    user: { id: user.id, login: user.login, name: user.display_name, role: user.role },
    must_change_password: user.must_change_password === 1,
  });
});

// POST /api/auth/demo
router.post("/demo", function (req, res) {
  var db = getDb();
  var user = db.prepare("SELECT * FROM users WHERE login = ?").get("john.doe");
  if (!user) return res.status(404).json({ error: "Compte demo introuvable" });
  var sess = createSession(user.id, req);
  setCookie(res, sess.token, sess.ttlHours);
  auditLog(user.id, "LOGIN_DEMO", "user", user.id, null, req.ip);
  res.json({ user: { id: user.id, login: user.login, name: user.display_name, role: user.role } });
});

// GET /api/auth/me
// Avatar is fetched here only — it is excluded from the per-request requireAuth load.
router.get("/me", requireAuth, function (req, res) {
  const db   = getDb();
  const full = db.prepare("SELECT avatar FROM users WHERE id = ?").get(req.user.id);
  res.json({ user: {
    id:                   req.user.id,
    login:                req.user.login,
    name:                 req.user.display_name,
    role:                 req.user.role,
    team:                 req.user.team,
    avatar:               (full && full.avatar) || null,
    must_change_password: req.user.must_change_password === 1,
  }});
});

// POST /api/auth/change-password
router.post("/change-password", requireAuth, function (req, res) {
  var current = req.body.current_password;
  var newPw = req.body.new_password;

  if (!newPw || typeof newPw !== "string") return res.status(400).json({ error: "Nouvelle passphrase requise" });
  if (newPw.length < 8) return res.status(400).json({ error: "Passphrase minimum 8 caractères" });
  if (newPw.length > 200) return res.status(400).json({ error: "Passphrase trop longue (max 200)" });
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(newPw)) {
    return res.status(400).json({ error: "Passphrase must contain at least one uppercase letter, one lowercase letter, and one digit" });
  }

  var db = getDb();
  var user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);

  // Vérifier l'ancien mot de passe, sauf si le changement est forcé (must_change_password)
  if (!user.must_change_password && user.password_hash && !verifyPassword(current || "", user.password_hash)) {
    return res.status(401).json({ error: "Passphrase actuelle incorrecte" });
  }

  db.prepare("UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = ?").run(
    hashPassword(newPw), req.user.id
  );
  auditLog(req.user.id, "PASSWORD_CHANGED", "user", req.user.id, null, req.ip);
  res.json({ ok: true });
});

// PUT /api/auth/profile (avatar uniquement — display_name est permanent)
router.put("/profile", requireAuth, function (req, res) {
  var raw = req.body.avatar;
  if (raw === undefined) return res.status(400).json({ error: "Rien à mettre à jour" });
  var avatarResult = validateAvatarDataUri(raw);
  if (!avatarResult.ok) return res.status(400).json({ error: avatarResult.error });
  var avatarVal = avatarResult.value;
  var db = getDb();
  db.prepare("UPDATE users SET avatar = ?, updated_at = datetime('now') WHERE id = ?").run(avatarVal, req.user.id);
  auditLog(req.user.id, "PROFILE_UPDATE", "user", req.user.id, null, req.ip);
  res.json({ ok: true });
});

// POST /api/auth/leave-team
router.post("/leave-team", requireAuth, function (req, res) {
  var db = getDb();
  db.prepare("UPDATE users SET team = 'none', updated_at = datetime('now') WHERE id = ?").run(req.user.id);
  auditLog(req.user.id, "LEAVE_TEAM", "user", req.user.id, null, req.ip);
  res.json({ ok: true });
});

// POST /api/auth/passkey/challenge
router.post("/passkey/challenge", requireAuth, function (req, res) {
  var challenge = crypto.randomBytes(32).toString("base64url");
  var db = getDb();
  db.prepare("INSERT OR REPLACE INTO passkey_challenges (user_id, challenge, expires_at) VALUES (?, ?, ?)").run(
    req.user.id,
    challenge,
    new Date(Date.now() + 5 * 60 * 1000).toISOString()
  );
  res.json({ challenge, userId: req.user.id, userName: req.user.login });
});

// POST /api/auth/passkey/register
router.post("/passkey/register", requireAuth, function (req, res) {
  var credentialId = sanitize(req.body.credentialId);
  var publicKey    = req.body.publicKey;
  var clientDataJSON = req.body.clientDataJSON;

  if (!credentialId || !publicKey || !clientDataJSON) {
    return res.status(400).json({ error: "Données manquantes" });
  }
  if (credentialId.length > 512) return res.status(400).json({ error: "credentialId invalide" });

  var db = getDb();
  var row = db.prepare("SELECT challenge FROM passkey_challenges WHERE user_id = ? AND expires_at > datetime('now')").get(req.user.id);
  if (!row) return res.status(400).json({ error: "Challenge expiré. Réessayez." });

  try {
    var clientData = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8"));
    if (clientData.type !== "webauthn.create") {
      return res.status(400).json({ error: "Type d'opération invalide" });
    }
    if (clientData.challenge !== row.challenge) {
      return res.status(400).json({ error: "Challenge invalide" });
    }
  } catch (e) {
    return res.status(400).json({ error: "Données client invalides" });
  }

  if (db.prepare("SELECT id FROM passkey_credentials WHERE credential_id = ?").get(credentialId)) {
    return res.status(409).json({ error: "Cette empreinte est déjà enregistrée" });
  }

  var credPk = "pk_" + crypto.randomBytes(12).toString("hex");
  db.prepare("INSERT INTO passkey_credentials (id, user_id, credential_id, public_key) VALUES (?, ?, ?, ?)").run(
    credPk, req.user.id, credentialId, encrypt(publicKey)
  );
  db.prepare("DELETE FROM passkey_challenges WHERE user_id = ?").run(req.user.id);

  auditLog(req.user.id, "PASSKEY_REGISTERED", "user", req.user.id, { credentialId: credentialId.slice(0, 12) + "..." }, req.ip);
  res.json({ ok: true });
});

// POST /api/auth/logout
router.post("/logout", function (req, res) {
  var token = req.cookies.kqlab_session;
  if (token) {
    var db = getDb();
    var tokenHash = hashToken(token);
    var session = db.prepare("SELECT user_id FROM sessions WHERE token_hash = ?").get(tokenHash);
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    auditLog(session ? session.user_id : null, "LOGOUT", null, null, null, req.ip);
  }
  res.clearCookie("kqlab_session");
  res.json({ ok: true });
});

module.exports = router;
