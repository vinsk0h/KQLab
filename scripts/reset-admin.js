/**
 * npm run reset-admin
 *
 * Regenerate the admin password without a running server.
 * Prints the new temporary password and forces change on next login.
 */

require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const crypto = require("crypto");
const { initDb, getDb, hashPassword } = require("../backend/db/database");

initDb();
const db = getDb();

const admin = db.prepare("SELECT id, login FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1").get();
if (!admin) {
  console.error("[ERROR] No admin user found in database.");
  process.exit(1);
}

const tempPw = crypto.randomBytes(8).toString("hex");
db.prepare(
  "UPDATE users SET password_hash = ?, must_change_password = 1, failed_attempts = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?"
).run(hashPassword(tempPw), admin.id);
db.prepare("DELETE FROM sessions WHERE user_id = ?").run(admin.id);

console.log("\n╔══════════════════════════════════════════╗");
console.log("║        MOT DE PASSE ADMIN RÉINITIALISÉ   ║");
console.log("║                                          ║");
console.log("║  Login      : " + admin.login.padEnd(26) + "║");
console.log("║  Passphrase : " + tempPw + "         ║");
console.log("║                                          ║");
console.log("║  Changez ce mot de passe dès la 1ère     ║");
console.log("║  connexion !                             ║");
console.log("╚══════════════════════════════════════════╝\n");
