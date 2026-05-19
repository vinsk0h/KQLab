const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const DB_PATH = path.join(__dirname, "kqlab.db");

// P12 — Clé cachée en mémoire après validation initiale (évite process.env à chaque opération crypto)
var _encKey = null;
function getEncKey() {
  if (_encKey) return _encKey;
  var raw = process.env.DB_ENCRYPTION_KEY;
  if (!raw || raw.length < 32 || raw === "CHANGE_ME_TO_A_STRONG_RANDOM_STRING_64_CHARS") {
    console.error("\n[FATAL] DB_ENCRYPTION_KEY not set or too short (min 32 chars).");
    console.error("Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"\n");
    process.exit(1);
  }
  _encKey = raw;
  return _encKey;
}

// VULN-01 FIX: unique random salt per value. Format: salt:iv:tag:ciphertext (all hex)
function deriveKey(salt) { return crypto.scryptSync(getEncKey(), salt, 32, { N: 16384, r: 8, p: 1 }); }

// Hachage de passphrase : salt:hash (hex)
function hashPassword(password) {
  var salt = crypto.randomBytes(16).toString("hex");
  var hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString("hex");
  return salt + ":" + hash;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string") return false;
  var parts = stored.split(":");
  if (parts.length !== 2) return false;
  try {
    var hash = crypto.scryptSync(password, parts[0], 64, { N: 16384, r: 8, p: 1 }).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(parts[1], "hex"));
  } catch (e) { return false; }
}

function encrypt(text) {
  if (!text) return null;
  var salt = crypto.randomBytes(16);
  var iv = crypto.randomBytes(12);
  var key = deriveKey(salt);
  var cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  var enc = cipher.update(text, "utf8", "hex") + cipher.final("hex");
  return salt.toString("hex") + ":" + iv.toString("hex") + ":" + cipher.getAuthTag().toString("hex") + ":" + enc;
}

function decrypt(data) {
  if (!data) return null;
  var p = data.split(":");
  if (p.length !== 4) return null;
  try {
    var key = deriveKey(Buffer.from(p[0], "hex"));
    var dec = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(p[1], "hex"));
    dec.setAuthTag(Buffer.from(p[2], "hex"));
    return dec.update(p[3], "hex", "utf8") + dec.final("utf8");
  } catch (e) { return null; }
}

// VULN-04 FIX: HMAC-SHA256 hash of session token stored in DB
function hashToken(token) { return crypto.createHmac("sha256", getEncKey()).update(token).digest("hex"); }

var db = null;

function initDb() {
  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("secure_delete = ON");
  db.pragma("auto_vacuum = FULL");
  // Performance pragmas
  db.pragma("synchronous = NORMAL");    // safe with WAL, faster than FULL
  db.pragma("cache_size = -64000");     // 64 MB page cache
  db.pragma("temp_store = MEMORY");     // temp tables/indexes in RAM
  db.pragma("mmap_size = 268435456");   // 256 MB memory-mapped I/O
  try { fs.chmodSync(DB_PATH, 0o600); } catch (e) {}

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT,
      must_change_password INTEGER DEFAULT 0,
      role TEXT DEFAULT 'analyst' CHECK(role IN ('admin','analyst','viewer')),
      team TEXT DEFAULT 't1',
      failed_attempts INTEGER DEFAULT 0,
      locked_until TEXT,
      avatar TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS queries (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, kql TEXT NOT NULL,
      language TEXT DEFAULT 'KQL',
      environment TEXT DEFAULT 'Defender' CHECK(environment IN ('Defender','Sentinel','Both')),
      severity TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
      mitre TEXT DEFAULT '[]', picerl TEXT DEFAULT '[]', playbook TEXT DEFAULT 'Uncategorized',
      folder_id TEXT, tags TEXT DEFAULT '[]', author_id TEXT, author_name TEXT, team TEXT DEFAULT 't1',
      stars INTEGER DEFAULT 0, versions TEXT DEFAULT '[]',
      created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, icon TEXT DEFAULT 'FD',
      scope TEXT DEFAULT 'personal' CHECK(scope IN ('personal','team')),
      team_id TEXT, color TEXT DEFAULT '#dc2626', owner_id TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS stars (
      user_id TEXT NOT NULL, query_id TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')),
      PRIMARY KEY (user_id, query_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (query_id) REFERENCES queries(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      color TEXT DEFAULT '#6366f1',
      avatar_url TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, action TEXT NOT NULL,
      target_type TEXT, target_id TEXT, details TEXT, ip_address TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      query_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      author_name TEXT NOT NULL,
      content TEXT NOT NULL,
      url TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (query_id) REFERENCES queries(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_sess_exp     ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_sess_user    ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_queries_team ON queries(team);
    CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_comments_query ON comments(query_id);
    CREATE TABLE IF NOT EXISTS investigations (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      status TEXT DEFAULT 'open' CHECK(status IN ('open','in-progress','closed')),
      severity TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
      team TEXT NOT NULL,
      analyst_id TEXT,
      analyst_name TEXT,
      description TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS investigation_iocs (
      id TEXT PRIMARY KEY,
      investigation_id TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('ip','domain','hash','url','email','filename','registry','process','useragent','cve','other')),
      value TEXT NOT NULL,
      context TEXT,
      malicious INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS investigation_findings (
      id TEXT PRIMARY KEY,
      investigation_id TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT DEFAULT '',
      severity TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_inv_team ON investigations(team);
    CREATE INDEX IF NOT EXISTS idx_iocs_inv ON investigation_iocs(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_findings_inv ON investigation_findings(investigation_id);
    CREATE TABLE IF NOT EXISTS environment_profiles (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      platform TEXT NOT NULL CHECK(platform IN ('Defender','Sentinel')),
      licenses TEXT DEFAULT '[]',
      connectors TEXT DEFAULT '[]',
      custom_tables TEXT DEFAULT '[]',
      is_default INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS table_requirements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      table_name TEXT NOT NULL UNIQUE,
      platform TEXT NOT NULL,
      requires_license TEXT,
      requires_connector TEXT,
      description TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_fp_user ON environment_profiles(user_id);
    CREATE TABLE IF NOT EXISTS user_environments (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      platform TEXT NOT NULL CHECK(platform IN ('defender_xdr','sentinel')),
      config TEXT NOT NULL DEFAULT '{}',
      is_active INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS query_compatibility (
      query_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('compatible','partial','incompatible','unknown')),
      tables_found TEXT DEFAULT '[]',
      tables_ok TEXT DEFAULT '[]',
      tables_missing TEXT DEFAULT '[]',
      checked_at TEXT DEFAULT (datetime('now')),
      PRIMARY KEY (query_id, user_id),
      FOREIGN KEY (query_id) REFERENCES queries(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_user_env_user ON user_environments(user_id);
    CREATE INDEX IF NOT EXISTS idx_qcompat_user ON query_compatibility(user_id);
    CREATE TABLE IF NOT EXISTS repo_sources (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      github_owner TEXT NOT NULL,
      github_repo TEXT NOT NULL,
      branch TEXT DEFAULT 'main',
      path_filter TEXT DEFAULT '',
      file_format TEXT NOT NULL CHECK(file_format IN ('yaml','md','kql','auto')),
      last_sync_at TEXT,
      last_sync_status TEXT DEFAULT 'never',
      last_sync_new INTEGER DEFAULT 0,
      last_sync_updated INTEGER DEFAULT 0,
      last_sync_errors INTEGER DEFAULT 0,
      target_folder_id TEXT,
      enabled INTEGER DEFAULT 1,
      added_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (target_folder_id) REFERENCES folders(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS repo_query_map (
      repo_id TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_sha TEXT,
      query_id TEXT NOT NULL,
      local_modified INTEGER DEFAULT 0,
      last_synced_at TEXT DEFAULT (datetime('now')),
      PRIMARY KEY (repo_id, file_path),
      FOREIGN KEY (repo_id) REFERENCES repo_sources(id) ON DELETE CASCADE,
      FOREIGN KEY (query_id) REFERENCES queries(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_rqm_query ON repo_query_map(query_id);
    CREATE TABLE IF NOT EXISTS watch_sources (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      feed_type TEXT NOT NULL CHECK(feed_type IN ('rss','json_cisa')),
      enabled INTEGER DEFAULT 1,
      last_fetch_at TEXT,
      last_fetch_status TEXT DEFAULT 'never',
      fetch_count INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS watch_articles (
      id TEXT PRIMARY KEY,
      source_id TEXT NOT NULL,
      external_id TEXT,
      title TEXT NOT NULL,
      summary TEXT,
      url TEXT,
      published_at TEXT,
      fetched_at TEXT DEFAULT (datetime('now')),
      keywords TEXT DEFAULT '[]',
      cves TEXT DEFAULT '[]',
      products TEXT DEFAULT '[]',
      severity TEXT DEFAULT 'medium',
      is_read INTEGER DEFAULT 0,
      is_dismissed INTEGER DEFAULT 0,
      UNIQUE(source_id, external_id),
      FOREIGN KEY (source_id) REFERENCES watch_sources(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_watch_articles_date      ON watch_articles(published_at DESC);
    CREATE INDEX IF NOT EXISTS idx_watch_articles_source    ON watch_articles(source_id);
    CREATE INDEX IF NOT EXISTS idx_watch_articles_dismissed ON watch_articles(is_dismissed, published_at DESC);
    CREATE INDEX IF NOT EXISTS idx_queries_folder      ON queries(folder_id);
    CREATE INDEX IF NOT EXISTS idx_queries_severity    ON queries(severity);
    CREATE INDEX IF NOT EXISTS idx_queries_language    ON queries(language);
    CREATE INDEX IF NOT EXISTS idx_queries_environment ON queries(environment);
    CREATE INDEX IF NOT EXISTS idx_queries_author      ON queries(author_id);
    CREATE INDEX IF NOT EXISTS idx_queries_stars       ON queries(stars DESC);
    CREATE INDEX IF NOT EXISTS idx_stars_query         ON stars(query_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user          ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action        ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_sessions_compound   ON sessions(user_id, expires_at);
    CREATE TABLE IF NOT EXISTS watch_article_matches (
      article_id TEXT NOT NULL,
      query_id TEXT NOT NULL,
      match_score INTEGER NOT NULL,
      match_reasons TEXT DEFAULT '[]',
      PRIMARY KEY (article_id, query_id),
      FOREIGN KEY (article_id) REFERENCES watch_articles(id) ON DELETE CASCADE,
      FOREIGN KEY (query_id)   REFERENCES queries(id)        ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_watch_matches_query ON watch_article_matches(query_id);
    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS report_templates (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      name            TEXT NOT NULL,
      slug            TEXT NOT NULL UNIQUE,
      type            TEXT NOT NULL DEFAULT 'custom',
      description     TEXT,
      icon            TEXT DEFAULT '📋',
      color           TEXT DEFAULT '#e63946',
      logo_url        TEXT,
      company_name    TEXT,
      company_subtitle TEXT,
      header_color    TEXT DEFAULT '#0d1117',
      created_at      INTEGER DEFAULT (unixepoch() * 1000),
      updated_at      INTEGER DEFAULT (unixepoch() * 1000),
      is_default      INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS template_sections (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      template_id   INTEGER NOT NULL REFERENCES report_templates(id) ON DELETE CASCADE,
      name          TEXT NOT NULL,
      slug          TEXT NOT NULL,
      type          TEXT NOT NULL,
      display_order INTEGER DEFAULT 0,
      required      INTEGER DEFAULT 0,
      placeholder   TEXT,
      default_content TEXT,
      icon          TEXT DEFAULT '📝'
    );
    CREATE TABLE IF NOT EXISTS investigation_section_content (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
      section_id       INTEGER NOT NULL REFERENCES template_sections(id),
      content          TEXT DEFAULT '',
      updated_at       INTEGER DEFAULT (unixepoch() * 1000),
      UNIQUE(investigation_id, section_id)
    );
    CREATE INDEX IF NOT EXISTS idx_tpl_sections ON template_sections(template_id);
    CREATE INDEX IF NOT EXISTS idx_isc_inv      ON investigation_section_content(investigation_id);
    CREATE TABLE IF NOT EXISTS passkey_credentials (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      credential_id TEXT NOT NULL UNIQUE,
      public_key TEXT NOT NULL,
      sign_count INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS passkey_challenges (
      user_id TEXT PRIMARY KEY,
      challenge TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_passkey_user ON passkey_credentials(user_id);
  `);

  // Seed default settings
  db.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('watch_sync_interval_minutes', '15')").run();

  // Helper : ignore uniquement "duplicate column name" (ré-exécution normale).
  // Toute autre erreur (table inexistante, corruption) est propagée.
  function addColumn(table, col, def) {
    try { db.exec("ALTER TABLE " + table + " ADD COLUMN " + col + " " + def); }
    catch(e) { if (!e.message.includes("duplicate column name")) throw e; }
  }

  // Migrations pour DBs existantes
  addColumn("users", "avatar", "TEXT");
  addColumn("users", "password_hash", "TEXT");
  addColumn("users", "must_change_password", "INTEGER DEFAULT 0");
  addColumn("queries", "language", "TEXT DEFAULT 'KQL'");
  addColumn("queries", "parsed_references", "TEXT DEFAULT '[]'");
  addColumn("investigations", "conclusion", "TEXT DEFAULT ''");
  addColumn("watch_articles", "image_url", "TEXT");
  addColumn("watch_sources", "last_error", "TEXT DEFAULT NULL");
  addColumn("watch_sources", "last_success_at", "INTEGER DEFAULT NULL");
  addColumn("watch_sources", "article_count", "INTEGER DEFAULT 0");
  addColumn("teams", "description", "TEXT DEFAULT ''");
  addColumn("teams", "color", "TEXT DEFAULT '#6366f1'");
  addColumn("teams", "avatar_url", "TEXT");

  // Findings timeline
  addColumn("investigation_findings", "event_at", "INTEGER DEFAULT NULL");
  addColumn("investigation_findings", "display_order", "INTEGER DEFAULT 0");
  addColumn("investigation_findings", "event_type", "TEXT DEFAULT 'finding'");
  addColumn("investigation_findings", "code_blocks", "TEXT DEFAULT '[]'");
  addColumn("investigation_findings", "screenshots", "TEXT DEFAULT '[]'");
  addColumn("investigation_findings", "color", "TEXT DEFAULT 'default'");
  // IoC édition
  addColumn("investigation_iocs", "severity", "TEXT DEFAULT 'medium'");
  addColumn("investigation_iocs", "updated_at", "TEXT DEFAULT NULL");
  // IoC enrichment persistence
  addColumn("investigation_iocs", "enrich_result", "TEXT DEFAULT NULL");
  addColumn("investigation_iocs", "enriched_at", "INTEGER DEFAULT NULL");
  // Finding IoC links
  addColumn("investigation_findings", "linked_ioc_ids", "TEXT DEFAULT '[]'");
  // Verrouillage rapport
  addColumn("investigations", "report_locked", "INTEGER DEFAULT 0");
  addColumn("investigations", "locked_at", "INTEGER DEFAULT NULL");
  addColumn("investigations", "locked_by", "TEXT DEFAULT NULL");
  // Système de templates
  addColumn("investigations", "template_id", "INTEGER");
  addColumn("investigations", "client_name", "TEXT");
  addColumn("investigations", "client_logo", "TEXT");
  addColumn("investigations", "client_color", "TEXT");
  addColumn("investigations", "mission_type", "TEXT");
  addColumn("investigations", "pentest_scope", "TEXT");
  addColumn("investigations", "cvss_score", "REAL");
  addColumn("investigations", "risk_rating", "TEXT");

  // Migrer les équipes existantes vers la table teams
  db.prepare("INSERT OR IGNORE INTO teams (id, name) SELECT DISTINCT team, team FROM users WHERE team IS NOT NULL AND team != 'none'").run();

  // VULN-05 FIX: cleanup expired sessions at boot
  db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();

  // Migration: ensure each repo source has its own dedicated folder
  try {
    var repoRows = db.prepare("SELECT * FROM repo_sources").all();
    var teamRow  = db.prepare("SELECT id FROM teams LIMIT 1").get();
    var defTeam  = teamRow ? teamRow.id : "t1";
    repoRows.forEach(function(src) {
      var fid = "f_" + src.id;
      var ini = ((src.github_owner || "?").slice(0, 1) + (src.github_repo || "?").slice(0, 1)).toUpperCase();
      // Create dedicated folder if it doesn't exist yet
      db.prepare("INSERT OR IGNORE INTO folders (id,name,icon,scope,team_id,color,owner_id) VALUES (?,?,?,?,?,?,?)").run(
        fid, src.name, ini, "team", defTeam, "#6e40c9", "u_admin_default"
      );
      // Point repo source to its own folder (only if still on the old community folder or null)
      db.prepare(
        "UPDATE repo_sources SET target_folder_id = ? WHERE id = ? AND (target_folder_id IS NULL OR target_folder_id = 'f_community')"
      ).run(fid, src.id);
      // Move already-imported queries from the community folder to the per-repo folder
      db.prepare(
        "UPDATE queries SET folder_id = ? WHERE folder_id IN ('f_community', NULL) AND id IN (SELECT query_id FROM repo_query_map WHERE repo_id = ?)"
      ).run(fid, src.id);
    });
  } catch(e) {}

  if (db.prepare("SELECT COUNT(*) as c FROM users").get().c === 0) seedData();
  if (db.prepare("SELECT COUNT(*) as c FROM table_requirements").get().c === 0) seedTableRequirements();
  if (db.prepare("SELECT COUNT(*) as c FROM report_templates").get().c === 0) seedReportTemplates();
  if (!db.prepare("SELECT id FROM investigations WHERE id = 'inv_demo_moveit'").get()) seedDemoInvestigation();
  // Patch: upgrade existing demo investigation to Markdown + screenshots
  var _demoFnd = db.prepare("SELECT screenshots FROM investigation_findings WHERE id = 'fnd_dm_001'").get();
  if (_demoFnd && (!_demoFnd.screenshots || _demoFnd.screenshots === '[]')) patchDemoInvestigation();

  // Schema version 2 — force full re-sync with improved parsers (severity / MITRE / PICERL / tags)
  // Clears SHA cache for non-locally-modified entries so next sync re-parses every file.
  try {
    var schemaVer = db.pragma("user_version", { simple: true });
    if (schemaVer < 2) {
      db.prepare("UPDATE repo_query_map SET file_sha = NULL WHERE local_modified = 0").run();
      db.pragma("user_version = 2");
    }
    else if (schemaVer < 3) {
      var cleared = db.prepare("UPDATE repo_query_map SET file_sha = NULL WHERE local_modified = 0").run();
      db.pragma("user_version = 3");
      if (cleared.changes > 0) {
        console.log("[DB] Migration v3: " + cleared.changes + " SHA(s) cleared — improved MITRE tactic parser, re-sync to refresh.");
      }
    }
  } catch(e) {}

  // Run ANALYZE to update query planner statistics
  try { db.pragma("optimize"); } catch(e) {}

  return db;
}

// P10/P11 — Prepared statements cached once after DB init, not re-compiled on every call
var _cleanupStmt = null;
var _auditStmt   = null;

function startSessionCleanup() {
  setInterval(function () {
    if (!db) return;
    if (!_cleanupStmt) _cleanupStmt = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')");
    _cleanupStmt.run();
  }, 15 * 60 * 1000);
  setInterval(function () {
    if (!db) return;
    try { db.pragma("wal_checkpoint(PASSIVE)"); } catch(e) {}
  }, 30 * 60 * 1000);
}

function auditLog(userId, action, targetType, targetId, details, ip) {
  if (!db) return;
  try {
    if (!_auditStmt) _auditStmt = db.prepare("INSERT INTO audit_log (user_id,action,target_type,target_id,details,ip_address) VALUES(?,?,?,?,?,?)");
    _auditStmt.run(userId, action, targetType, targetId, typeof details === "object" ? JSON.stringify(details) : details, ip);
  } catch (e) { console.error("[audit]", e.message); }
}

function seedData() {
  // Équipe par défaut
  db.prepare("INSERT INTO teams (id, name) VALUES (?, ?)").run("t1", "SOC Team");

  // Compte admin par défaut avec mot de passe temporaire aléatoire
  var tempPw = crypto.randomBytes(8).toString("hex"); // 16 caractères hex
  db.prepare("INSERT INTO users (id,login,display_name,password_hash,must_change_password,role,team) VALUES(?,?,?,?,?,?,?)").run(
    "u_admin_default", "admin", "Administrator", hashPassword(tempPw), 1, "admin", "t1"
  );
  console.log("\n╔══════════════════════════════════════════╗");
  console.log("║        COMPTE ADMIN CRÉÉ                 ║");
  console.log("║                                          ║");
  console.log("║  Login      : admin                      ║");
  console.log("║  Passphrase : " + tempPw + "         ║");
  console.log("║                                          ║");
  console.log("║  Changez ce mot de passe dès la 1ère     ║");
  console.log("║  connexion !                             ║");
  console.log("╚══════════════════════════════════════════╝\n");

  // Compte démo lecture seule (pas de passphrase — accès via /api/auth/demo)
  var uid = "u_demo_john";
  db.prepare("INSERT INTO users (id,login,display_name,role,team) VALUES(?,?,?,?,?)").run(uid, "john.doe", "John Doe (Demo)", "viewer", "t1");
  [["f1","Incident Response","IR","team","t1","#dc2626"],["f2","Threat Hunting","TH","team","t1","#f97316"],["f3","Compliance","CO","team","t1","#22c55e"],["f4","My Drafts","DR","personal",null,"#a855f7"],["f5","Sentinel","SN","team","t1","#3b82f6"]].forEach(function(f) {
    db.prepare("INSERT INTO folders (id,name,icon,scope,team_id,color,owner_id) VALUES(?,?,?,?,?,?,?)").run(f[0],f[1],f[2],f[3],f[4],f[5],uid);
  });
}

function seedTableRequirements() {
  var rows = [
    // Defender — MDE P1 included (no special license)
    ["DeviceProcessEvents","Defender",null,null,"Process events — MDE P1"],
    ["DeviceNetworkEvents","Defender",null,null,"Network events — MDE P1"],
    ["DeviceFileEvents","Defender",null,null,"File events — MDE P1"],
    ["DeviceRegistryEvents","Defender",null,null,"Registry events — MDE P1"],
    ["DeviceLogonEvents","Defender",null,null,"Logon events — MDE P1"],
    ["DeviceEvents","Defender",null,null,"Device events — MDE P1"],
    ["DeviceInfo","Defender",null,null,"Device info — MDE P1"],
    ["DeviceImageLoadEvents","Defender",null,null,"Image load events — MDE P1"],
    ["AlertInfo","Defender",null,null,"Alert info — MDE P1"],
    ["AlertEvidence","Defender",null,null,"Alert evidence — MDE P1"],
    // Defender — MDE P2
    ["DeviceTvmSoftwareVulnerabilities","Defender","MDE_P2",null,"Vulnerability data — requires MDE P2"],
    ["DeviceTvmSoftwareInventory","Defender","MDE_P2",null,"Software inventory — requires MDE P2"],
    ["DeviceTvmInfoGathering","Defender","MDE_P2",null,"Info gathering — requires MDE P2"],
    ["DeviceTvmSecureConfigurationAssessment","Defender","MDE_P2",null,"Config assessment — requires MDE P2"],
    // Defender — MDI
    ["IdentityLogonEvents","Defender","MDI",null,"Identity logon events — requires MDI"],
    ["IdentityQueryEvents","Defender","MDI",null,"Identity query events — requires MDI"],
    ["IdentityDirectoryEvents","Defender","MDI",null,"Identity directory events — requires MDI"],
    // Defender — MDO
    ["EmailEvents","Defender","MDO",null,"Email events — requires MDO"],
    ["EmailAttachmentInfo","Defender","MDO",null,"Email attachment info — requires MDO"],
    ["EmailUrlInfo","Defender","MDO",null,"Email URL info — requires MDO"],
    ["EmailPostDeliveryEvents","Defender","MDO",null,"Email post-delivery — requires MDO"],
    ["UrlClickEvents","Defender","MDO",null,"URL click events — requires MDO"],
    // Defender — MDA
    ["CloudAppEvents","Defender","MDA",null,"Cloud app events — requires MDA"],
    // Sentinel — Entra ID connector
    ["SigninLogs","Sentinel",null,"EntraID","Sign-in logs — requires Entra ID connector"],
    ["AADNonInteractiveUserSignInLogs","Sentinel",null,"EntraID","Non-interactive sign-ins — requires Entra ID connector"],
    ["AuditLogs","Sentinel",null,"EntraID","Azure AD audit logs — requires Entra ID connector"],
    ["AADServicePrincipalSignInLogs","Sentinel",null,"EntraID","Service principal sign-ins — requires Entra ID connector"],
    ["AADManagedIdentitySignInLogs","Sentinel",null,"EntraID","Managed identity sign-ins — requires Entra ID connector"],
    // Sentinel — Office 365 connector
    ["OfficeActivity","Sentinel",null,"Office365","Office 365 activity — requires Office 365 connector"],
    // Sentinel — Security Events connector
    ["SecurityEvent","Sentinel",null,"SecurityEvents","Windows security events — requires Security Events connector"],
    ["Event","Sentinel",null,"SecurityEvents","Windows events — requires Security Events connector"],
    ["Syslog","Sentinel",null,"SecurityEvents","Syslog — requires Security Events connector"],
    // Sentinel — Azure Activity connector
    ["AzureActivity","Sentinel",null,"AzureActivity","Azure activity logs — requires Azure Activity connector"],
    ["AzureDiagnostics","Sentinel",null,"AzureActivity","Azure diagnostics — requires Azure Activity connector"],
    // Sentinel — Azure Monitor connector
    ["AzureMetrics","Sentinel",null,"AzureMonitor","Azure metrics — requires Azure Monitor connector"],
    ["Heartbeat","Sentinel",null,"AzureMonitor","Agent heartbeat — requires Azure Monitor connector"],
    ["Perf","Sentinel",null,"AzureMonitor","Performance counters — requires Azure Monitor connector"],
    ["VMConnection","Sentinel",null,"AzureMonitor","VM connections — requires Azure Monitor connector"],
    // Sentinel — included by default (no connector)
    ["SecurityAlert","Sentinel",null,null,"Security alerts — included by default"],
    ["SecurityIncident","Sentinel",null,null,"Security incidents — included by default"],
    ["ThreatIntelligenceIndicator","Sentinel",null,null,"Threat intelligence — included by default"],
    ["Watchlist","Sentinel",null,null,"Watchlist entries — included by default"],
    ["SentinelHealth","Sentinel",null,null,"Sentinel health — included by default"],
  ];
  var stmt = db.prepare("INSERT OR IGNORE INTO table_requirements (table_name, platform, requires_license, requires_connector, description) VALUES (?,?,?,?,?)");
  db.transaction(function(items) { items.forEach(function(r) { stmt.run(r[0],r[1],r[2],r[3],r[4]); }); })(rows);
}


function seedReportTemplates() {
  var tplStmt = db.prepare("INSERT OR IGNORE INTO report_templates (name,slug,type,icon,color,description,is_default) VALUES (?,?,?,?,?,?,?)");
  var secStmt = db.prepare("INSERT INTO template_sections (template_id,name,slug,type,display_order,required,placeholder,icon) VALUES (?,?,?,?,?,?,?,?)");

  var templates = [
    { name: 'SOC Incident Report',                slug: 'soc-incident',       type: 'blueteam', icon: '🔵', color: '#3b82f6', desc: 'Standard SOC incident investigation report',                                     def: 1 },
    { name: 'Red Team Assessment',                slug: 'redteam-assessment', type: 'redteam',  icon: '🔴', color: '#ef4444', desc: 'Red team engagement findings and attack paths',                                  def: 0 },
    { name: 'Vulnerability Assessment & Pentest', slug: 'vapt',               type: 'vapt',     icon: '🟠', color: '#f97316', desc: 'Comprehensive vulnerability assessment and penetration test report',            def: 0 },
    { name: 'Phishing Simulation Report',         slug: 'phishing-sim',       type: 'phishing', icon: '🎣', color: '#a855f7', desc: 'Phishing campaign simulation results and awareness recommendations',           def: 0 },
    { name: 'Security Audit',                     slug: 'audit-sec',          type: 'audit',    icon: '✅', color: '#22c55e', desc: 'Security audit controls assessment and gap analysis',                          def: 0 },
  ];

  var tplSections = {
    'soc-incident': [
      { name: 'Executive Summary',      slug: 'exec-summary',      type: 'richtext',       icon: '📋', req: 1, ph: 'High-level summary of the incident, its scope, impact, and key findings...' },
      { name: 'Timeline',               slug: 'timeline',           type: 'timeline',       icon: '⏱️', req: 0, ph: '' },
      { name: 'IoCs',                   slug: 'iocs',               type: 'iocs',           icon: '🔍', req: 0, ph: '' },
      { name: 'Findings',               slug: 'findings',           type: 'findings',       icon: '⚠️', req: 0, ph: '' },
      { name: 'Detection Queries',      slug: 'detection-queries',  type: 'richtext',       icon: '🔎', req: 0, ph: 'KQL/SPL queries used to detect and hunt for this threat...' },
      { name: 'Remediation',            slug: 'remediation',        type: 'recommendation', icon: '🛠️', req: 0, ph: '' },
      { name: 'Conclusion',             slug: 'conclusion',         type: 'richtext',       icon: '✅', req: 0, ph: 'Lessons learned, next steps, and closure confirmation...' },
    ],
    'redteam-assessment': [
      { name: 'Executive Summary',           slug: 'exec-summary',  type: 'richtext',       icon: '📋', req: 1, ph: 'High-level summary of the red team engagement and key findings...' },
      { name: 'Scope & Rules of Engagement', slug: 'scope-roe',     type: 'richtext',       icon: '📜', req: 1, ph: 'Scope, excluded systems, rules of engagement, and timeframe...' },
      { name: 'Attack Path',                 slug: 'attack-path',   type: 'richtext',       icon: '🎯', req: 0, ph: 'Attack path from initial access to objectives achieved...' },
      { name: 'Findings (CVSS)',             slug: 'findings-cvss', type: 'cvss',           icon: '⚠️', req: 0, ph: '' },
      { name: 'Lateral Movement',            slug: 'lateral-move',  type: 'richtext',       icon: '↔️', req: 0, ph: 'Lateral movement techniques, pivoting, and host compromise...' },
      { name: 'Persistence',                 slug: 'persistence',   type: 'richtext',       icon: '🔒', req: 0, ph: 'Persistence mechanisms established during the engagement...' },
      { name: 'Recommendations',             slug: 'recommendations',type: 'recommendation',icon: '💡', req: 0, ph: '' },
      { name: 'Conclusion',                  slug: 'conclusion',    type: 'richtext',       icon: '✅', req: 0, ph: 'Engagement outcomes and overall security posture assessment...' },
    ],
    'vapt': [
      { name: 'Executive Summary', slug: 'exec-summary',  type: 'richtext',       icon: '📋', req: 1, ph: 'Key risks, critical findings, and overall risk rating for management...' },
      { name: 'Scope',             slug: 'scope',         type: 'richtext',       icon: '🎯', req: 1, ph: 'Systems, applications, networks assessed and exclusions defined...' },
      { name: 'Methodology',       slug: 'methodology',   type: 'richtext',       icon: '🔬', req: 0, ph: 'Testing methodology, frameworks (OWASP, PTES, NIST), and approach...' },
      { name: 'Findings (CVSS)',   slug: 'findings-cvss', type: 'cvss',           icon: '⚠️', req: 0, ph: '' },
      { name: 'Risk Matrix',       slug: 'risk-matrix',   type: 'richtext',       icon: '📊', req: 0, ph: 'Risk matrix summarizing findings by likelihood and impact...' },
      { name: 'Remediation Plan',  slug: 'remediation',   type: 'recommendation', icon: '🛠️', req: 0, ph: '' },
    ],
    'phishing-sim': [
      { name: 'Executive Summary',         slug: 'exec-summary',   type: 'richtext',       icon: '📋', req: 1, ph: 'Summary of the phishing simulation — objectives, results, and key insights...' },
      { name: 'Campaign Setup',            slug: 'campaign-setup', type: 'richtext',       icon: '📧', req: 0, ph: 'Templates used, targets, sending infrastructure, and timeline...' },
      { name: 'Results & Statistics',      slug: 'results',        type: 'richtext',       icon: '📊', req: 0, ph: 'Click rates, credential submission, reporting rates, departmental breakdown...' },
      { name: 'Awareness Recommendations', slug: 'recommendations',type: 'recommendation', icon: '💡', req: 0, ph: '' },
    ],
    'audit-sec': [
      { name: 'Executive Summary',      slug: 'exec-summary', type: 'richtext',       icon: '📋', req: 1, ph: 'Scope, methodology, and key findings of the security audit...' },
      { name: 'Audit Scope',            slug: 'audit-scope',  type: 'richtext',       icon: '🎯', req: 1, ph: 'Systems, processes, and standards assessed (ISO 27001, NIST, SOC2)...' },
      { name: 'Controls Assessment',    slug: 'controls',     type: 'checklist',      icon: '☑️', req: 0, ph: '' },
      { name: 'Gaps & Non-conformities',slug: 'gaps',         type: 'findings',       icon: '⚠️', req: 0, ph: '' },
      { name: 'Recommendations',        slug: 'recommendations',type: 'recommendation',icon: '💡', req: 0, ph: '' },
    ],
  };

  db.transaction(function() {
    templates.forEach(function(tpl) {
      tplStmt.run(tpl.name, tpl.slug, tpl.type, tpl.icon, tpl.color, tpl.desc || '', tpl.def || 0);
      var row = db.prepare("SELECT id FROM report_templates WHERE slug=?").get(tpl.slug);
      if (!row) return;
      (tplSections[tpl.slug] || []).forEach(function(sec, i) {
        secStmt.run(row.id, sec.name, sec.slug, sec.type, i, sec.req || 0, sec.ph || null, sec.icon || '📝');
      });
    });
  })();
}

function getDb() { if (!db) initDb(); return db; }
function getSetting(key, defaultValue) {
  if (!db) return defaultValue;
  try {
    var row = db.prepare("SELECT value FROM settings WHERE key=?").get(key);
    return row ? row.value : defaultValue;
  } catch(e) { return defaultValue; }
}

function setSetting(key, value) {
  if (!db) return;
  db.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at").run(key, String(value));
}

// ── Demo investigation seed — MOVEit / CVE-2023-34362 ────────────────────────
function seedDemoInvestigation() {
  var invId = "inv_demo_moveit";

  var description = [
    "EXECUTIVE SUMMARY",
    "==================",
    "Between 02:14 and 03:01 UTC on June 1, 2023, the SOC detected and contained an active intrusion targeting the organisation's MOVEit Transfer server (moveit.corp.local / 10.0.5.22 — MOVEit Transfer v2021.0.6).",
    "",
    "The threat actor exploited CVE-2023-34362, a critical unauthenticated SQL injection vulnerability (CVSS 9.8) in Progress MOVEit Transfer. The campaign is attributed with high confidence to TA505 / Cl0p based on infrastructure overlap with published threat intelligence and use of the LEMURLOOT web shell.",
    "",
    "IMPACT",
    "------",
    "• ~4.2 GB of HR and Finance data exfiltrated before containment",
    "• No ransomware payload deployed — attacker was in exfiltration-only phase",
    "• 47 minutes from initial exploitation to server isolation",
    "• No confirmed lateral movement beyond the MOVEit Transfer host",
    "• 12 Azure AD accounts with MOVEit portal access: credentials reset as precaution",
    "",
    "AFFECTED ASSETS",
    "---------------",
    "• moveit.corp.local (10.0.5.22) — MOVEit Transfer v2021.0.6 [PATCHED]",
    "• HR SharePoint library — read access via svc_moveit_admin service account",
    "• Finance shared drive — read access via svc_moveit_admin service account",
    "",
    "ATTRIBUTION",
    "-----------",
    "TA505 / Cl0p ransomware group. This attack was part of a coordinated mass-exploitation campaign targeting hundreds of organisations globally between May 27 – June 9, 2023. Multiple government agencies (CISA AA23-158A) and security vendors have attributed the campaign to Cl0p with high confidence."
  ].join("\n");

  var conclusion = [
    "INCIDENT CLOSURE",
    "================",
    "The MOVEit Transfer server was successfully isolated, the LEMURLOOT web shell removed, and the emergency vendor patch applied. Forensic analysis confirmed no ransomware payload was installed and no lateral movement beyond the initial host occurred.",
    "",
    "DWELL TIME: 47 minutes  |  TTR: 3 min  |  TTC: 47 min",
    "",
    "LESSONS LEARNED",
    "---------------",
    "1. PATCH VELOCITY — CVE-2023-34362 was published May 31; the server was exploited 26 hours later. Critical internet-facing assets require a 24-hour emergency patch SLA.",
    "2. NETWORK EXPOSURE — MOVEit Transfer had direct internet exposure on port 443. Placement behind VPN or zero-trust gateway would have eliminated the unauthenticated attack surface.",
    "3. WAF COVERAGE — SQL injection patterns in POST bodies to /guestaccess.aspx were not covered by WAF rules. A generic SQLi rule would have generated an alert before web shell deployment.",
    "4. SERVICE ACCOUNT LEAST PRIVILEGE — svc_moveit_admin had broad read access to HR and Finance shares. Scope reduction would have limited exfiltrated data volume.",
    "",
    "REMEDIATION STATUS",
    "------------------",
    "• Apply MOVEit Transfer patch (2023.0.3+) ............... COMPLETE",
    "• Block all Cl0p C2 IPs at perimeter firewall ........... COMPLETE",
    "• Reset MOVEit user credentials + Azure AD tokens ....... COMPLETE",
    "• Deploy WAF rules for MOVEit-specific SQLi patterns .... IN PROGRESS",
    "• Review service account permissions (file transfer) .... PLANNED",
    "• GDPR Art. 33 notification (72h deadline) .............. IN PROGRESS"
  ].join("\n");

  db.prepare(
    "INSERT INTO investigations (id,title,status,severity,team,analyst_id,analyst_name,description,conclusion,report_locked,locked_at,locked_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))"
  ).run(
    invId, "[IR-2023-047] MOVEit Transfer — Cl0p/TA505 Supply Chain Exploitation",
    "closed", "critical", "t1", "u_admin_default", "Administrator",
    description, conclusion, 1, Date.now(), "u_admin_default"
  );

  // ── IoCs ──────────────────────────────────────────────────────────────────────
  var iocDefs = [
    { id: "ioc_dm_00", type: "ip",       value: "104.223.34.198",    malicious: 1, severity: "critical", context: "Cl0p primary C2 / exfiltration endpoint — ThreatFox confidence 90%. AS: COGENT-174 (US)" },
    { id: "ioc_dm_01", type: "ip",       value: "45.227.255.190",    malicious: 1, severity: "critical", context: "Cl0p secondary C2 — observed in multiple 2023 campaigns. Associated with Cl0p Go implant" },
    { id: "ioc_dm_02", type: "ip",       value: "89.34.27.167",      malicious: 1, severity: "high",     context: "Initial exploitation source — Tor exit node. Previously linked to TA505 reconnaissance infrastructure" },
    { id: "ioc_dm_03", type: "ip",       value: "5.252.23.119",      malicious: 1, severity: "high",     context: "Pre-exploitation scanner — automated SQLi probing observed from this IP targeting MOVEit installations" },
    { id: "ioc_dm_04", type: "domain",   value: "moveit-update.com", malicious: 1, severity: "critical", context: "Fake MOVEit update domain — registered 2023-05-29 (2 days before CVE publication). Used for second-stage payload delivery" },
    { id: "ioc_dm_05", type: "domain",   value: "api.moveit-corp.net",malicious: 1, severity: "high",    context: "Cl0p secondary C2 domain — typosquat of legitimate Progress vendor domain. Observed in DNS queries post-compromise" },
    { id: "ioc_dm_06", type: "hash",     value: "2fb198f5a4c7e35cd3ae12e4e01f5a4d5ada18cd33b3e9b4c0e89b0e4e1f6b23", malicious: 1, severity: "critical", context: "LEMURLOOT web shell (human.aspx) SHA256 — MalwareBazaar confirmed. Deployed at C:\\inetpub\\wwwroot\\moveitisapi\\" },
    { id: "ioc_dm_07", type: "hash",     value: "48367d94ccb4411f15d7ef9c455c92125f3ad8122c5f3afb8a9b4d45cafe8e12", malicious: 1, severity: "critical", context: "LEMURLOOT loader DLL SHA256 — loaded in-memory by human.aspx for .NET assembly execution and Azure AD credential harvesting" },
    { id: "ioc_dm_08", type: "filename", value: "human.aspx",        malicious: 1, severity: "critical", context: "LEMURLOOT web shell filename — masquerades as MOVEit health-check endpoint to evade detection. Path: C:\\inetpub\\wwwroot\\moveitisapi\\" },
    { id: "ioc_dm_09", type: "url",      value: "/human.aspx",       malicious: 1, severity: "critical", context: "LEMURLOOT web shell access URL — all POST requests to this endpoint are malicious. GET requests serve fake 200 OK for evasion" },
    { id: "ioc_dm_10", type: "url",      value: "/guestaccess.aspx", malicious: 0, severity: "medium",   context: "CVE-2023-34362 vulnerable endpoint — SQL injection entry point. Monitor for anomalous POST volume and SQLi patterns in body" },
    { id: "ioc_dm_11", type: "cve",      value: "CVE-2023-34362",    malicious: 1, severity: "critical", context: "MOVEit Transfer SQL injection — CVSS 9.8. Exploited as 0-day from May 27, 2023. Affects all versions prior to 2021.0.7 / 2022.0.3 / 2022.1.4 / 2023.0.1" },
    { id: "ioc_dm_12", type: "process",  value: "csc.exe",           malicious: 1, severity: "high",     context: "C# compiler spawned by w3wp.exe — LEMURLOOT uses csc.exe for in-memory .NET assembly compilation. Abnormal for IIS worker process" },
    { id: "ioc_dm_13", type: "registry", value: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MOVEit DMZ", malicious: 0, severity: "info", context: "MOVEit Transfer service registry key — useful for version fingerprinting and presence detection during threat hunts" },
  ];

  var iocInsert = db.prepare("INSERT INTO investigation_iocs (id,investigation_id,type,value,context,malicious,severity) VALUES (?,?,?,?,?,?,?)");
  db.transaction(function() {
    iocDefs.forEach(function(ioc) {
      iocInsert.run(ioc.id, invId, ioc.type, ioc.value, ioc.context, ioc.malicious, ioc.severity);
    });
  })();

  // ── Findings ──────────────────────────────────────────────────────────────────
  var fndInsert = db.prepare(
    "INSERT INTO investigation_findings (id,investigation_id,title,content,severity,event_at,display_order,event_type,code_blocks,screenshots,color,linked_ioc_ids) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  );

  // T+00:00 — Initial access
  fndInsert.run("fnd_dm_001", invId,
    "T+00:00 — CVE-2023-34362 SQL Injection — Unauthenticated Session Theft",
    [
      "TECHNIQUE: T1190 — Exploit Public-Facing Application",
      "",
      "The attacker sent crafted HTTP POST requests to the /guestaccess.aspx endpoint exploiting a SQL injection vulnerability in MOVEit's session validation logic. Using UNION-based injection, the attacker enumerated the database schema, extracted active session tokens, and forged an authenticated administrator session without valid credentials.",
      "",
      "OBSERVED INDICATORS:",
      "• 847 POST requests from 89.34.27.167 between 02:14–02:28 UTC",
      "• Escalating payload complexity consistent with sqlmap or custom automation",
      "• IIS W3SVC logs show request bodies containing UNION SELECT patterns targeting the sessions table",
      "• Final request returned HTTP 302 redirect with Set-Cookie containing stolen session token for svc_moveit_admin",
      "",
      "NOTE: MOVEit Transfer v2021.0.6 does not enforce prepared statements for session token lookups, allowing the injection."
    ].join("\n"),
    "critical", new Date("2023-06-01T02:14:33Z").getTime(), 0, "initial_access",
    JSON.stringify([{
      lang: "kql",
      content: [
        "// CVE-2023-34362 — Detect anomalous POST volume to MOVEit /guestaccess.aspx",
        "// Run in: Microsoft Sentinel (CommonSecurityLog) or Defender XDR",
        "",
        "CommonSecurityLog",
        "| where TimeGenerated > ago(7d)",
        "| where DeviceProduct has_any (\"MOVEit\", \"IIS\", \"w3svc\")",
        "| where RequestURL has \"/guestaccess.aspx\"",
        "| where RequestMethod == \"POST\"",
        "| summarize",
        "    RequestCount       = count(),",
        "    UniqueSourceIPs    = dcount(SourceIP),",
        "    AvgBodySize        = avg(RequestSize),",
        "    FirstSeen          = min(TimeGenerated),",
        "    LastSeen           = max(TimeGenerated)",
        "    by SourceIP",
        "| where RequestCount > 20",
        "| extend RiskScore = case(",
        "    RequestCount > 500, \"CRITICAL — active exploitation\",",
        "    RequestCount > 100, \"HIGH — likely exploitation attempt\",",
        "    RequestCount > 20,  \"MEDIUM — investigate\",",
        "    \"LOW\")",
        "| project FirstSeen, LastSeen, SourceIP, RequestCount, UniqueSourceIPs, AvgBodySize, RiskScore",
        "| order by RequestCount desc"
      ].join("\n")
    }]),
    "[]", "default",
    JSON.stringify(["ioc_dm_02", "ioc_dm_03", "ioc_dm_10", "ioc_dm_11"])
  );

  // T+13:38 — Web shell deployment
  fndInsert.run("fnd_dm_002", invId,
    "T+13:38 — LEMURLOOT Web Shell Deployed (human.aspx) — C2 Established",
    [
      "TECHNIQUE: T1505.003 — Server Software Component: Web Shell",
      "",
      "Following session token theft, the attacker authenticated to the MOVEit administrative interface and uploaded human.aspx — the LEMURLOOT web shell specifically developed for MOVEit Transfer exploitation.",
      "",
      "LEMURLOOT CAPABILITIES:",
      "• File enumeration and download from MOVEit Transfer's file storage",
      "• Arbitrary command execution via cmd.exe and PowerShell",
      "• Azure Active Directory credential harvesting from MOVEit config",
      "• In-memory .NET assembly execution via csc.exe (no binary dropped to disk)",
      "• Scheduled task creation for persistence (not observed in this incident)",
      "",
      "PLACEMENT: C:\\inetpub\\wwwroot\\moveitisapi\\human.aspx",
      "The file mimics the legitimate MOVEit health-check endpoint. GET requests return HTTP 200 with empty body to evade monitoring.",
      "",
      "SHA256: 2fb198f5a4c7e35cd3ae12e4e01f5a4d5ada18cd33b3e9b4c0e89b0e4e1f6b23",
      "First seen: MalwareBazaar 2023-05-31 18:42 UTC"
    ].join("\n"),
    "critical", new Date("2023-06-01T02:28:11Z").getTime(), 1, "finding",
    JSON.stringify([
      {
        lang: "kql",
        content: [
          "// LEMURLOOT detection — human.aspx file creation event",
          "// Run in: Microsoft Defender XDR (Advanced Hunting)",
          "",
          "DeviceFileEvents",
          "| where Timestamp > ago(14d)",
          "| where FileName =~ \"human.aspx\"",
          "| project",
          "    Timestamp,",
          "    DeviceName,",
          "    FileName,",
          "    FolderPath,",
          "    InitiatingProcessFileName,",
          "    InitiatingProcessCommandLine,",
          "    SHA256,",
          "    ActionType",
          "| order by Timestamp desc"
        ].join("\n")
      },
      {
        lang: "kql",
        content: [
          "// Web shell execution indicator — IIS worker spawning compiler/shell processes",
          "// w3wp.exe should NEVER spawn csc.exe, cmd.exe, or powershell.exe",
          "",
          "DeviceProcessEvents",
          "| where Timestamp > ago(14d)",
          "| where InitiatingProcessFileName =~ \"w3wp.exe\"",
          "| where FileName in~ (",
          "    \"cmd.exe\", \"powershell.exe\", \"csc.exe\", \"vbc.exe\",",
          "    \"wscript.exe\", \"cscript.exe\", \"certutil.exe\",",
          "    \"mshta.exe\", \"net.exe\", \"whoami.exe\", \"ipconfig.exe\"",
          ")",
          "| project",
          "    Timestamp,",
          "    DeviceName,",
          "    FileName,",
          "    ProcessCommandLine,",
          "    InitiatingProcessFileName,",
          "    AccountName",
          "| extend RiskLevel = iff(FileName in~ (\"csc.exe\", \"powershell.exe\"), \"HIGH\", \"MEDIUM\")",
          "| order by Timestamp desc"
        ].join("\n")
      }
    ]),
    "[]", "default",
    JSON.stringify(["ioc_dm_06", "ioc_dm_07", "ioc_dm_08", "ioc_dm_09", "ioc_dm_12"])
  );

  // T+16:32 — Lateral movement attempt (blocked)
  fndInsert.run("fnd_dm_003", invId,
    "T+16:32 — Lateral Movement Attempt — SMB/RDP Blocked by Host Firewall",
    [
      "TECHNIQUE: T1021.002 — Remote Services: SMB/Windows Admin Shares",
      "",
      "Following web shell establishment, LEMURLOOT executed a network reconnaissance script via cmd.exe. The attacker attempted internal SMB and RDP connections to adjacent servers.",
      "",
      "ATTEMPTS OBSERVED:",
      "• [02:29 UTC] SMB scan (TCP/445) — internal /24 subnet sweep — BLOCKED by host-based firewall",
      "• [02:31 UTC] LDAP bind to DC01 (TCP/389) — ALLOWED (read-only, schema query only)",
      "• [02:35 UTC] RDP attempt to FS02 (TCP/3389) — BLOCKED by Network Policy Server",
      "",
      "RESULT: No successful lateral movement. The restrictive outbound firewall policy on the MOVEit server was a critical control that limited the blast radius to a single host.",
      "",
      "RECOMMENDED CONTROL: Validate that internet-facing servers have deny-all outbound firewall rules for internal lateral movement protocols (SMB/445, RDP/3389, WinRM/5985)."
    ].join("\n"),
    "high", new Date("2023-06-01T02:29:00Z").getTime(), 2, "lateral_movement",
    JSON.stringify([{
      lang: "kql",
      content: [
        "// Lateral movement detection — suspicious outbound connections from MOVEit server",
        "// Replace 10.0.5.22 with the actual MOVEit server IP",
        "",
        "let moveit_host    = \"10.0.5.22\";",
        "let lateral_ports  = dynamic([445, 3389, 135, 139, 5985, 5986, 22]);",
        "",
        "DeviceNetworkEvents",
        "| where Timestamp > ago(7d)",
        "| where LocalIP == moveit_host",
        "| where RemotePort in (lateral_ports)",
        "| where RemoteIPType != \"Public\"  // internal targets only",
        "| summarize",
        "    AttemptCount = count(),",
        "    TargetHosts  = make_set(RemoteIP, 30),",
        "    FirstAttempt = min(Timestamp)",
        "    by RemotePort, ActionType",
        "| extend Protocol = case(",
        "    RemotePort == 445,  \"SMB\",",
        "    RemotePort == 3389, \"RDP\",",
        "    RemotePort == 5985, \"WinRM-HTTP\",",
        "    RemotePort == 5986, \"WinRM-HTTPS\",",
        "    tostring(RemotePort))",
        "| project FirstAttempt, Protocol, ActionType, AttemptCount, TargetHosts",
        "| order by AttemptCount desc"
      ].join("\n")
    }]),
    "[]", "default", "[]"
  );

  // T+16:52 — Exfiltration
  fndInsert.run("fnd_dm_004", invId,
    "T+16:52 — Data Exfiltration — ~4.2 GB HR & Finance Data (104.223.34.198:443)",
    [
      "TECHNIQUE: T1048.002 — Exfiltration Over Alternative Protocol: HTTPS",
      "",
      "LEMURLOOT enumerated the MOVEit Transfer file store via its internal API, targeting HR and Finance folders. Data was staged in-memory then exfiltrated via HTTP POST to C2 IP 104.223.34.198:443 over TLS 1.2.",
      "",
      "The exfiltration used a custom HTTP header (X-siLock-Step) as an authentication token — a signature behavior of LEMURLOOT documented by Huntress and Mandiant.",
      "",
      "EXFILTRATION DETAILS:",
      "• Duration: 02:31 — 02:59 UTC (28 minutes)",
      "• Volume: ~4.2 GB",
      "• Destination: 104.223.34.198:443 (AS: COGENT-174, US)",
      "• Protocol: HTTPS / TLS 1.2 — no certificate validation",
      "• C2 Auth header: X-siLock-Step: [token]",
      "",
      "CONFIRMED EXFILTRATED FILES (partial):",
      "• /HR/2023/HR_Annual_Review_2023_Q1.xlsx",
      "• /HR/2023/HR_Salary_Bands_2023.xlsx",
      "• /HR/2023/Org_Chart_June2023.pdf",
      "• /Finance/Reports/Q1_2023_Consolidated.pdf",
      "• /Finance/Reports/Q2_2023_Preliminary.xlsx",
      "• [+307 additional files — see forensic annex FA-001]"
    ].join("\n"),
    "critical", new Date("2023-06-01T02:31:05Z").getTime(), 3, "exfiltration",
    JSON.stringify([
      {
        lang: "kql",
        content: [
          "// Exfiltration detection — sustained large outbound transfers from MOVEit server",
          "// Alert threshold: > 50 MB per 5-minute window to a single external IP",
          "",
          "let moveit_ip          = \"10.0.5.22\";",
          "let threshold_bytes    = 50000000;  // 50 MB",
          "let window_minutes     = 5;",
          "",
          "DeviceNetworkEvents",
          "| where Timestamp > ago(48h)",
          "| where LocalIP == moveit_ip",
          "| where RemoteIPType == \"Public\"",
          "| summarize",
          "    TotalBytesSent  = sum(SentBytes),",
          "    ConnectionCount = count(),",
          "    Protocols       = make_set(Protocol)",
          "    by RemoteIP, bin(Timestamp, window_minutes * 1m)",
          "| where TotalBytesSent > threshold_bytes",
          "| extend GBSent = round(toreal(TotalBytesSent) / 1073741824, 3)",
          "| project Timestamp, RemoteIP, GBSent, ConnectionCount, Protocols",
          "| order by TotalBytesSent desc"
        ].join("\n")
      },
      {
        lang: "kql",
        content: [
          "// X-siLock-Step C2 header detection (LEMURLOOT-specific)",
          "// Requires proxy/WAF logs in Sentinel (e.g., Zscaler, Azure AppGW, Palo Alto)",
          "",
          "AzureDiagnostics",
          "| where Category == \"ApplicationGatewayAccessLog\"",
          "| where requestUri_s has \"human.aspx\"",
          "    or (httpMethod_s == \"POST\" and sentBytes_d > 1000000)",
          "| extend IsLemurloot = requestUri_s has \"human.aspx\"",
          "| project",
          "    TimeGenerated,",
          "    clientIP_s,",
          "    requestUri_s,",
          "    httpMethod_s,",
          "    httpStatus_i,",
          "    sentBytes_d,",
          "    receivedBytes_d,",
          "    IsLemurloot",
          "| order by sentBytes_d desc"
        ].join("\n")
      }
    ]),
    "[]", "default",
    JSON.stringify(["ioc_dm_00", "ioc_dm_01", "ioc_dm_04"])
  );

  // T+44:11 — SOC Detection
  fndInsert.run("fnd_dm_005", invId,
    "T+44:11 — SOC Detection — MDE Alert: IIS Worker Spawned Compiler (T1059.003)",
    [
      "At 02:58:44 UTC, Microsoft Defender for Endpoint raised Alert on moveit.corp.local:",
      "",
      "  Alert ID: da637922498671111_1741621038",
      "  Title:    'Suspicious process execution by IIS worker process'",
      "  Severity: High  |  Category: Execution  |  MITRE: T1059.003",
      "",
      "The alert fired because w3wp.exe spawned csc.exe — the C# compiler. This is highly anomalous for a production web application server. The SOC L2 analyst on-call was paged at 02:59 and acknowledged within 3 minutes.",
      "",
      "PARALLEL DETECTION: At 03:00 UTC, the SOC custom Sentinel alert rule '[SOC-IR-003] IIS spawning compiler processes' also fired independently, corroborating the MDE alert.",
      "",
      "KEY METRICS:",
      "• Detection latency: 44 minutes from initial exploitation",
      "• Time to acknowledge: 3 minutes from alert",
      "• Time to contain: 47 minutes from initial exploitation"
    ].join("\n"),
    "high", new Date("2023-06-01T02:58:44Z").getTime(), 4, "finding",
    JSON.stringify([{
      lang: "kql",
      content: [
        "// [SOC-IR-003] Custom detection rule — IIS worker spawning compiler/scripting processes",
        "// This rule should be in your Sentinel Analytics or Defender Custom Detection library",
        "// Recommended: alert within 5 minutes, severity: High",
        "",
        "DeviceProcessEvents",
        "| where Timestamp > ago(1h)",
        "| where InitiatingProcessFileName =~ \"w3wp.exe\"",
        "| where FileName in~ (",
        "    \"csc.exe\",        // C# compiler   — CRITICAL",
        "    \"vbc.exe\",        // VB compiler    — CRITICAL",
        "    \"powershell.exe\", // PowerShell     — HIGH",
        "    \"cmd.exe\",        // Command shell  — HIGH",
        "    \"wscript.exe\",    // Windows Script — MEDIUM",
        "    \"cscript.exe\",    // CScript        — MEDIUM",
        "    \"certutil.exe\",   // Living off land — HIGH",
        "    \"net.exe\",        // Net commands   — MEDIUM",
        "    \"whoami.exe\"      // Recon          — MEDIUM",
        ")",
        "| extend AlertSeverity = case(",
        "    FileName in~ (\"csc.exe\", \"vbc.exe\"), \"CRITICAL\",",
        "    FileName in~ (\"powershell.exe\", \"cmd.exe\", \"certutil.exe\"), \"HIGH\",",
        "    \"MEDIUM\")",
        "| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, AlertSeverity",
        "| order by Timestamp desc"
      ].join("\n")
    }]),
    "[]", "#f59e0b",
    JSON.stringify(["ioc_dm_12"])
  );

  // T+47:00 — Containment
  fndInsert.run("fnd_dm_006", invId,
    "T+47:00 — Containment — Host Isolated, C2 Blocked, Web Shell Removed",
    [
      "ACTIONS TAKEN (03:01 — 03:09 UTC) — Incident Commander: John Anderson (IR Lead)",
      "",
      "[03:01] ISOLATE — moveit.corp.local isolated via MDE Live Response 'Isolate Device'. Network connectivity severed while maintaining MDE telemetry channel.",
      "[03:02] FIREWALL — C2 IPs 104.223.34.198, 45.227.255.190 added to deny ACL on Palo Alto NGFW (rule INB-DENY-CLOP-001). Change ticket: CHG-2023-06-0341.",
      "[03:04] REVOKE — All active MOVEit sessions terminated via admin API. Azure AD refresh tokens revoked for svc_moveit_admin via PowerShell (Revoke-AzureADUserAllRefreshToken).",
      "[03:05] SNAPSHOT — Forensic Azure VM snapshot taken: moveit-corp-local_20230601T030500Z. IIS logs (C:\\inetpub\\logs\\) and event logs archived to IR evidence storage.",
      "[03:07] CLEAN — human.aspx deleted (confirmed by DeviceFileEvents). IIS application pool 'MoveItDMZ' recycled to flush in-memory .NET assemblies.",
      "[03:09] PATCH — MOVEit Transfer emergency patch 2023.0.3 applied per vendor advisory MOV-2023-03. Service restarted and web shell absence re-confirmed.",
      "",
      "DWELL TIME: 47 minutes | TTR: 3 min | TTC: 47 min"
    ].join("\n"),
    "medium", new Date("2023-06-01T03:01:22Z").getTime(), 5, "finding",
    "[]", "[]", "#22c55e",
    JSON.stringify(["ioc_dm_00", "ioc_dm_01", "ioc_dm_08"])
  );

  // T+56:00 — Threat Hunt
  fndInsert.run("fnd_dm_007", invId,
    "T+56:00 — Post-Incident Threat Hunt — Fleet-wide IOC Sweep (All Negative)",
    [
      "Post-containment threat hunt to confirm no additional compromise and absence of persistent implants.",
      "",
      "SCOPE: All Windows servers in VLAN PROD-10 (192.168.10.0/24) — 47 servers",
      "DURATION: 03:10 — 05:45 UTC (155 minutes)",
      "",
      "HUNTED FOR:",
      "• LEMURLOOT presence (human.aspx on other IIS servers) ............. NEGATIVE",
      "• Known Cl0p C2 IP connections across all endpoints ................. NEGATIVE",
      "• Scheduled tasks created by IIS worker processes (persistence) ..... NEGATIVE",
      "• Azure AD sign-ins from Cl0p IP ranges ............................. NEGATIVE",
      "• LDAP enumeration patterns from production servers ................. NEGATIVE",
      "• MOVEit Transfer installations on non-inventoried hosts ............ NEGATIVE",
      "",
      "RESULT: Investigation scope confirmed to single host (moveit.corp.local)."
    ].join("\n"),
    "info", new Date("2023-06-01T03:10:00Z").getTime(), 6, "finding",
    JSON.stringify([
      {
        lang: "kql",
        content: [
          "// Fleet-wide LEMURLOOT & Cl0p IOC hunt",
          "// Run across all endpoints — union of file, network, and sign-in indicators",
          "",
          "let clop_c2_ips = dynamic([",
          "    \"104.223.34.198\", \"45.227.255.190\",",
          "    \"89.34.27.167\",   \"5.252.23.119\"",
          "]);",
          "let lemurloot_hashes = dynamic([",
          "    \"2fb198f5a4c7e35cd3ae12e4e01f5a4d5ada18cd33b3e9b4c0e89b0e4e1f6b23\",",
          "    \"48367d94ccb4411f15d7ef9c455c92125f3ad8122c5f3afb8a9b4d45cafe8e12\"",
          "]);",
          "",
          "union",
          "(",
          "    DeviceFileEvents",
          "    | where Timestamp > ago(7d)",
          "    | where FileName =~ \"human.aspx\" or SHA256 in (lemurloot_hashes)",
          "    | extend HuntHit = \"LEMURLOOT File Found\"",
          "    | project Timestamp, DeviceName, HuntHit, Detail = strcat(FolderPath, \"\\\\\", FileName)",
          "),",
          "(",
          "    DeviceNetworkEvents",
          "    | where Timestamp > ago(7d)",
          "    | where RemoteIP in (clop_c2_ips)",
          "    | extend HuntHit = \"Cl0p C2 Connection\"",
          "    | project Timestamp, DeviceName, HuntHit, Detail = RemoteIP",
          ")",
          "| order by Timestamp desc"
        ].join("\n")
      },
      {
        lang: "kql",
        content: [
          "// Azure AD sign-in hunt — Cl0p IPs and service account anomalies",
          "",
          "let clop_ips = dynamic([\"104.223.34.198\",\"45.227.255.190\",\"89.34.27.167\"]);",
          "",
          "SigninLogs",
          "| where TimeGenerated > ago(7d)",
          "| where ResultType == 0  // successful sign-ins only",
          "| where IPAddress in (clop_ips)",
          "    or UserPrincipalName has \"svc_moveit\"",
          "    or UserPrincipalName has \"moveit\"",
          "| project",
          "    TimeGenerated,",
          "    UserPrincipalName,",
          "    IPAddress,",
          "    AppDisplayName,",
          "    ClientAppUsed,",
          "    RiskState,",
          "    LocationDetails",
          "| order by TimeGenerated desc"
        ].join("\n")
      }
    ]),
    "[]", "default", "[]"
  );
}

// ── Patch: convert demo investigation to Markdown + add screenshots ───────────
function patchDemoInvestigation() {
  function svgUri(svg) {
    return 'data:image/svg+xml;base64,' + Buffer.from(svg.trim()).toString('base64');
  }

  // ── SVG screenshots ────────────────────────────────────────────────────────

  var svgIisLog = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 200" width="700" height="200">
<style>text{font-family:Consolas,Menlo,monospace;font-size:10.5px;}</style>
<rect width="700" height="200" rx="6" fill="#0d1117"/>
<rect width="700" height="29" rx="6" fill="#161b22"/><rect y="23" width="700" height="6" fill="#161b22"/>
<circle cx="14" cy="14" r="5" fill="#ff5f57"/><circle cx="30" cy="14" r="5" fill="#febc2e"/><circle cx="46" cy="14" r="5" fill="#28c840"/>
<text x="65" y="19" fill="#768390">u_ex230601.log — IIS W3SVC1 — moveit.corp.local (10.0.5.22)</text>
<text x="10" y="47" fill="#3d4f5e">UTC TIME        SOURCE IP        STATUS  ENDPOINT                ANOMALY</text>
<line x1="10" y1="51" x2="690" y2="51" stroke="#21262d" stroke-width="1"/>
<text x="10" y="65" fill="#768390">02:14:22.041    89.34.27.167     302     /guestaccess.aspx</text>
<rect x="6" y="68" width="688" height="17" rx="2" fill="#1c0a00"/>
<text x="10" y="80" fill="#f0883e">02:14:33.218    89.34.27.167     200     /guestaccess.aspx       UNION SELECT NULL,session_token --</text>
<text x="10" y="97" fill="#768390">02:14:51.339    89.34.27.167     200     /guestaccess.aspx</text>
<rect x="6" y="100" width="688" height="17" rx="2" fill="#1c0a00"/>
<text x="10" y="112" fill="#f0883e">02:15:03.104    89.34.27.167     200     /guestaccess.aspx       UNION SELECT session_token FROM sessions</text>
<text x="10" y="130" fill="#3d4f5e">  ... 843 similar POST requests from 89.34.27.167 between 02:14:22 and 02:27:44 UTC ...</text>
<rect x="6" y="133" width="688" height="19" rx="2" fill="#0a1e0a"/>
<text x="10" y="146" fill="#3fb950">02:27:44.881    89.34.27.167     302     /guestaccess.aspx       Set-Cookie: siLockSSSessionID=[STOLEN TOKEN]</text>
<rect y="167" width="700" height="33" fill="#161b22"/>
<rect x="10" y="175" width="10" height="10" rx="2" fill="#e3b341"/>
<text x="26" y="184" fill="#e3b341">ALERT  847 POST requests in 13 min — SQLi pattern confirmed — Source: 89.34.27.167</text>
<text x="26" y="195" fill="#768390">Attribution: TA505/Cl0p — Tor exit node — 0-day exploitation of CVE-2023-34362</text>
</svg>`;

  var svgVt = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 225" width="700" height="225">
<style>text{font-family:'Segoe UI',Arial,sans-serif;font-size:11px;}</style>
<rect width="700" height="225" rx="6" fill="#f8f9fa"/>
<rect width="700" height="46" rx="6" fill="#394bf0"/><rect y="40" width="700" height="6" fill="#394bf0"/>
<text x="14" y="20" fill="#fff" font-size="15" font-weight="bold">VirusTotal</text>
<text x="120" y="20" fill="#b0c0ff" font-size="12">File Analysis</text>
<text x="14" y="36" fill="#b0c0ff" font-size="9" font-family="Consolas,monospace">2fb198f5a4c7e35cd3ae12e4e01f5a4d5ada18cd33b3e9b4c0e89b0e4e1f6b23</text>
<text x="14" y="86" fill="#dc2626" font-size="38" font-weight="bold">52</text>
<text x="72" y="86" fill="#6b7280" font-size="30">/72</text>
<text x="142" y="73" fill="#dc2626" font-size="14" font-weight="bold">MALICIOUS</text>
<text x="142" y="89" fill="#6b7280" font-size="10">security vendors flagged this file</text>
<line x1="14" y1="97" x2="686" y2="97" stroke="#e5e7eb" stroke-width="1"/>
<text x="14" y="111" fill="#6b7280" font-size="9">FILE TYPE</text><text x="14" y="124" fill="#111827" font-size="10" font-weight="bold">ASP.NET Web Shell (LEMURLOOT)</text>
<text x="220" y="111" fill="#6b7280" font-size="9">FIRST SEEN</text><text x="220" y="124" fill="#111827" font-size="10" font-weight="bold">2023-05-31 18:42 UTC</text>
<text x="420" y="111" fill="#6b7280" font-size="9">FILE NAME</text><text x="420" y="124" fill="#111827" font-size="10" font-weight="bold">human.aspx</text>
<line x1="14" y1="132" x2="686" y2="132" stroke="#e5e7eb" stroke-width="1"/>
<text x="14" y="146" fill="#6b7280" font-size="9">TOP VENDOR DETECTIONS</text>
<rect x="14" y="150" width="672" height="15" rx="2" fill="#fef2f2"/>
<text x="20" y="161" fill="#dc2626" font-size="10" font-weight="bold">Microsoft</text><text x="120" y="161" fill="#111827" font-size="10">Trojan:ASP/LEMURLOOT.A!</text>
<rect x="14" y="166" width="672" height="15" rx="2"/>
<text x="20" y="177" fill="#dc2626" font-size="10" font-weight="bold">CrowdStrike</text><text x="120" y="177" fill="#111827" font-size="10">Win.Trojan.LEMURLOOT-10000028-0</text>
<rect x="14" y="182" width="672" height="15" rx="2" fill="#fef2f2"/>
<text x="20" y="193" fill="#dc2626" font-size="10" font-weight="bold">Elastic</text><text x="120" y="193" fill="#111827" font-size="10">Trojan.GenericKD.66701532 (100%)</text>
<rect x="14" y="198" width="672" height="15" rx="2"/>
<text x="20" y="209" fill="#dc2626" font-size="10" font-weight="bold">SentinelOne</text><text x="120" y="209" fill="#111827" font-size="10">Static AI — Malicious ASP — LEMURLOOT family</text>
<rect y="215" width="700" height="10" fill="#f1f5f9"/>
<text x="14" y="222" fill="#6b7280" font-size="8">Analysis: 2023-06-01 09:15 UTC  |  Community score: -100  |  Tags: trojan, webshell, clop, lemurloot, apt</text>
</svg>`;

  var svgMde = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 215" width="700" height="215">
<style>text{font-family:'Segoe UI',Arial,sans-serif;font-size:11px;}</style>
<rect width="700" height="215" rx="6" fill="#1f2937"/>
<rect width="700" height="40" rx="6" fill="#111827"/><rect y="34" width="700" height="6" fill="#111827"/>
<text x="14" y="16" fill="#3b82f6" font-size="13" font-weight="bold">Microsoft</text>
<text x="96" y="16" fill="#d1d5db" font-size="13">Defender XDR</text>
<text x="14" y="32" fill="#6b7280" font-size="9">Incidents &amp; alerts  ›  Alert details</text>
<rect x="12" y="48" width="676" height="52" rx="4" fill="#1a0000"/>
<rect x="12" y="48" width="5" height="52" rx="2" fill="#ef4444"/>
<text x="26" y="66" fill="#f87171" font-size="12" font-weight="bold">HIGH SEVERITY</text>
<rect x="168" y="55" width="88" height="17" rx="8" fill="#ef4444"/>
<text x="176" y="67" fill="#fff" font-size="9" font-weight="bold">T1059.003</text>
<text x="26" y="84" fill="#e5e7eb" font-size="11">Suspicious process execution by IIS worker process</text>
<text x="26" y="95" fill="#9ca3af" font-size="9">2023-06-01 02:58:44 UTC  ·  moveit.corp.local (10.0.5.22)  ·  ID: da637922498671111_1741621038</text>
<text x="14" y="118" fill="#6b7280" font-size="9" font-weight="bold">PROCESS TREE</text>
<rect x="14" y="122" width="672" height="58" rx="4" fill="#111827"/>
<text x="24" y="140" fill="#6b7280" font-family="Consolas,monospace" font-size="10">services.exe (PID 668)</text>
<text x="24" y="156" fill="#9ca3af" font-family="Consolas,monospace" font-size="10">  └── w3wp.exe [MoveItDMZ] (PID 4823)   ← IIS worker process</text>
<text x="24" y="172" fill="#fbbf24" font-family="Consolas,monospace" font-size="10">        └── csc.exe (PID 7291)   ← C# compiler — ANOMALOUS PARENT</text>
<rect y="192" width="700" height="23" fill="#111827"/>
<rect x="14" y="199" width="8" height="8" rx="2" fill="#ef4444"/>
<text x="28" y="207" fill="#9ca3af" font-size="9">REMEDIATION   Isolate device  ·  Collect investigation package  ·  Run antivirus scan  ·  Block indicator</text>
</svg>`;

  var svgNet = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 205" width="700" height="205">
<style>text{font-family:'Segoe UI',Arial,sans-serif;font-size:10px;}</style>
<rect width="700" height="205" rx="6" fill="#0f172a"/>
<rect width="700" height="38" rx="6" fill="#1e293b"/><rect y="32" width="700" height="6" fill="#1e293b"/>
<text x="14" y="14" fill="#94a3b8" font-size="9">AZURE MONITOR — Network Watcher  ·  moveit.corp.local (10.0.5.22)</text>
<text x="14" y="29" fill="#e2e8f0" font-size="13" font-weight="bold">Outbound Traffic — Bytes Sent / Minute</text>
<text x="8" y="60" fill="#475569" font-size="8">400 MB</text>
<text x="8" y="82" fill="#475569" font-size="8">300 MB</text>
<text x="8" y="104" fill="#475569" font-size="8">200 MB</text>
<text x="8" y="126" fill="#475569" font-size="8">100 MB</text>
<text x="16" y="148" fill="#475569" font-size="8">0</text>
<line x1="52" y1="56" x2="688" y2="56" stroke="#1e293b" stroke-width="1"/>
<line x1="52" y1="78" x2="688" y2="78" stroke="#1e293b" stroke-width="1"/>
<line x1="52" y1="100" x2="688" y2="100" stroke="#1e293b" stroke-width="1"/>
<line x1="52" y1="122" x2="688" y2="122" stroke="#1e293b" stroke-width="1"/>
<line x1="52" y1="144" x2="688" y2="144" stroke="#334155" stroke-width="1"/>
<text x="52" y="158" fill="#475569" font-size="8">02:14</text>
<text x="156" y="158" fill="#475569" font-size="8">02:22</text>
<text x="260" y="158" fill="#475569" font-size="8">02:30</text>
<text x="364" y="158" fill="#ef4444" font-size="8" font-weight="bold">02:31 EXFIL</text>
<text x="468" y="158" fill="#475569" font-size="8">02:38</text>
<text x="572" y="158" fill="#475569" font-size="8">02:46</text>
<text x="648" y="158" fill="#475569" font-size="8">02:53</text>
<rect x="54" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="67" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="80" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="93" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="106" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="119" y="139" width="10" height="5" fill="#22c55e" rx="1"/>
<rect x="132" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="145" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="158" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="171" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="184" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="197" y="139" width="10" height="5" fill="#22c55e" rx="1"/>
<rect x="210" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="223" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="236" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="249" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="262" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="275" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="288" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="301" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="314" y="96" width="10" height="48" fill="#ef4444" rx="1"/>
<rect x="327" y="76" width="10" height="68" fill="#ef4444" rx="1"/>
<rect x="340" y="64" width="10" height="80" fill="#ef4444" rx="1"/>
<rect x="353" y="58" width="10" height="86" fill="#ef4444" rx="1"/>
<rect x="366" y="56" width="10" height="88" fill="#ef4444" rx="1"/>
<rect x="379" y="57" width="10" height="87" fill="#ef4444" rx="1"/>
<rect x="392" y="58" width="10" height="86" fill="#ef4444" rx="1"/>
<rect x="405" y="60" width="10" height="84" fill="#ef4444" rx="1"/>
<rect x="418" y="62" width="10" height="82" fill="#ef4444" rx="1"/>
<rect x="431" y="63" width="10" height="81" fill="#ef4444" rx="1"/>
<rect x="444" y="65" width="10" height="79" fill="#ef4444" rx="1"/>
<rect x="457" y="64" width="10" height="80" fill="#ef4444" rx="1"/>
<rect x="470" y="67" width="10" height="77" fill="#ef4444" rx="1"/>
<rect x="483" y="68" width="10" height="76" fill="#ef4444" rx="1"/>
<rect x="496" y="70" width="10" height="74" fill="#ef4444" rx="1"/>
<rect x="509" y="72" width="10" height="72" fill="#ef4444" rx="1"/>
<rect x="522" y="76" width="10" height="68" fill="#ef4444" rx="1"/>
<rect x="535" y="80" width="10" height="64" fill="#ef4444" rx="1"/>
<rect x="548" y="86" width="10" height="58" fill="#ef4444" rx="1"/>
<rect x="561" y="94" width="10" height="50" fill="#ef4444" rx="1"/>
<rect x="574" y="104" width="10" height="40" fill="#ef4444" rx="1"/>
<rect x="587" y="116" width="10" height="28" fill="#ef4444" rx="1"/>
<rect x="600" y="128" width="10" height="16" fill="#ef4444" rx="1"/>
<rect x="613" y="136" width="10" height="8" fill="#ef4444" rx="1"/>
<rect x="626" y="140" width="10" height="4" fill="#ef4444" rx="1"/>
<rect x="639" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="652" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<rect x="665" y="141" width="10" height="3" fill="#22c55e" rx="1"/>
<rect x="678" y="140" width="10" height="4" fill="#22c55e" rx="1"/>
<line x1="314" y1="44" x2="626" y2="44" stroke="#ef4444" stroke-width="1" stroke-dasharray="3,2" opacity="0.7"/>
<text x="320" y="41" fill="#ef4444" font-size="8" font-weight="bold">EXFILTRATION: 02:31–02:59 UTC — ~4.2 GB to 104.223.34.198</text>
<rect y="168" width="700" height="37" fill="#1e293b"/>
<rect x="14" y="178" width="12" height="8" rx="2" fill="#22c55e"/>
<text x="30" y="185" fill="#94a3b8" font-size="9">Normal baseline (&lt;5 MB/min)</text>
<rect x="160" y="178" width="12" height="8" rx="2" fill="#ef4444"/>
<text x="176" y="185" fill="#ef4444" font-size="9">Anomalous exfiltration</text>
<text x="14" y="199" fill="#94a3b8" font-size="9">Peak: ~395 MB/min at 02:37 UTC  ·  Total volume: 4.2 GB in 28 min  ·  Destination: 104.223.34.198 (AS: COGENT-174)</text>
</svg>`;

  // ── Markdown content ───────────────────────────────────────────────────────

  var description = `## Incident Overview

Between **02:14 and 03:01 UTC on June 1, 2023**, the SOC detected and contained an active intrusion targeting the organisation's MOVEit Transfer server (\`moveit.corp.local / 10.0.5.22\` — MOVEit Transfer v2021.0.6).

The threat actor exploited **CVE-2023-34362**, a critical unauthenticated SQL injection vulnerability (CVSS 9.8) in Progress MOVEit Transfer. The campaign is attributed with high confidence to **TA505 / Cl0p** based on infrastructure overlap with published threat intelligence and use of the LEMURLOOT web shell.

---

## Impact

- Approximately **4.2 GB** of HR and Finance data exfiltrated before containment
- No ransomware payload deployed — attacker was in exfiltration-only phase
- **47 minutes** from initial exploitation to server isolation
- No confirmed lateral movement beyond the MOVEit Transfer host
- 12 Azure AD accounts with MOVEit portal access — credentials reset as precaution

## Affected Assets

- \`moveit.corp.local (10.0.5.22)\` — MOVEit Transfer v2021.0.6 **[PATCHED]**
- HR SharePoint library — read access via \`svc_moveit_admin\` service account
- Finance shared drive — read access via \`svc_moveit_admin\` service account

## Attribution

**TA505 / Cl0p ransomware group.** This attack was part of a coordinated mass-exploitation campaign targeting hundreds of organisations globally between May 27 – June 9, 2023. Multiple government agencies (CISA AA23-158A) and security vendors have attributed the campaign to Cl0p with high confidence.`;

  var conclusion = `## Incident Closure

The MOVEit Transfer server was successfully isolated, the LEMURLOOT web shell removed, and the emergency vendor patch applied. Forensic analysis confirmed no ransomware payload was installed and no lateral movement beyond the initial host occurred.

**Dwell Time:** 47 min · **TTR:** 3 min · **TTC:** 47 min

---

## Lessons Learned

- **Patch Velocity** — CVE-2023-34362 was published May 31; the server was exploited 26 hours later. Critical internet-facing assets require a **24-hour emergency patch SLA**.
- **Network Exposure** — MOVEit Transfer had direct internet exposure on port 443. Placement behind VPN or zero-trust gateway would have eliminated the attack surface entirely.
- **WAF Coverage** — SQL injection patterns in POST bodies to \`/guestaccess.aspx\` were not covered by WAF rules. A basic SQLi rule would have generated an alert before web shell deployment.
- **Service Account Least Privilege** — \`svc_moveit_admin\` had broad read access to HR and Finance shares. Scope reduction would have limited the exfiltrated data volume.

---

## Remediation Status

- Apply MOVEit Transfer patch (2023.0.3+) — **COMPLETE**
- Block all Cl0p C2 IPs at perimeter firewall — **COMPLETE**
- Reset MOVEit user credentials + Azure AD tokens — **COMPLETE**
- Deploy WAF rules for MOVEit-specific SQLi patterns — *IN PROGRESS*
- Review service account permissions across file transfer platform — *PLANNED*
- GDPR Art. 33 notification (72h deadline) — *IN PROGRESS*`;

  var f1Content = `**MITRE:** \`T1190\` — Exploit Public-Facing Application

The attacker sent crafted HTTP POST requests to the \`/guestaccess.aspx\` endpoint exploiting a SQL injection vulnerability in MOVEit's session validation logic. Using UNION-based injection, the attacker enumerated the database schema, extracted active session tokens, and forged an authenticated administrator session without valid credentials.

---

## Evidence

IIS W3SVC logs on the MOVEit server show **847 POST requests** from \`89.34.27.167\` between 02:14–02:28 UTC, with escalating payload complexity consistent with automated SQL injection tooling (likely sqlmap or custom automation).

The final successful payload extracted a valid session token for the service account \`svc_moveit_admin\`, which was subsequently used to upload the LEMURLOOT web shell.

**Note:** MOVEit Transfer v2021.0.6 does not enforce prepared statements for session token lookups — this allows UNION-based injection.`;

  var f2Content = `**MITRE:** \`T1505.003\` — Server Software Component: Web Shell

Following session token theft, the attacker authenticated to the MOVEit administrative interface and uploaded \`human.aspx\` — the **LEMURLOOT** web shell specifically developed for MOVEit Transfer exploitation.

---

## LEMURLOOT Capabilities

- File enumeration and download from MOVEit Transfer's file storage
- Arbitrary command execution via \`cmd.exe\` and PowerShell
- Azure Active Directory credential harvesting from MOVEit config
- In-memory .NET assembly execution via \`csc.exe\` (no binary dropped to disk)
- Scheduled task creation for persistence (not observed in this incident)

---

## Indicators

- **Placement:** \`C:\\inetpub\\wwwroot\\moveitisapi\\human.aspx\`
- **SHA256:** \`2fb198f5a4c7e35cd3ae12e4e01f5a4d5ada18cd33b3e9b4c0e89b0e4e1f6b23\`
- **First seen:** MalwareBazaar 2023-05-31 18:42 UTC

The web shell mimics the legitimate MOVEit health-check endpoint. GET requests return HTTP 200 with an empty body to evade monitoring.`;

  var f3Content = `**MITRE:** \`T1021.002\` — Remote Services: SMB/Windows Admin Shares

Following web shell establishment, LEMURLOOT executed a network reconnaissance script via \`cmd.exe\`. The attacker attempted internal SMB and RDP connections to adjacent servers.

---

## Attempts Observed

- \`[02:29]\` SMB scan (\`TCP/445\`) — internal /24 subnet sweep — **BLOCKED** by host-based firewall
- \`[02:31]\` LDAP bind to DC01 (\`TCP/389\`) — **ALLOWED** (read-only schema query only)
- \`[02:35]\` RDP attempt to FS02 (\`TCP/3389\`) — **BLOCKED** by Network Policy Server

**Result:** No successful lateral movement. The restrictive outbound firewall policy on the MOVEit server was a critical control that limited the blast radius to a single host.

**Recommended Control:** Validate that internet-facing servers have deny-all outbound rules for lateral movement protocols (SMB/445, RDP/3389, WinRM/5985-5986).`;

  var f4Content = `**MITRE:** \`T1048.002\` — Exfiltration Over Alternative Protocol: HTTPS

LEMURLOOT enumerated the MOVEit Transfer file store via its internal API, targeting HR and Finance folders. Data was staged in-memory then exfiltrated via HTTP POST to C2 IP \`104.223.34.198:443\` over TLS 1.2.

The exfiltration used a custom HTTP header (\`X-siLock-Step\`) as an authentication token — a **signature behavior** of LEMURLOOT documented by Huntress and Mandiant.

---

## Exfiltration Details

- **Duration:** 02:31 — 02:59 UTC (28 minutes)
- **Volume:** ~4.2 GB total
- **Destination:** \`104.223.34.198:443\` (AS: COGENT-174, US)
- **Protocol:** HTTPS / TLS 1.2 — no certificate validation
- **C2 Auth:** Custom header \`X-siLock-Step: [token]\`

## Confirmed Exfiltrated Files (partial)

- \`HR_Annual_Review_2023_Q1.xlsx\` (2.1 MB)
- \`HR_Salary_Bands_2023.xlsx\` (4.8 MB)
- \`Finance_Q1_2023_Consolidated.pdf\` (1.2 MB)
- *+307 additional files — see forensic annex FA-001*`;

  var f5Content = `At 02:58:44 UTC, Microsoft Defender for Endpoint raised the following alert on \`moveit.corp.local\`:

---

- **Alert ID:** \`da637922498671111_1741621038\`
- **Title:** Suspicious process execution by IIS worker process
- **Severity:** High
- **Category:** Execution
- **MITRE:** \`T1059.003\`

---

The alert fired because \`w3wp.exe\` spawned \`csc.exe\` — the C# compiler. This is **highly anomalous** for a production web application server. The SOC L2 analyst on-call was paged at 02:59 and acknowledged within 3 minutes.

**Parallel Detection:** At 03:00 UTC, the SOC custom Sentinel rule \`[SOC-IR-003] IIS spawning compiler processes\` fired independently, corroborating the MDE alert.

## Key Metrics

- **Detection latency:** 44 minutes from initial exploitation
- **Time to acknowledge:** 3 minutes from alert
- **Time to contain:** 47 minutes from initial exploitation`;

  var f6Content = `**Incident Commander:** John Anderson (IR Lead)

Actions taken between **03:01 – 03:09 UTC:**

- \`[03:01]\` **ISOLATE** — \`moveit.corp.local\` isolated via MDE Live Response. Network severed while maintaining MDE telemetry channel.
- \`[03:02]\` **FIREWALL** — C2 IPs \`104.223.34.198\`, \`45.227.255.190\` added to deny ACL on Palo Alto NGFW. Change ticket: CHG-2023-06-0341.
- \`[03:04]\` **REVOKE** — All active MOVEit sessions terminated via admin API. Azure AD refresh tokens revoked for \`svc_moveit_admin\`.
- \`[03:05]\` **SNAPSHOT** — Forensic Azure VM snapshot taken. IIS logs and Event Logs archived to IR evidence storage.
- \`[03:07]\` **CLEAN** — \`human.aspx\` deleted (confirmed via DeviceFileEvents). IIS app pool \`MoveItDMZ\` recycled to flush in-memory .NET assemblies.
- \`[03:09]\` **PATCH** — MOVEit Transfer emergency patch 2023.0.3 applied. Web shell absence re-confirmed.

---

**Dwell Time:** 47 minutes · **TTR:** 3 min · **TTC:** 47 min`;

  var f7Content = `Post-containment threat hunt to confirm no additional compromise and absence of persistent implants.

- **Scope:** All Windows servers in VLAN PROD-10 (\`192.168.10.0/24\`) — 47 servers
- **Duration:** 03:10 — 05:45 UTC (155 minutes)
- **Result:** Investigation scope confirmed to single host

---

## Hunt Checklist

- LEMURLOOT presence (\`human.aspx\`) on other IIS servers — **NEGATIVE**
- Known Cl0p C2 IP connections across all endpoints — **NEGATIVE**
- Scheduled tasks created by IIS worker processes — **NEGATIVE**
- Azure AD sign-ins from Cl0p IP ranges — **NEGATIVE**
- LDAP enumeration patterns from production servers — **NEGATIVE**
- MOVEit Transfer on non-inventoried hosts — **NEGATIVE**`;

  // ── Apply updates ──────────────────────────────────────────────────────────

  db.prepare("UPDATE investigations SET description=?, conclusion=? WHERE id='inv_demo_moveit'")
    .run(description, conclusion);

  db.prepare("UPDATE investigation_findings SET content=?, screenshots=? WHERE id='fnd_dm_001'")
    .run(f1Content, JSON.stringify([{ url: svgUri(svgIisLog), caption: "IIS W3SVC Access Log — 847 SQL injection requests from 89.34.27.167 (02:14–02:27 UTC)" }]));

  db.prepare("UPDATE investigation_findings SET content=?, screenshots=? WHERE id='fnd_dm_002'")
    .run(f2Content, JSON.stringify([{ url: svgUri(svgVt), caption: "VirusTotal — LEMURLOOT (human.aspx) — 52/72 vendor detections — Trojan:ASP/LEMURLOOT.A" }]));

  db.prepare("UPDATE investigation_findings SET content=? WHERE id='fnd_dm_003'")
    .run(f3Content);

  db.prepare("UPDATE investigation_findings SET content=?, screenshots=? WHERE id='fnd_dm_004'")
    .run(f4Content, JSON.stringify([{ url: svgUri(svgNet), caption: "Azure Monitor Network Watcher — Outbound traffic spike: ~395 MB/min sustained over 28 min to 104.223.34.198" }]));

  db.prepare("UPDATE investigation_findings SET content=?, screenshots=? WHERE id='fnd_dm_005'")
    .run(f5Content, JSON.stringify([{ url: svgUri(svgMde), caption: "Microsoft Defender XDR — High severity alert — w3wp.exe → csc.exe process chain — T1059.003" }]));

  db.prepare("UPDATE investigation_findings SET content=? WHERE id='fnd_dm_006'")
    .run(f6Content);

  db.prepare("UPDATE investigation_findings SET content=? WHERE id='fnd_dm_007'")
    .run(f7Content);
}

module.exports = { initDb, getDb, encrypt, decrypt, hashToken, hashPassword, verifyPassword, auditLog, startSessionCleanup, getSetting, setSetting };
