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
  if (db.prepare("SELECT COUNT(*) as c FROM repo_sources").get().c === 0) seedRepoSources();
  if (db.prepare("SELECT COUNT(*) as c FROM watch_sources").get().c === 0) seedWatchSources();
  if (db.prepare("SELECT COUNT(*) as c FROM report_templates").get().c === 0) seedReportTemplates();

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
  var ins = db.prepare("INSERT INTO queries (id,title,description,kql,environment,severity,mitre,picerl,playbook,folder_id,tags,author_id,author_name,team,versions) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
  var qs = [
    {id:"c01",t:"Encoded PowerShell",d:"Detects encoded PS commands.",e:"Defender",k:'DeviceProcessEvents\n| where Timestamp > ago({{TimeRange}})\n| where FileName in~ ("powershell.exe","pwsh.exe")\n| where ProcessCommandLine has_any ("-enc","-EncodedCommand","FromBase64String","IEX")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',m:'["TA0002","TA0005"]',p:'["I","C"]',s:"high",pb:"Malware",f:"f1",tg:'["powershell"]'},
    {id:"c02",t:"LSASS Credential Dump",d:"Detects LSASS memory access.",e:"Defender",k:'DeviceProcessEvents\n| where Timestamp > ago({{TimeRange}})\n| where FileName in~ ("procdump.exe","mimikatz.exe","nanodump.exe")\n| project Timestamp, DeviceName, FileName, ProcessCommandLine',m:'["TA0006"]',p:'["I","C"]',s:"critical",pb:"CredComp",f:"f1",tg:'["lsass","mimikatz"]'},
    {id:"c03",t:"RDP Lateral Movement",d:"Tracks internal RDP.",e:"Defender",k:'DeviceNetworkEvents\n| where Timestamp > ago({{TimeRange}})\n| where RemotePort == 3389 and ActionType == "ConnectionSuccess"\n| summarize Cnt = count(), Targets = make_set(RemoteIP) by DeviceName, AccountName\n| where Cnt > {{Threshold}}',m:'["TA0008"]',p:'["I","C"]',s:"high",pb:"LatMov",f:"f1",tg:'["rdp"]'},
    {id:"c04",t:"Registry Run Key",d:"Monitors Run/RunOnce keys.",e:"Defender",k:'DeviceRegistryEvents\n| where Timestamp > ago({{TimeRange}})\n| where ActionType == "RegistryValueSet"\n| where RegistryKey has_any (@"\\CurrentVersion\\Run",@"\\CurrentVersion\\RunOnce")\n| project Timestamp, DeviceName, RegistryKey, RegistryValueData',m:'["TA0003"]',p:'["I","E"]',s:"medium",pb:"Persistence",f:"f2",tg:'["registry"]'},
    {id:"c05",t:"DNS Tunneling",d:"Detects long DNS queries.",e:"Defender",k:'DeviceNetworkEvents\n| where Timestamp > ago({{TimeRange}})\n| where ActionType == "DnsQueryResponse"\n| extend DLen = strlen(tostring(parse_json(AdditionalFields).DnsQueryString))\n| where DLen > 50\n| summarize Cnt = count() by DeviceName\n| where Cnt > {{Threshold}}',m:'["TA0010","TA0011"]',p:'["I","C"]',s:"critical",pb:"Exfil",f:"f1",tg:'["dns","exfil"]'},
    {id:"c06",t:"RMM Tools",d:"Known remote monitoring tools.",e:"Defender",k:'DeviceProcessEvents\n| where Timestamp > ago({{TimeRange}})\n| where FileName in~ ("anydesk.exe","teamviewer.exe","screenconnect.exe","rustdesk.exe")\n| summarize Cnt = count(), Dev = dcount(DeviceName) by FileName',m:'["TA0011"]',p:'["P","I"]',s:"medium",pb:"Shadow IT",f:"f2",tg:'["rmm"]'},
    {id:"c07",t:"Certutil Download",d:"certutil.exe LOLBin abuse.",e:"Both",k:'DeviceProcessEvents\n| where Timestamp > ago({{TimeRange}})\n| where FileName == "certutil.exe" and ProcessCommandLine has_any ("-urlcache","http")\n| project Timestamp, DeviceName, ProcessCommandLine',m:'["TA0002","TA0011"]',p:'["I"]',s:"high",pb:"Execution",f:"f2",tg:'["certutil","lolbin"]'},
    {id:"c08",t:"Security Log Cleared",d:"Event log tampering.",e:"Defender",k:'DeviceProcessEvents\n| where Timestamp > ago({{TimeRange}})\n| where FileName == "wevtutil.exe" and ProcessCommandLine has_any ("cl Security","clear-log")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',m:'["TA0005"]',p:'["I"]',s:"high",pb:"Evasion",f:"f2",tg:'["log-clearing"]'},
    {id:"c09",t:"Brute Force Entra ID",d:"Multiple failed sign-ins.",e:"Sentinel",k:'SigninLogs\n| where TimeGenerated > ago({{TimeRange}})\n| where ResultType != "0"\n| summarize Failed = count(), IPs = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated,5m)\n| where Failed > {{Threshold}}',m:'["TA0006","TA0001"]',p:'["I"]',s:"critical",pb:"CredComp",f:"f5",tg:'["brute-force"]'},
    {id:"c10",t:"Impossible Travel",d:"Distant sign-ins in short time.",e:"Sentinel",k:'SigninLogs\n| where TimeGenerated > ago({{TimeRange}})\n| where ResultType == "0"\n| project TimeGenerated, UserPrincipalName, Location, IPAddress\n| sort by UserPrincipalName, TimeGenerated asc\n| serialize\n| extend PrevLoc=prev(Location),PrevTime=prev(TimeGenerated),PrevUser=prev(UserPrincipalName)\n| where UserPrincipalName==PrevUser and Location!=PrevLoc\n| extend Diff=datetime_diff("minute",TimeGenerated,PrevTime)\n| where Diff < 60',m:'["TA0001"]',p:'["I"]',s:"high",pb:"AccComp",f:"f5",tg:'["impossible-travel"]'},
    {id:"c11",t:"MFA Disabled",d:"MFA removed from account.",e:"Sentinel",k:'AuditLogs\n| where TimeGenerated > ago({{TimeRange}})\n| where OperationName has_any ("Disable Strong Authentication","Delete strong auth")\n| extend Target=tostring(TargetResources[0].userPrincipalName)\n| project TimeGenerated, InitiatedBy, Target',m:'["TA0005","TA0003"]',p:'["I"]',s:"high",pb:"AccComp",f:"f5",tg:'["mfa"]'},
    {id:"c12",t:"External Email Forward",d:"Mailbox forwarding externally.",e:"Sentinel",k:'OfficeActivity\n| where TimeGenerated > ago({{TimeRange}})\n| where Operation in ("New-TransportRule","Set-Mailbox")\n| where Parameters has_any ("ForwardingSmtpAddress","ForwardTo")\n| project TimeGenerated, UserId, Operation',m:'["TA0010"]',p:'["I","C"]',s:"critical",pb:"EmailComp",f:"f5",tg:'["email-forward"]'},
  ];
  db.transaction(function(items) { items.forEach(function(c) { ins.run(c.id,c.t,c.d,c.k,c.e,c.s,c.m,c.p,c.pb,c.f,c.tg,uid,"Bert-JanP","t1",'[{"v":1,"date":"2026-01-01","author":"Bert-JanP","note":"From GitHub"}]'); }); })(qs);
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

function seedRepoSources() {
  // One dedicated folder per repo source
  var repoFolders = [
    ["f_rs_bertjanp",   "Bert-JanP Hunting",         "BJ", "t1", "#6e40c9"],
    ["f_rs_azsentinel", "Azure Sentinel Community",   "AS", "t1", "#0078d4"],
    ["f_rs_reprise99",  "reprise99 Queries",          "R9", "t1", "#38bdf8"],
  ];
  repoFolders.forEach(function(f) {
    db.prepare("INSERT OR IGNORE INTO folders (id,name,icon,scope,team_id,color,owner_id) VALUES (?,?,?,?,?,?,?)").run(
      f[0], f[1], f[2], "team", f[3], f[4], "u_admin_default"
    );
  });
  var stmt = db.prepare("INSERT OR IGNORE INTO repo_sources (id,name,github_owner,github_repo,branch,path_filter,file_format,target_folder_id,added_by) VALUES (?,?,?,?,?,?,?,?,?)");
  stmt.run("rs_bertjanp",  "Bert-JanP Hunting Rules",   "Bert-JanP", "Hunting-Queries-Detection-Rules", "main",   "",               "md",   "f_rs_bertjanp",   "u_admin_default");
  stmt.run("rs_azsentinel","Azure Sentinel",             "Azure",     "Azure-Sentinel",                  "master", "Hunting Queries", "yaml", "f_rs_azsentinel", "u_admin_default");
  stmt.run("rs_reprise99", "reprise99 Sentinel Queries", "reprise99", "Sentinel-Queries",                "main",   "",               "kql",  "f_rs_reprise99",  "u_admin_default");
}

function seedWatchSources() {
  var stmt = db.prepare("INSERT OR IGNORE INTO watch_sources (id, name, url, feed_type, enabled) VALUES (?,?,?,?,1)");
  stmt.run("ws_bleeping",    "BleepingComputer",  "https://www.bleepingcomputer.com/feed/",                                                    "rss");
  stmt.run("ws_hackernews",  "TheHackerNews",     "https://feeds.feedburner.com/TheHackersNews",                                               "rss");
  stmt.run("ws_cisa_kev",    "CISA KEV",          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",        "json_cisa");
  stmt.run("ws_msrc",        "Microsoft MSRC",    "https://api.msrc.microsoft.com/update-guide/rss",                                           "rss");
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

module.exports = { initDb, getDb, encrypt, decrypt, hashToken, hashPassword, verifyPassword, auditLog, startSessionCleanup, getSetting, setSetting };
