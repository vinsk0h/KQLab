const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const { initDb, startSessionCleanup } = require("./db/database");

require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const authRoutes        = require("./routes/auth");
const queryRoutes       = require("./routes/queries");
const folderRoutes      = require("./routes/folders");
const adminRoutes       = require("./routes/admin");
const commentRoutes     = require("./routes/comments");
const investigationRoutes  = require("./routes/investigations");
const templateRoutes       = require("./routes/templates");
const settingsRoutes       = require("./routes/settings");
const { router: fingerprintRoutes } = require("./routes/fingerprint");
const repoRoutes           = require("./routes/repos");
const watchRoutes          = require("./routes/watch");

const app  = express();
const PORT = process.env.PORT || 3000;
const isDev = process.env.NODE_ENV !== "production";

// Trust the first proxy hop so req.ip reflects the real client IP
app.set("trust proxy", 1);

// Security headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],  // inline + Monaco CDN (unsafe-eval required by Monaco workers)
      styleSrc:   ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      imgSrc:     ["'self'", "data:", "https://github.com", "https://avatars.githubusercontent.com", "https:"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
      workerSrc:  ["'self'", "blob:", "https://cdn.jsdelivr.net"],  // blob: + CDN required by Monaco workers
      objectSrc:  ["'none'"],
      frameSrc:   ["'none'"],
      upgradeInsecureRequests: isDev ? null : [],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Request logging — development only
if (isDev) {
  app.use((req, res, next) => {
    if (req.url.startsWith("/api")) {
      console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
    }
    next();
  });
}

// General rate limiter — all /api/ routes (120 req/min)
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: { error: "Too many requests" },
});

// Stricter rate limiter on auth routes (30 req/15 min)
// In development, localhost is skipped; in production all IPs are limited.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  skip: (req) => {
    if (!isDev) return false;
    const ip = req.ip || "";
    return ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1";
  },
  message: { error: "Too many requests" },
});

app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));
app.use(cookieParser());

// Static files — no-store for HTML (SPA shell), long-lived cache for versioned assets
app.use(express.static(path.join(__dirname, "..", "frontend"), {
  setHeaders: function (res, filePath) {
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-store");
    } else if (/\.(js|css|svg|png|ico|woff2?)$/.test(filePath)) {
      res.setHeader("Cache-Control", isDev ? "no-store" : "public, max-age=604800");
    }
  },
}));

// Health check (no auth, no rate limit — for load balancers / uptime monitors)
app.get("/health", (req, res) => {
  res.json({ ok: true, uptime: Math.floor(process.uptime()) });
});

// CSRF: require X-Requested-With on all state-mutating API calls
// sameSite=strict cookie already blocks cross-site requests; this is belt-and-suspenders
app.use("/api", function(req, res, next) {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
  if (req.headers["x-requested-with"] !== "XMLHttpRequest") {
    return res.status(403).json({ error: "CSRF validation failed" });
  }
  next();
});

// API routes
app.use("/api",                apiLimiter);
app.use("/api/auth",           authLimiter, authRoutes);
app.use("/api/queries",        queryRoutes);
app.use("/api/folders",        folderRoutes);
app.use("/api/admin",          adminRoutes);
app.use("/api/comments",       commentRoutes);
app.use("/api/investigations",  investigationRoutes);
app.use("/api/templates",       templateRoutes);
app.use("/api/settings",        settingsRoutes);
app.use("/api/env",            fingerprintRoutes);
app.use("/api/repos",          repoRoutes);
app.use("/api/watch",          watchRoutes);

// JSON error handler for all /api routes — prevents Express default HTML error pages
app.use("/api", (err, req, res, next) => {
  res.status(err.status || 500).json({ error: err.message || "Server error" });
});

// SPA fallback — only for extensionless paths
app.get("*", (req, res) => {
  if (path.extname(req.path)) return res.status(404).end();
  res.sendFile(path.join(__dirname, "..", "frontend", "index.html"));
});

async function runAutoSync() {
  const { getDb, auditLog } = require("./db/database");
  const { syncRepo }        = require("./lib/repo-parser");
  const db = getDb();
  const sources = db.prepare(
    "SELECT * FROM repo_sources WHERE enabled=1 AND (last_sync_at IS NULL OR datetime(last_sync_at,'+24 hours') < datetime('now'))"
  ).all();
  if (!sources.length) return;
  const team = db.prepare("SELECT id FROM teams LIMIT 1").get();
  if (!team) { console.warn("[AutoSync] No teams found — skipping sync"); return; }
  const teamId = team.id;
  console.log(`[AutoSync] ${sources.length} source(s) due for sync`);
  for (const src of sources) {
    try {
      const stats = await syncRepo(src, db, teamId);
      db.prepare(
        "UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status='ok',last_sync_new=?,last_sync_updated=?,last_sync_errors=? WHERE id=?"
      ).run(stats.new, stats.updated, stats.errors, src.id);
      auditLog(null, "REPO_AUTOSYNC", "repo_source", src.id, { new: stats.new, updated: stats.updated, errors: stats.errors }, "");
      console.log(`[AutoSync] ${src.name}: +${stats.new} new, ~${stats.updated} updated, ${stats.errors} errors`);
    } catch(e) {
      db.prepare("UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status=? WHERE id=?")
        .run("error: " + e.message.slice(0, 100), src.id);
      console.error(`[AutoSync] ${src.name} failed:`, e.message);
    }
  }
}

function start() {
  try {
    initDb();
    startSessionCleanup();
    const server = app.listen(PORT, () => {
      console.log(`\nServer running: http://localhost:${PORT}`);
    });

    function gracefulShutdown(signal) {
      console.log(`\n[${signal}] Shutting down gracefully…`);
      server.close(() => {
        console.log("[Shutdown] HTTP server closed.");
        process.exit(0);
      });
      // Force-kill after 10 s if pending requests don't drain
      setTimeout(() => { console.error("[Shutdown] Timeout — forcing exit."); process.exit(1); }, 10000).unref();
    }
    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
    process.on("SIGINT",  () => gracefulShutdown("SIGINT"));
    // Auto-sync: check every 6h, sync sources that haven't synced in 24h
    setInterval(runAutoSync, 6 * 60 * 60 * 1000);

    // Cyber Watch: dynamic auto-fetch (interval configurable from admin portal)
    var watchScheduler = require("./lib/watch-scheduler");
    watchScheduler.init(require("./db/database").getDb());
    watchScheduler.schedule();

    // First fetch 30s after startup if DB is empty
    setTimeout(async function() {
      try {
        var watchDb = require("./db/database").getDb();
        var count = watchDb.prepare("SELECT COUNT(*) as c FROM watch_articles").get().c;
        if (count === 0) {
          console.log("[WATCH] First run, fetching feeds...");
          var { runWatchCycle } = require("./lib/watch-engine");
          var result = await runWatchCycle(watchDb);
          console.log("[WATCH] First fetch done: " + result.new_articles + " articles, " + result.matched + " matches");
        }
      } catch(e) { console.error("[WATCH] First fetch error:", e.message); }
    }, 30000);
  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
}
start();