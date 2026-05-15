/**
 * npm run sync-repos
 *
 * Force re-sync of all enabled GitHub repo sources.
 * Runs from the CLI — no server needed.
 * Locally-modified queries are never overwritten.
 */

require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const { initDb, getDb, auditLog } = require("../backend/db/database");
const { syncRepo }                = require("../backend/lib/repo-parser");

const COL = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  green:  "\x1b[32m",
  yellow: "\x1b[33m",
  red:    "\x1b[31m",
  cyan:   "\x1b[36m",
  dim:    "\x1b[2m",
};

function pad(str, len) {
  return String(str).padEnd(len);
}

async function main() {
  initDb();
  const db = getDb();

  const sources = db.prepare("SELECT * FROM repo_sources WHERE enabled = 1 ORDER BY created_at ASC").all();
  if (!sources.length) {
    console.log(COL.yellow + "No enabled repository sources found." + COL.reset);
    process.exit(0);
  }

  const team   = db.prepare("SELECT id FROM teams LIMIT 1").get();
  const teamId = team ? team.id : "t1";

  // Force re-parse of all non-locally-modified files
  const cleared = db.prepare("UPDATE repo_query_map SET file_sha = NULL WHERE local_modified = 0").run();

  console.log("\n" + COL.bold + "KQLab — GitHub Repository Sync" + COL.reset);
  console.log(COL.dim + "─".repeat(50) + COL.reset);
  if (cleared.changes > 0) {
    console.log(COL.dim + "SHA cache cleared (" + cleared.changes + " entries) → full re-parse\n" + COL.reset);
  }

  var totalNew = 0, totalUpdated = 0, totalErrors = 0;
  const t0Global = Date.now();

  for (const src of sources) {
    console.log(COL.cyan + COL.bold + src.name + COL.reset +
                COL.dim + "  (" + src.github_owner + "/" + src.github_repo + " @ " + src.branch + ")" + COL.reset);

    const t0 = Date.now();
    try {
      const stats = await syncRepo(src, db, teamId);
      const dur   = ((Date.now() - t0) / 1000).toFixed(1);

      db.prepare(
        "UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status='ok',last_sync_new=?,last_sync_updated=?,last_sync_errors=? WHERE id=?"
      ).run(stats.new, stats.updated, stats.errors, src.id);
      auditLog(null, "REPO_SYNC_SCRIPT", "repo_source", src.id,
               { new: stats.new, updated: stats.updated, errors: stats.errors }, "cli");

      totalNew     += stats.new;
      totalUpdated += stats.updated;
      totalErrors  += stats.errors;

      const newStr  = stats.new      > 0 ? COL.green  + "+" + stats.new      + " new"     + COL.reset : COL.dim + "+0 new" + COL.reset;
      const updStr  = stats.updated  > 0 ? COL.cyan   + "~" + stats.updated  + " updated" + COL.reset : COL.dim + "~0 updated" + COL.reset;
      const skipStr = COL.dim + stats.skipped + " skipped" + COL.reset;
      const errStr  = stats.errors   > 0 ? COL.red    + stats.errors + " errors" + COL.reset : "";
      const durStr  = COL.dim + dur + "s  " + stats.total_files + " files" + COL.reset;

      console.log("  " + [newStr, updStr, skipStr, errStr, durStr].filter(Boolean).join("  "));

      if (stats.warnings.length) {
        const shown = stats.warnings.slice(0, 5);
        shown.forEach(function(w) { console.log("  " + COL.yellow + "⚠ " + w + COL.reset); });
        if (stats.warnings.length > 5) {
          console.log("  " + COL.dim + "… and " + (stats.warnings.length - 5) + " more warning(s)" + COL.reset);
        }
      }
    } catch(e) {
      const dur = ((Date.now() - t0) / 1000).toFixed(1);
      db.prepare("UPDATE repo_sources SET last_sync_at=datetime('now'),last_sync_status=? WHERE id=?")
        .run("error: " + e.message.slice(0, 100), src.id);
      console.log("  " + COL.red + "✗ " + e.message + COL.reset + "  " + COL.dim + dur + "s" + COL.reset);
      totalErrors++;
    }
    console.log();
  }

  const totalDur = ((Date.now() - t0Global) / 1000).toFixed(1);
  console.log(COL.dim + "─".repeat(50) + COL.reset);
  console.log(
    COL.bold + "Done in " + totalDur + "s" + COL.reset + "  " +
    COL.green + "+" + totalNew + " new" + COL.reset + "  " +
    COL.cyan  + "~" + totalUpdated + " updated" + COL.reset +
    (totalErrors ? "  " + COL.red + totalErrors + " errors" + COL.reset : "") + "\n"
  );

  process.exit(totalErrors > 0 ? 1 : 0);
}

main().catch(function(e) {
  console.error(COL.red + "Fatal: " + e.message + COL.reset);
  process.exit(1);
});
