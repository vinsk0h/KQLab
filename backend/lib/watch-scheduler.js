// Dynamic watch feed scheduler
// Reads sync interval from DB settings each cycle so admin changes take effect automatically.

var _timer = null;
var _db    = null;

async function _run() {
  try {
    var { runWatchCycle } = require("./watch-engine");
    var { auditLog }      = require("../db/database");
    console.log("[WATCH] Auto-fetch: starting...");
    var result = await runWatchCycle(_db);
    console.log("[WATCH] Done: " + result.new_articles + " new articles, " + result.matched + " matches" + (result.errors && result.errors.length ? ", errors: " + result.errors.join("; ") : ""));
    auditLog(null, "WATCH_AUTO_FETCH", "watch", null, result, "system");
  } catch(e) {
    console.error("[WATCH] Auto-fetch error:", e.message);
  }
}

function schedule() {
  if (_timer) { clearTimeout(_timer); _timer = null; }
  var { getSetting } = require("../db/database");
  var mins = Math.max(1, parseInt(getSetting("watch_sync_interval_minutes", "15")) || 15);
  var ms = mins * 60 * 1000;
  _timer = setTimeout(async function() {
    await _run();
    schedule(); // reschedule with potentially updated interval
  }, ms);
  console.log("[WATCH] Next auto-fetch in " + mins + " min");
  return mins;
}

function init(db) {
  _db = db;
}

module.exports = { init, schedule };
