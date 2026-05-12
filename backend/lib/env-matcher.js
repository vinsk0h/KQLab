var { TABLE_KB, DEFENDER_TABLES_IN_SENTINEL } = require("./table-knowledge");
var { extractTables } = require("./kql-table-parser");

/**
 * Check if a query is compatible with a user's environment profile.
 *
 * @param {string} kqlBody - The query body
 * @param {string} queryLanguage - "KQL", "SPL", or "ELK"
 * @param {string|Object} envConfig - The user's environment config (JSON string or object)
 * @param {string} envPlatform - "defender_xdr" or "sentinel"
 * @returns {Object} { status, tables_found[], tables_ok[], tables_missing[] }
 */
function checkCompatibility(kqlBody, queryLanguage, envConfig, envPlatform) {
  // SPL et ELK ne sont pas matchables contre les tables Microsoft
  if (queryLanguage !== "KQL") {
    return { status: "unknown", tables_found: [], tables_ok: [], tables_missing: [], reason: "Only KQL queries can be checked" };
  }

  var tables = extractTables(kqlBody);

  if (tables.length === 0) {
    return { status: "unknown", tables_found: [], tables_ok: [], tables_missing: [], reason: "No tables detected in query" };
  }

  var config;
  try {
    config = typeof envConfig === "string" ? JSON.parse(envConfig) : (envConfig || {});
  } catch(e) {
    config = {};
  }

  var ok = [];
  var missing = [];

  tables.forEach(function(tableName) {
    var tableInfo = TABLE_KB[tableName];

    if (!tableInfo) {
      // Table inconnue (custom table, watchlist, etc.)
      if (envPlatform === "sentinel" && config.custom_tables && config.custom_tables.indexOf(tableName) >= 0) {
        ok.push({ table: tableName, status: "ok", detail: "Custom table" });
      } else {
        // Table inconnue = traiter comme OK avec warning
        ok.push({ table: tableName, status: "ok", detail: "Unknown table (not in knowledge base)" });
      }
      return;
    }

    if (envPlatform === "defender_xdr") {
      // ── Profil Defender XDR ──
      if (tableInfo.platform === "defender_xdr") {
        if (tableInfo.requires === null || config[tableInfo.requires]) {
          ok.push({ table: tableName, status: "ok", detail: tableInfo.desc });
        } else {
          missing.push({ table: tableName, status: "missing_license", detail: "Requires " + tableInfo.requires.toUpperCase(), requires: tableInfo.requires });
        }
      } else if (tableInfo.platform === "sentinel") {
        missing.push({ table: tableName, status: "wrong_platform", detail: "This table is only in Sentinel" });
      }

    } else if (envPlatform === "sentinel") {
      // ── Profil Sentinel ──
      if (tableInfo.platform === "sentinel") {
        if (tableInfo.requires === null) {
          ok.push({ table: tableName, status: "ok", detail: tableInfo.desc });
        } else if (config.connectors && config.connectors.indexOf(tableInfo.requires) >= 0) {
          ok.push({ table: tableName, status: "ok", detail: tableInfo.desc });
        } else {
          missing.push({ table: tableName, status: "missing_connector", detail: "Requires connector: " + tableInfo.requires, requires: tableInfo.requires });
        }
      } else if (tableInfo.platform === "defender_xdr") {
        // Table Defender dans Sentinel : possible si connecteur MicrosoftThreatProtection
        if (config.connectors && config.connectors.indexOf("MicrosoftThreatProtection") >= 0) {
          if (DEFENDER_TABLES_IN_SENTINEL.indexOf(tableName) >= 0) {
            ok.push({ table: tableName, status: "ok", detail: tableInfo.desc + " (via MTP connector)" });
          } else {
            missing.push({ table: tableName, status: "missing_license", detail: "Table not available via MTP connector", requires: tableInfo.requires });
          }
        } else {
          missing.push({ table: tableName, status: "missing_connector", detail: "Requires MicrosoftThreatProtection connector in Sentinel to access Defender tables", requires: "MicrosoftThreatProtection" });
        }
      }
    }
  });

  var status;
  if (missing.length === 0) status = "compatible";
  else if (ok.length > 0 && missing.length > 0) status = "partial";
  else status = "incompatible";

  return {
    status: status,
    tables_found: tables,
    tables_ok: ok,
    tables_missing: missing
  };
}

module.exports = { checkCompatibility };
