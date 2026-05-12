/**
 * Extract table names from a KQL query body.
 * Handles: first line (table name), union, join, let statements, parenthesized subqueries.
 * Does NOT extract from comments or string literals.
 */

var { TABLE_KB } = require("./table-knowledge");
var KNOWN_TABLES = Object.keys(TABLE_KB);

function extractTables(kqlBody) {
  if (!kqlBody || typeof kqlBody !== "string") return [];

  var found = new Set();
  var lines = kqlBody.split("\n");

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();

    // Ignorer les commentaires de ligne entière
    if (line.startsWith("//")) continue;
    // Retirer les commentaires inline
    var commentIdx = line.indexOf("//");
    if (commentIdx > 0) line = line.slice(0, commentIdx).trim();

    // Ignorer les lignes vides
    if (!line) continue;

    // Ignorer les lignes pipe qui ne sont pas union/join
    if (line.startsWith("|") && !line.match(/^\|\s*(union|join)/i)) continue;

    // CAS 1 : Premiere ligne ou ligne sans pipe = nom de table possible
    if (i === 0 || (!line.startsWith("|") && !line.toLowerCase().startsWith("let ") && !line.startsWith("print") && !line.startsWith("//"))) {
      var firstWord = line.split(/[\s|;(,]/)[0];
      if (firstWord && isKnownTable(firstWord)) {
        found.add(firstWord);
      }
    }

    // CAS 2 : "union" keyword
    // Ex: "| union DeviceFileEvents" ou "| union DeviceFileEvents, DeviceRegistryEvents"
    var unionMatch = line.match(/union\s+([\w\s,*]+)/i);
    if (unionMatch) {
      unionMatch[1].split(",").forEach(function(t) {
        var name = t.trim().replace(/\*/g, "").split(/\s/)[0];
        if (name && isKnownTable(name)) found.add(name);
      });
    }

    // CAS 3 : "join" keyword
    // Ex: "| join kind=inner (DeviceLogonEvents | where ...) on DeviceName"
    var joinMatch = line.match(/join\s+(?:kind\s*=\s*\w+\s*)?\(?\s*(\w+)/i);
    if (joinMatch && isKnownTable(joinMatch[1])) {
      found.add(joinMatch[1]);
    }

    // CAS 4 : "let" statement avec une table
    // Ex: "let events = DeviceProcessEvents | where ..."
    var letMatch = line.match(/let\s+\w+\s*=\s*(\w+)/i);
    if (letMatch && isKnownTable(letMatch[1])) {
      found.add(letMatch[1]);
    }

    // CAS 5 : table dans une sous-requete entre parentheses
    // Ex: "(SigninLogs | where ...)" dans un join ou union
    var subqueryMatches = line.match(/\(\s*(\w+)\s*\|/g);
    if (subqueryMatches) {
      subqueryMatches.forEach(function(m) {
        var name = m.replace(/[()|\s]/g, "");
        if (isKnownTable(name)) found.add(name);
      });
    }

    // CAS 6 : _GetWatchlist function
    var funcMatch = line.match(/_GetWatchlist\s*\(/i);
    if (funcMatch) found.add("_GetWatchlist");

    // CAS 7 : datatable — ignorer (inline data, pas une vraie table)

    // CAS 8 : scan generique pour les noms de tables connus dans la ligne
    KNOWN_TABLES.forEach(function(tableName) {
      if (found.has(tableName)) return;
      var re = new RegExp("\\b" + escapeRegex(tableName) + "\\b");
      if (re.test(line)) {
        // Verifier que ce n'est pas dans une string (nombre pair de guillemets avant)
        var beforeMatch = line.slice(0, line.search(re));
        var quoteCount = (beforeMatch.match(/"/g) || []).length;
        if (quoteCount % 2 === 0) {
          found.add(tableName);
        }
      }
    });
  }

  return Array.from(found);
}

function isKnownTable(name) {
  return Object.prototype.hasOwnProperty.call(TABLE_KB, name);
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { extractTables, isKnownTable };
