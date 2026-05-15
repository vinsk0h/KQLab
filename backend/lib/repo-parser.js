const yaml  = require("js-yaml");
const crypto = require("crypto");
const { detectEnvironment, buildExtrasFromDb } = require("./env-detector");

const TACTIC_MAP = {
  InitialAccess:        "TA0001", Execution:           "TA0002", Persistence:         "TA0003",
  PrivilegeEscalation:  "TA0004", DefenseEvasion:      "TA0005", CredentialAccess:    "TA0006",
  Discovery:            "TA0007", LateralMovement:     "TA0008", Collection:          "TA0009",
  Exfiltration:         "TA0010", CommandAndControl:   "TA0011", Impact:              "TA0040",
  Reconnaissance:       "TA0043", ResourceDevelopment: "TA0042",
  // Lowercase / no-space aliases for robustness
  "initial access":     "TA0001", "execution":         "TA0002", "persistence":       "TA0003",
  "privilege escalation":"TA0004","defense evasion":   "TA0005", "credential access": "TA0006",
  "discovery":          "TA0007", "lateral movement":  "TA0008", "collection":        "TA0009",
  "exfiltration":       "TA0010", "command and control":"TA0011","impact":            "TA0040",
  "reconnaissance":     "TA0043", "resource development":"TA0042",
};

// Case-insensitive tactic lookup: strips spaces + lowercases before matching
function mapTactic(raw) {
  if (!raw) return null;
  var direct = TACTIC_MAP[raw];
  if (direct) return direct;
  var lower = raw.toLowerCase();
  if (TACTIC_MAP[lower]) return TACTIC_MAP[lower];
  var nospace = lower.replace(/[\s_-]/g, "");
  for (var key in TACTIC_MAP) {
    if (key.toLowerCase().replace(/[\s_-]/g, "") === nospace) return TACTIC_MAP[key];
  }
  return null;
}

// MITRE tactic → SANS IR Cycle (PICERL) inference
const TACTIC_TO_PICERL = {
  TA0001: ["I"],        // Initial Access       → Identification
  TA0002: ["I"],        // Execution            → Identification
  TA0003: ["I", "C"],   // Persistence          → Identification + Containment
  TA0004: ["I", "C"],   // Privilege Escalation → Identification + Containment
  TA0005: ["I", "C"],   // Defense Evasion      → Identification + Containment
  TA0006: ["I", "C"],   // Credential Access    → Identification + Containment
  TA0007: ["I"],        // Discovery            → Identification
  TA0008: ["C"],        // Lateral Movement     → Containment
  TA0009: ["C"],        // Collection           → Containment
  TA0010: ["C", "E"],   // Exfiltration         → Containment + Eradication
  TA0011: ["C"],        // Command and Control  → Containment
  TA0040: ["C", "E"],   // Impact               → Containment + Eradication
};

const SEVKEYS = ["critical", "high", "medium", "low", "info"];

// ── GitHub API helpers ────────────────────────────────────────────────────────

function ghHeaders() {
  var h = { "Accept": "application/vnd.github.v3+json", "User-Agent": "KQLab" };
  if (process.env.GITHUB_TOKEN) h["Authorization"] = "token " + process.env.GITHUB_TOKEN;
  return h;
}

async function listRepoFiles(owner, repo, branch, pathFilter, fileFormat) {
  var debug = process.env.REPO_PARSER_DEBUG === 'true';
  var url = "https://api.github.com/repos/" + owner + "/" + repo + "/git/trees/" + branch + "?recursive=1";
  if (debug) console.log("[REPO_PARSER] Fetching tree:", url);
  var res = await fetch(url, { headers: ghHeaders() });
  if (!res.ok) throw new Error("GitHub tree fetch failed: " + res.status + " " + url);
  var data = await res.json();
  if (!data.tree) throw new Error("No tree in response");

  if (data.truncated) {
    console.warn("[REPO_PARSER] GitHub tree response truncated for " + owner + "/" + repo +
      " (repo has >1000 files or tree exceeds size limit). Some files may be missing. " +
      "Use path_filter to narrow the scope.");
  }

  var exts = fileFormat === "yaml" ? [".yaml", ".yml"]
           : fileFormat === "md"   ? [".md"]
           : fileFormat === "kql"  ? [".kql"]
           : [".yaml", ".yml", ".md", ".kql"];

  var filtered = data.tree.filter(function(item) {
    if (item.type !== "blob") return false;
    var p = item.path.toLowerCase();
    var hasExt = exts.some(function(e) { return p.endsWith(e); });
    if (!hasExt) return false;
    // pathFilter: case-insensitive substring match
    if (pathFilter && item.path.toLowerCase().indexOf(pathFilter.toLowerCase()) < 0) return false;
    // Azure-Sentinel: ignore Detections/, Playbooks/, Workbooks/
    if (owner === "Azure" && repo === "Azure-Sentinel") {
      if (/^(Detections|Playbooks|Workbooks)\//i.test(item.path)) return false;
    }
    return true;
  });

  if (debug) console.log("[REPO_PARSER] listRepoFiles:", filtered.length, "files matched (truncated:", !!data.truncated, ")");
  return filtered;
}

async function fetchFileContent(owner, repo, filePath, branch) {
  var url = "https://api.github.com/repos/" + owner + "/" + repo + "/contents/" + encodeURIComponent(filePath) + "?ref=" + branch;
  var res = await fetch(url, { headers: ghHeaders() });
  if (!res.ok) throw new Error("GitHub content fetch failed: " + res.status);
  var data = await res.json();
  if (!data.content) throw new Error("No content in response");
  return Buffer.from(data.content, "base64").toString("utf8");
}

// ── Shared extraction helpers ─────────────────────────────────────────────────

function sanitizeStr(s, max) {
  if (typeof s !== "string") return "";
  return s.replace(/[<>]/g, "").trim().slice(0, max);
}

// Detect severity from any free text. Looks for "severity: X" first, then standalone keywords.
function detectSeverity(text) {
  var m = (text || "").match(/\bseverity[\s:—\-]+([a-zA-Z]+)/i);
  if (m) {
    var s = m[1].toLowerCase();
    if (SEVKEYS.includes(s)) return s;
  }
  var t = (text || "").toLowerCase();
  if (/\bcritical\b/.test(t)) return "critical";
  if (/\bhigh\b/.test(t))     return "high";
  if (/\blow\b/.test(t))      return "low";
  if (/\binfo(rmation)?\b/.test(t)) return "info";
  return "medium";
}

// Extract MITRE tactic IDs (TA0001 … TA0040) from any text.
function extractMitre(text) {
  var matches = (text || "").match(/\bTA\d{4}\b/g) || [];
  var seen = {}, ids = [];
  matches.forEach(function(m) { if (!seen[m]) { seen[m] = true; ids.push(m); } });
  return ids;
}

// Extract ATT&CK technique IDs (T1055, T1059.003 …) — used as tags.
function extractTechniqueTags(text) {
  var matches = (text || "").match(/\bT\d{4}(?:\.\d{3})?\b/g) || [];
  var seen = {}, tags = [];
  matches.forEach(function(t) { if (!seen[t]) { seen[t] = true; tags.push(t); } });
  return tags;
}

// Infer PICERL phases from a list of MITRE tactic IDs.
function picerlFromMitre(mitreIds) {
  var seen = {}, result = [];
  (mitreIds || []).forEach(function(id) {
    (TACTIC_TO_PICERL[id] || []).forEach(function(p) {
      if (!seen[p]) { seen[p] = true; result.push(p); }
    });
  });
  return result;
}

// Detect environment from file path.
function envFromPath(filePath) {
  var p = filePath.toLowerCase();
  var isDef = /\b(defender|mde|mtp|mdatp|endpoint|xdr)\b/.test(p);
  var isSen = /\b(sentinel|azure.?active.?directory|entra|aad|office.?365|o365)\b/.test(p);
  if (isDef && isSen) return "Both";
  if (isDef) return "Defender";
  if (isSen) return "Sentinel";
  return "Both";
}

// Deduplicate a string array preserving order.
function dedup(arr) {
  var seen = {}, out = [];
  arr.forEach(function(v) { if (v && !seen[v]) { seen[v] = true; out.push(v); } });
  return out;
}

// Extract CVE IDs from any text.
function extractCVEs(text) {
  var matches = (text || "").match(/CVE-\d{4}-\d{4,7}/gi) || [];
  var seen = {}, cves = [];
  matches.forEach(function(c) { var u = c.toUpperCase(); if (!seen[u]) { seen[u] = true; cves.push(u); } });
  return cves;
}

// Extract hashtags (#Tag) from text (excludes #numbers and single chars).
function extractHashtags(text) {
  var matches = (text || "").match(/#([A-Za-z][A-Za-z0-9_-]{1,40})\b/g) || [];
  var seen = {}, tags = [];
  matches.forEach(function(h) { var t = h.slice(1); if (!seen[t]) { seen[t] = true; tags.push(t); } });
  return tags;
}

// Headings that indicate a generic section rather than a query title.
// When the heading immediately before a KQL block matches this, prefer H1.
var GENERIC_SECTION_RE = /^(kql(\s+(query|for|in))?|kusto(\s+query)?|sentinel\s+query|advanced\s+hunting(\s+query)?|detection(\s+rule)?|hunting(\s+query)?|query(\s+(for|in|example))?|example(\s+query)?|microsoft\s+(sentinel|defender)|azure\s+(sentinel|monitor))/i;

// ── Parser: YAML (Azure-Sentinel format) ─────────────────────────────────────

function parseYamlFile(content, filePath, extras) {
  var debug = process.env.REPO_PARSER_DEBUG === 'true';
  try {
    var doc = yaml.load(content);
    if (!doc || typeof doc !== "object") return null;

    // Support multiple field name aliases across repos
    var kqlRaw = doc.query || doc.queryText || doc.Query || doc.kql || "";
    if (typeof kqlRaw !== "string") return null;
    var kql = kqlRaw.trim();
    if (kql.length < 10) return null;

    var title = sanitizeStr(doc.name || doc.Name || doc.title || doc.id || "", 200);
    if (!title) return null;

    var description = sanitizeStr(
      typeof doc.description === "string" ? doc.description
      : typeof doc.Description === "string" ? doc.Description
      : typeof doc.summary === "string" ? doc.summary
      : "", 500
    );

    // Severity — handle 'informational' alias and case variations
    var sev = "medium";
    var sevRaw = String(doc.severity || doc.Severity || "").toLowerCase().trim();
    if (sevRaw === "informational") sev = "info";
    else if (SEVKEYS.includes(sevRaw)) sev = sevRaw;

    // MITRE — from tactics array (case-insensitive)
    var mitre = [];
    var tacticsSrc = Array.isArray(doc.tactics) ? doc.tactics
                   : Array.isArray(doc.Tactics) ? doc.Tactics
                   : Array.isArray(doc.tactic)  ? doc.tactic : [];
    tacticsSrc.forEach(function(t) { var id = mapTactic(String(t)); if (id && mitre.indexOf(id) < 0) mitre.push(id); });
    // Also scan description + query for stray TA00XX refs
    mitre = dedup(mitre.concat(extractMitre(description + " " + kql)));

    // Tags — relevantTechniques + doc.tags + doc.categories + T1xxx from text + CVEs
    var tags = [];
    var techSrc = Array.isArray(doc.relevantTechniques) ? doc.relevantTechniques
                : Array.isArray(doc.techniques)         ? doc.techniques
                : Array.isArray(doc.Techniques)         ? doc.Techniques : [];
    techSrc.forEach(function(t) { var s = sanitizeStr(String(t), 50); if (s) tags.push(s); });

    // doc.tags / doc.Tags / doc.categories — custom string labels (e.g. Bert-JanP)
    var labelTags = Array.isArray(doc.tags)       ? doc.tags
                  : Array.isArray(doc.Tags)       ? doc.Tags
                  : Array.isArray(doc.categories) ? doc.categories : [];
    labelTags.forEach(function(t) { var s = sanitizeStr(String(t), 50); if (s) tags.push(s); });

    tags = dedup(tags.concat(extractTechniqueTags(description + " " + kql)));

    // CVEs from description + KQL comments → merge into tags
    var cves = extractCVEs(description + " " + kql);
    tags = dedup(tags.concat(cves));

    // PICERL — inferred from MITRE tactics
    var picerl = picerlFromMitre(mitre);

    // Environment — requiredDataConnectors is authoritative; fall back to KQL content
    var environment;
    if (Array.isArray(doc.requiredDataConnectors) && doc.requiredDataConnectors.length > 0) {
      var connectors = doc.requiredDataConnectors.map(function(c) { return (c.connectorId || ""); });
      environment = connectors.some(function(c) { return c === "MicrosoftThreatProtection"; }) ? "Defender" : "Sentinel";
    } else {
      environment = detectEnvironment(kql, extras) || "Sentinel";
    }

    if (debug) {
      console.log("[REPO_PARSER] YAML file:", filePath);
      console.log("[REPO_PARSER]   Title:", title);
      console.log("[REPO_PARSER]   Desc (" + description.length + " chars):", description.slice(0, 80));
      console.log("[REPO_PARSER]   KQL:", kql.length, "chars");
      console.log("[REPO_PARSER]   MITRE:", mitre.join(", ") || "none");
      console.log("[REPO_PARSER]   Tags:", tags.join(", ") || "none");
      console.log("[REPO_PARSER]   CVEs:", cves.join(", ") || "none");
    }

    return { title, description, kql, mitre, picerl, tags, environment, severity: sev, language: "KQL" };
  } catch(e) {
    if (process.env.REPO_PARSER_DEBUG === 'true') console.error("[REPO_PARSER] YAML error:", filePath, e.message);
    return null;
  }
}

// ── Markdown noise-line detection ────────────────────────────────────────────

var NOISE_LINE_RES = [
  /^\*{0,2}\s*author\b/i,              // **Author:** or * Author:
  /\bBlu[\s-]?Raven\b/i,               // Blu Raven Academy promos
  /\bmedium\.com\b/i,                  // Medium blog links
  /twitter\.com\//i,                   // Twitter profile links
  /linkedin\.com\//i,                  // LinkedIn profile links
  /youtube\.com\//i,                   // YouTube channel links
  /^\|.*TA\d{4}.*\|/,                  // MITRE table rows
  /^\|\s*[-:]+\s*\|/,                  // markdown table separator rows
  /\|\s*tactic\s*\|/i,                 // table headers containing "Tactic"
  /^!\[/,                              // inline image tags
  /^\[!\[/,                            // badge/shield images
  /^\s*[-*]\s+https?:\/\//,            // bare URL list items
];

function isNoiseLine(line) {
  return NOISE_LINE_RES.some(function(re) { return re.test(line); });
}

// Extract hyperlinks from a Markdown file → [{url, note}]
// Covers: [text](url), bare list items "- https://...", and lone URLs on their own line.
function extractReferencesFromMd(content) {
  var refs = [];
  var seen = {};
  function addRef(url, note) {
    url = (url || "").trim().replace(/[.,;!?)]+$/, "");
    if (url.length > 10 && !seen[url]) {
      seen[url] = true;
      refs.push({ url: url, note: (note || "").trim() });
    }
  }
  var m;
  // [text](https://...) inline links
  var mdLink = /\[([^\]]*)\]\((https?:\/\/[^)\s]+)\)/g;
  while ((m = mdLink.exec(content)) !== null) addRef(m[2], m[1] !== m[2] ? m[1] : "");
  // - https://... or * https://... list items
  var listUrl = /^[ \t]*[-*][ \t]+(https?:\/\/[^\s\])\'"<>]+)/mg;
  while ((m = listUrl.exec(content)) !== null) addRef(m[1], "");
  // bare https://... on its own line
  var bareUrl = /^[ \t]*(https?:\/\/[^\s\])\'"<>]+)[ \t]*$/mg;
  while ((m = bareUrl.exec(content)) !== null) addRef(m[1], "");
  return refs;
}

// Priority heading names for description extraction
var DESC_HEADING_RE = /^(goal|description|detection|summary|overview|about|purpose|use[\s_-]*case|context)/i;

// Extract a clean description from Markdown.
// Tries priority sections (## Goal, ## Description, etc.) first,
// then falls back to the text immediately after the first heading.
function extractDescriptionFromMd(content) {
  var headingRe = /^(#{1,4})[ \t]+(.+)$/gm;
  var headings = [];
  var m;
  while ((m = headingRe.exec(content)) !== null) {
    headings.push({ index: m.index, end: m.index + m[0].length, title: m[2].trim() });
  }

  var candidateText = "";

  var priIdx = -1;
  for (var i = 0; i < headings.length; i++) {
    if (DESC_HEADING_RE.test(headings[i].title)) { priIdx = i; break; }
  }

  if (priIdx >= 0) {
    var start = headings[priIdx].end;
    var end = priIdx + 1 < headings.length ? headings[priIdx + 1].index : content.length;
    candidateText = content.slice(start, end).trim();
  } else if (headings.length > 0) {
    // Fallback: text right after the first heading (document title)
    var start = headings[0].end;
    var end = headings.length > 1 ? headings[1].index : content.length;
    candidateText = content.slice(start, end).trim();
  } else {
    candidateText = content.trim();
  }

  // Cut at first code block
  var cbIdx = candidateText.indexOf("```");
  if (cbIdx >= 0) candidateText = candidateText.slice(0, cbIdx).trim();

  var lines = candidateText.split("\n")
    .map(function(l) { return l.trim(); })
    .filter(function(l) { return l.length > 0 && !isNoiseLine(l); });

  return sanitizeStr(lines.join(" ").replace(/\s+/g, " "), 500);
}

// Get filtered description text from the section immediately above a code block.
function _descBetweenHeadingAndBlock(content, blockIndex) {
  var before = content.slice(0, blockIndex);
  var headingRe = /^#{1,4}[ \t]+.+$/gm;
  var lastEnd = 0;
  var m;
  while ((m = headingRe.exec(before)) !== null) lastEnd = m.index + m[0].length;

  var between = before.slice(lastEnd).trim();
  if (!between) return "";

  var lines = between.split("\n")
    .map(function(l) { return l.trim(); })
    .filter(function(l) { return l.length > 0 && !isNoiseLine(l); });

  return sanitizeStr(lines.join(" ").replace(/\s+/g, " "), 500);
}

// Extract MITRE tactic IDs from both TA00XX patterns and tactic name keywords.
function extractMitreEnhanced(text) {
  var ids = extractMitre(text); // TA00XX pattern scan
  var textLower = (text || "").toLowerCase();
  Object.keys(TACTIC_MAP).forEach(function(name) {
    if (/^TA\d{4}$/.test(name)) return; // already covered by extractMitre
    var id = TACTIC_MAP[name];
    if (!id || ids.indexOf(id) >= 0) return;
    var escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp("\\b" + escaped + "\\b", "i").test(textLower)) ids.push(id);
  });
  return dedup(ids);
}

// ── Parser: Markdown — supports multiple KQL blocks per file ──────────────────

// Find the best title to use for a KQL block at `blockIndex`.
// Prefers H1 when the immediately-preceding heading is a generic section label.
function _bestTitleBefore(content, blockIndex) {
  var before = content.slice(0, blockIndex);
  var re = /^(#{1,4})[ \t]+(.+)/gm;
  var m, h1 = null, lastLevel = 0, lastTitle = null;
  while ((m = re.exec(before)) !== null) {
    var level = m[1].length;
    var title = m[2].trim();
    if (level === 1 && !h1) h1 = title;
    lastLevel = level;
    lastTitle = title;
  }
  if (!lastTitle) return h1 || null;
  // If the last heading before the block is a generic section label (H2+), fall back to H1
  if (lastLevel > 1 && GENERIC_SECTION_RE.test(lastTitle) && h1) return h1;
  return lastTitle;
}

function parseMdFile(content, filePath, extras) {
  var debug = process.env.REPO_PARSER_DEBUG === 'true';
  try {
    var parts     = filePath.split("/");
    var fileName  = parts.pop();
    var folderSeg = parts.length ? sanitizeStr(parts[parts.length - 1], 50) : "";
    var fileSeg   = sanitizeStr(fileName.replace(/\.md$/i, "").replace(/[-_]/g, " "), 50);
    var baseName  = fileSeg || "Query";

    // Shared metadata from full document
    var mitre    = extractMitreEnhanced(content);
    var severity = detectSeverity(content);
    var picerl   = picerlFromMitre(mitre);

    // CVEs from full content (KQL comments included)
    var cves = extractCVEs(content);

    // Tags: T1xxx techniques + hashtags (#Learning) + folder segment + CVEs
    var baseTags = dedup(
      extractTechniqueTags(content)
        .concat(extractHashtags(content))
        .concat(cves)
        .concat(folderSeg ? [folderSeg] : [])
    );

    // File-level description — fallback when a block has no local text
    var fileDesc = extractDescriptionFromMd(content);
    var fileRefs = extractReferencesFromMd(content);

    var results = [];

    // Pass 1: named KQL/Kusto code fences (```kql, ```KQL, ```kusto, ```Kusto)
    var kqlRe = /```[ \t]*(?:kql|kusto)[ \t]*(?:\r?\n)([\s\S]*?)```/gi;
    var match;
    while ((match = kqlRe.exec(content)) !== null) {
      var kql = match[1].trim();
      if (kql.length < 20) continue;

      // Also scan the KQL block itself for additional CVEs (comments)
      var blockCves = extractCVEs(kql);
      if (blockCves.length) baseTags = dedup(baseTags.concat(blockCves));

      var heading = _bestTitleBefore(content, match.index);
      var blockTitle = sanitizeStr(heading || baseName, 200) || baseName;
      // Disambiguate duplicate titles
      if (results.some(function(r) { return r.title === blockTitle; })) {
        blockTitle = sanitizeStr(blockTitle + " " + (results.length + 1), 200);
      }

      // Description: text in the section above this block, or file-level fallback
      var blockDesc = _descBetweenHeadingAndBlock(content, match.index) || fileDesc;

      var environment = envFromPath(filePath);
      if (environment === "Both") environment = detectEnvironment(kql, extras) || "Both";

      if (debug) {
        console.log("[REPO_PARSER] MD kql-block:", filePath, "->", blockTitle, "(" + kql.length + " chars)");
        console.log("[REPO_PARSER]   Desc (" + blockDesc.length + " chars):", blockDesc.slice(0, 80));
        console.log("[REPO_PARSER]   MITRE:", mitre.join(", ") || "none");
        console.log("[REPO_PARSER]   Tags:", baseTags.join(", ") || "none");
        if (blockCves.length) console.log("[REPO_PARSER]   CVEs:", blockCves.join(", "));
      }
      var blockRefs = mergeRefs(fileRefs, extractReferencesFromKqlComments(kql));
      results.push({ title: blockTitle, description: blockDesc, kql, mitre, picerl, tags: baseTags, environment, severity, language: "KQL", references: blockRefs });
    }

    // Pass 2 (fallback): generic ``` fences whose content looks like KQL
    if (results.length === 0) {
      var genericRe = /```[ \t]*(?:\r?\n)([\s\S]*?)```/g;
      while ((match = genericRe.exec(content)) !== null) {
        var kql = match[1].trim();
        if (kql.length < 20) continue;
        // Heuristic: must have a pipe operator OR a known KQL keyword
        if (!/\|/.test(kql) && !/\b(where|project|summarize|extend|let|join)\b/i.test(kql)) continue;

        var blockCves = extractCVEs(kql);
        if (blockCves.length) baseTags = dedup(baseTags.concat(blockCves));

        var heading = _bestTitleBefore(content, match.index);
        var blockTitle = sanitizeStr(heading || baseName, 200) || baseName;
        if (results.some(function(r) { return r.title === blockTitle; })) {
          blockTitle = sanitizeStr(blockTitle + " " + (results.length + 1), 200);
        }

        var blockDesc = _descBetweenHeadingAndBlock(content, match.index) || fileDesc;

        var environment = envFromPath(filePath);
        if (environment === "Both") environment = detectEnvironment(kql, extras) || "Both";

        if (debug) console.log("[REPO_PARSER] MD generic-block:", filePath, "->", blockTitle, "(" + kql.length + " chars)");
        var blockRefs = mergeRefs(fileRefs, extractReferencesFromKqlComments(kql));
        results.push({ title: blockTitle, description: blockDesc, kql, mitre, picerl, tags: baseTags, environment, severity, language: "KQL", references: blockRefs });
      }
    }

    if (debug) console.log("[REPO_PARSER] parseMdFile:", filePath, "->", results.length, "queries");
    return results.length > 0 ? results : null;
  } catch(e) {
    if (process.env.REPO_PARSER_DEBUG === 'true') console.error("[REPO_PARSER] parseMdFile error:", filePath, e.message);
    return null;
  }
}

function mergeRefs(a, b) {
  var seen = {}, out = [];
  (a || []).concat(b || []).forEach(function(r) {
    if (!seen[r.url]) { seen[r.url] = true; out.push(r); }
  });
  return out;
}

// Extract URLs from KQL // comment lines → [{url, note}]
function extractReferencesFromKqlComments(kql) {
  var refs = [], seen = {};
  (kql || "").split("\n").forEach(function(line) {
    var t = line.trim();
    if (!t.startsWith("//")) return;
    var m = t.match(/https?:\/\/[^\s,;)'"<>]+/);
    if (!m) return;
    var url = m[0].replace(/[.,;!?)+]+$/, "");
    if (seen[url]) return;
    seen[url] = true;
    var note = t.replace(/^\/\/\s*/, "").replace(m[0], "").replace(/^[:\-–\s]+/, "").trim();
    refs.push({ url: url, note: note });
  });
  return refs;
}

// ── Parser: raw KQL (reprise99 format) ───────────────────────────────────────

function parseKqlFile(content, filePath, extras) {
  try {
    var kql = content.trim();
    if (kql.length < 20) return null;

    // Title from filename
    var parts    = filePath.split("/");
    var baseName = parts.pop().replace(/\.kql$/i, "");
    var title    = sanitizeStr(
      baseName.replace(/[-_]/g, " ").replace(/\b\w/g, function(c) { return c.toUpperCase(); }), 200
    );
    if (!title) return null;

    // Extract all comment lines for metadata scanning
    var commentLines = kql.split("\n").filter(function(l) { return l.trim().startsWith("//"); });
    var commentText  = commentLines.map(function(l) { return l.replace(/^\/\/\s*/, ""); }).join(" ");

    // Description: first non-CVE comment line content (if any)
    var descLine = commentLines.find(function(l) {
      var t = l.replace(/^\/\/\s*/, "").trim();
      return t.length > 5 && !/^CVE-/i.test(t);
    });
    var description = descLine ? sanitizeStr(descLine.replace(/^\/\/\s*/, ""), 500) : "";

    // Environment: path-based first, then KQL content as tiebreaker for 'Both'
    var environment = envFromPath(filePath);
    if (environment === "Both") environment = detectEnvironment(kql, extras) || "Both";

    // Severity — scan comment block
    var severity = detectSeverity(commentText);

    // MITRE — TA00XX in comments + query body
    var mitre = extractMitre(commentText + " " + kql);

    // CVEs from comment lines (e.g. // CVE-2019-3396 - Software update)
    var cves = extractCVEs(commentText);

    // Tags — T1xxx in comments + CVEs + folder name
    var folderSeg = parts.length ? sanitizeStr(parts[parts.length - 1], 50) : "";
    var tags = dedup(
      extractTechniqueTags(commentText + " " + kql)
        .concat(cves)
        .concat(folderSeg ? [folderSeg] : [])
    );

    // PICERL — inferred from MITRE
    var picerl = picerlFromMitre(mitre);

    var references = extractReferencesFromKqlComments(kql);

    return { title, description, kql, mitre, picerl, tags, environment, severity, language: "KQL", references };
  } catch(e) {
    return null;
  }
}

// ── Auto-detect format from file extension ────────────────────────────────────
// Always returns an array of parsed results, or null if nothing extracted.

function parseFile(content, filePath, extras) {
  var p = filePath.toLowerCase();
  if (p.endsWith(".yaml") || p.endsWith(".yml")) {
    var r = parseYamlFile(content, filePath, extras);
    return r ? [r] : null;
  }
  if (p.endsWith(".md")) {
    return parseMdFile(content, filePath, extras); // already returns array or null
  }
  if (p.endsWith(".kql")) {
    var r = parseKqlFile(content, filePath, extras);
    return r ? [r] : null;
  }
  return null;
}

// ── Main sync function ────────────────────────────────────────────────────────

async function syncRepo(repoSource, db, teamId) {
  var stats = { new: 0, updated: 0, skipped: 0, errors: 0, warnings: [], total_files: 0 };
  var extras = buildExtrasFromDb(db);

  var files;
  try {
    files = await listRepoFiles(
      repoSource.github_owner, repoSource.github_repo,
      repoSource.branch, repoSource.path_filter || "", repoSource.file_format
    );
  } catch(e) {
    stats.errors++;
    stats.warnings.push("Failed to list repo files: " + e.message);
    return stats;
  }

  // Cap at 500 files per sync
  if (files.length > 500) files = files.slice(0, 500);
  stats.total_files = files.length;

  var folderId  = repoSource.target_folder_id || null;
  var repoLabel = repoSource.github_owner + "/" + repoSource.github_repo;

  var debug = process.env.REPO_PARSER_DEBUG === 'true';

  for (var i = 0; i < files.length; i++) {
    // Rate limit: 200ms pause every 10 requests
    if (i > 0 && i % 10 === 0) await new Promise(function(r) { setTimeout(r, 200); });

    var file = files[i];
    try {
      // Check the primary map entry (file.path) for SHA — covers single-block and multi-block files
      var primaryExisting = db.prepare("SELECT * FROM repo_query_map WHERE repo_id = ? AND file_path = ?").get(repoSource.id, file.path);

      // Same SHA — skip entire file
      if (primaryExisting && primaryExisting.file_sha === file.sha) { stats.skipped++; continue; }

      // Changed SHA but locally modified — warn and skip
      if (primaryExisting && primaryExisting.local_modified === 1) {
        stats.skipped++;
        stats.warnings.push("Skipped (locally modified): " + file.path);
        continue;
      }

      // Fetch + parse
      var content = await fetchFileContent(repoSource.github_owner, repoSource.github_repo, file.path, repoSource.branch);
      var parsedArr = parseFile(content, file.path, extras);
      if (!parsedArr || parsedArr.length === 0) { stats.skipped++; continue; }

      if (debug) console.log("[REPO_PARSER] File", file.path, "->", parsedArr.length, "block(s)");

      var now = new Date().toISOString().slice(0, 10);

      for (var pi = 0; pi < parsedArr.length; pi++) {
        var parsed = parsedArr[pi];
        // Primary block uses file.path; additional blocks use file.path#N
        var mapKey = pi === 0 ? file.path : (file.path + "#" + pi);

        var existing = pi === 0
          ? primaryExisting
          : db.prepare("SELECT * FROM repo_query_map WHERE repo_id = ? AND file_path = ?").get(repoSource.id, mapKey);

        if (existing) {
          // UPDATE — includes picerl
          var qRow = db.prepare("SELECT versions FROM queries WHERE id = ?").get(existing.query_id);
          if (!qRow) { continue; }
          var currentVersions = JSON.parse(qRow.versions || "[]");
          var nextV = (currentVersions.length > 0 ? currentVersions[currentVersions.length - 1].v : 0) + 1;
          currentVersions.push({ v: nextV, date: now, author: repoLabel, note: "Auto-sync from GitHub" });

          db.prepare(
            "UPDATE queries SET title=?,description=?,kql=?,environment=?,severity=?,mitre=?,picerl=?,tags=?,versions=?,parsed_references=?,updated_at=datetime('now') WHERE id=?"
          ).run(
            parsed.title, parsed.description, parsed.kql, parsed.environment, parsed.severity,
            JSON.stringify(parsed.mitre), JSON.stringify(parsed.picerl), JSON.stringify(parsed.tags),
            JSON.stringify(currentVersions), JSON.stringify(parsed.references || []), existing.query_id
          );
          db.prepare("UPDATE repo_query_map SET file_sha=?,last_synced_at=datetime('now') WHERE repo_id=? AND file_path=?")
            .run(file.sha, repoSource.id, mapKey);
          stats.updated++;
        } else {
          // INSERT — deduplication by title + team
          var dup = db.prepare("SELECT id FROM queries WHERE title = ? AND team = ?").get(parsed.title, teamId);
          var queryId;
          if (dup) {
            queryId = dup.id;
          } else {
            queryId = "q_" + crypto.randomBytes(8).toString("hex");
            db.prepare(
              "INSERT INTO queries (id,title,description,kql,language,environment,severity,mitre,picerl,playbook,folder_id,tags,author_id,author_name,team,versions,parsed_references) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            ).run(
              queryId, parsed.title, parsed.description, parsed.kql, parsed.language,
              parsed.environment, parsed.severity,
              JSON.stringify(parsed.mitre), JSON.stringify(parsed.picerl), "Community",
              folderId, JSON.stringify(parsed.tags),
              null, repoLabel, teamId,
              JSON.stringify([{ v: 1, date: now, author: repoLabel, note: "Imported from GitHub" }]),
              JSON.stringify(parsed.references || [])
            );
            stats.new++;
          }
          db.prepare(
            "INSERT OR REPLACE INTO repo_query_map (repo_id,file_path,file_sha,query_id,local_modified,last_synced_at) VALUES(?,?,?,?,0,datetime('now'))"
          ).run(repoSource.id, mapKey, file.sha, queryId);
        }
      }
    } catch(e) {
      stats.errors++;
      stats.warnings.push("Error on " + file.path + ": " + e.message);
      if (debug) console.error("[REPO_PARSER] Error on", file.path, ":", e.message);
    }
  }

  return stats;
}

module.exports = { parseYamlFile, parseMdFile, parseKqlFile, syncRepo, fetchFileContent };
