const express = require("express");
const crypto  = require("crypto");
const { getDb, auditLog, getSetting }                        = require("../db/database");
const { requireAuth }                                        = require("../middleware/auth");
const { sanitize, requireWriter, requireAdmin, validateEnum, isValidHexColor } = require("../middleware/utils");
const { generatePDF, generateDOCX, generateHTML, safeFilename } = require("../lib/reportGenerator");

const router = express.Router();
router.use(requireAuth);

const STATUSES   = ["open", "in-progress", "closed"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const IOC_TYPES  = ["ip","domain","hash","url","email","filename","registry","process","useragent","cve","other"];
const EVENT_TYPES = ["finding","ioc_detected","lateral_movement","exfiltration","initial_access","custom"];

// Helper: fetch an investigation that belongs to the user's team.
function getTeamInvestigation(db, id, teamId) {
  return db.prepare("SELECT * FROM investigations WHERE id = ? AND team = ?").get(id, teamId);
}

// Helper: check if a report is locked for the given user.
function isLocked(inv, user) {
  return !!(inv.report_locked && user.role !== "admin");
}

// GET /api/investigations
router.get("/", function (req, res) {
  const rows = getDb().prepare(
    "SELECT * FROM investigations WHERE team = ? ORDER BY updated_at DESC"
  ).all(req.user.team);
  res.json(rows);
});

// POST /api/investigations
router.post("/", requireWriter, function (req, res) {
  const b     = req.body;
  const title = sanitize(b.title || "", 200);
  if (!title) return res.status(400).json({ error: "Title is required" });

  const db = getDb();
  const id = "inv_" + crypto.randomBytes(8).toString("hex");

  // Validate template_id if provided
  let templateId = null;
  if (b.template_id) {
    const tpl = db.prepare("SELECT id FROM report_templates WHERE id=?").get(b.template_id);
    if (tpl) templateId = tpl.id;
  }

  db.prepare(
    "INSERT INTO investigations (id,title,status,severity,team,analyst_id,analyst_name,description,template_id,client_name,mission_type) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
  ).run(
    id,
    title,
    validateEnum(b.status,   STATUSES,   "open"),
    validateEnum(b.severity, SEVERITIES, "medium"),
    req.user.team,
    req.user.id,
    req.user.display_name,
    (b.description || "").slice(0, 5000),
    templateId,
    sanitize(b.client_name || "", 200),
    b.mission_type || null
  );

  // If a template was chosen, copy its sections into investigation_section_content
  if (templateId) {
    const sections = db.prepare("SELECT * FROM template_sections WHERE template_id=? ORDER BY display_order ASC").all(templateId);
    const insContent = db.prepare("INSERT OR IGNORE INTO investigation_section_content (investigation_id,section_id,content) VALUES (?,?,?)");
    db.transaction(function() {
      sections.forEach(function(s) {
        insContent.run(id, s.id, s.default_content || "");
      });
    })();
  }

  auditLog(req.user.id, "INVESTIGATION_CREATE", "investigation", id, { title, templateId }, req.ip);
  res.json(db.prepare("SELECT * FROM investigations WHERE id = ?").get(id));
});

// GET /api/investigations/:id
router.get("/:id", function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });

  const iocs     = db.prepare("SELECT * FROM investigation_iocs WHERE investigation_id = ? ORDER BY created_at ASC").all(req.params.id);
  const findings = db.prepare(
    "SELECT * FROM investigation_findings WHERE investigation_id = ? ORDER BY display_order ASC, event_at ASC, created_at ASC"
  ).all(req.params.id);
  res.json(Object.assign({}, inv, { iocs, findings }));
});

// PUT /api/investigations/:id
router.put("/:id", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });

  // If locked, only admins can modify
  if (isLocked(inv, req.user)) {
    return res.status(403).json({ error: "Le rapport est verrouillé. Contactez un administrateur." });
  }

  const b = req.body;
  const newStatus = validateEnum(b.status, STATUSES, inv.status);

  // Auto-lock when closing
  let report_locked = inv.report_locked || 0;
  let locked_at     = inv.locked_at     || null;
  let locked_by     = inv.locked_by     || null;

  if (newStatus === "closed" && inv.status !== "closed") {
    report_locked = 1;
    locked_at     = Date.now();
    locked_by     = req.user.id;
  }
  // Admin reopening: auto-unlock
  if (newStatus !== "closed" && inv.status === "closed" && req.user.role === "admin") {
    report_locked = 0;
    locked_at     = null;
    locked_by     = null;
  }

  db.prepare(
    "UPDATE investigations SET title=?,status=?,severity=?,description=?,conclusion=?,report_locked=?,locked_at=?,locked_by=?,updated_at=datetime('now') WHERE id=?"
  ).run(
    sanitize(b.title || inv.title, 200),
    newStatus,
    validateEnum(b.severity, SEVERITIES, inv.severity),
    (b.description !== undefined ? b.description : inv.description || "").slice(0, 5000),
    (b.conclusion  !== undefined ? b.conclusion  : inv.conclusion  || "").slice(0, 10000),
    report_locked, locked_at, locked_by,
    req.params.id
  );

  auditLog(req.user.id, "INVESTIGATION_UPDATE", "investigation", req.params.id, { status: newStatus, report_locked }, req.ip);
  res.json({ ok: true, report_locked: !!report_locked });
});

// DELETE /api/investigations/:id
router.delete("/:id", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (inv.analyst_id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "Not authorized" });
  }

  db.prepare("DELETE FROM investigations WHERE id = ?").run(req.params.id);
  auditLog(req.user.id, "INVESTIGATION_DELETE", "investigation", req.params.id, { title: inv.title }, req.ip);
  res.json({ ok: true });
});

// POST /api/investigations/:id/unlock  (admin only)
router.post("/:id/unlock", requireAdmin, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });

  db.prepare(
    "UPDATE investigations SET report_locked=0, locked_at=NULL, locked_by=NULL, updated_at=datetime('now') WHERE id=?"
  ).run(req.params.id);

  auditLog(req.user.id, "INVESTIGATION_UNLOCKED", "investigation", req.params.id, null, req.ip);
  res.json({ ok: true });
});

// ── Report download ───────────────────────────────────────────────────────────

// GET /api/investigations/:id/report?format=pdf|docx
router.get("/:id/report", function (req, res) {
  const format = (req.query.format || "pdf").toLowerCase();
  if (format !== "pdf" && format !== "docx" && format !== "html") {
    return res.status(400).json({ error: "Invalid format. Use pdf, docx or html." });
  }

  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });

  const iocs     = db.prepare("SELECT * FROM investigation_iocs     WHERE investigation_id = ? ORDER BY created_at ASC").all(req.params.id);
  const findings = db.prepare(
    "SELECT * FROM investigation_findings WHERE investigation_id = ? ORDER BY display_order ASC, event_at ASC, created_at ASC"
  ).all(req.params.id);

  const settings = {
    company_name:        getSetting("company_name",        "KQL Vault"),
    company_subtitle:    getSetting("company_subtitle",    "Security Operations Center"),
    company_logo:        getSetting("company_logo",        ""),
    report_header_color: getSetting("report_header_color", "#e63946"),
  };
  const lang = getSetting("report_lang", "fr");

  const analyst = {
    display_name: inv.analyst_name || req.user.display_name || "Analyst",
    role:         req.user.role    || "SOC Analyst",
  };

  auditLog(req.user.id, "INVESTIGATION_REPORT_DOWNLOAD", "investigation", req.params.id, { format }, req.ip);

  const filename = `report_${safeFilename(inv.title)}.${format}`;

  if (format === "pdf") {
    generatePDF(inv, findings, iocs, analyst, settings, lang).then(function (buffer) {
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", buffer.length);
      res.end(buffer);
    }).catch(function (err) {
      console.error("PDF generation error:", err);
      if (!res.headersSent) res.status(500).json({ error: "Report generation failed" });
    });
  } else if (format === "docx") {
    generateDOCX(inv, findings, iocs, analyst, settings, lang).then(function (buffer) {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", buffer.length);
      res.end(buffer);
    }).catch(function (err) {
      console.error("DOCX generation error:", err);
      if (!res.headersSent) res.status(500).json({ error: "Report generation failed" });
    });
  } else {
    generateHTML(inv, findings, iocs, analyst, settings, lang).then(function (html) {
      const buf = Buffer.from(html, 'utf8');
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", buf.length);
      res.end(buf);
    }).catch(function (err) {
      console.error("HTML generation error:", err);
      if (!res.headersSent) res.status(500).json({ error: "Report generation failed" });
    });
  }
});

// ── IOCs ─────────────────────────────────────────────────────────────────────

// POST /api/investigations/:id/iocs
router.post("/:id/iocs", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const b     = req.body;
  const value = (b.value || "").trim();
  if (!value) return res.status(400).json({ error: "IoC value is required" });
  if (value.length > 500) return res.status(400).json({ error: "Value too long (max 500)" });
  if (!IOC_TYPES.includes(b.type)) return res.status(400).json({ error: "Invalid IoC type" });

  const id = "ioc_" + crypto.randomBytes(8).toString("hex");
  db.prepare(
    "INSERT INTO investigation_iocs (id,investigation_id,type,value,context,malicious,severity) VALUES (?,?,?,?,?,?,?)"
  ).run(id, req.params.id, b.type, value, (b.context || "").slice(0, 500), b.malicious ? 1 : 0, validateEnum(b.severity, SEVERITIES, "medium"));

  db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json(db.prepare("SELECT * FROM investigation_iocs WHERE id = ?").get(id));
});

// POST /api/investigations/:id/iocs/bulk — create multiple IoCs at once
router.post("/:id/iocs/bulk", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const items = req.body.items;
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: "items array required" });

  const insert = db.prepare(
    "INSERT INTO investigation_iocs (id,investigation_id,type,value,context,malicious,severity) VALUES (?,?,?,?,?,?,?)"
  );
  const created = [];
  db.transaction(function() {
    items.slice(0, 200).forEach(function(item) {
      const value = (item.value || "").trim();
      if (!value || value.length > 500) return;
      const type = IOC_TYPES.includes(item.type) ? item.type : "other";
      const id = "ioc_" + crypto.randomBytes(8).toString("hex");
      insert.run(id, req.params.id, type, value, (item.context || "").slice(0, 500), item.malicious ? 1 : 0, validateEnum(item.severity, SEVERITIES, "medium"));
      created.push({ id, type, value });
    });
  })();

  if (created.length) {
    db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  }
  res.json({ ok: true, created: created.length });
});

// DELETE /api/investigations/:id/iocs/bulk — delete multiple IoCs
router.delete("/:id/iocs/bulk", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const ids = req.body.ids;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: "ids array required" });

  const del = db.prepare("DELETE FROM investigation_iocs WHERE id=? AND investigation_id=?");
  db.transaction(function() {
    ids.forEach(function(id) { del.run(id, req.params.id); });
    db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  })();
  res.json({ ok: true });
});

// PUT /api/investigations/:id/iocs/:iocId — full edit (type, value, context/description, severity)
router.put("/:id/iocs/:iocId", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const ioc = db.prepare(
    "SELECT * FROM investigation_iocs WHERE id = ? AND investigation_id = ?"
  ).get(req.params.iocId, req.params.id);
  if (!ioc) return res.status(404).json({ error: "IoC not found" });

  const b = req.body;

  // Full edit mode: type, value, context (sent as "description" or "context"), severity
  if (b.type !== undefined || b.value !== undefined) {
    if (b.type && !IOC_TYPES.includes(b.type)) return res.status(400).json({ error: "Invalid IoC type" });
    const value = b.value !== undefined ? (b.value || "").trim().slice(0, 500) : ioc.value;
    if (!value) return res.status(400).json({ error: "IoC value is required" });

    const context  = b.description !== undefined ? sanitize(b.description || "", 500)
                   : b.context    !== undefined  ? sanitize(b.context    || "", 500)
                   : (ioc.context || "");
    const severity = validateEnum(b.severity, SEVERITIES, ioc.severity || "medium");
    const type     = b.type ? validateEnum(b.type, IOC_TYPES, ioc.type) : ioc.type;
    const malicious = b.malicious !== undefined ? (b.malicious ? 1 : 0) : ioc.malicious;

    db.prepare(
      "UPDATE investigation_iocs SET type=?,value=?,context=?,severity=?,malicious=?,updated_at=datetime('now') WHERE id=?"
    ).run(type, value, context, severity, malicious, req.params.iocId);
  } else {
    // Legacy toggle-only path
    db.prepare("UPDATE investigation_iocs SET malicious=?,context=?,updated_at=datetime('now') WHERE id=?").run(
      b.malicious ? 1 : 0,
      b.context !== undefined ? (b.context || "").slice(0, 500) : (ioc.context || ""),
      req.params.iocId
    );
  }

  res.json({ ok: true });
});

// DELETE /api/investigations/:id/iocs/:iocId
router.delete("/:id/iocs/:iocId", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const ioc = db.prepare(
    "SELECT id FROM investigation_iocs WHERE id = ? AND investigation_id = ?"
  ).get(req.params.iocId, req.params.id);
  if (!ioc) return res.status(404).json({ error: "IoC not found" });

  db.prepare("DELETE FROM investigation_iocs WHERE id = ?").run(req.params.iocId);
  db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// ── IoC Enrichment ────────────────────────────────────────────────────────────

// POST /api/investigations/:id/iocs/:iocId/enrich
router.post("/:id/iocs/:iocId/enrich", requireWriter, async function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const ioc = db.prepare(
    "SELECT * FROM investigation_iocs WHERE id = ? AND investigation_id = ?"
  ).get(req.params.iocId, req.params.id);
  if (!ioc) return res.status(404).json({ error: "IoC not found" });

  const vtKey = process.env.VT_API_KEY;
  const results = [];

  try {
    // ── VirusTotal ────────────────────────────────────────────────────────────
    if (vtKey) {
      let vtUrl;
      const t = ioc.type;
      const v = ioc.value;
      if (t === "hash")    vtUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(v)}`;
      else if (t === "ip") vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(v)}`;
      else if (t === "domain") vtUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(v)}`;
      else if (t === "url") {
        const id64 = Buffer.from(v).toString("base64").replace(/=/g, "");
        vtUrl = `https://www.virustotal.com/api/v3/urls/${id64}`;
      }
      if (vtUrl) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 8000);
        try {
          const vtRes = await fetch(vtUrl, {
            headers: { "x-apikey": vtKey },
            signal: ctrl.signal
          });
          clearTimeout(timer);
          if (vtRes.ok) {
            const vt = await vtRes.json();
            const stats = (vt.data && vt.data.attributes && vt.data.attributes.last_analysis_stats) || {};
            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const total = Object.values(stats).reduce((a, b) => a + b, 0);
            const names = (vt.data && vt.data.attributes && vt.data.attributes.meaningful_name) || null;
            results.push({
              source: "VirusTotal",
              verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean",
              malicious, suspicious, total,
              names: names ? [names] : [],
              link: `https://www.virustotal.com/gui/search/${encodeURIComponent(ioc.value)}`
            });
          } else if (vtRes.status === 404) {
            results.push({ source: "VirusTotal", verdict: "not_found", total: 0, malicious: 0 });
          }
        } catch(e) {
          clearTimeout(timer);
          results.push({ source: "VirusTotal", verdict: "error", error: e.message });
        }
      }
    }

    // ── abuse.ch MalwareBazaar (hashes) ──────────────────────────────────────
    if (ioc.type === "hash") {
      const ctrl2 = new AbortController();
      const timer2 = setTimeout(() => ctrl2.abort(), 8000);
      try {
        const bzRes = await fetch("https://mb-api.abuse.ch/api/v1/", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `query=get_info&hash=${encodeURIComponent(ioc.value)}`,
          signal: ctrl2.signal
        });
        clearTimeout(timer2);
        if (bzRes.ok) {
          const bz = await bzRes.json();
          if (bz.query_status === "ok" && bz.data && bz.data.length) {
            const entry = bz.data[0];
            results.push({
              source: "MalwareBazaar",
              verdict: "malicious",
              malware_family: entry.tags ? entry.tags.join(", ") : (entry.signature || "unknown"),
              first_seen: entry.first_seen || null,
              file_type: entry.file_type || null,
              link: `https://bazaar.abuse.ch/sample/${ioc.value}/`
            });
          } else {
            results.push({ source: "MalwareBazaar", verdict: "not_found" });
          }
        }
      } catch(e) {
        clearTimeout(timer2);
      }
    }

    // ── abuse.ch ThreatFox (IPs and domains) ─────────────────────────────────
    if (ioc.type === "ip" || ioc.type === "domain") {
      const ctrl3 = new AbortController();
      const timer3 = setTimeout(() => ctrl3.abort(), 8000);
      try {
        const tfRes = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: "search_ioc", search_term: ioc.value }),
          signal: ctrl3.signal
        });
        clearTimeout(timer3);
        if (tfRes.ok) {
          const tf = await tfRes.json();
          if (tf.query_status === "ok" && tf.data && tf.data.length) {
            const entry = tf.data[0];
            results.push({
              source: "ThreatFox",
              verdict: "malicious",
              threat_type: entry.threat_type || null,
              malware: entry.malware || null,
              confidence: entry.confidence_level || null,
              first_seen: entry.first_seen || null,
              link: `https://threatfox.abuse.ch/ioc/${entry.id}/`
            });
          } else {
            results.push({ source: "ThreatFox", verdict: "not_found" });
          }
        }
      } catch(e) {
        clearTimeout(timer3);
      }
    }

    if (!results.length) {
      return res.json({ ok: false, error: vtKey ? "No results from threat intelligence sources" : "VT_API_KEY not configured. Set it in .env to enable enrichment.", results: [] });
    }

    // Determine overall verdict
    const isMalicious = results.some(function(r) { return r.verdict === "malicious"; });
    const isSuspicious = !isMalicious && results.some(function(r) { return r.verdict === "suspicious"; });

    const verdict = isMalicious ? "malicious" : isSuspicious ? "suspicious" : "clean";
    const enrichResult = JSON.stringify({ verdict, results, date: Date.now() });

    // Persist enrichment result and update malicious flag
    db.prepare(
      "UPDATE investigation_iocs SET enrich_result=?, enriched_at=?, malicious=?, updated_at=datetime('now') WHERE id=?"
    ).run(enrichResult, Date.now(), isMalicious ? 1 : ioc.malicious, ioc.id);

    auditLog(req.user.id, "IOC_ENRICH", "investigation", req.params.id, { ioc_id: ioc.id, type: ioc.type, verdict }, req.ip);
    res.json({ ok: true, verdict, results, enrich_result: enrichResult });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Findings ─────────────────────────────────────────────────────────────────

// POST /api/investigations/:id/findings
router.post("/:id/findings", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const title = sanitize(req.body.title || "", 200);
  if (!title) return res.status(400).json({ error: "Title is required" });

  // Get next display_order
  const maxOrder = db.prepare(
    "SELECT MAX(display_order) as m FROM investigation_findings WHERE investigation_id = ?"
  ).get(req.params.id);
  const nextOrder = (maxOrder && maxOrder.m !== null) ? maxOrder.m + 1 : 0;

  const id = "fnd_" + crypto.randomBytes(8).toString("hex");
  db.prepare(
    "INSERT INTO investigation_findings (id,investigation_id,title,content,severity,event_at,display_order,event_type,code_blocks,screenshots,color,linked_ioc_ids) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  ).run(
    id,
    req.params.id,
    title,
    (req.body.description || req.body.content || "").slice(0, 10000),
    validateEnum(req.body.severity, SEVERITIES, "medium"),
    req.body.event_at    || null,
    nextOrder,
    req.body.event_type  ? validateEnum(req.body.event_type, EVENT_TYPES, "finding") : "finding",
    JSON.stringify(Array.isArray(req.body.code_blocks) ? req.body.code_blocks : []),
    JSON.stringify(Array.isArray(req.body.screenshots)  ? req.body.screenshots  : []),
    req.body.color || "default",
    JSON.stringify(Array.isArray(req.body.linked_ioc_ids) ? req.body.linked_ioc_ids : [])
  );

  db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json(db.prepare("SELECT * FROM investigation_findings WHERE id = ?").get(id));
});

// PUT /api/investigations/:id/findings/reorder  — MUST be before /:findingId
router.put("/:id/findings/reorder", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const order = req.body.order;
  if (!Array.isArray(order)) return res.status(400).json({ error: "order array required" });

  const stmt = db.prepare(
    "UPDATE investigation_findings SET display_order=? WHERE id=? AND investigation_id=?"
  );
  const txn = db.transaction(function () {
    order.forEach(function (item) {
      stmt.run(item.display_order, item.id, req.params.id);
    });
  });
  txn();
  res.json({ ok: true });
});

// PUT /api/investigations/:id/findings/:findingId
router.put("/:id/findings/:findingId", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const f = db.prepare(
    "SELECT * FROM investigation_findings WHERE id = ? AND investigation_id = ?"
  ).get(req.params.findingId, req.params.id);
  if (!f) return res.status(404).json({ error: "Finding not found" });

  const b = req.body;
  db.prepare(
    "UPDATE investigation_findings SET title=?,content=?,severity=?,event_at=?,display_order=?,event_type=?,code_blocks=?,screenshots=?,color=?,linked_ioc_ids=?,updated_at=datetime('now') WHERE id=?"
  ).run(
    sanitize(b.title || f.title, 200),
    (b.description !== undefined ? b.description : b.content !== undefined ? b.content : f.content || "").slice(0, 10000),
    validateEnum(b.severity, SEVERITIES, f.severity),
    b.event_at    !== undefined ? (b.event_at || null)    : f.event_at,
    b.display_order !== undefined ? b.display_order        : f.display_order,
    b.event_type  ? validateEnum(b.event_type, EVENT_TYPES, f.event_type || "finding") : (f.event_type || "finding"),
    b.code_blocks  !== undefined ? JSON.stringify(Array.isArray(b.code_blocks)  ? b.code_blocks  : []) : (f.code_blocks  || "[]"),
    b.screenshots  !== undefined ? JSON.stringify(Array.isArray(b.screenshots)  ? b.screenshots  : []) : (f.screenshots  || "[]"),
    b.color        !== undefined ? (b.color || "default")  : (f.color || "default"),
    b.linked_ioc_ids !== undefined ? JSON.stringify(Array.isArray(b.linked_ioc_ids) ? b.linked_ioc_ids : []) : (f.linked_ioc_ids || "[]"),
    req.params.findingId
  );

  db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// DELETE /api/investigations/:id/findings/:findingId
router.delete("/:id/findings/:findingId", requireWriter, function (req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const f = db.prepare(
    "SELECT id FROM investigation_findings WHERE id = ? AND investigation_id = ?"
  ).get(req.params.findingId, req.params.id);
  if (!f) return res.status(404).json({ error: "Finding not found" });

  db.prepare("DELETE FROM investigation_findings WHERE id = ?").run(req.params.findingId);
  db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// ── Template sections content ─────────────────────────────────────────────────

// GET /api/investigations/:id/sections
router.get("/:id/sections", function(req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (!inv.template_id) return res.json([]);

  const sections = db.prepare(
    "SELECT ts.*, isc.content FROM template_sections ts " +
    "LEFT JOIN investigation_section_content isc ON isc.section_id=ts.id AND isc.investigation_id=? " +
    "WHERE ts.template_id=? ORDER BY ts.display_order ASC"
  ).all(req.params.id, inv.template_id);

  res.json(sections.map(function(s) { return Object.assign({}, s, { content: s.content || "" }); }));
});

// PUT /api/investigations/:id/sections/:sid
router.put("/:id/sections/:sid", requireWriter, function(req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  // Verify section belongs to this investigation's template
  const sec = db.prepare(
    "SELECT id FROM template_sections WHERE id=? AND template_id=?"
  ).get(req.params.sid, inv.template_id);
  if (!sec) return res.status(404).json({ error: "Section not found" });

  const content = (req.body.content !== undefined ? req.body.content : "").slice(0, 50000);
  db.prepare(
    "INSERT INTO investigation_section_content (investigation_id,section_id,content,updated_at) VALUES (?,?,?,unixepoch()*1000) " +
    "ON CONFLICT(investigation_id,section_id) DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at"
  ).run(req.params.id, req.params.sid, content);

  db.prepare("UPDATE investigations SET updated_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// PUT /api/investigations/:id/branding
router.put("/:id/branding", requireWriter, function(req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });
  if (isLocked(inv, req.user)) return res.status(403).json({ error: "Le rapport est verrouillé." });

  const b = req.body;
  const updates = [];
  const params  = [];

  if (b.client_name  !== undefined) { updates.push("client_name=?");  params.push(sanitize(b.client_name  || "", 200)); }
  if (b.client_color !== undefined) { updates.push("client_color=?"); params.push(isValidHexColor(b.client_color) ? b.client_color : null); }
  if (b.client_logo  !== undefined) {
    // Accept null/empty to clear logo, or a base64 data URL
    const logo = b.client_logo || null;
    if (logo && !logo.startsWith("data:image/")) return res.status(400).json({ error: "Invalid logo format" });
    if (logo && logo.length > 2 * 1024 * 1024) return res.status(413).json({ error: "Logo too large" });
    updates.push("client_logo=?"); params.push(logo);
  }
  if (b.mission_type   !== undefined) { updates.push("mission_type=?");   params.push(b.mission_type || null); }
  if (b.pentest_scope  !== undefined) { updates.push("pentest_scope=?");   params.push((b.pentest_scope || "").slice(0, 5000)); }
  if (b.cvss_score     !== undefined) { updates.push("cvss_score=?");      params.push(parseFloat(b.cvss_score) || null); }
  if (b.risk_rating    !== undefined) { updates.push("risk_rating=?");     params.push(["critical","high","medium","low","info"].includes(b.risk_rating) ? b.risk_rating : null); }

  if (!updates.length) return res.json({ ok: true });
  updates.push("updated_at=datetime('now')");
  params.push(req.params.id);
  db.prepare("UPDATE investigations SET " + updates.join(",") + " WHERE id=?").run(...params);
  res.json({ ok: true });
});

// GET /api/investigations/:id/completeness
router.get("/:id/completeness", function(req, res) {
  const db  = getDb();
  const inv = getTeamInvestigation(db, req.params.id, req.user.team);
  if (!inv) return res.status(404).json({ error: "Investigation not found" });

  if (!inv.template_id) {
    // Classic completeness (no template)
    const iocCount     = db.prepare("SELECT COUNT(*) as c FROM investigation_iocs WHERE investigation_id=?").get(req.params.id).c;
    const findingCount = db.prepare("SELECT COUNT(*) as c FROM investigation_findings WHERE investigation_id=?").get(req.params.id).c;
    const checks = [
      { label: "Description",  done: !!(inv.description && inv.description.trim()) },
      { label: "IoCs",         done: iocCount > 0 },
      { label: "Findings",     done: findingCount > 0 },
      { label: "Conclusion",   done: !!(inv.conclusion && inv.conclusion.trim()) },
    ];
    const done = checks.filter(function(c) { return c.done; }).length;
    return res.json({ pct: Math.round(done / checks.length * 100), checks });
  }

  const sections = db.prepare(
    "SELECT ts.id, ts.name, ts.type, ts.required, isc.content FROM template_sections ts " +
    "LEFT JOIN investigation_section_content isc ON isc.section_id=ts.id AND isc.investigation_id=? " +
    "WHERE ts.template_id=? ORDER BY ts.display_order ASC"
  ).all(req.params.id, inv.template_id);

  const iocCount     = db.prepare("SELECT COUNT(*) as c FROM investigation_iocs WHERE investigation_id=?").get(req.params.id).c;
  const findingCount = db.prepare("SELECT COUNT(*) as c FROM investigation_findings WHERE investigation_id=?").get(req.params.id).c;

  const checks = sections.map(function(s) {
    let done = false;
    if (s.type === "iocs")     done = iocCount > 0;
    else if (s.type === "findings" || s.type === "timeline") done = findingCount > 0;
    else done = !!(s.content && s.content.trim());
    return { label: s.name, type: s.type, required: !!s.required, done };
  });

  const total = checks.length || 1;
  const done  = checks.filter(function(c) { return c.done; }).length;
  res.json({ pct: Math.round(done / total * 100), checks });
});

module.exports = router;
