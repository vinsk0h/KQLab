'use strict';
const express  = require('express');
const { getDb, auditLog }                               = require('../db/database');
const { requireAuth }                                   = require('../middleware/auth');
const { sanitize, requireAdmin, isValidHexColor }       = require('../middleware/utils');

const router = express.Router();
router.use(requireAuth);

const SECTION_TYPES = ['richtext','findings','iocs','cvss','checklist','timeline','recommendation','custom'];
const MISSION_TYPES = ['blueteam','redteam','vapt','phishing','audit','custom'];

// ── GET /api/templates ────────────────────────────────────────────────────────
router.get('/', function(req, res) {
  const db = getDb();
  const rows = db.prepare('SELECT * FROM report_templates ORDER BY is_default DESC, name ASC').all();
  res.json(rows);
});

// ── POST /api/templates (admin) ───────────────────────────────────────────────
router.post('/', requireAdmin, function(req, res) {
  const b  = req.body;
  const db = getDb();
  const name = sanitize(b.name || '', 120);
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const slug = (b.slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60)) || 'custom-' + Date.now();
  const existing = db.prepare('SELECT id FROM report_templates WHERE slug=?').get(slug);
  if (existing) return res.status(409).json({ error: 'Slug already exists' });

  const color = isValidHexColor(b.color) ? b.color : '#e63946';
  const result = db.prepare(
    'INSERT INTO report_templates (name,slug,type,description,icon,color,company_name,company_subtitle,header_color,is_default) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).run(
    name,
    slug,
    MISSION_TYPES.includes(b.type) ? b.type : 'custom',
    sanitize(b.description || '', 500),
    sanitize(b.icon || '📋', 8),
    color,
    sanitize(b.company_name || '', 120),
    sanitize(b.company_subtitle || '', 120),
    isValidHexColor(b.header_color) ? b.header_color : '#0d1117',
    b.is_default ? 1 : 0
  );
  const tpl = db.prepare('SELECT * FROM report_templates WHERE id=?').get(result.lastInsertRowid);
  auditLog(req.user.id, 'TEMPLATE_CREATE', 'report_template', String(tpl.id), { name }, req.ip);
  res.json(tpl);
});

// ── PUT /api/templates/:id (admin) ────────────────────────────────────────────
router.put('/:id', requireAdmin, function(req, res) {
  const db  = getDb();
  const tpl = db.prepare('SELECT * FROM report_templates WHERE id=?').get(req.params.id);
  if (!tpl) return res.status(404).json({ error: 'Template not found' });

  const b = req.body;
  db.prepare(
    'UPDATE report_templates SET name=?,type=?,description=?,icon=?,color=?,company_name=?,company_subtitle=?,header_color=?,is_default=?,updated_at=(unixepoch()*1000) WHERE id=?'
  ).run(
    sanitize(b.name || tpl.name, 120),
    MISSION_TYPES.includes(b.type) ? b.type : tpl.type,
    sanitize(b.description !== undefined ? b.description : (tpl.description || ''), 500),
    sanitize(b.icon || tpl.icon, 8),
    isValidHexColor(b.color) ? b.color : tpl.color,
    sanitize(b.company_name !== undefined ? b.company_name : (tpl.company_name || ''), 120),
    sanitize(b.company_subtitle !== undefined ? b.company_subtitle : (tpl.company_subtitle || ''), 120),
    isValidHexColor(b.header_color) ? b.header_color : (tpl.header_color || '#0d1117'),
    b.is_default !== undefined ? (b.is_default ? 1 : 0) : tpl.is_default,
    req.params.id
  );
  auditLog(req.user.id, 'TEMPLATE_UPDATE', 'report_template', req.params.id, { name: b.name }, req.ip);
  res.json({ ok: true });
});

// ── DELETE /api/templates/:id (admin) ─────────────────────────────────────────
router.delete('/:id', requireAdmin, function(req, res) {
  const db  = getDb();
  const tpl = db.prepare('SELECT * FROM report_templates WHERE id=?').get(req.params.id);
  if (!tpl) return res.status(404).json({ error: 'Template not found' });

  const used = db.prepare('SELECT COUNT(*) as c FROM investigations WHERE template_id=?').get(req.params.id);
  if (used && used.c > 0) return res.status(409).json({ error: 'Template is in use by ' + used.c + ' investigation(s)' });

  db.prepare('DELETE FROM report_templates WHERE id=?').run(req.params.id);
  auditLog(req.user.id, 'TEMPLATE_DELETE', 'report_template', req.params.id, { name: tpl.name }, req.ip);
  res.json({ ok: true });
});

// ── POST /api/templates/:id/duplicate (admin) ─────────────────────────────────
router.post('/:id/duplicate', requireAdmin, function(req, res) {
  const db  = getDb();
  const tpl = db.prepare('SELECT * FROM report_templates WHERE id=?').get(req.params.id);
  if (!tpl) return res.status(404).json({ error: 'Template not found' });

  const newSlug = tpl.slug + '-copy-' + Date.now().toString(36);
  const result = db.prepare(
    'INSERT INTO report_templates (name,slug,type,description,icon,color,company_name,company_subtitle,header_color,is_default) VALUES (?,?,?,?,?,?,?,?,?,0)'
  ).run(
    tpl.name + ' (copie)',
    newSlug,
    tpl.type, tpl.description, tpl.icon, tpl.color,
    tpl.company_name, tpl.company_subtitle, tpl.header_color
  );
  const newId = result.lastInsertRowid;

  // Copy sections
  const sections = db.prepare('SELECT * FROM template_sections WHERE template_id=? ORDER BY display_order ASC').all(req.params.id);
  const secStmt  = db.prepare('INSERT INTO template_sections (template_id,name,slug,type,display_order,required,placeholder,default_content,icon) VALUES (?,?,?,?,?,?,?,?,?)');
  db.transaction(function() {
    sections.forEach(function(s) {
      secStmt.run(newId, s.name, s.slug, s.type, s.display_order, s.required, s.placeholder, s.default_content, s.icon);
    });
  })();

  auditLog(req.user.id, 'TEMPLATE_DUPLICATE', 'report_template', String(newId), { source: req.params.id }, req.ip);
  res.json(db.prepare('SELECT * FROM report_templates WHERE id=?').get(newId));
});

// ── GET /api/templates/:id/sections ──────────────────────────────────────────
router.get('/:id/sections', function(req, res) {
  const db  = getDb();
  const tpl = db.prepare('SELECT id FROM report_templates WHERE id=?').get(req.params.id);
  if (!tpl) return res.status(404).json({ error: 'Template not found' });
  const sections = db.prepare('SELECT * FROM template_sections WHERE template_id=? ORDER BY display_order ASC').all(req.params.id);
  res.json(sections);
});

// ── POST /api/templates/:id/sections (admin) ──────────────────────────────────
router.post('/:id/sections', requireAdmin, function(req, res) {
  const db  = getDb();
  const tpl = db.prepare('SELECT id FROM report_templates WHERE id=?').get(req.params.id);
  if (!tpl) return res.status(404).json({ error: 'Template not found' });

  const b    = req.body;
  const name = sanitize(b.name || '', 120);
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const maxOrder = db.prepare('SELECT MAX(display_order) as m FROM template_sections WHERE template_id=?').get(req.params.id);
  const nextOrder = (maxOrder && maxOrder.m !== null) ? maxOrder.m + 1 : 0;

  const result = db.prepare(
    'INSERT INTO template_sections (template_id,name,slug,type,display_order,required,placeholder,default_content,icon) VALUES (?,?,?,?,?,?,?,?,?)'
  ).run(
    parseInt(req.params.id),
    name,
    sanitize(b.slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60), 60),
    SECTION_TYPES.includes(b.type) ? b.type : 'richtext',
    nextOrder,
    b.required ? 1 : 0,
    sanitize(b.placeholder || '', 500),
    b.default_content || '',
    sanitize(b.icon || '📝', 8)
  );
  res.json(db.prepare('SELECT * FROM template_sections WHERE id=?').get(result.lastInsertRowid));
});

// ── PUT /api/templates/:id/sections/reorder (admin) — MUST be before /:sid ───
router.put('/:id/sections/reorder', requireAdmin, function(req, res) {
  const db    = getDb();
  const order = req.body.order;
  if (!Array.isArray(order)) return res.status(400).json({ error: 'order array required' });

  const stmt = db.prepare('UPDATE template_sections SET display_order=? WHERE id=? AND template_id=?');
  db.transaction(function() {
    order.forEach(function(item) { stmt.run(item.display_order, item.id, req.params.id); });
  })();
  res.json({ ok: true });
});

// ── PUT /api/templates/:id/sections/:sid (admin) ──────────────────────────────
router.put('/:id/sections/:sid', requireAdmin, function(req, res) {
  const db  = getDb();
  const sec = db.prepare('SELECT * FROM template_sections WHERE id=? AND template_id=?').get(req.params.sid, req.params.id);
  if (!sec) return res.status(404).json({ error: 'Section not found' });

  const b = req.body;
  db.prepare(
    'UPDATE template_sections SET name=?,type=?,display_order=?,required=?,placeholder=?,default_content=?,icon=? WHERE id=?'
  ).run(
    sanitize(b.name || sec.name, 120),
    SECTION_TYPES.includes(b.type) ? b.type : sec.type,
    b.display_order !== undefined ? b.display_order : sec.display_order,
    b.required !== undefined ? (b.required ? 1 : 0) : sec.required,
    sanitize(b.placeholder !== undefined ? b.placeholder : (sec.placeholder || ''), 500),
    b.default_content !== undefined ? b.default_content : (sec.default_content || ''),
    sanitize(b.icon || sec.icon, 8),
    req.params.sid
  );
  res.json({ ok: true });
});

// ── DELETE /api/templates/:id/sections/:sid (admin) ───────────────────────────
router.delete('/:id/sections/:sid', requireAdmin, function(req, res) {
  const db  = getDb();
  const sec = db.prepare('SELECT id FROM template_sections WHERE id=? AND template_id=?').get(req.params.sid, req.params.id);
  if (!sec) return res.status(404).json({ error: 'Section not found' });
  db.prepare('DELETE FROM template_sections WHERE id=?').run(req.params.sid);
  res.json({ ok: true });
});

module.exports = router;
