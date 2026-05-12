'use strict';
const express      = require('express');
const router       = express.Router();
const { getDb }    = require('../db/database');
const { requireAuth }                    = require('../middleware/auth');
const { sanitize, requireAdmin }         = require('../middleware/utils');

router.use(requireAuth);

// GET /api/settings/report — lecture des paramètres rapport (tous utilisateurs authentifiés)
router.get('/report', function (req, res) {
  try {
    const db   = getDb();
    const keys = ['company_logo', 'company_name', 'company_subtitle', 'report_header_color', 'report_lang'];
    const out  = {};
    keys.forEach(function (k) {
      const row = db.prepare('SELECT value FROM settings WHERE key=?').get(k);
      out[k] = row ? row.value : null;
    });
    res.json(out);
  } catch (err) {
    console.error('[Settings] GET /report error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// PUT /api/settings/report — sauvegarde des paramètres rapport (admin uniquement)
router.put('/report', requireAdmin, function (req, res) {
  try {
    const { company_name, company_subtitle, report_header_color, company_logo, report_lang } = req.body;

    if (company_logo !== undefined && company_logo !== null && company_logo !== '') {
      if (typeof company_logo !== 'string' || !company_logo.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Le logo doit être une image (data URL)' });
      }
      if (company_logo.length > 700000) {
        return res.status(400).json({ error: 'Logo trop grand — max 500 KB' });
      }
    }

    const db   = getDb();
    const stmt = db.prepare(
      'INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime(\'now\')'
    );
    const txn = db.transaction(function () {
      if (company_name        !== undefined) stmt.run('company_name',        sanitize(company_name    || '', 200));
      if (company_subtitle    !== undefined) stmt.run('company_subtitle',    sanitize(company_subtitle || '', 200));
      if (report_header_color !== undefined) stmt.run('report_header_color', report_header_color || '#e63946');
      if (company_logo        !== undefined) stmt.run('company_logo',        company_logo        || '');
      if (report_lang         !== undefined) stmt.run('report_lang',         ['fr','en'].includes(report_lang) ? report_lang : 'fr');
    });
    txn();

    res.json({ ok: true });
  } catch (err) {
    console.error('[Settings] PUT /report error:', err);
    res.status(500).json({ error: 'Erreur serveur lors de la sauvegarde' });
  }
});

// DELETE /api/settings/report/logo — suppression du logo uniquement (admin)
router.delete('/report/logo', requireAdmin, function (req, res) {
  try {
    const db = getDb();
    db.prepare(
      "INSERT INTO settings (key, value) VALUES ('company_logo','') ON CONFLICT(key) DO UPDATE SET value='', updated_at=datetime('now')"
    ).run();
    res.json({ ok: true });
  } catch (err) {
    console.error('[Settings] DELETE /report/logo error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
