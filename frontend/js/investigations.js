// investigations.js — KQL Vault Investigations module

// ─── State ────────────────────────────────────────────────────
var I = {
  user: null, list: [], cur: null,
  statusFilter: 'all', searchQuery: '',
  templates: [], sections: [],
  iocSort: { col: 'none', dir: 'asc' },
  iocFilterType: 'all', iocFilterVerdict: 'all',
  selectedIocs: []
};
var _reportSettings = {};   // paramètres du rapport (logo, couleurs, nom entreprise)
var _pendingLogo;           // undefined = pas de changement, '' = supprimé, 'data:...' = nouveau
var _pendingClientLogo;     // logo client de l'investigation
var _saveDebounce = null;   // debounce timer for inline header auto-save
var _activeSecId  = null;   // active tab section ID

// ─── Modal state (finding & IoC edit) ────────────────────────────────────────
var _ms = { invId: null, findingId: null, iocId: null };
// ─── Drag & drop state ───────────────────────────────────────────────────────
var _dragSrc = null;

// ─── Constants ───────────────────────────────────────────────
var IOC = {
  ip:        { l: 'IP Address',   c: '#3b82f6' },
  domain:    { l: 'Domain',       c: '#f97316' },
  hash:      { l: 'File Hash',    c: '#6b7280' },
  url:       { l: 'URL',          c: '#a855f7' },
  email:     { l: 'Email',        c: '#ec4899' },
  filename:  { l: 'Filename',     c: '#eab308' },
  registry:  { l: 'Registry Key', c: '#14b8a6' },
  process:   { l: 'Process',      c: '#22c55e' },
  useragent: { l: 'User-Agent',   c: '#6366f1' },
  cve:       { l: 'CVE',          c: '#ef4444' },
  other:     { l: 'Other',        c: '#9ca3af' }
};
var SEV_C = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6' };
var SEV_E = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' };

// ─── SVG icon strings (14px) ──────────────────────────────────
var I_EYE      = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
var I_DL       = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
var I_LOCK     = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
var I_UNLOCK   = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>';
var I_TRASH    = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>';
var I_PLUS     = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>';
var I_EDIT     = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
var I_X        = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
var I_SHIELD   = '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
var I_SEARCH   = '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
var I_CODE     = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
var I_IMG      = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';

// ─── Section type → human label ───────────────────────────────
var SECTION_TYPE_LABEL = {
  classic_summary:    'Summary',
  classic_conclusion: 'Conclusion',
  richtext:           'Rich Text',
  custom:             'Custom',
  timeline:           'Timeline',
  findings:           'Timeline',
  iocs:               'IoCs',
  report_preview:     'Report',
  cvss:               'CVSS',
  checklist:          'Checklist',
  recommendation:     'Actions'
};

var STS = {
  open:          { l: 'Open',        c: '#3b82f6' },
  'in-progress': { l: 'In Progress', c: '#f97316' },
  closed:        { l: 'Closed',      c: '#22c55e' }
};

// ─── Helpers ─────────────────────────────────────────────────
function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function elOn(id, fn) { var e = document.getElementById(id); if (e) e.addEventListener('click', fn); }
function val(id) { var e = document.getElementById(id); return e ? e.value : ''; }
function showToast(msg, err) {
  var t = document.getElementById('toast-el');
  if (t) t.innerHTML = '<div class="toast" style="' + (err ? 'background:#450a0a;border-color:#7f1d1d;color:#fca5a5' : '') + '">' + esc(msg) + '</div>';
  setTimeout(function () { var t = document.getElementById('toast-el'); if (t) t.innerHTML = ''; }, 3000);
}
function sevBadge(s) {
  var c = SEV_C[s] || 'var(--t4)';
  return '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:' + c + '20;color:' + c + ';border:1px solid ' + c + '30">' + esc(s) + '</span>';
}
function invStatusLabel(s) {
  var k = s === 'in-progress' ? 'inprogress' : (s || 'open');
  return T('inv.status.' + k) || (STS[s] || { l: s }).l;
}
function stsBadge(s) {
  var st = STS[s] || { l: s, c: 'var(--t4)' };
  return '<span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:20px;background:' + st.c + '18;color:' + st.c + ';border:1px solid ' + st.c + '30">' + invStatusLabel(s) + '</span>';
}

// ─── IoC type auto-detection ──────────────────────────────────
function detectIocType(v) {
  v = (v || '').trim();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(v)) return 'ip';
  if (/^[0-9a-f]{64}$/i.test(v) || /^[0-9a-f]{40}$/i.test(v) || /^[0-9a-f]{32}$/i.test(v)) return 'hash';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(v)) return 'email';
  if (/^CVE-\d{4}-\d+$/i.test(v)) return 'cve';
  if (/^HKEY_|^HK(LM|CU|CR|U|CC)[\\/]/i.test(v)) return 'registry';
  if (/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v) && !v.includes(' ')) return 'domain';
  return 'other';
}

// ─── Duration helper ──────────────────────────────────────────
function formatDuration(fromIsoStr) {
  if (!fromIsoStr) return '';
  var from = new Date(fromIsoStr);
  var ms = Date.now() - from.getTime();
  if (isNaN(ms) || ms < 0) return '';
  var d = Math.floor(ms / 86400000);
  var h = Math.floor((ms % 86400000) / 3600000);
  if (d > 0) return d + 'd ' + h + 'h';
  var m = Math.floor((ms % 3600000) / 60000);
  return h + 'h ' + m + 'm';
}

// ─── D+N · HH:MM indicator for timeline ──────────────────────
function fmtTimeline(eventAt, createdAt) {
  if (!eventAt) return '';
  var origin = createdAt ? new Date(createdAt) : null;
  var evt    = new Date(eventAt);
  if (!origin) return evt.toLocaleString(typeof i18n !== 'undefined' ? i18n.lang : undefined, { dateStyle: 'short', timeStyle: 'short' });
  var dayN   = Math.floor((evt - origin) / 86400000);
  var hh     = String(evt.getHours()).padStart(2, '0');
  var mm     = String(evt.getMinutes()).padStart(2, '0');
  return 'D+' + dayN + ' · ' + hh + ':' + mm;
}

// ─── Save indicator helper ────────────────────────────────────
var _saveTimer = null;
function showSaveIndicator(state) {
  var el = document.getElementById('inv-save-indicator');
  if (!el) return;
  el.className = 'inv-save-indicator ' + (state || '');
  el.textContent = state === 'saving' ? '⏳ Saving…' : state === 'saved' ? '✓ Saved' : '';
  if (_saveTimer) clearTimeout(_saveTimer);
  if (state === 'saved') _saveTimer = setTimeout(function() { showSaveIndicator(''); }, 2500);
}

// ─── Synthetic default sections for classic (no template) investigations ──────
function getDefaultSections() {
  return [
    { id: '__summary',    type: 'classic_summary',    name: T('report.section_summary') || 'Executive Summary', icon: '📋', required: true },
    { id: '__iocs',       type: 'iocs',               name: T('iocs.title')             || 'IoCs',              icon: '☣' },
    { id: '__timeline',   type: 'timeline',            name: T('findings.title')         || 'Timeline',          icon: '📅' },
    { id: '__conclusion', type: 'classic_conclusion',  name: T('report.section_conclusion') || 'Conclusion',     icon: '✅' },
    { id: '__report',     type: 'report_preview',      name: 'Report Preview',           icon: '📄' },
  ];
}

// ─── API ─────────────────────────────────────────────────────
async function loadReportSettings() {
  try {
    var s = await API.get('/settings/report');
    if (s && !s.error) _reportSettings = s;
  } catch(e) { /* silencieux — on utilise les défauts */ }
}

async function loadTemplates() {
  try {
    var d = await API.get('/templates');
    I.templates = Array.isArray(d) ? d : [];
  } catch(e) { I.templates = []; }
}
async function loadList() {
  var d = await API.get('/investigations');
  I.list = Array.isArray(d) ? d : [];
}
async function loadSections(invId) {
  try {
    var d = await API.get('/investigations/' + invId + '/sections');
    I.sections = Array.isArray(d) ? d : [];
  } catch(e) { I.sections = []; }
}
async function selectInv(id) {
  var d = await API.get('/investigations/' + id);
  if (d && !d.error) {
    I.cur = d;
    // Load template sections if this investigation uses a template; otherwise use defaults
    if (d.template_id) {
      await loadSections(id);
    } else {
      I.sections = getDefaultSections();
    }
    // Reset IoC filters + active tab on investigation change
    I.iocFilterType = 'all';
    I.iocFilterVerdict = 'all';
    I.selectedIocs = [];
    _activeSecId = null;
    var bc = document.getElementById('inv-breadcrumb');
    if (bc) bc.textContent = d.title;
    render();
  } else {
    showToast(T('inv.error.load'), true);
  }
}

// ─── Report generator (Markdown) ─────────────────────────────
function genReport(inv) {
  var md = '# Investigation Report — ' + inv.title + '\n\n';
  md += '| | |\n|---|---|\n';
  md += '| **Date** | ' + (inv.created_at || '').slice(0, 10) + ' |\n';
  md += '| **Updated** | ' + (inv.updated_at || '').slice(0, 10) + ' |\n';
  md += '| **Analyst** | ' + (inv.analyst_name || '') + ' |\n';
  md += '| **Severity** | ' + (SEV_E[inv.severity] || '') + ' ' + (inv.severity || '').toUpperCase() + ' |\n';
  md += '| **Status** | ' + ((STS[inv.status] || {}).l || inv.status) + ' |\n\n';
  md += '---\n\n## Executive Summary\n\n' + (inv.description && inv.description.trim() || '_No description provided._') + '\n\n---\n\n';
  var iocs = inv.iocs || [];
  md += '## Indicators of Compromise — ' + iocs.length + '\n\n';
  if (iocs.length) {
    md += '| Type | Indicator | Status | Context |\n|:---|:---|:---|:---|\n';
    iocs.forEach(function (ioc) {
      md += '| **' + ((IOC[ioc.type] || {}).l || ioc.type) + '** | `' + ioc.value + '` | ' + (ioc.malicious ? '🔴 Malicious' : '⚪ Unknown') + ' | ' + (ioc.context || '—') + ' |\n';
    });
    var mal = iocs.filter(function (i) { return i.malicious; }).length;
    md += '\n> **Summary:** ' + iocs.length + ' IoC(s)  |  🔴 ' + mal + ' malicious  |  ⚪ ' + (iocs.length - mal) + ' unknown\n\n';
  } else { md += '_No IoCs recorded._\n\n'; }
  md += '---\n\n';
  var findings = inv.findings || [];
  md += '## Findings — ' + findings.length + '\n\n';
  if (findings.length) {
    findings.forEach(function (f, i) {
      md += '### ' + (i + 1) + '. [' + (SEV_E[f.severity] || '') + ' ' + (f.severity || '').toUpperCase() + '] ' + f.title + '\n\n';
      md += (f.content && f.content.trim() || '_No details recorded._') + '\n\n---\n\n';
    });
  } else { md += '_No findings recorded._\n\n---\n\n'; }
  md += '## Conclusion\n\n';
  md += (inv.conclusion && inv.conclusion.trim() || '_No conclusion provided._') + '\n\n';
  md += '---\n_Generated by **KQL Vault** on ' + new Date().toISOString().slice(0, 19).replace('T', ' ') + ' UTC_\n';
  return md;
}

// ─── Report HTML preview ──────────────────────────────────────
function buildPreviewHTML(inv) {
  var SEV_CSS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6' };
  var h = '';
  h += '<h1>' + esc(inv.title) + '</h1>';
  h += '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 18px;margin-bottom:20px">';
  [['Created', (inv.created_at || '').slice(0, 10)],
   ['Updated', (inv.updated_at || '').slice(0, 10)],
   ['Analyst', inv.analyst_name || ''],
   ['Status', (STS[inv.status] || { l: inv.status }).l],
   ['Severity', (inv.severity || '').toUpperCase()]].forEach(function (item, i) {
    var col = i === 4 ? (SEV_CSS[inv.severity] || '#374151') : '#111827';
    h += '<div><div class="meta-lbl">' + item[0] + '</div>';
    h += '<div class="meta-val" style="color:' + col + '">' + esc(item[1]) + '</div></div>';
  });
  h += '</div>';
  h += '<h2>Executive Summary</h2>';
  h += (inv.description && inv.description.trim()
    ? '<div class="preview-md">' + (typeof RichEditor !== 'undefined' ? RichEditor.mdToHtml(inv.description) : esc(inv.description)) + '</div>'
    : '<p style="color:#9ca3af;font-style:italic">No description provided.</p>');
  h += '<hr class="sep">';
  var iocs = inv.iocs || [];
  h += '<h2>Indicators of Compromise — ' + iocs.length + '</h2>';
  if (iocs.length) {
    h += '<table><thead><tr><th>Type</th><th>Indicator</th><th>Status</th><th>Context</th></tr></thead><tbody>';
    iocs.forEach(function (ioc) {
      var lbl = (IOC[ioc.type] || { l: ioc.type }).l;
      h += '<tr><td>' + esc(lbl) + '</td>';
      h += '<td><code>' + esc(ioc.value) + '</code></td>';
      h += '<td style="font-weight:700;color:' + (ioc.malicious ? '#dc2626' : '#9ca3af') + '">' + (ioc.malicious ? '🔴 Malicious' : '⚪ Unknown') + '</td>';
      h += '<td style="color:#6b7280">' + esc(ioc.context || '—') + '</td></tr>';
    });
    h += '</tbody></table>';
    var mal = iocs.filter(function (i) { return i.malicious; }).length;
    h += '<p style="font-size:12px;color:#6b7280;font-style:italic">Total: ' + iocs.length + '  ·  Malicious: ' + mal + '  ·  Unknown: ' + (iocs.length - mal) + '</p>';
  } else {
    h += '<p style="color:#9ca3af;font-style:italic">No IoCs recorded.</p>';
  }
  h += '<hr class="sep">';
  var findings = inv.findings || [];
  h += '<h2>Findings — ' + findings.length + '</h2>';
  if (findings.length) {
    findings.forEach(function (f, i) {
      var sc = SEV_CSS[f.severity] || '#374151';
      h += '<div class="finding-blk" style="border-left-color:' + sc + ';margin-bottom:12px">';
      h += '<div style="font-weight:700;font-size:13px;margin-bottom:8px">';
      h += '<span style="color:' + sc + '">[' + esc((f.severity || '').toUpperCase()) + ']</span> ';
      h += (i + 1) + '. ' + esc(f.title) + '</div>';
      h += (f.content && f.content.trim()
        ? '<div class="preview-md" style="font-size:12px">' + (typeof RichEditor !== 'undefined' ? RichEditor.mdToHtml(f.content) : esc(f.content)) + '</div>'
        : '<p style="color:#9ca3af;font-style:italic;margin:0;font-size:12px">No details recorded.</p>');
      h += '</div>';
    });
  } else {
    h += '<p style="color:#9ca3af;font-style:italic">No findings recorded.</p>';
  }
  h += '<hr class="sep">';
  h += '<h2>Conclusion</h2>';
  if (inv.conclusion && inv.conclusion.trim()) {
    h += '<div class="conclusion-blk preview-md">' + (typeof RichEditor !== 'undefined' ? RichEditor.mdToHtml(inv.conclusion) : esc(inv.conclusion)) + '</div>';
  } else {
    h += '<p style="color:#9ca3af;font-style:italic">No conclusion provided.</p>';
  }
  h += '<hr class="sep">';
  h += '<p style="font-size:11px;color:#9ca3af;text-align:center">Generated by KQL Vault · ' + new Date().toISOString().slice(0, 19).replace('T', ' ') + ' UTC</p>';
  return h;
}

// ─── Sidebar list render ──────────────────────────────────────
function renderSidebar() {
  // Sort by updated_at descending (most recent first)
  var sorted = I.list.slice().sort(function(a, b) {
    return (b.updated_at || '').localeCompare(a.updated_at || '');
  });

  // Filter by status
  var filtered = I.statusFilter === 'all'
    ? sorted
    : sorted.filter(function (inv) { return inv.status === I.statusFilter; });

  // Filter by search query
  var q = I.searchQuery.trim().toLowerCase();
  if (q) {
    filtered = filtered.filter(function(inv) {
      return (inv.title || '').toLowerCase().includes(q) ||
             (inv.description || '').toLowerCase().includes(q);
    });
  }

  var h = '';
  if (!filtered.length) {
    h = '<div class="inv-list-empty">' + I_SEARCH
      + '<span>' + (q ? 'No results for &ldquo;' + esc(q) + '&rdquo;'
           : I.statusFilter !== 'all'
             ? T('inv.empty.filter', { status: invStatusLabel(I.statusFilter) })
             : T('inv.empty.title'))
      + '</span></div>';
  } else {
    filtered.forEach(function (inv) {
      var sc  = SEV_C[inv.severity] || 'var(--t4)';
      var st  = STS[inv.status] || { l: inv.status, c: 'var(--t4)' };
      var active = I.cur && I.cur.id === inv.id;
      var dur = formatDuration(inv.created_at);

      h += '<div class="inv-item' + (active ? ' active' : '') + '" data-inv="' + inv.id + '">';
      h += '<div class="inv-item-row">';
      h += '<span class="inv-item-dot" style="background:' + sc + '"></span>';
      h += '<span class="inv-item-title">' + esc(inv.title) + '</span>';
      h += '</div>';
      h += '<div class="inv-item-badges">';
      h += '<span class="inv-item-badge" style="color:' + st.c + ';background:' + st.c + '18;border:1px solid ' + st.c + '30">' + st.l + '</span>';
      if (dur) h += '<span class="inv-item-badge inv-item-badge-muted">' + dur + '</span>';
      h += '</div></div>';
    });
  }

  var listEl = document.getElementById('inv-list');
  if (listEl) listEl.innerHTML = h;
}

// ─── Right panel render ───────────────────────────────────────
function renderRight() {
  var el = document.getElementById('inv-right');
  if (!el) return;
  if (!I.cur) {
    el.innerHTML = '<div class="inv-right-empty"><span style="font-size:36px;opacity:.3">🔍</span><span>' + T('inv.select') + '</span></div>';
    return;
  }
  // All investigations use the unified right panel (I.sections always populated)
  el.innerHTML = buildRightPanelTemplate(I.cur);
  if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(el); });
  bindRightPanel();
}

// ─── Inline progress widget (header) ──────────────────────────
function buildHeaderProgress(inv) {
  var sections = I.sections.length ? I.sections : getDefaultSections();
  var iocs     = inv.iocs || [], findings = inv.findings || [];
  var checks   = sections.filter(function(s) { return s.type !== 'report_preview'; }).map(function(s) {
    var done = false;
    if      (s.type === 'iocs')             done = iocs.length > 0;
    else if (s.type === 'timeline' || s.type === 'findings') done = findings.length > 0;
    else if (s.type === 'classic_summary')  done = !!(inv.description && inv.description.trim());
    else if (s.type === 'classic_conclusion') done = !!(inv.conclusion && inv.conclusion.trim());
    else                                    done = !!(s.content && s.content.trim());
    return { label: s.name, done: done };
  });
  var done = checks.filter(function(c) { return c.done; }).length;
  var pct  = checks.length ? Math.round(done / checks.length * 100) : 0;
  var col  = pct === 100 ? '#22c55e' : pct >= 50 ? '#0ea5e9' : '#f97316';

  var h = '<div class="inv-hdr-progress">';
  // Progress bar
  h += '<div class="inv-hdr-progress-bar"><div class="inv-hdr-progress-fill" style="width:' + pct + '%;background:' + col + '"></div></div>';
  // Percentage label
  h += '<span class="inv-hdr-progress-pct" style="color:' + col + '">' + pct + '%</span>';
  // Section dots
  h += '<div class="inv-hdr-progress-dots">';
  checks.forEach(function(c) {
    h += '<span class="inv-hdr-dot' + (c.done ? ' done' : '') + '" title="' + esc(c.label) + '">'
      + (c.done
        ? '<svg width="9" height="9" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="2,6 5,9 10,3"/></svg>'
        : '')
      + '</span>';
  });
  h += '</div>';
  h += '</div>';
  return h;
}

// ─── Inline document header ───────────────────────────────────
function buildInvHeader(inv, canDel, canEdit) {
  var sc = SEV_C[inv.severity] || 'var(--t4)';
  var st = STS[inv.status] || { l: inv.status, c: 'var(--t4)' };
  var dur = formatDuration(inv.created_at);
  var isLocked = !!(inv.report_locked && I.user && I.user.role !== 'admin');

  var h = '<div class="inv-doc-header">';
  h += '<div class="inv-doc-title-row">';
  h += '<span style="width:10px;height:10px;border-radius:50%;background:' + sc + ';flex-shrink:0"></span>';
  if (canEdit) {
    h += '<span class="inv-title-editable" id="inv-title-inline" contenteditable="true" spellcheck="false" data-orig="' + esc(inv.title) + '">' + esc(inv.title) + '</span>';
  } else {
    h += '<span style="font-size:17px;font-weight:800;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(inv.title) + '</span>';
  }

  if (canEdit) {
    h += '<select id="inv-status-inline" class="inv-styled-sel" style="color:' + st.c + ';border-color:' + st.c + '44;background:' + st.c + '12">';
    ['open','in-progress','closed'].forEach(function(s) {
      var sl = STS[s] || { l: s };
      h += '<option value="' + s + '"' + (inv.status === s ? ' selected' : '') + '>' + sl.l + '</option>';
    });
    h += '</select>';
    h += '<select id="inv-sev-inline" class="inv-styled-sel" style="color:' + sc + ';border-color:' + sc + '44;background:' + sc + '12">';
    ['critical','high','medium','low','info'].forEach(function(s) {
      h += '<option value="' + s + '"' + (inv.severity === s ? ' selected' : '') + '>' + s.charAt(0).toUpperCase() + s.slice(1) + '</option>';
    });
    h += '</select>';
  } else {
    h += stsBadge(inv.status) + ' ' + sevBadge(inv.severity);
  }

  h += buildHeaderProgress(inv);
  if (dur) h += '<span class="inv-duration-badge" title="Duration since creation">' + dur + '</span>';
  h += '</div>';

  h += '<div class="inv-doc-actions">';
  h += '<button class="hdr-btn-tool" id="btn-preview-rpt">' + I_EYE + ' Preview</button>';
  h += '<button class="hdr-btn-tool" id="btn-print-pdf">' + I_DL + ' PDF</button>';
  h += '<button class="hdr-btn-tool inv-btn-docx" id="btn-dl-docx">' + I_DL + ' DOCX</button>';
  h += '<button class="hdr-btn-tool inv-btn-html" id="btn-dl-html">' + I_DL + ' HTML</button>';
  if (!isLocked && canEdit) {
    h += '<button class="hdr-btn-tool" id="btn-close-inv">' + I_LOCK + ' Close</button>';
  }
  if (canDel) {
    h += '<button class="hdr-btn-tool inv-btn-danger" id="btn-del-inv">' + I_TRASH + ' Delete</button>';
  }
  if (inv.report_locked && I.user && I.user.role === 'admin') {
    h += '<button class="hdr-btn-tool" id="btn-unlock-rpt">' + I_UNLOCK + ' Unlock</button>';
  }
  h += '<span id="inv-save-indicator" class="inv-save-indicator"></span>';
  h += '</div>';
  h += '</div>';
  return h;
}

// ─── Main panel render — unified scrollable document ──────────
function renderMain() {
  var el = document.getElementById('inv-main');
  if (!el) return;
  if (!I.cur) {
    el.innerHTML = '<div class="empty-state">'
      + '<div class="empty-state-icon">' + I_SHIELD + '</div>'
      + '<div class="empty-state-title">' + T('inv.select') + '</div>'
      + '<div class="empty-state-sub">' + T('inv.select_sub') + '</div>'
      + (I.user && I.user.role !== 'viewer' ? '<button class="pri" id="btn-new-inv2">' + I_PLUS + ' ' + T('inv.new') + '</button>' : '')
      + '</div>';
    return;
  }

  var inv      = I.cur;
  var isWriter = I.user && I.user.role !== 'viewer';
  var isLocked = !!(inv.report_locked && I.user && I.user.role !== 'admin');
  var canEdit  = isWriter && !isLocked;
  var canDel   = isWriter && (inv.analyst_id === I.user.id || I.user.role === 'admin');
  var sections = inv.template_id ? I.sections : getDefaultSections();

  // Resolve active section (use string coercion — DB section IDs are numbers, tab attr returns string)
  if (!_activeSecId || !sections.find(function(s) { return String(s.id) === String(_activeSecId); })) {
    _activeSecId = sections.length ? sections[0].id : null;
  }
  var activeSection = sections.find(function(s) { return String(s.id) === String(_activeSecId); });

  var h = '';
  h += renderLockBanner(inv);
  h += buildInvHeader(inv, canDel, canEdit);

  // ── Tab bar ──────────────────────────────────────────────────
  h += '<div class="inv-tab-bar">';
  sections.forEach(function(s) {
    var isActive = s.id === _activeSecId;
    var badge = '';
    if (s.type === 'iocs' && inv.iocs && inv.iocs.length) {
      badge = '<span class="inv-tab-badge">' + inv.iocs.length + '</span>';
    }
    if ((s.type === 'timeline' || s.type === 'findings') && inv.findings && inv.findings.length) {
      badge = '<span class="inv-tab-badge">' + inv.findings.length + '</span>';
    }
    h += '<button class="inv-tab' + (isActive ? ' active' : '') + '" data-sec-tab="' + s.id + '">'
      + esc(s.name) + badge + '</button>';
  });
  h += '</div>';

  // ── Active section pane ──────────────────────────────────────
  var isReport = activeSection && activeSection.type === 'report_preview';
  h += '<div class="inv-section-pane' + (isReport ? ' inv-section-pane--report' : '') + '">';
  if (activeSection) {
    h += buildSectionBodyUnified(activeSection, inv, canEdit);
  }
  h += '</div>';

  el.innerHTML = h;
  if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(el); });
}

// ─── Unified section body dispatcher ─────────────────────────
function buildSectionBodyUnified(s, inv, canEdit) {
  switch (s.type) {
    case 'classic_summary':
      return buildClassicRichtext('__summary', inv.description || '', canEdit, T('inv.field.desc_ph') || 'Executive summary…');
    case 'classic_conclusion':
      return buildClassicRichtext('__conclusion', inv.conclusion || '', canEdit, T('inv.field.conc_ph') || 'Conclusion…');
    case 'richtext':
    case 'custom':
      return buildSectionRichtext(s, inv, canEdit);
    case 'findings':
    case 'timeline':
      return buildFindings(inv, canEdit);
    case 'iocs':
      return buildIocs(inv, canEdit);
    case 'report_preview':
      return buildSectionReportPreview(inv);
    case 'cvss':
      return buildSectionCVSS(s, inv, canEdit);
    case 'checklist':
      return buildSectionChecklist(s, inv, canEdit);
    case 'recommendation':
      return buildSectionRecommendation(s, inv, canEdit);
    default:
      return buildSectionRichtext(s, inv, canEdit);
  }
}

// ─── Classic richtext (maps to inv.description / inv.conclusion) ──
function buildClassicRichtext(secId, value, canEdit, placeholder) {
  if (!canEdit) {
    var rendered = value && typeof RichEditor !== 'undefined'
      ? RichEditor.mdToHtml(value)
      : esc(value || '');
    return '<div class="re-preview re-preview--always">'
      + (rendered || '<p style="color:var(--t5);font-style:italic">' + esc(placeholder) + '</p>')
      + '</div>';
  }
  return '<div id="re-container-' + secId + '"></div>';
}

function buildOverview(inv, isWriter) {
  var isLocked = !!(inv.report_locked && I.user && I.user.role !== 'admin');
  if (!isWriter || isLocked) {
    var descHtml = typeof RichEditor !== 'undefined' && inv.description
      ? RichEditor.mdToHtml(inv.description)
      : esc(inv.description || T('inv.field.no_desc'));
    var concHtml = typeof RichEditor !== 'undefined' && inv.conclusion
      ? RichEditor.mdToHtml(inv.conclusion)
      : esc(inv.conclusion || '');
    return '<div class="ov-readonly">'
      + '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">' + sevBadge(inv.severity) + stsBadge(inv.status) + '</div>'
      + '<div style="margin-bottom:20px">'
      + '<div class="lbl" style="margin-bottom:8px">' + T('report.section_summary') + '</div>'
      + '<div class="re-preview re-preview--always">' + (descHtml || '<p class="re-empty-hint">' + T('inv.field.no_desc') + '</p>') + '</div>'
      + '</div>'
      + (inv.conclusion && inv.conclusion.trim()
        ? '<div style="border-top:1px solid var(--bd);padding-top:16px">'
          + '<div class="lbl" style="margin-bottom:8px">' + T('report.section_conclusion') + '</div>'
          + '<div class="re-preview re-preview--always" style="border-left:3px solid #22c55e40;padding-left:14px">' + concHtml + '</div></div>'
        : '')
      + '</div>';
  }
  var h = '<div class="ov-form">';
  // Top : status, severity, title
  h += '<div class="ov-meta">';
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">';
  h += '<div><label class="lbl">' + T('inv.field.status') + '</label><select id="inv-status" style="width:100%">';
  h += '<option value="open"'         + (inv.status === 'open'         ? ' selected' : '') + '>' + T('inv.status.open') + '</option>';
  h += '<option value="in-progress"'  + (inv.status === 'in-progress'  ? ' selected' : '') + '>' + T('inv.status.inprogress') + '</option>';
  h += '<option value="closed"'       + (inv.status === 'closed'       ? ' selected' : '') + '>' + T('inv.status.closed') + '</option>';
  h += '</select></div>';
  h += '<div><label class="lbl">' + T('inv.field.severity') + '</label><select id="inv-sev" style="width:100%">';
  ['critical', 'high', 'medium', 'low', 'info'].forEach(function (s) {
    h += '<option value="' + s + '"' + (inv.severity === s ? ' selected' : '') + '>' + s.charAt(0).toUpperCase() + s.slice(1) + '</option>';
  });
  h += '</select></div></div>';
  h += '<div><label class="lbl">' + T('inv.field.title') + '</label><input id="inv-title" value="' + esc(inv.title) + '" style="width:100%;font-size:15px;font-weight:600"></div>';
  h += '</div>'; // end ov-meta
  // Rich editors (containers — initialisés dans bindMain après injection dans le DOM)
  h += '<div class="ov-textareas">';
  h += '<div class="ov-field"><div id="re-container-desc"></div></div>';
  h += '<div class="ov-field"><div id="re-container-conclusion"></div></div>';
  h += '</div>';
  // Footer
  h += '<div class="ov-footer"><button class="pri" id="btn-save-inv">' + T('inv.save') + '</button></div>';
  h += '</div>'; // end ov-form
  return h;
}

function buildIocs(inv, canEdit) {
  if (canEdit === undefined) { canEdit = !!(I.user && I.user.role !== 'viewer' && !(inv.report_locked && I.user.role !== 'admin')); }
  var iocs = inv.iocs || [];
  var h = '';

  // ─── Add IoC form ────
  if (canEdit) {
    h += '<div class="card-form" style="margin-bottom:16px">';
    h += '<p class="inv-form-title">' + T('iocs.btn_add') + '</p>';
    // Single IoC row
    h += '<div style="display:grid;grid-template-columns:160px 1fr 1fr auto;gap:8px;margin-bottom:8px;align-items:flex-end">';
    h += '<div><label class="lbl">' + T('iocs.form.type') + '</label><select id="ioc-type" style="width:100%">';
    Object.keys(IOC).forEach(function (k) { h += '<option value="' + k + '">' + IOC[k].l + '</option>'; });
    h += '</select></div>';
    h += '<div><label class="lbl">' + T('iocs.form.value') + '</label><input id="ioc-val" placeholder="' + T('iocs.form.placeholder_val') + '" style="font-family:var(--mono);font-size:12px;width:100%" oninput="invAutoDetectIocType(this.value)"></div>';
    h += '<div><label class="lbl">' + T('iocs.form.ctx') + '</label><input id="ioc-ctx" placeholder="' + T('iocs.form.placeholder_ctx') + '" style="width:100%"></div>';
    h += '<div style="padding-bottom:2px;display:flex;align-items:center;gap:8px">';
    h += '<label style="display:flex;align-items:center;gap:5px;cursor:pointer;font-size:12px;white-space:nowrap"><input type="checkbox" id="ioc-mal"> <span style="color:#ef4444;font-weight:700">' + T('iocs.status.mal') + '</span></label>';
    h += '<button class="pri btn-sm" id="btn-add-ioc">' + T('iocs.form.btn_add') + '</button>';
    h += '</div></div>';
    // Bulk input
    h += '<details style="margin-top:6px"><summary style="font-size:12px;color:var(--t4);cursor:pointer;user-select:none">📋 Bulk paste (one per line)</summary>';
    h += '<div style="margin-top:8px">';
    h += '<textarea id="ioc-bulk" rows="4" style="width:100%;font-family:var(--mono);font-size:12px;resize:vertical" placeholder="192.168.1.1&#10;evil.com&#10;d41d8cd98f00b204e9800998ecf8427e&#10;..."></textarea>';
    h += '<div style="display:flex;gap:8px;margin-top:6px"><button class="pri btn-sm" id="btn-bulk-add-ioc">Add All</button><button class="btn-sm" id="btn-bulk-clear">Clear</button></div>';
    h += '</div></details>';
    h += '</div>';
  }

  // ─── Filter row ────
  var typeKeys = Object.keys(IOC);
  h += '<div class="ioc-filter-row">';
  h += '<span style="font-size:10px;font-weight:700;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Filter:</span>';
  h += '<button class="ioc-filter-chip' + (I.iocFilterType === 'all' ? ' active' : '') + '" data-ioc-ftype="all">All types</button>';
  typeKeys.forEach(function(k) {
    if (iocs.some(function(i) { return i.type === k; })) {
      h += '<button class="ioc-filter-chip' + (I.iocFilterType === k ? ' active' : '') + '" data-ioc-ftype="' + k + '">' + IOC[k].l + '</button>';
    }
  });
  h += '<span style="margin-left:4px;border-left:1px solid var(--bd);padding-left:8px;font-size:10px;font-weight:700;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Verdict:</span>';
  h += '<button class="ioc-filter-chip' + (I.iocFilterVerdict === 'all' ? ' active' : '') + '" data-ioc-fverdict="all">All</button>';
  h += '<button class="ioc-filter-chip' + (I.iocFilterVerdict === 'malicious' ? ' active' : '') + '" data-ioc-fverdict="malicious">🔴 Malicious</button>';
  h += '<button class="ioc-filter-chip' + (I.iocFilterVerdict === 'clean' ? ' active' : '') + '" data-ioc-fverdict="clean">⚪ Clean/Unknown</button>';
  h += '</div>';

  // ─── Apply filters ────
  var visible = iocs.filter(function(ioc) {
    if (I.iocFilterType !== 'all' && ioc.type !== I.iocFilterType) return false;
    if (I.iocFilterVerdict === 'malicious' && !ioc.malicious) return false;
    if (I.iocFilterVerdict === 'clean' && ioc.malicious) return false;
    return true;
  });

  // ─── Apply sort ────
  var sc = I.iocSort;
  if (sc.col !== 'none') {
    visible = visible.slice().sort(function(a, b) {
      var av = a[sc.col] || '', bv = b[sc.col] || '';
      return sc.dir === 'asc' ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });
  }

  if (!visible.length && !iocs.length) {
    h += '<div style="text-align:center;padding:44px;color:var(--t5);font-size:14px">' + T('iocs.empty_yet') + '</div>';
    return h;
  }
  if (!visible.length) {
    h += '<div style="text-align:center;padding:24px;color:var(--t5);font-size:13px">No IoCs match the current filter.</div>';
    return h;
  }

  function sortHeader(col, label) {
    var active = sc.col === col;
    var arrow  = active ? (sc.dir === 'asc' ? '▲' : '▼') : '▼';
    return '<th data-sort="' + col + '" style="cursor:pointer;user-select:none">' + label
      + '<span class="sort-arrow' + (active ? ' active' : '') + '">' + arrow + '</span></th>';
  }

  h += '<div style="border:1px solid var(--bd);border-radius:10px;overflow:hidden;margin-bottom:10px">';
  h += '<table class="ioc-tbl"><thead><tr>';
  if (canEdit) h += '<th style="width:30px"><input type="checkbox" id="ioc-sel-all" title="Select all"></th>';
  h += sortHeader('type', T('iocs.col.type'));
  h += sortHeader('value', T('iocs.col.indicator'));
  h += '<th>' + T('iocs.col.status') + '</th>';
  h += '<th>' + T('iocs.col.context') + '</th>';
  h += sortHeader('severity', T('iocs.col.sev'));
  h += '<th>Threat Intel</th>';
  if (canEdit) h += '<th></th>';
  h += '</tr></thead><tbody>';

  visible.forEach(function (ioc) {
    var td  = IOC[ioc.type] || { l: ioc.type, c: '#9ca3af' };
    var sel = I.selectedIocs.indexOf(ioc.id) >= 0;
    // Parse persisted enrichment from DB
    var enriched = null;
    if (ioc.enrich_result) {
      try { enriched = JSON.parse(ioc.enrich_result); } catch(e) {}
    }
    if (!enriched && ioc._enrichResult) enriched = ioc._enrichResult;

    h += '<tr' + (sel ? ' style="background:rgba(220,38,38,.06)"' : '') + '>';
    if (canEdit) h += '<td><input type="checkbox" class="ioc-sel-cb" data-ioc-id="' + ioc.id + '"' + (sel ? ' checked' : '') + '></td>';
    h += '<td><span class="ioc-badge" style="background:' + td.c + '20;color:' + td.c + '">' + esc(td.l) + '</span></td>';
    h += '<td><code style="font-size:12px;word-break:break-all">' + esc(ioc.value) + '</code></td>';
    h += '<td>';
    if (canEdit) {
      h += '<button data-ioc-toggle="' + ioc.id + '" data-mal="' + (ioc.malicious ? '1' : '0') + '" style="font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;cursor:pointer;border:1px solid;' + (ioc.malicious ? 'color:#ef4444;background:#7f1d1d20;border-color:#991b1b' : 'color:var(--t4);background:var(--s2);border-color:var(--bd)') + '">' + (ioc.malicious ? T('iocs.status.mal') : T('iocs.status.unk')) + '</button>';
    } else {
      h += '<span style="font-size:12px;font-weight:700;' + (ioc.malicious ? 'color:#ef4444' : 'color:var(--t5)') + '">' + (ioc.malicious ? T('iocs.status.mal') : T('iocs.status.unk')) + '</span>';
    }
    h += '</td>';
    h += '<td style="color:var(--t3);font-size:12px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(ioc.context || '') + '">' + esc(ioc.context || '—') + '</td>';
    h += '<td>' + sevBadge(ioc.severity || 'medium') + '</td>';
    // Threat intel — from DB or in-memory
    h += '<td style="min-width:100px">';
    if (enriched && enriched.verdict) {
      var vc  = enriched.verdict === 'malicious' ? 'malicious' : enriched.verdict === 'suspicious' ? 'suspicious' : 'clean';
      var vtRes = enriched.results ? enriched.results.find(function(r) { return r.source === 'VirusTotal'; }) : null;
      var vtLbl = vtRes && vtRes.total ? ' · VT ' + vtRes.malicious + '/' + vtRes.total : '';
      var dateStr = enriched.date ? ' · ' + new Date(enriched.date).toISOString().slice(0, 10) : '';
      h += '<span class="enrich-badge ' + vc + '">' + (vc === 'malicious' ? '🔴' : vc === 'suspicious' ? '🟡' : '✅') + ' ' + vc.charAt(0).toUpperCase() + vc.slice(1) + vtLbl + dateStr + '</span>';
      if (canEdit && ['hash','ip','domain','url'].indexOf(ioc.type) >= 0) {
        h += '<br><button data-enrich-ioc="' + ioc.id + '" style="font-size:10px;padding:1px 6px;margin-top:3px;color:var(--t4);cursor:pointer">🔄 Re-enrich</button>';
      }
    } else if (canEdit && ['hash','ip','domain','url'].indexOf(ioc.type) >= 0) {
      h += '<button data-enrich-ioc="' + ioc.id + '" style="font-size:10px;padding:2px 8px;color:var(--t3);cursor:pointer" title="Lookup on VirusTotal &amp; abuse.ch">🔍 Enrich</button>';
    } else {
      h += '<span style="color:var(--t5);font-size:11px">—</span>';
    }
    h += '</td>';
    if (canEdit) {
      h += '<td><div style="display:flex;gap:3px">';
      h += '<button data-edit-ioc="' + ioc.id + '" style="color:var(--t4);background:none;border:none;cursor:pointer;font-size:13px;padding:2px 4px;border-radius:4px" title="' + T('det_edit_btn') + '">✏</button>';
      h += '<button data-del-ioc="' + ioc.id + '" style="color:var(--t5);background:none;border:none;cursor:pointer;font-size:14px;padding:2px 5px;border-radius:4px" title="Delete">✕</button>';
      h += '</div></td>';
    }
    h += '</tr>';
  });
  h += '</tbody></table></div>';

  // Footer actions
  h += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">';
  if (canEdit) {
    h += '<button id="btn-bulk-del-iocs" style="font-size:12px;color:var(--red);border-color:var(--red)" title="Delete selected">🗑 Delete selected (<span id="ioc-sel-count">0</span>)</button>';
  }
  h += '<button id="btn-copy-iocs" style="font-size:12px">' + T('iocs.copy') + '</button>';
  h += '<span style="font-size:11px;color:var(--t5);margin-left:auto">' + visible.length + ' / ' + iocs.length + ' IoCs</span>';
  h += '</div>';

  return h;
}

// Global helper called from inline oninput — must be on window
window.invAutoDetectIocType = function(v) {
  var sel = document.getElementById('ioc-type');
  if (!sel || !v.trim()) return;
  var detected = detectIocType(v.trim());
  sel.value = detected;
};

function buildFindings(inv, canEdit) {
  if (canEdit === undefined) { canEdit = !!(I.user && I.user.role !== 'viewer' && !(inv.report_locked && I.user.role !== 'admin')); }
  var isLocked = !!(inv.report_locked && I.user && I.user.role !== 'admin');
  var findings = inv.findings || [];

  // Chronological sort: event_at first (when set), then display_order
  var sorted = findings.slice().sort(function (a, b) {
    var aHasDate = !!(a.event_at), bHasDate = !!(b.event_at);
    if (aHasDate && bHasDate) return a.event_at - b.event_at;
    if (aHasDate) return -1;
    if (bHasDate) return 1;
    return (a.display_order || 0) - (b.display_order || 0);
  });

  var EVENT_ICONS = { finding: '🔍', ioc_detected: '⚠️', lateral_movement: '↔️', exfiltration: '📤', initial_access: '🚪', custom: '📌' };

  var h = '';
  h += '<div class="findings-panel">';

  // Header
  h += '<div class="findings-header">';
  h += '<div><div class="findings-title">' + T('findings.title') + '</div>';
  h += '<div class="findings-sub">' + T('findings.count', { n: sorted.length }) + (canEdit ? ' — ' + T('findings.drag') : '') + '</div></div>';
  h += '<div style="display:flex;gap:8px;align-items:center">';
  if (isLocked) h += '<span class="lock-badge">' + T('findings.lock_badge') + '</span>';
  if (canEdit)  h += '<button class="pri btn-sm" id="btn-add-fnd">' + T('findings.btn_add') + '</button>';
  h += '</div></div>';

  // Timeline
  h += '<div class="timeline-wrap" id="findings-timeline" data-inv-id="' + inv.id + '">';
  if (!sorted.length) {
    h += '<div style="text-align:center;padding:44px;color:var(--t5);font-size:14px">' + T('findings.empty') + ' — ';
    if (canEdit) h += '<a href="#" id="btn-add-fnd-empty" style="color:var(--primary)">' + T('findings.empty_hint') + '</a>';
    else h += T('findings.empty_locked');
    h += '</div>';
  } else {
    sorted.forEach(function (f, i) {
      var sc  = SEV_C[f.severity] || 'var(--t4)';
      var ei  = EVENT_ICONS[f.event_type || 'finding'] || '🔍';
      var dt  = f.event_at ? fmtTimeline(f.event_at, inv.created_at) : T('findings.date.unknown');
      var cbs = [];
      var scs = [];
      try { cbs = JSON.parse(f.code_blocks || '[]'); } catch(e) {}
      try { scs = JSON.parse(f.screenshots  || '[]'); } catch(e) {}

      h += '<div class="timeline-item" ' + (canEdit ? 'draggable="true"' : '') + ' data-finding-id="' + f.id + '">';
      h += '<div class="timeline-connector">';
      if (i > 0) h += '<div class="timeline-line"></div>';
      h += '<div class="timeline-dot" style="background:' + sc + ';box-shadow:0 0 0 4px ' + sc + '22"></div>';
      h += '</div>';
      h += '<div class="timeline-card" style="border-left:3px solid ' + sc + '">';
      if (canEdit) h += '<div class="drag-handle" title="' + T('findings.drag') + '">⠿</div>';
      h += '<div class="timeline-card-header">';
      h += '<div class="timeline-card-meta">';
      h += '<span class="timeline-event-type">' + ei + '</span>';
      h += '<span class="timeline-event-date">' + dt + '</span>';
      h += sevBadge(f.severity);
      h += '</div>';
      if (canEdit) {
        h += '<div class="timeline-card-actions">';
        h += '<button data-edit-fnd="' + f.id + '" title="' + T('det_edit_btn') + '" style="background:none;border:none;cursor:pointer;color:var(--t4);padding:3px;border-radius:4px;font-size:13px">✏</button>';
        h += '<button data-del-fnd="' + f.id + '" title="' + T('delete') + '" style="background:none;border:none;cursor:pointer;color:var(--sev-critical);padding:3px;border-radius:4px;font-size:13px">🗑</button>';
        h += '</div>';
      }
      h += '</div>';
      h += '<div class="timeline-card-title">' + esc(f.title || T('findings.no_title')) + '</div>';
      if (f.content && f.content.trim()) {
        h += '<div class="timeline-card-desc">' + esc(f.content) + '</div>';
      }
      // Linked IoCs
      var linkedIds = [];
      try { linkedIds = JSON.parse(f.linked_ioc_ids || '[]'); } catch(e) {}
      if (linkedIds.length) {
        var invIocs = inv.iocs || [];
        var linkedIocsInfo = linkedIds.map(function(lid) {
          var iocObj = invIocs.find(function(x) { return x.id === lid; });
          return iocObj ? esc(iocObj.value) : null;
        }).filter(Boolean);
        if (linkedIocsInfo.length) {
          h += '<div style="font-size:10px;color:var(--t4);margin-top:4px">🔗 ' + linkedIocsInfo.join(' · ') + '</div>';
        }
      }
      // Code blocks
      cbs.forEach(function (cb) {
        if (!cb.content) return;
        h += '<div class="code-block-wrap">';
        h += '<div class="code-block-header"><span class="code-block-lang">' + esc(cb.lang || 'kql') + '</span>';
        h += '<button class="btn-copy-cb" data-code="' + esc(cb.content) + '" style="background:none;border:none;cursor:pointer;color:var(--t4);font-size:11px">' + T('findings.copy.code') + '</button></div>';
        h += '<pre class="code-block-content"><code>' + esc(cb.content) + '</code></pre></div>';
      });
      // Screenshots
      if (scs.length) {
        h += '<div class="screenshots-grid">';
        scs.forEach(function (s) {
          if (!s.url) return;
          h += '<div class="screenshot-wrap" data-url="' + esc(s.url) + '">';
          h += '<img src="' + esc(s.url) + '" alt="' + esc(s.caption || '') + '" style="width:100%;height:100px;object-fit:cover;border-radius:6px;cursor:pointer">';
          if (s.caption) h += '<span class="screenshot-caption">' + esc(s.caption) + '</span>';
          h += '</div>';
        });
        h += '</div>';
      }
      h += '</div></div>';
    });
  }
  h += '</div></div>';
  return h;
}

// ─── Finding modal (add / edit) ───────────────────────────────────────────────
function openAddFinding(invId, existingFinding) {
  var isEdit = !!existingFinding;
  var f = existingFinding || {};
  var cbs = [];
  var scs = [];
  try { cbs = JSON.parse(f.code_blocks || '[]'); } catch(e) {}
  try { scs = JSON.parse(f.screenshots  || '[]'); } catch(e) {}

  _ms.invId     = invId;
  _ms.findingId = isEdit ? f.id : null;

  var eventTypes = [
    { v: 'finding',          l: T('findings.type.finding') },
    { v: 'initial_access',   l: T('findings.type.initial') },
    { v: 'lateral_movement', l: T('findings.type.lateral') },
    { v: 'ioc_detected',     l: T('findings.type.ioc') },
    { v: 'exfiltration',     l: T('findings.type.exfil') },
    { v: 'custom',           l: T('findings.type.custom') },
  ];

  var dateVal = f.event_at ? new Date(f.event_at).toISOString().slice(0, 16) : '';

  var ov = document.createElement('div');
  ov.className = 'inv-modal-overlay';
  ov.innerHTML = '<div class="inv-modal">'
    + '<div class="inv-modal-hdr">'
    + '<h2 class="inv-modal-title">' + T(isEdit ? 'findings.modal.title_edit' : 'findings.modal.title_new') + '</h2>'
    + '<button class="inv-modal-close" id="fmd-close">' + I_X + '</button></div>'
    + '<div class="inv-modal-body">'
    // Row 1: type + severity
    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'
    + '<div><label class="lbl">' + T('findings.modal.label_type') + '</label><select id="f-type" style="width:100%">'
    + eventTypes.map(function(t) { return '<option value="' + t.v + '"' + ((f.event_type || 'finding') === t.v ? ' selected' : '') + '>' + t.l + '</option>'; }).join('')
    + '</select></div>'
    + '<div><label class="lbl">' + T('findings.modal.label_sev') + '</label><select id="f-sev" style="width:100%">'
    + ['critical','high','medium','low','info'].map(function(s) { return '<option value="' + s + '"' + ((f.severity || 'medium') === s ? ' selected' : '') + '>' + s.charAt(0).toUpperCase() + s.slice(1) + '</option>'; }).join('')
    + '</select></div></div>'
    // Title
    + '<div><label class="lbl">' + T('findings.modal.label_title') + '</label><input id="f-title" type="text" value="' + esc(f.title || '') + '" placeholder="' + T('findings.modal.placeholder_title') + '" style="width:100%;font-size:14px"></div>'
    // Date
    + '<div><label class="lbl">' + T('findings.modal.label_date') + '</label><input id="f-date" type="datetime-local" value="' + dateVal + '" style="width:100%"><div style="font-size:11px;color:var(--t5);margin-top:4px">' + T('findings.modal.date_hint') + '</div></div>'
    // Description
    + '<div><label class="lbl">' + T('findings.modal.label_desc') + '</label><textarea id="f-desc" rows="4" style="width:100%;font-family:var(--sans);font-size:13px;resize:vertical" placeholder="' + T('findings.modal.placeholder_desc') + '">' + esc(f.content || '') + '</textarea></div>'
    // Code blocks
    + '<div>'
    + '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px"><label class="lbl" style="margin:0">' + T('findings.modal.label_code') + '</label><button id="btn-add-cb" class="hdr-btn-tool">' + I_CODE + ' ' + T('findings.add.code') + '</button></div>'
    + '<div id="cbs-container">'
    + cbs.map(function(b, i) { return renderCodeBlockEditor(b, i); }).join('')
    + '</div></div>'
    // Linked IoCs
    + (function() {
        var invIocs = (I.cur && I.cur.iocs) || [];
        var linkedIds = [];
        try { linkedIds = JSON.parse(f.linked_ioc_ids || '[]'); } catch(e) {}
        if (!invIocs.length) return '';
        return '<div><label class="lbl">Related IoCs <span style="font-weight:400;color:var(--t5)">(optional)</span></label>'
          + '<div style="max-height:120px;overflow-y:auto;border:1px solid var(--bd);border-radius:7px;padding:6px 8px;display:flex;flex-wrap:wrap;gap:5px" id="ioc-link-container">'
          + invIocs.map(function(ioc) {
              var sel = linkedIds.indexOf(ioc.id) >= 0;
              var td  = IOC[ioc.type] || { c: '#9ca3af' };
              return '<label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:11px;padding:2px 6px;border-radius:4px;border:1px solid ' + td.c + '30;background:' + (sel ? td.c + '20' : 'none') + '">'
                + '<input type="checkbox" class="ioc-link-cb" value="' + ioc.id + '"' + (sel ? ' checked' : '') + '>'
                + '<span style="font-family:var(--mono);color:' + td.c + '">' + esc(ioc.value) + '</span>'
                + '</label>';
            }).join('')
          + '</div></div>';
      })()
    // Screenshots
    + '<div>'
    + '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px"><label class="lbl" style="margin:0">' + T('findings.modal.label_scr') + '</label>'
    + '<label for="sc-upload" class="hdr-btn-tool" style="cursor:pointer">' + I_IMG + ' ' + T('findings.add.screenshot') + '</label>'
    + '<input type="file" id="sc-upload" accept="image/*" style="display:none"></div>'
    + '<div id="scs-container" style="display:flex;flex-wrap:wrap;gap:8px">'
    + scs.map(function(s, i) { return renderScreenshotThumb(s, i); }).join('')
    + '</div></div>'
    + '</div>'
    + '<div class="inv-modal-footer">'
    + '<button id="fmd-cancel">' + T('findings.modal.btn_cancel') + '</button>'
    + '<button class="pri" id="fmd-save">' + T(isEdit ? 'findings.modal.btn_save' : 'findings.modal.btn_add') + '</button>'
    + '</div></div>';

  document.body.appendChild(ov);
  var close = function () { if (document.body.contains(ov)) document.body.removeChild(ov); };
  document.getElementById('fmd-close').onclick  = close;
  document.getElementById('fmd-cancel').onclick = close;
  ov.onclick = function(e) { if (e.target === ov) close(); };
  document.getElementById('f-title').focus();
  document.getElementById('btn-add-cb').onclick = function() { addCodeBlockEditor(); };
  document.getElementById('sc-upload').onchange = function() { addScreenshotUpload(this); };
  document.getElementById('fmd-save').onclick = function() { saveFinding(close); };
}

function renderCodeBlockEditor(block, index) {
  return '<div class="cb-editor inv-code-editor" data-idx="' + index + '">'
    + '<div class="inv-code-editor-toolbar">'
    + '<select class="cb-lang inv-code-lang-sel">'
    + ['kql','powershell','bash','cmd','python','json','yaml','sql','text','xml'].map(function(l) {
        return '<option value="' + l + '"' + ((block.lang || 'kql') === l ? ' selected' : '') + '>' + l.toUpperCase() + '</option>';
      }).join('')
    + '</select>'
    + '<button class="btn-rm-cb inv-code-rm-btn" title="Remove">' + I_X + '</button></div>'
    + '<textarea class="cb-content inv-code-textarea" rows="5" placeholder="' + T('findings.modal.placeholder_code') + '">' + esc(block.content || '') + '</textarea>'
    + '</div>';
}

function renderScreenshotThumb(s, i) {
  return '<div class="sc-thumb" style="position:relative;width:90px">'
    + '<img src="' + esc(s.url || '') + '" style="width:90px;height:65px;object-fit:cover;border-radius:6px;display:block">'
    + '<input type="text" class="sc-caption" value="' + esc(s.caption || '') + '" placeholder="' + T('findings.copy.caption') + '" style="width:90px;font-size:10px;padding:2px 4px;margin-top:3px">'
    + '<input type="hidden" class="sc-data" value="' + esc(s.url || '') + '">'
    + '<button class="btn-rm-sc" style="position:absolute;top:2px;right:2px;background:rgba(0,0,0,.7);border:none;cursor:pointer;color:#fff;font-size:10px;border-radius:3px;padding:1px 4px">✕</button>'
    + '</div>';
}

function addCodeBlockEditor() {
  var container = document.getElementById('cbs-container');
  if (!container) return;
  var idx = container.querySelectorAll('.cb-editor').length;
  container.insertAdjacentHTML('beforeend', renderCodeBlockEditor({ lang: 'kql', content: '' }, idx));
  container.addEventListener('click', function(e) {
    if (e.target.classList.contains('btn-rm-cb')) e.target.closest('.cb-editor').remove();
  });
}

function addScreenshotUpload(input) {
  var file = input.files[0];
  if (!file) return;
  if (file.size > 3 * 1024 * 1024) { showToast(T('findings.error.image_size'), true); return; }
  var reader = new FileReader();
  reader.onload = function(e) {
    var container = document.getElementById('scs-container');
    if (!container) return;
    var idx = container.querySelectorAll('.sc-thumb').length;
    container.insertAdjacentHTML('beforeend', renderScreenshotThumb({ url: e.target.result, caption: '' }, idx));
    container.addEventListener('click', function(ev) {
      if (ev.target.classList.contains('btn-rm-sc')) ev.target.closest('.sc-thumb').remove();
    });
    input.value = '';
  };
  reader.readAsDataURL(file);
}

async function saveFinding(closeFn) {
  var title = (document.getElementById('f-title') || {}).value;
  if (!title || !title.trim()) { showToast(T('findings.error.title_required'), true); return; }

  var dateVal  = (document.getElementById('f-date') || {}).value;
  var event_at = dateVal ? new Date(dateVal).getTime() : null;

  var code_blocks = [].slice.call(document.querySelectorAll('.cb-editor')).map(function(el) {
    return { lang: el.querySelector('.cb-lang').value, content: el.querySelector('.cb-content').value.trim() };
  }).filter(function(b) { return b.content; });

  var screenshots = [].slice.call(document.querySelectorAll('.sc-thumb')).map(function(el) {
    return { url: (el.querySelector('.sc-data') || {}).value || (el.querySelector('img') || {}).src || '', caption: (el.querySelector('.sc-caption') || {}).value || '' };
  }).filter(function(s) { return s.url; });

  var linkedIocIds = [].slice.call(document.querySelectorAll('.ioc-link-cb:checked')).map(function(cb) { return cb.value; });

  var payload = {
    title:          title.trim(),
    description:    (document.getElementById('f-desc') || {}).value || '',
    severity:       (document.getElementById('f-sev')  || {}).value || 'medium',
    event_type:     (document.getElementById('f-type') || {}).value || 'finding',
    event_at:       event_at,
    code_blocks:    code_blocks,
    screenshots:    screenshots,
    linked_ioc_ids: linkedIocIds
  };

  try {
    if (_ms.findingId) {
      var d = await API.put('/investigations/' + _ms.invId + '/findings/' + _ms.findingId, payload);
      if (d && d.error) { showToast(d.error, true); return; }
      showToast(T('findings.toast.updated'));
    } else {
      var d2 = await API.post('/investigations/' + _ms.invId + '/findings', payload);
      if (d2 && d2.error) { showToast(d2.error, true); return; }
      showToast(T('findings.toast.added'));
    }
    if (closeFn) closeFn();
    await selectInv(_ms.invId);
  } catch(e) {
    showToast(T('findings.error.save'), true);
  }
}

// ─── Drag & drop ─────────────────────────────────────────────────────────────
function bindDragDrop(container) {
  if (!container) return;
  [].slice.call(container.querySelectorAll('.timeline-item[draggable="true"]')).forEach(function(item) {
    item.addEventListener('dragstart', function(e) {
      _dragSrc = item;
      item.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
    });
    item.addEventListener('dragend', function() {
      item.classList.remove('dragging');
      [].slice.call(container.querySelectorAll('.timeline-item')).forEach(function(x) { x.classList.remove('drag-over'); });
    });
    item.addEventListener('dragover', function(e) {
      e.preventDefault();
      if (item !== _dragSrc) item.classList.add('drag-over');
    });
    item.addEventListener('dragleave', function() { item.classList.remove('drag-over'); });
    item.addEventListener('drop', function(e) {
      e.preventDefault();
      item.classList.remove('drag-over');
      if (!_dragSrc || item === _dragSrc) return;
      var items = [].slice.call(container.querySelectorAll('.timeline-item'));
      var si = items.indexOf(_dragSrc), ti = items.indexOf(item);
      // snapshot for rollback
      var snapshot = items.map(function(el) { return el; });
      if (si < ti) item.after(_dragSrc); else item.before(_dragSrc);
      saveTimelineOrder(container.dataset.invId, snapshot);
    });
  });
}

async function saveTimelineOrder(invId, snapshot) {
  var container = document.getElementById('findings-timeline');
  var items = [].slice.call(document.querySelectorAll('#findings-timeline .timeline-item'));
  var order = items.map(function(el, i) { return { id: el.dataset.findingId, display_order: i }; });
  var d = await API.put('/investigations/' + invId + '/findings/reorder', { order: order });
  if (d && d.error) {
    showToast(T('inv.error.order') || 'Reorder failed', true);
    // Rollback DOM to snapshot order
    if (snapshot && container) {
      snapshot.forEach(function(el) { container.appendChild(el); });
    }
    return;
  }
  // Update local state
  if (I.cur && I.cur.findings) {
    order.forEach(function(item) {
      var f = I.cur.findings.find(function(x) { return x.id === item.id; });
      if (f) f.display_order = item.display_order;
    });
  }
}

// ─── IoC edit modal ───────────────────────────────────────────────────────────
function openEditIoC(iocId, invId) {
  var ioc = (I.cur && I.cur.iocs || []).find(function(i) { return i.id === iocId; });
  if (!ioc) return;
  _ms.iocId = iocId;
  _ms.invId  = invId;

  var TYPES = ['ip','hash','domain','url','email','cve','filename','registry','process','useragent','other'];

  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:200;display:flex;align-items:center;justify-content:center;padding:16px';
  ov.innerHTML = '<div style="background:var(--s1);border:1px solid var(--bd);border-radius:14px;width:100%;max-width:480px">'
    + '<div style="padding:16px 22px;border-bottom:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center">'
    + '<h2 style="font-size:16px;margin:0">' + T('iocs.edit.title') + '</h2>'
    + '<button id="imd-close" style="background:none;border:none;color:var(--t4);font-size:22px;cursor:pointer;line-height:1">×</button></div>'
    + '<div style="padding:20px 22px;display:flex;flex-direction:column;gap:14px">'
    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'
    + '<div><label class="lbl">' + T('iocs.edit.label_type') + '</label><select id="ioc-type" style="width:100%">'
    + TYPES.map(function(t) { return '<option value="' + t + '"' + (ioc.type === t ? ' selected' : '') + '>' + t.toUpperCase() + '</option>'; }).join('')
    + '</select></div>'
    + '<div><label class="lbl">' + T('iocs.edit.label_sev') + '</label><select id="ioc-sev" style="width:100%">'
    + ['critical','high','medium','low','info'].map(function(s) { return '<option value="' + s + '"' + ((ioc.severity || 'medium') === s ? ' selected' : '') + '>' + s.charAt(0).toUpperCase() + s.slice(1) + '</option>'; }).join('')
    + '</select></div></div>'
    + '<div><label class="lbl">' + T('iocs.edit.label_val') + '</label><input id="ioc-value" type="text" value="' + esc(ioc.value || '') + '" style="width:100%;font-family:var(--mono);font-size:13px"></div>'
    + '<div><label class="lbl">' + T('iocs.edit.label_desc') + '</label><input id="ioc-desc" type="text" value="' + esc(ioc.context || '') + '" placeholder="' + T('iocs.edit.placeholder_desc') + '" style="width:100%"></div>'
    + '</div>'
    + '<div style="padding:14px 22px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end;gap:8px">'
    + '<button id="imd-cancel">' + T('iocs.edit.btn_cancel') + '</button>'
    + '<button class="pri" id="imd-save">' + T('iocs.edit.btn_save') + '</button>'
    + '</div></div>';

  document.body.appendChild(ov);
  var close = function() { if (document.body.contains(ov)) document.body.removeChild(ov); };
  document.getElementById('imd-close').onclick  = close;
  document.getElementById('imd-cancel').onclick = close;
  ov.onclick = function(e) { if (e.target === ov) close(); };
  document.getElementById('ioc-value').focus();
  document.getElementById('imd-save').onclick = function() { saveIoC(close); };
}

async function saveIoC(closeFn) {
  var value = ((document.getElementById('ioc-value') || {}).value || '').trim();
  if (!value) { showToast(T('iocs.error.val_required'), true); return; }
  try {
    var d = await API.put('/investigations/' + _ms.invId + '/iocs/' + _ms.iocId, {
      type:        (document.getElementById('ioc-type') || {}).value,
      value:       value,
      description: (document.getElementById('ioc-desc') || {}).value || '',
      severity:    (document.getElementById('ioc-sev')  || {}).value || 'medium'
    });
    if (d && d.error) { showToast(d.error, true); return; }
    showToast(T('iocs.toast.updated'));
    if (closeFn) closeFn();
    await selectInv(_ms.invId);
  } catch(e) {
    showToast(T('iocs.error.save'), true);
  }
}

// ─── Lock banner ──────────────────────────────────────────────────────────────
function renderLockBanner(inv) {
  if (!inv.report_locked) return '';
  var lockedDate = inv.locked_at
    ? new Date(inv.locked_at).toLocaleString(i18n.lang, { dateStyle: 'medium', timeStyle: 'short' })
    : '';
  var isAdmin = I.user && I.user.role === 'admin';
  return '<div class="lock-banner">'
    + '<div class="lock-banner-left">' + T('inv.locked.banner')
    + (lockedDate ? T('inv.locked.until', { date: lockedDate }) : '')
    + '. ' + T('inv.locked.no_edit') + '</div>'
    + (isAdmin ? '<button id="btn-unlock-rpt" style="font-size:12px;padding:5px 12px">' + T('inv.locked.unlock') + '</button>' : '')
    + '</div>';
}

var _rptFmt = 'pdf';

// ─── Personnalisation du rapport ──────────────────────────────
function buildReportCustomization() {
  var rs     = _reportSettings || {};
  var logo   = rs.company_logo    || '';
  var name   = rs.company_name    || '';
  var sub    = rs.company_subtitle || '';
  var color  = rs.report_header_color || '#e63946';
  var presets = ['#e63946','#1e3a5f','#0d1b2a','#1a1a2e','#2d6a4f','#7c3aed'];

  var h = '<div class="report-customization" id="report-customization">';

  // Bouton toggle
  h += '<button class="report-custom-toggle" id="rc-toggle" aria-expanded="false" aria-controls="rc-body">'
    + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14" stroke="currentColor" stroke-width="2"/></svg>'
    + ' ' + T('report.custom.toggle')
    + '<svg id="rc-chevron" width="11" height="11" viewBox="0 0 24 24" fill="none" style="margin-left:auto;transition:transform 200ms"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
    + '</button>';

  // Corps (replié par défaut)
  h += '<div class="report-custom-body" id="rc-body" style="display:none">';

  // Aperçu de l'en-tête
  h += '<div class="report-header-preview" id="rc-header-preview" style="background:' + esc(color) + '">';
  if (logo) {
    h += '<img src="' + esc(logo) + '" class="report-header-logo" alt="Logo" id="rc-logo-img">';
  } else {
    h += '<div class="report-header-logo-placeholder" id="rc-logo-placeholder">Logo</div>';
  }
  h += '<div class="report-header-texts">';
  h += '<div class="report-header-company" id="rc-prev-name">' + esc(name || T('report.custom.company_ph')) + '</div>';
  h += '<div class="report-header-sub" id="rc-prev-sub">' + esc(sub || T('report.custom.sub_ph')) + '</div>';
  h += '</div>';
  h += '<div class="report-header-type">' + T('report.header_type') + '</div>';
  h += '</div>';

  // Formulaire
  h += '<div class="report-custom-form">';

  // Nom + Département
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">';
  h += '<div><label class="lbl">' + T('report.custom.company') + '</label><input id="rc-name" type="text" class="input" value="' + esc(name) + '" placeholder="' + T('report.custom.company_ph') + '" style="width:100%"></div>';
  h += '<div><label class="lbl">' + T('report.custom.sub') + '</label><input id="rc-sub" type="text" class="input" value="' + esc(sub) + '" placeholder="' + T('report.custom.sub_ph') + '" style="width:100%"></div>';
  h += '</div>';

  // Couleur de l'en-tête
  h += '<div><label class="lbl">' + T('report.custom.color') + '</label>';
  h += '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">';
  h += '<input type="color" id="rc-color" value="' + esc(color) + '" style="width:44px;height:36px;border-radius:6px;cursor:pointer;border:1px solid var(--bd);padding:2px">';
  h += '<div style="display:flex;gap:5px">';
  presets.forEach(function(c) {
    h += '<button type="button" onclick="document.getElementById(\'rc-color\').value=\'' + c + '\';invUpdateHeaderPreview()" '
      + 'style="width:22px;height:22px;border-radius:50%;background:' + c + ';border:2px solid transparent;cursor:pointer" title="' + c + '"></button>';
  });
  h += '</div></div></div>';

  // Logo upload
  h += '<div><label class="lbl">' + T('report.custom.logo') + '</label>';
  h += '<div style="display:flex;align-items:center;gap:14px">';
  h += '<div id="rc-logo-thumb" style="width:56px;height:56px;border-radius:8px;background:var(--s2);border:1px solid var(--bd);display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0">';
  if (logo) {
    h += '<img src="' + esc(logo) + '" style="max-width:100%;max-height:100%;object-fit:contain">';
  } else {
    h += '<span style="font-size:10px;color:var(--t5);text-align:center">' + T('report.custom.no_logo') + '</span>';
  }
  h += '</div>';
  h += '<div style="display:flex;flex-direction:column;gap:5px">';
  h += '<label for="rc-logo-upload" class="btn btn-secondary btn-sm" style="cursor:pointer;display:inline-flex;align-items:center;gap:5px">' + T('report.custom.upload') + '</label>';
  h += '<input type="file" id="rc-logo-upload" accept="image/png,image/jpeg,image/svg+xml,image/webp" style="display:none">';
  if (logo) {
    h += '<button type="button" class="btn btn-sm" id="rc-logo-remove" style="color:var(--sev-critical,#ef4444)">' + T('report.custom.remove_logo') + '</button>';
  }
  h += '<span style="font-size:10px;color:var(--t5)">' + T('report.custom.logo_hint').replace('\n', '<br>') + '</span>';
  h += '</div></div></div>';

  // Actions
  h += '<div style="display:flex;justify-content:flex-end;gap:8px">';
  h += '<button type="button" class="btn btn-secondary btn-sm" id="rc-reset">' + T('report.custom.btn_reset') + '</button>';
  h += '<button type="button" class="btn btn-primary btn-sm" id="rc-save">' + T('report.custom.btn_save') + '</button>';
  h += '</div>';

  h += '</div>'; // end report-custom-form
  h += '</div>'; // end rc-body
  h += '</div>'; // end report-customization
  return h;
}

function invToggleReportCustom() {
  var body    = document.getElementById('rc-body');
  var chevron = document.getElementById('rc-chevron');
  var btn     = document.getElementById('rc-toggle');
  if (!body) return;
  var isOpen  = body.style.display !== 'none';
  body.style.display  = isOpen ? 'none' : '';
  if (chevron) chevron.style.transform = isOpen ? '' : 'rotate(180deg)';
  if (btn)     btn.setAttribute('aria-expanded', !isOpen);
}

function invUpdateHeaderPreview() {
  var preview = document.getElementById('rc-header-preview');
  if (!preview) return;
  var name  = (document.getElementById('rc-name')  || {}).value || '';
  var sub   = (document.getElementById('rc-sub')   || {}).value || '';
  var color = (document.getElementById('rc-color') || {}).value || '#e63946';
  preview.style.background = color;
  var nameEl = document.getElementById('rc-prev-name');
  var subEl  = document.getElementById('rc-prev-sub');
  if (nameEl) nameEl.textContent = name  || T('report.custom.company_ph');
  if (subEl)  subEl.textContent  = sub   || T('report.custom.sub_ph');
}

function invApplyLogo(dataUrl) {
  _pendingLogo = dataUrl;
  var thumb = document.getElementById('rc-logo-thumb');
  if (thumb) thumb.innerHTML = '<img src="' + esc(dataUrl) + '" style="max-width:100%;max-height:100%;object-fit:contain">';
  var hdr = document.getElementById('rc-header-preview');
  if (hdr) {
    var existing = hdr.querySelector('.report-header-logo, .report-header-logo-placeholder');
    if (existing) {
      var imgEl = document.createElement('img');
      imgEl.src = dataUrl;
      imgEl.className = 'report-header-logo';
      imgEl.alt = 'Logo';
      existing.parentNode.replaceChild(imgEl, existing);
    }
  }
}

function invUploadLogo(input) {
  var file = input.files && input.files[0];
  if (!file) return;

  if (!file.type.startsWith('image/')) {
    showToast(T('findings.error.image_size'), true);
    input.value = '';
    return;
  }

  // Fichiers petits : lecture directe sans resize
  if (file.size <= 200 * 1024) {
    var reader = new FileReader();
    reader.onload = function(e) { invApplyLogo(e.target.result); };
    reader.readAsDataURL(file);
    return;
  }

  // Fichiers plus grands : resize via canvas (max 400×200 px) pour garder le payload raisonnable
  var objectUrl = URL.createObjectURL(file);
  var img = new Image();
  img.onload = function() {
    URL.revokeObjectURL(objectUrl);
    var MAX_W = 400, MAX_H = 200;
    var w = img.width, h = img.height;
    if (w > MAX_W) { h = Math.round(h * MAX_W / w); w = MAX_W; }
    if (h > MAX_H) { w = Math.round(w * MAX_H / h); h = MAX_H; }
    var canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    var ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    var dataUrl = canvas.toDataURL('image/png');
    var sizeKB = Math.round(dataUrl.length * 0.75 / 1024);
    if (sizeKB > 800) {
      showToast(T('findings.error.image_size') + ' (' + sizeKB + ' KB)', true);
      input.value = '';
      return;
    }
    invApplyLogo(dataUrl);
  };
  img.onerror = function() {
    URL.revokeObjectURL(objectUrl);
    showToast(T('error'), true);
    input.value = '';
  };
  img.src = objectUrl;
}

function invRemoveLogo() {
  _pendingLogo = '';
  var thumb = document.getElementById('rc-logo-thumb');
  if (thumb) thumb.innerHTML = '<span style="font-size:10px;color:var(--t5);text-align:center">' + T('report.custom.no_logo') + '</span>';
  var hdr  = document.getElementById('rc-header-preview');
  if (hdr) {
    var img = hdr.querySelector('.report-header-logo');
    if (img) {
      var ph = document.createElement('div');
      ph.className = 'report-header-logo-placeholder';
      ph.id        = 'rc-logo-placeholder';
      ph.textContent = 'Logo';
      img.parentNode.replaceChild(ph, img);
    }
  }
  // Masquer le bouton Supprimer
  var btn = document.getElementById('rc-logo-remove');
  if (btn) btn.style.display = 'none';
}

async function invSaveReportSettings() {
  var payload = {
    company_name:        ((document.getElementById('rc-name')  || {}).value || '').trim(),
    company_subtitle:    ((document.getElementById('rc-sub')   || {}).value || '').trim(),
    report_header_color: ((document.getElementById('rc-color') || {}).value || '#e63946'),
  };
  if (_pendingLogo !== undefined) payload.company_logo = _pendingLogo;

  // Vérification préventive de la taille du payload
  var bodyStr    = JSON.stringify(payload);
  var payloadKB  = Math.round(bodyStr.length / 1024);
  if (bodyStr.length > 1.8 * 1024 * 1024) {
    showToast('Payload trop grand (' + payloadKB + ' KB) — utilisez un logo plus petit.', true);
    return;
  }

  var saveBtn = document.getElementById('rc-save');
  if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = T('report.settings.saving'); }

  try {
    var res = await fetch('/api/settings/report', {
      method:      'PUT',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json' },
      body:        bodyStr,
    });

    var ct = res.headers.get('content-type') || '';
    var text = await res.text();

    if (!ct.includes('application/json')) {
      console.error('[Settings] Réponse non-JSON HTTP', res.status, ':', text.substring(0, 200));
      if (res.status === 413) {
        showToast('Payload trop grand (HTTP 413) — augmentez la limite dans server.js.', true);
      } else if (res.status === 404) {
        showToast('Route introuvable (HTTP 404) — /api/settings non monté dans server.js.', true);
      } else {
        showToast('Erreur HTTP ' + res.status + ' — réponse non-JSON (voir console).', true);
      }
      return;
    }

    var data = JSON.parse(text);
    if (!res.ok) { showToast(data.error || ('Erreur ' + res.status), true); return; }

    // Mettre à jour l'état local
    _reportSettings.company_name        = payload.company_name;
    _reportSettings.company_subtitle    = payload.company_subtitle;
    _reportSettings.report_header_color = payload.report_header_color;
    if (_pendingLogo !== undefined) _reportSettings.company_logo = _pendingLogo;
    _pendingLogo = undefined;
    showToast(T('report.settings.saved'));

  } catch(e) {
    console.error('[Settings] Erreur réseau:', e);
    showToast('Erreur réseau : ' + e.message, true);
  } finally {
    if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = T('report.custom.btn_save'); }
  }
}

function buildReport(inv) {
  var iocs         = inv.iocs     || [];
  var findings     = inv.findings || [];
  var iocCount     = iocs.length;
  var findingCount = findings.length;
  var hasConclusion  = !!(inv.conclusion  && inv.conclusion.trim());
  var hasDescription = !!(inv.description && inv.description.trim());
  var malCount  = iocs.filter(function (i) { return i.malicious; }).length;
  var unknCount = iocCount - malCount;
  var malPct    = iocCount ? Math.round(malCount / iocCount * 100) : 0;
  var sevBrk = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(function (f) { if (sevBrk[f.severity] !== undefined) sevBrk[f.severity]++; });
  var sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  var checks = [hasDescription, iocCount > 0, findingCount > 0, hasConclusion];
  var doneCount = checks.filter(Boolean).length;
  var compPct = Math.round(doneCount / 4 * 100);
  var compColor = compPct === 100 ? '#22c55e' : compPct >= 50 ? '#3b82f6' : '#f97316';
  var checkLabels = [T('report.section_summary'), 'IoCs', T('report.findings'), T('report.section_conclusion')];
  var sevColor = SEV_C[inv.severity] || 'var(--t4)';
  var stObj    = STS[inv.status] || { l: inv.status, c: 'var(--t4)' };
  var R = 18; var circ = +(2 * Math.PI * R).toFixed(2);
  var fill = +(circ * compPct / 100).toFixed(2);
  var gap  = +(circ - fill).toFixed(2);

  var h = '<div class="rpt-controls">';

  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px">';

  h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:12px;padding:16px">';
  h += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t4);margin-bottom:8px">' + T('report.indicators') + '</div>';
  h += '<div style="font-size:28px;font-weight:800;color:#3b82f6;line-height:1;margin-bottom:10px">' + iocCount + '</div>';
  if (iocCount > 0) {
    h += '<div style="height:5px;border-radius:3px;background:var(--bd);overflow:hidden;margin-bottom:7px">';
    h += '<div style="height:100%;width:' + malPct + '%;background:#ef4444;border-radius:3px"></div>';
    h += '</div>';
    h += '<div style="font-size:10px;display:flex;gap:8px">';
    h += '<span style="color:#ef4444;font-weight:700">' + malCount + ' ' + T('report.malicious') + '</span>';
    h += '<span style="color:var(--t5)">' + unknCount + ' ' + T('report.unknown') + '</span>';
    h += '</div>';
  } else { h += '<div style="font-size:10px;color:var(--t5)">' + T('report.no_iocs') + '</div>'; }
  h += '</div>';

  h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:12px;padding:16px">';
  h += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t4);margin-bottom:8px">' + T('report.findings') + '</div>';
  h += '<div style="font-size:28px;font-weight:800;color:#f97316;line-height:1;margin-bottom:10px">' + findingCount + '</div>';
  if (findingCount > 0) {
    h += '<div style="display:flex;height:5px;border-radius:3px;overflow:hidden;margin-bottom:7px;gap:1px">';
    sevOrder.forEach(function (s) { if (sevBrk[s] > 0) h += '<div style="flex:' + sevBrk[s] + ';background:' + SEV_C[s] + '"></div>'; });
    h += '</div>';
    h += '<div style="font-size:10px;display:flex;flex-wrap:wrap;gap:6px">';
    sevOrder.forEach(function (s) { if (sevBrk[s] > 0) h += '<span style="color:' + SEV_C[s] + ';font-weight:700">' + sevBrk[s] + ' ' + s + '</span>'; });
    h += '</div>';
  } else { h += '<div style="font-size:10px;color:var(--t5)">' + T('report.no_findings') + '</div>'; }
  h += '</div>';

  var sevBg = (SEV_C[inv.severity] || '#9ca3af') + '1a';
  var sevBd = (SEV_C[inv.severity] || '#9ca3af') + '44';
  h += '<div style="background:' + sevBg + ';border:1px solid ' + sevBd + ';border-radius:12px;padding:16px">';
  h += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t4);margin-bottom:8px">' + T('report.severity') + '</div>';
  h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">';
  h += '<div style="width:12px;height:12px;border-radius:50%;background:' + sevColor + ';flex-shrink:0;box-shadow:0 0 8px ' + sevColor + '88"></div>';
  h += '<div style="font-size:22px;font-weight:800;color:' + sevColor + '">' + (inv.severity || '—').toUpperCase() + '</div>';
  h += '</div>';
  h += '<div style="font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;display:inline-block;background:' + stObj.c + '22;color:' + stObj.c + '">' + stObj.l + '</div>';
  h += '</div>';

  h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:12px;padding:16px">';
  h += '<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t4);margin-bottom:8px">' + T('report.completeness') + '</div>';
  h += '<div style="display:flex;align-items:center;gap:12px">';
  h += '<svg width="44" height="44" viewBox="0 0 48 48" style="flex-shrink:0">';
  h += '<circle cx="24" cy="24" r="' + R + '" fill="none" stroke="var(--bd)" stroke-width="5"/>';
  h += '<circle cx="24" cy="24" r="' + R + '" fill="none" stroke="' + compColor + '" stroke-width="5"';
  h += ' stroke-dasharray="' + fill + ' ' + gap + '" stroke-linecap="round" transform="rotate(-90 24 24)"/>';
  h += '<text x="24" y="29" text-anchor="middle" font-size="11" font-weight="800" fill="' + compColor + '">' + compPct + '%</text>';
  h += '</svg>';
  h += '<div style="display:flex;flex-direction:column;gap:5px">';
  checks.forEach(function (ok, i) {
    h += '<div style="font-size:10px;display:flex;align-items:center;gap:5px">';
    h += '<span style="font-size:11px;font-weight:800;color:' + (ok ? '#22c55e' : 'var(--t5)') + ';">' + (ok ? '✓' : '○') + '</span>';
    h += '<span style="color:' + (ok ? 'var(--t2)' : 'var(--t5)') + '">' + checkLabels[i] + '</span>';
    h += '</div>';
  });
  h += '</div></div>';
  h += '</div>';
  h += '</div>';

  h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:16px 18px;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">';
  h += '<div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--t4)">' + T('report.label_format') + '</div>';
  h += '<div style="display:flex;gap:8px">';
  h += '<button class="rpt-format-btn' + (_rptFmt === 'pdf' ? ' selected' : '') + '" id="fmt-pdf">📄 PDF<span style="font-size:10px;opacity:.6;margin-left:5px">(.pdf)</span></button>';
  h += '<button class="rpt-format-btn' + (_rptFmt === 'docx' ? ' selected' : '') + '" id="fmt-docx">📝 Word<span style="font-size:10px;opacity:.6;margin-left:5px">(.docx)</span></button>';
  h += '</div></div>';

  if (!hasConclusion) {
    h += '<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:#78350f18;border:1px solid #78350f40;border-radius:8px;margin-bottom:14px;font-size:13px;color:#fcd34d">';
    h += '<span>⚠️</span><span>' + T('report.conclusion_empty') + '</span>';
    h += '</div>';
  }

  h += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;align-items:center">';
  h += '<button class="rpt-dl-btn" id="btn-download-rpt">' + T('report.btn_download') + '</button>';
  h += '<button id="btn-preview-rpt" style="font-size:13px;font-weight:600;padding:10px 18px;border-radius:9px">' + T('report.btn_preview') + '</button>';
  h += '<button id="btn-copy-md" style="font-size:13px;padding:10px 16px;border-radius:9px">' + T('report.btn_copy_md') + '</button>';
  h += '</div>';

  h += '</div>'; // end rpt-controls

  // Section personnalisation du rapport (admin uniquement)
  if (I.user && I.user.role === 'admin') {
    h += buildReportCustomization();
  }

  // En-tête rapport affiché si des settings sont configurés
  var _rs = _reportSettings || {};
  if (_rs.company_name || _rs.report_header_color) {
    var _rhColor = _rs.report_header_color || '#e63946';
    h += '<div class="report-header-preview" style="background:' + esc(_rhColor) + ';margin-bottom:14px">';
    if (_rs.company_logo) {
      h += '<img src="' + esc(_rs.company_logo) + '" class="report-header-logo" alt="' + esc(_rs.company_name || '') + '">';
    } else {
      h += '<div class="report-header-logo-placeholder">Logo</div>';
    }
    h += '<div class="report-header-texts">';
    if (_rs.company_name) h += '<div class="report-header-company">' + esc(_rs.company_name) + '</div>';
    if (_rs.company_subtitle) h += '<div class="report-header-sub">' + esc(_rs.company_subtitle) + '</div>';
    h += '</div>';
    h += '<div class="report-header-type">' + T('report.header_type') + '</div>';
    h += '</div>';
  }

  // Aperçu rendu (HTML) des sections principales
  h += '<div class="rpt-preview">';
  if (typeof RichEditor !== 'undefined') {
    if (inv.description && inv.description.trim()) {
      h += '<div class="rpt-section">';
      h += '<div class="rpt-preview-label">' + T('report.section_summary') + '</div>';
      h += '<div class="rpt-md-body">' + RichEditor.mdToHtml(inv.description) + '</div>';
      h += '</div>';
    }
    if (inv.conclusion && inv.conclusion.trim()) {
      h += '<div class="rpt-section" style="border-left:3px solid #22c55e40;padding-left:14px">';
      h += '<div class="rpt-preview-label">' + T('report.section_conclusion') + '</div>';
      h += '<div class="rpt-md-body">' + RichEditor.mdToHtml(inv.conclusion) + '</div>';
      h += '</div>';
    }
    if (!inv.description && !inv.conclusion) {
      h += '<div class="rpt-preview-label" style="padding:20px 0">' + T('report.complete_overview') + '</div>';
    }
  } else {
    h += '<div class="rpt-preview-label">Markdown preview</div>';
    h += '<div class="report-pre" id="rpt-content">' + esc(genReport(inv)) + '</div>';
  }
  h += '</div>';
  return h;
}

// ─── Report preview section (bottom of document, used for CSS print) ──────────
function buildSectionReportPreview(inv) {
  var previewHtml = buildPreviewHTML(inv);
  // Wrap in the light-theme preview container
  var h = '<div class="inv-report-preview-wrap" id="inv-report-preview">';
  h += previewHtml;
  h += '</div>';
  return h;
}

// ─── Filters render (active state) ───────────────────────────
function renderFilters() {
  document.querySelectorAll('#inv-filters .inv-filter-btn').forEach(function (btn) {
    btn.classList.toggle('active', btn.getAttribute('data-status') === I.statusFilter);
  });
}

// ─── Full render ──────────────────────────────────────────────
function render() {
  renderFilters();
  renderSidebar();
  bindSidebar();
  renderMain();
  bindMain();
  renderRight();
}

// ─── Bind sidebar list ────────────────────────────────────────
function bindSidebar() {
  document.querySelectorAll('#inv-list [data-inv]').forEach(function (x) {
    x.addEventListener('click', function () { selectInv(x.getAttribute('data-inv')); });
  });
}

// ─── Inline header auto-save ──────────────────────────────────
async function saveInvMeta(opts) {
  if (!I.cur) return;
  opts = opts || {};
  var titleEl  = document.getElementById('inv-title-inline');
  var statusEl = document.getElementById('inv-status-inline');
  var sevEl    = document.getElementById('inv-sev-inline');
  var title    = titleEl ? (titleEl.textContent || '').trim() : I.cur.title;
  var status   = statusEl ? statusEl.value : I.cur.status;
  var severity = sevEl    ? sevEl.value    : I.cur.severity;
  if (!title) { if (titleEl) titleEl.textContent = I.cur.title; return; }

  showSaveIndicator('saving');
  var d = await API.put('/investigations/' + I.cur.id, {
    title, status, severity,
    description: I.cur.description || '',
    conclusion:  I.cur.conclusion  || ''
  });
  if (d && d.error) { showSaveIndicator(''); showToast(d.error, true); return; }

  var changed = title !== I.cur.title || status !== I.cur.status || severity !== I.cur.severity;
  I.cur.title    = title;
  I.cur.status   = status;
  I.cur.severity = severity;
  if (d.report_locked !== undefined) I.cur.report_locked = d.report_locked ? 1 : 0;
  var bc = document.getElementById('inv-breadcrumb');
  if (bc) bc.textContent = title;
  showSaveIndicator('saved');
  if (changed) { await loadList(); renderSidebar(); bindSidebar(); }
}

// ─── Classic section save (description / conclusion) ─────────
async function saveClassicSection(field, value) {
  if (!I.cur) return;
  showSaveIndicator('saving');
  var payload = {
    title:       I.cur.title,
    status:      I.cur.status,
    severity:    I.cur.severity,
    description: I.cur.description || '',
    conclusion:  I.cur.conclusion  || ''
  };
  payload[field] = value;
  var d = await API.put('/investigations/' + I.cur.id, payload);
  if (d && d.error) { showSaveIndicator(''); showToast(d.error, true); return; }
  I.cur[field] = value;
  showSaveIndicator('saved');
}

// ─── Bind main panel ─────────────────────────────────────────
function bindMain() {
  if (!I.cur) return elOn('btn-new-inv2', function () { openNewModal(); });

  // ── Inline header bindings ───────────────────────────────────
  var titleEl = document.getElementById('inv-title-inline');
  if (titleEl) {
    titleEl.addEventListener('blur', function() {
      if (_saveDebounce) clearTimeout(_saveDebounce);
      saveInvMeta();
    });
    titleEl.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); titleEl.blur(); }
      if (e.key === 'Escape') { titleEl.textContent = I.cur.title; titleEl.blur(); }
    });
    titleEl.addEventListener('input', function() {
      if (_saveDebounce) clearTimeout(_saveDebounce);
      _saveDebounce = setTimeout(saveInvMeta, 800);
    });
  }
  var statusEl = document.getElementById('inv-status-inline');
  if (statusEl) statusEl.addEventListener('change', function() { saveInvMeta(); });
  var sevEl = document.getElementById('inv-sev-inline');
  if (sevEl) sevEl.addEventListener('change', function() { saveInvMeta(); });

  // Close / lock investigation
  elOn('btn-close-inv', async function() {
    if (!confirm('Close this investigation? It will be locked for editing.')) return;
    var d = await API.put('/investigations/' + I.cur.id, {
      title: I.cur.title, status: 'closed', severity: I.cur.severity,
      description: I.cur.description || '', conclusion: I.cur.conclusion || ''
    });
    if (d && d.error) return showToast(d.error, true);
    I.cur.status = 'closed';
    I.cur.report_locked = 1;
    await loadList();
    render();
    showToast('Investigation closed.');
  });

  elOn('btn-del-inv', async function () {
    if (!confirm(T('inv.delete.confirm'))) return;
    var d = await API.del('/investigations/' + I.cur.id);
    if (d && d.error) return showToast(d.error, true);
    I.cur = null;
    var bc = document.getElementById('inv-breadcrumb');
    if (bc) bc.textContent = T('inv.title');
    await loadList();
    render();
    showToast(T('inv.deleted'));
  });

  // Unlock report (admin only)
  elOn('btn-unlock-rpt', async function () {
    if (!confirm(T('inv.unlock.confirm'))) return;
    var d = await API.post('/investigations/' + I.cur.id + '/unlock');
    if (d && d.error) return showToast(d.error, true);
    I.cur.report_locked = 0;
    I.cur.locked_at = null;
    showToast(T('inv.unlocked'));
    await loadList();
    renderMain(); bindMain(); renderRight();
  });

  // ── PDF / DOCX / HTML / Preview ──────────────────────────────
  async function _downloadReport(format, btnId, label) {
    var btn = document.getElementById(btnId);
    if (btn) { btn.disabled = true; btn.textContent = '⏳...'; }
    try {
      var resp = await fetch('/api/investigations/' + I.cur.id + '/report?format=' + format, { credentials: 'same-origin' });
      if (!resp.ok) { var err = await resp.json().catch(function() { return { error: 'Server error' }; }); showToast(err.error || 'Server error', true); return; }
      var blob = await resp.blob();
      var url  = URL.createObjectURL(blob);
      var a    = document.createElement('a');
      a.href   = url;
      a.download = 'report_' + I.cur.title.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').slice(0, 50) + '.' + format;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      showToast(label + ' downloaded ✓');
    } catch(e) { showToast('Error generating ' + label, true); }
    finally { if (btn) { btn.disabled = false; btn.textContent = '⬇ ' + label; } }
  }

  elOn('btn-print-pdf',  function() { _downloadReport('pdf',  'btn-print-pdf',  'PDF');  });
  elOn('btn-dl-docx',    function() { _downloadReport('docx', 'btn-dl-docx',    'DOCX'); });
  elOn('btn-dl-html',    function() { _downloadReport('html', 'btn-dl-html',    'HTML'); });

  // ── Classic richtext editors (summary / conclusion sections) ─
  if (typeof RichEditor !== 'undefined') {
    if (document.getElementById('re-container-__summary')) {
      RichEditor.create({
        containerId: 're-container-__summary',
        textareaId:  'inv-sec-__summary',
        label:       (T('report.section_summary') || 'Executive Summary').toUpperCase(),
        placeholder: T('inv.field.desc_ph') || 'Executive summary…',
        rows: 10,
        value: I.cur.description || ''
      });
      setTimeout(function() {
        var ta = document.getElementById('inv-sec-__summary');
        if (ta) ta.addEventListener('blur', function() { saveClassicSection('description', ta.value); });
      }, 300);
    }
    if (document.getElementById('re-container-__conclusion')) {
      RichEditor.create({
        containerId: 're-container-__conclusion',
        textareaId:  'inv-sec-__conclusion',
        label:       (T('report.section_conclusion') || 'Conclusion').toUpperCase(),
        placeholder: T('inv.field.conc_ph') || 'Conclusion…',
        rows: 6,
        value: I.cur.conclusion || ''
      });
      setTimeout(function() {
        var ta = document.getElementById('inv-sec-__conclusion');
        if (ta) ta.addEventListener('blur', function() { saveClassicSection('conclusion', ta.value); });
      }, 300);
    }
  }

  // ── IoC add (single) ─────────────────────────────────────────
  elOn('btn-add-ioc', async function () {
    var v = val('ioc-val').trim(); if (!v) return showToast(T('iocs.error.val_required'), true);
    var d = await API.post('/investigations/' + I.cur.id + '/iocs', { type: val('ioc-type'), value: v, context: val('ioc-ctx'), malicious: (document.getElementById('ioc-mal') || {}).checked });
    if (d && d.error) return showToast(d.error, true);
    I.cur.iocs.push(d);
    var iocVal = document.getElementById('ioc-val');
    if (iocVal) iocVal.value = '';
    renderMain(); bindMain(); renderRight(); showToast(T('iocs.toast.added'));
  });

  // ── Bulk IoC add ──────────────────────────────────────────────
  elOn('btn-bulk-add-ioc', async function() {
    var ta  = document.getElementById('ioc-bulk');
    if (!ta || !ta.value.trim()) return;
    var lines = ta.value.split('\n').map(function(l) { return l.trim(); }).filter(Boolean);
    if (!lines.length) return;
    var items = lines.map(function(v) { return { type: detectIocType(v), value: v, malicious: false, severity: 'medium' }; });
    var d = await API.post('/investigations/' + I.cur.id + '/iocs/bulk', { items });
    if (d && d.error) return showToast(d.error, true);
    ta.value = '';
    await selectInv(I.cur.id);
    showToast('Added ' + (d.created || 0) + ' IoC(s)');
  });

  elOn('btn-bulk-clear', function() { var ta = document.getElementById('ioc-bulk'); if (ta) ta.value = ''; });

  // ── IoC filter chips ──────────────────────────────────────────
  document.querySelectorAll('[data-ioc-ftype]').forEach(function(x) {
    x.addEventListener('click', function() { I.iocFilterType = x.getAttribute('data-ioc-ftype'); renderMain(); bindMain(); });
  });
  document.querySelectorAll('[data-ioc-fverdict]').forEach(function(x) {
    x.addEventListener('click', function() { I.iocFilterVerdict = x.getAttribute('data-ioc-fverdict'); renderMain(); bindMain(); });
  });

  // ── IoC column sort ───────────────────────────────────────────
  document.querySelectorAll('.ioc-tbl th[data-sort]').forEach(function(th) {
    th.addEventListener('click', function() {
      var col = th.getAttribute('data-sort');
      if (I.iocSort.col === col) {
        I.iocSort.dir = I.iocSort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        I.iocSort = { col: col, dir: 'asc' };
      }
      renderMain(); bindMain();
    });
  });

  // ── IoC checkboxes ────────────────────────────────────────────
  elOn('ioc-sel-all', function() {
    var checked = (document.getElementById('ioc-sel-all') || {}).checked;
    document.querySelectorAll('.ioc-sel-cb').forEach(function(cb) {
      cb.checked = checked;
      var id = cb.getAttribute('data-ioc-id');
      if (checked) { if (I.selectedIocs.indexOf(id) < 0) I.selectedIocs.push(id); }
      else { I.selectedIocs = I.selectedIocs.filter(function(x) { return x !== id; }); }
    });
    var cntEl = document.getElementById('ioc-sel-count');
    if (cntEl) cntEl.textContent = I.selectedIocs.length;
  });

  document.querySelectorAll('.ioc-sel-cb').forEach(function(cb) {
    cb.addEventListener('change', function() {
      var id = cb.getAttribute('data-ioc-id');
      if (cb.checked) { if (I.selectedIocs.indexOf(id) < 0) I.selectedIocs.push(id); }
      else { I.selectedIocs = I.selectedIocs.filter(function(x) { return x !== id; }); }
      var cntEl = document.getElementById('ioc-sel-count');
      if (cntEl) cntEl.textContent = I.selectedIocs.length;
    });
  });

  // ── Bulk IoC delete ───────────────────────────────────────────
  elOn('btn-bulk-del-iocs', async function() {
    if (!I.selectedIocs.length) return showToast('No IoCs selected', true);
    if (!confirm('Delete ' + I.selectedIocs.length + ' IoC(s)?')) return;
    var d = await API.del('/investigations/' + I.cur.id + '/iocs/bulk', { ids: I.selectedIocs });
    if (d && d.error) return showToast(d.error, true);
    I.cur.iocs = I.cur.iocs.filter(function(ioc) { return I.selectedIocs.indexOf(ioc.id) < 0; });
    I.selectedIocs = [];
    renderMain(); bindMain(); renderRight(); showToast('Deleted');
  });

  document.querySelectorAll('[data-ioc-toggle]').forEach(function (x) {
    x.addEventListener('click', async function () {
      var id = x.getAttribute('data-ioc-toggle'), curMal = x.getAttribute('data-mal') === '1';
      var ioc = (I.cur.iocs || []).find(function (i) { return i.id === id; });
      if (!ioc) return;
      var d = await API.put('/investigations/' + I.cur.id + '/iocs/' + id, { malicious: !curMal, context: ioc.context || '' });
      if (d && d.error) return showToast(d.error, true);
      ioc.malicious = curMal ? 0 : 1; renderMain(); bindMain(); renderRight();
    });
  });

  document.querySelectorAll('[data-edit-ioc]').forEach(function (x) {
    x.addEventListener('click', function () {
      openEditIoC(x.getAttribute('data-edit-ioc'), I.cur.id);
    });
  });

  document.querySelectorAll('[data-del-ioc]').forEach(function (x) {
    x.addEventListener('click', async function () {
      if (!confirm(T('inv.delete.confirm'))) return;
      var id = x.getAttribute('data-del-ioc');
      var d = await API.del('/investigations/' + I.cur.id + '/iocs/' + id);
      if (d && d.error) return showToast(d.error, true);
      I.cur.iocs = I.cur.iocs.filter(function (i) { return i.id !== id; });
      renderMain(); bindMain(); renderRight(); showToast(T('iocs.toast.deleted'));
    });
  });

  document.querySelectorAll('[data-enrich-ioc]').forEach(function (x) {
    x.addEventListener('click', async function () {
      var iocId = x.getAttribute('data-enrich-ioc');
      var orig = x.textContent;
      x.textContent = '⏳ Enriching…';
      x.disabled = true;
      var d = await API.post('/investigations/' + I.cur.id + '/iocs/' + iocId + '/enrich', {});
      if (d && d.error) { showToast(d.error, true); x.textContent = orig; x.disabled = false; return; }
      // Update local IoC with persisted enrich_result
      var ioc = (I.cur.iocs || []).find(function(i) { return i.id === iocId; });
      if (ioc) {
        ioc.enrich_result = d.enrich_result || JSON.stringify({ verdict: d.verdict, results: d.results, date: Date.now() });
        if (d.verdict === 'malicious') ioc.malicious = 1;
      }
      renderMain(); bindMain(); renderRight();
      showToast('Enrichment complete — ' + (d.verdict || 'unknown'), d.verdict === 'malicious');
    });
  });

  elOn('btn-copy-iocs', function () {
    var text = (I.cur.iocs || []).map(function (i) { return ((IOC[i.type] || {}).l || i.type) + ': ' + i.value + (i.context ? ' [' + i.context + ']' : '') + (i.malicious ? ' ← MALICIOUS' : ''); }).join('\n');
    navigator.clipboard.writeText(text).then(function () { showToast(T('copied')); });
  });

  // ─── Timeline Findings ──────────────────────────────────────────────────────
  elOn('btn-add-fnd', function () { openAddFinding(I.cur.id); });
  elOn('btn-add-fnd-empty', function (e) { e.preventDefault(); openAddFinding(I.cur.id); });

  document.querySelectorAll('[data-edit-fnd]').forEach(function (x) {
    x.addEventListener('click', function () {
      var id = x.getAttribute('data-edit-fnd');
      var f  = (I.cur.findings || []).find(function(f) { return f.id === id; });
      if (f) openAddFinding(I.cur.id, f);
    });
  });

  document.querySelectorAll('[data-del-fnd]').forEach(function (x) {
    x.addEventListener('click', async function (e) {
      e.stopPropagation();
      if (!confirm(T('inv.delete.confirm'))) return;
      var id = x.getAttribute('data-del-fnd');
      var d  = await API.del('/investigations/' + I.cur.id + '/findings/' + id);
      if (d && d.error) return showToast(d.error, true);
      I.cur.findings = (I.cur.findings || []).filter(function (f) { return f.id !== id; });
      renderMain(); bindMain(); renderRight(); showToast(T('findings.toast.deleted'));
    });
  });

  // Drag & drop binding for timeline
  var tl = document.getElementById('findings-timeline');
  if (tl) bindDragDrop(tl);

  // Code block copy buttons
  document.querySelectorAll('.btn-copy-cb').forEach(function (x) {
    x.addEventListener('click', function () {
      var code = x.getAttribute('data-code') || '';
      navigator.clipboard.writeText(code).then(function() { showToast(T('copied')); });
    });
  });

  // Screenshot lightbox
  document.querySelectorAll('.screenshot-wrap[data-url]').forEach(function (x) {
    x.addEventListener('click', function () {
      var url = x.getAttribute('data-url');
      if (!url) return;
      var ov = document.createElement('div');
      ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:999;display:flex;align-items:center;justify-content:center;cursor:zoom-out';
      ov.innerHTML = '<img src="' + esc(url) + '" style="max-width:90vw;max-height:90vh;border-radius:8px;box-shadow:0 4px 40px rgba(0,0,0,.6)">';
      ov.onclick = function() { document.body.removeChild(ov); };
      document.body.appendChild(ov);
    });
  });

  // ── Personnalisation du rapport (admin) ──────────────────────
  elOn('rc-toggle', invToggleReportCustom);
  elOn('rc-save', invSaveReportSettings);
  elOn('rc-logo-remove', invRemoveLogo);
  elOn('rc-reset', function () { _pendingLogo = undefined; invToggleReportCustom(); renderMain(); bindMain(); });
  var rcColor = document.getElementById('rc-color');
  if (rcColor) rcColor.addEventListener('input', invUpdateHeaderPreview);
  var rcName  = document.getElementById('rc-name');
  if (rcName)  rcName.addEventListener('input',  invUpdateHeaderPreview);
  var rcSub   = document.getElementById('rc-sub');
  if (rcSub)   rcSub.addEventListener('input',   invUpdateHeaderPreview);
  var rcLogo  = document.getElementById('rc-logo-upload');
  if (rcLogo)  rcLogo.addEventListener('change',  function() { invUploadLogo(this); });

  elOn('fmt-pdf', function () {
    _rptFmt = 'pdf';
    document.querySelectorAll('.rpt-format-btn').forEach(function (b) { b.classList.remove('selected'); });
    var b = document.getElementById('fmt-pdf'); if (b) b.classList.add('selected');
  });
  elOn('fmt-docx', function () {
    _rptFmt = 'docx';
    document.querySelectorAll('.rpt-format-btn').forEach(function (b) { b.classList.remove('selected'); });
    var b = document.getElementById('fmt-docx'); if (b) b.classList.add('selected');
  });

  elOn('btn-download-rpt', async function () {
    var btn = document.getElementById('btn-download-rpt');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Generating...'; }
    try {
      var resp = await fetch('/api/investigations/' + I.cur.id + '/report?format=' + _rptFmt, { credentials: 'same-origin' });
      if (!resp.ok) {
        var err = await resp.json().catch(function () { return { error: 'Server error' }; });
        showToast(err.error || 'Server error', true);
        return;
      }
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'report_' + I.cur.title.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').slice(0, 50) + '.' + _rptFmt;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Report ' + _rptFmt.toUpperCase() + ' downloaded ✓');
    } catch (e) {
      showToast('Error generating report', true);
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '⬇ Download report'; }
    }
  });

  elOn('btn-preview-rpt', function () {
    var ov = document.createElement('div');
    ov.className = 'preview-overlay';
    var inv = I.cur;
    var previewContent = buildPreviewHTML(inv);
    ov.innerHTML =
      '<div class="preview-modal">'
      + '<div class="preview-hdr">'
      + '<div style="display:flex;align-items:center;gap:10px">'
      + '<span style="color:#dc2626;font-size:15px;font-weight:900">KQL</span><span style="color:#ef4444;font-size:15px;font-weight:900">Vault</span>'
      + '<span style="color:#6b7280;font-size:12px;margin-left:4px">— Report preview</span></div>'
      + '<div style="display:flex;align-items:center;gap:8px">'
      + '<span style="font-size:12px;color:#6b7280">This view reflects the PDF/DOCX content</span>'
      + '<button id="pv-close" style="background:none;border:none;color:#9ca3af;font-size:22px;cursor:pointer;line-height:1">×</button>'
      + '</div></div>'
      + '<div class="preview-body">' + previewContent + '</div>'
      + '<div style="padding:12px 20px;background:#f9fafb;border-top:1px solid #e5e7eb;display:flex;justify-content:space-between;align-items:center;flex-shrink:0">'
      + '<span style="font-size:12px;color:#6b7280">' + esc(inv.title) + '</span>'
      + '<div style="display:flex;gap:8px">'
      + '<button id="pv-dl-pdf"  style="font-size:12px;padding:6px 14px;border-radius:7px;background:#dc2626;color:#fff;border:none;cursor:pointer;font-weight:700">⬇ PDF</button>'
      + '<button id="pv-dl-docx" style="font-size:12px;padding:6px 14px;border-radius:7px;background:#2563eb;color:#fff;border:none;cursor:pointer;font-weight:700">⬇ DOCX</button>'
      + '<button id="pv-close2"  style="font-size:12px;padding:6px 14px;border-radius:7px">Close</button>'
      + '</div></div>'
      + '</div>';
    document.body.appendChild(ov);
    if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(ov); });
    var close = function () { if (document.body.contains(ov)) document.body.removeChild(ov); };
    document.getElementById('pv-close').onclick = close;
    document.getElementById('pv-close2').onclick = close;
    ov.onclick = function (e) { if (e.target === ov) close(); };
    async function dlFrom(fmt) {
      var resp = await fetch('/api/investigations/' + I.cur.id + '/report?format=' + fmt, { credentials: 'same-origin' });
      if (!resp.ok) { showToast('Generation error', true); return; }
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = 'report_' + I.cur.title.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').slice(0, 50) + '.' + fmt;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      showToast('Report ' + fmt.toUpperCase() + ' downloaded ✓');
    }
    document.getElementById('pv-dl-pdf').onclick  = function () { dlFrom('pdf'); };
    document.getElementById('pv-dl-docx').onclick = function () { dlFrom('docx'); };
  });

  elOn('btn-copy-md', function () {
    navigator.clipboard.writeText(genReport(I.cur)).then(function () { showToast(T('copied')); });
  });

  // ── Tab bar navigation ───────────────────────────────────────
  document.querySelectorAll('[data-sec-tab]').forEach(function(tab) {
    tab.addEventListener('click', function() {
      _activeSecId = tab.getAttribute('data-sec-tab');
      renderMain(); bindMain();
    });
  });

  if (I.cur) bindSectionInteractions();
}

// ─── New investigation modal ──────────────────────────────────
function openNewModal() {
  var TYPE_ICONS = { blueteam:'🔵', redteam:'🔴', vapt:'🟠', phishing:'🎣', audit:'✅', custom:'📋' };
  var TYPE_COLORS = { blueteam:'#3b82f6', redteam:'#ef4444', vapt:'#f97316', phishing:'#a855f7', audit:'#22c55e', custom:'#6b7280' };
  var TYPE_LABELS = { blueteam:'SOC / Blue Team', redteam:'Red Team', vapt:'VAPT', phishing:'Phishing Sim', audit:'Security Audit', custom:'Custom' };

  // Determine default template
  var defaultTpl = I.templates.find(function(t) { return t.is_default; }) || I.templates[0] || null;

  var ov = document.createElement('div');
  ov.className = 'inv-modal-overlay';

  // Build mission type pills
  var allTypes = Object.keys(TYPE_ICONS);
  var typePills = allTypes.map(function(t) {
    var c = TYPE_COLORS[t];
    return '<button type="button" class="mission-type-btn" data-mtype="' + t + '" '
      + 'style="padding:7px 14px;border-radius:20px;border:2px solid ' + c + '44;background:none;color:var(--t3);cursor:pointer;font-size:12px;font-weight:600;transition:all .15s"'
      + ' onclick="selectMissionType(this)">'
      + TYPE_ICONS[t] + ' ' + TYPE_LABELS[t]
      + '</button>';
  }).join('');

  // Build template dropdown options
  var tplOptions = I.templates.map(function(t) {
    return '<option value="' + t.id + '"' + (defaultTpl && t.id === defaultTpl.id ? ' selected' : '') + '>' + esc(t.icon + ' ' + t.name) + '</option>';
  }).join('');
  if (!tplOptions) tplOptions = '<option value="">— No templates available —</option>';

  ov.innerHTML = '<div class="inv-modal inv-modal--sm">'
    + '<div class="inv-modal-hdr">'
    + '<h2 class="inv-modal-title">' + T('inv.modal.title') + '</h2>'
    + '<button class="inv-modal-close" id="mdl-close">' + I_X + '</button></div>'
    + '<div class="inv-modal-body">'
    // Mission type selector
    + '<div>'
    + '<div class="lbl" style="margin-bottom:8px">' + T('inv.modal.mission_type') + '</div>'
    + '<div id="mission-type-pills" style="display:flex;flex-wrap:wrap;gap:7px">' + typePills + '</div>'
    + '<input type="hidden" id="new-mtype" value="">'
    + '</div>'
    // Title
    + '<div><label class="lbl">' + T('inv.modal.title_field') + '</label><input id="new-title" placeholder="Ex: APT28 Phishing Wave Q1 2026 / Incident #42 Ransomware..." style="width:100%;font-size:14px" autofocus></div>'
    // Client + severity / template row
    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'
    + '<div><label class="lbl">' + T('inv.modal.client') + '</label><input id="new-client" placeholder="ACME Corp" style="width:100%"></div>'
    + '<div><label class="lbl">' + T('inv.modal.severity') + '</label><select id="new-sev" style="width:100%"><option value="critical">🔴 Critical</option><option value="high">🟠 High</option><option value="medium" selected>🟡 Medium</option><option value="low">🟢 Low</option><option value="info">🔵 Info</option></select></div>'
    + '</div>'
    // Template selector
    + '<div><label class="lbl">' + T('inv.modal.template') + '</label><select id="new-tpl" style="width:100%">'
    + '<option value="">' + T('inv.modal.no_template') + '</option>'
    + tplOptions
    + '</select></div>'
    // Error
    + '<div id="new-inv-err" class="err" style="display:none"></div>'
    + '</div>'
    + '<div class="inv-modal-footer">'
    + '<button id="mdl-cancel">' + T('cancel') + '</button>'
    + '<button class="pri" id="mdl-create">' + I_PLUS + ' ' + T('inv.modal.create_btn') + '</button>'
    + '</div></div>';

  document.body.appendChild(ov);

  // Mission type pill click handler (global scope needed for inline onclick)
  window.selectMissionType = function(btn) {
    document.querySelectorAll('.mission-type-btn').forEach(function(b) {
      b.style.background = 'none';
      b.style.color = 'var(--t3)';
      b.style.borderColor = TYPE_COLORS[b.getAttribute('data-mtype')] + '44';
    });
    var t = btn.getAttribute('data-mtype');
    var c = TYPE_COLORS[t] || '#6b7280';
    btn.style.background = c + '20';
    btn.style.color = c;
    btn.style.borderColor = c;
    document.getElementById('new-mtype').value = t;
    // Auto-select matching template
    var matchTpl = I.templates.find(function(tpl) { return tpl.type === t; });
    var sel = document.getElementById('new-tpl');
    if (matchTpl && sel) sel.value = matchTpl.id;
  };

  var close = function () { if (document.body.contains(ov)) document.body.removeChild(ov); };
  document.getElementById('mdl-close').onclick  = close;
  document.getElementById('mdl-cancel').onclick = close;
  ov.onclick = function (e) { if (e.target === ov) close(); };
  document.getElementById('new-title').focus();

  document.getElementById('mdl-create').onclick = async function () {
    var title = (document.getElementById('new-title') || { value: '' }).value.trim();
    var errEl = document.getElementById('new-inv-err');
    function showErr(msg) { if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; } }
    if (!title) return showErr(T('inv.modal.title_required'));
    var btn = document.getElementById('mdl-create');
    if (btn) { btn.disabled = true; btn.textContent = T('inv.modal.creating'); }
    try {
      var tplVal = (document.getElementById('new-tpl') || {}).value || '';
      var d = await API.post('/investigations', {
        title:       title,
        severity:    val('new-sev'),
        status:      'open',
        template_id: tplVal ? parseInt(tplVal) : null,
        client_name: (document.getElementById('new-client') || { value: '' }).value,
        mission_type: (document.getElementById('new-mtype') || { value: '' }).value || null,
      });
      if (!d || d.error) {
        showErr(d && d.error ? d.error : T('error'));
        if (btn) { btn.disabled = false; btn.textContent = T('inv.modal.create_btn'); }
        return;
      }
      close();
      await loadList();
      await selectInv(d.id);
    } catch (e) {
      showErr(T('error') + ': ' + e.message);
      if (btn) { btn.disabled = false; btn.textContent = T('inv.modal.create_btn'); }
    }
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEMPLATE-BASED SECTION RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Render sidebar section navigation (below selected investigation) ─────────
function renderSectionNav() {
  var inv = I.cur;
  if (!inv || !I.sections.length) return '';
  var h = '<div class="inv-sec-nav" id="inv-sec-nav">';
  I.sections.forEach(function(s) {
    var isDone = s.content && s.content.trim();
    if (s.type === 'iocs')    isDone = inv.iocs    && inv.iocs.length;
    if (s.type === 'findings' || s.type === 'timeline') isDone = inv.findings && inv.findings.length;
    h += '<div class="inv-sec-nav-item" data-scroll-to="sec-' + s.id + '" title="' + esc(s.name) + '">'
      + '<span class="inv-sec-nav-dot" style="background:' + (isDone ? '#22c55e' : 'var(--t5)') + '"></span>'
      + '<span class="inv-sec-nav-icon">' + esc(s.icon || '📝') + '</span>'
      + '<span class="inv-sec-nav-label">' + esc(s.name) + '</span>'
      + '</div>';
  });
  h += '</div>';
  return h;
}

// ─── Main: render sections vertically (template mode) ─────────────────────────
function buildSectionsView(inv, isWriter) {
  var isLocked = !!(inv.report_locked && I.user && I.user.role !== 'admin');
  var canEdit  = isWriter && !isLocked;
  var h = '';
  h += '<div class="inv-sections-wrap" id="inv-sections-wrap">';

  I.sections.forEach(function(s) {
    h += '<div class="inv-section" id="sec-' + s.id + '" data-section-id="' + s.id + '">';
    h += '<div class="inv-section-header">';
    h += '<span class="inv-section-icon">' + esc(s.icon || '📝') + '</span>';
    h += '<h2 class="inv-section-title">' + esc(s.name) + '</h2>';
    h += '<span class="inv-section-type-badge">' + esc(s.type) + '</span>';
    if (s.required) h += '<span style="font-size:10px;color:var(--red);font-weight:700">required</span>';
    h += '</div>';
    h += '<div class="inv-section-body">';
    h += buildSectionBody(s, inv, canEdit);
    h += '</div>';
    h += '</div>';
  });

  if (!I.sections.length) {
    h += '<div style="text-align:center;padding:60px;color:var(--t5)">'
      + '<div style="font-size:36px;margin-bottom:12px">📋</div>'
      + '<div>Aucune section définie pour ce template.</div></div>';
  }

  h += '</div>';
  return h;
}

// ─── Section body by type ─────────────────────────────────────────────────────
function buildSectionBody(sec, inv, canEdit) {
  switch (sec.type) {
    case 'richtext':
    case 'custom':
      return buildSectionRichtext(sec, inv, canEdit);
    case 'findings':
    case 'timeline':
      return buildFindings(inv, canEdit);
    case 'iocs':
      return buildIocs(inv, canEdit);
    case 'cvss':
      return buildSectionCVSS(sec, inv, canEdit);
    case 'checklist':
      return buildSectionChecklist(sec, inv, canEdit);
    case 'recommendation':
      return buildSectionRecommendation(sec, inv, canEdit);
    default:
      return buildSectionRichtext(sec, inv, canEdit);
  }
}

// ─── Richtext section ─────────────────────────────────────────────────────────
function buildSectionRichtext(sec, inv, canEdit) {
  var contentHtml = '';
  if (!canEdit) {
    var rendered = sec.content && typeof RichEditor !== 'undefined'
      ? RichEditor.mdToHtml(sec.content)
      : esc(sec.content || '');
    return '<div class="re-preview re-preview--always">'
      + (rendered || '<p style="color:var(--t5);font-style:italic">' + esc(sec.placeholder || 'Aucun contenu.') + '</p>')
      + '</div>';
  }
  return '<div id="re-container-' + sec.id + '"></div>';
}

// ─── CVSS 3.1 Calculator section ──────────────────────────────────────────────
var _cvssDefaults = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
var _cvssState = {};

function parseCVSSContent(content) {
  if (!content) return Object.assign({}, _cvssDefaults);
  try {
    // Try JSON
    var parsed = JSON.parse(content);
    if (parsed && parsed.AV) return parsed;
  } catch(e) {}
  // Try CVSS vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
  var m = content.match(/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])/);
  if (m) return { AV:m[1], AC:m[2], PR:m[3], UI:m[4], S:m[5], C:m[6], I:m[7], A:m[8] };
  return Object.assign({}, _cvssDefaults);
}

function calcCVSS31(m) {
  var AV  = { N:0.85, A:0.62, L:0.55, P:0.20 };
  var AC  = { L:0.77, H:0.44 };
  var PRu = { N:0.85, L:0.62, H:0.27 };
  var PRc = { N:0.85, L:0.68, H:0.50 };
  var UI  = { N:0.85, R:0.62 };
  var CIA = { N:0.00, L:0.22, H:0.56 };
  var av = AV[m.AV]||0, ac = AC[m.AC]||0, ui = UI[m.UI]||0;
  var pr = (m.S==='C' ? PRc : PRu)[m.PR]||0;
  var c = CIA[m.C]||0, i = CIA[m.I]||0, a = CIA[m.A]||0;
  var ISC = 1-(1-c)*(1-i)*(1-a);
  var Exp = 8.22*av*ac*pr*ui;
  var Impact, Base;
  if (m.S==='U') {
    Impact = 6.42*ISC;
    if (ISC===0) return { score:0, rating:'None', vector:buildCVSSVector(m) };
    Base = Math.ceil(Math.min(Impact+Exp,10)*10)/10;
  } else {
    Impact = 7.52*(ISC-0.029)-3.25*Math.pow(ISC-0.02,15);
    if (ISC===0) return { score:0, rating:'None', vector:buildCVSSVector(m) };
    Base = Math.ceil(Math.min(1.08*(Impact+Exp),10)*10)/10;
  }
  var rating = Base>=9?'Critical':Base>=7?'High':Base>=4?'Medium':Base>0?'Low':'None';
  return { score:Base, rating, vector:buildCVSSVector(m) };
}
function buildCVSSVector(m) {
  return 'CVSS:3.1/AV:'+m.AV+'/AC:'+m.AC+'/PR:'+m.PR+'/UI:'+m.UI+'/S:'+m.S+'/C:'+m.C+'/I:'+m.I+'/A:'+m.A;
}

function buildSectionCVSS(sec, inv, canEdit) {
  var state = parseCVSSContent(sec.content);
  var res   = calcCVSS31(state);
  var skey  = 'cvss_' + sec.id;
  _cvssState[skey] = state;

  var RATING_C = { None:'#6b7280', Low:'#22c55e', Medium:'#eab308', High:'#f97316', Critical:'#ef4444' };
  var rColor = RATING_C[res.rating] || '#6b7280';

  var factors = [
    { k:'AV', label:'Attack Vector',    opts:['N','A','L','P'], lbl:['Network','Adjacent','Local','Physical'] },
    { k:'AC', label:'Attack Complexity',opts:['L','H'],         lbl:['Low','High'] },
    { k:'PR', label:'Privileges Req.',  opts:['N','L','H'],     lbl:['None','Low','High'] },
    { k:'UI', label:'User Interaction', opts:['N','R'],         lbl:['None','Required'] },
    { k:'S',  label:'Scope',            opts:['U','C'],         lbl:['Unchanged','Changed'] },
    { k:'C',  label:'Confidentiality',  opts:['N','L','H'],     lbl:['None','Low','High'] },
    { k:'I',  label:'Integrity',        opts:['N','L','H'],     lbl:['None','Low','High'] },
    { k:'A',  label:'Availability',     opts:['N','L','H'],     lbl:['None','Low','High'] },
  ];

  var h = '<div class="cvss-grid" id="cvss-grid-' + sec.id + '" data-sec-id="' + sec.id + '">';
  factors.forEach(function(f) {
    h += '<div class="cvss-factor">';
    h += '<div class="cvss-factor-label">' + esc(f.label) + '</div>';
    h += '<div class="cvss-factor-btns">';
    f.opts.forEach(function(opt, i) {
      var isActive = state[f.k] === opt;
      h += '<button type="button" class="cvss-opt-btn' + (isActive ? ' active' : '') + '" '
        + 'data-cvss-key="' + f.k + '" data-cvss-val="' + opt + '" data-cvss-sec="' + sec.id + '"'
        + (canEdit ? '' : ' disabled')
        + '>' + esc(f.lbl[i]) + '</button>';
    });
    h += '</div></div>';
  });
  h += '</div>';

  h += '<div class="cvss-score-panel" id="cvss-score-' + sec.id + '">';
  h += '<div class="cvss-score-display" style="color:' + rColor + '">' + res.score.toFixed(1) + '</div>';
  h += '<div class="cvss-rating-badge" style="background:' + rColor + '">' + esc(res.rating) + '</div>';
  h += '<div class="cvss-vector" id="cvss-vec-' + sec.id + '">' + esc(res.vector) + '</div>';
  if (canEdit) {
    h += '<button class="btn-sm" id="cvss-save-' + sec.id + '" data-sec-id="' + sec.id + '" style="margin-top:8px">💾 Save</button>';
  }
  h += '</div>';

  return h;
}

// ─── Checklist section ────────────────────────────────────────────────────────
function parseChecklist(content) {
  if (!content) return [];
  try { var a = JSON.parse(content); if (Array.isArray(a)) return a; } catch(e) {}
  return [];
}
function buildSectionChecklist(sec, inv, canEdit) {
  var items = parseChecklist(sec.content);
  if (!items.length && !canEdit) {
    return '<div style="color:var(--t5);font-style:italic;padding:8px 0">No checklist items.</div>';
  }
  var h = '<div class="checklist-wrap" id="chk-' + sec.id + '" data-sec-id="' + sec.id + '">';
  items.forEach(function(item, i) {
    h += '<label class="chk-item" style="display:flex;align-items:center;gap:9px;padding:7px 0;cursor:' + (canEdit ? 'pointer' : 'default') + '">';
    h += '<input type="checkbox" class="chk-box" data-chk-idx="' + i + '"' + (item.checked ? ' checked' : '') + (canEdit ? '' : ' disabled') + ' style="width:15px;height:15px;accent-color:var(--red)">';
    h += '<span style="font-size:13px;' + (item.checked ? 'text-decoration:line-through;color:var(--t4)' : 'color:var(--t2)') + '">' + esc(item.label) + '</span>';
    if (canEdit) {
      h += '<button type="button" class="chk-del" data-chk-idx="' + i + '" style="background:none;border:none;cursor:pointer;color:var(--t5);font-size:12px;margin-left:auto;padding:2px 5px">✕</button>';
    }
    h += '</label>';
  });
  if (canEdit) {
    h += '<div style="display:flex;gap:8px;margin-top:8px">';
    h += '<input id="chk-new-' + sec.id + '" class="input" placeholder="New checklist item…" style="flex:1;font-size:13px">';
    h += '<button type="button" class="btn-sm pri" id="chk-add-' + sec.id + '" data-sec-id="' + sec.id + '">Add</button>';
    h += '</div>';
  }
  h += '</div>';
  return h;
}

// ─── Recommendation section ───────────────────────────────────────────────────
function parseRecommendations(content) {
  if (!content) return [];
  try { var a = JSON.parse(content); if (Array.isArray(a)) return a; } catch(e) {}
  return [];
}
function buildSectionRecommendation(sec, inv, canEdit) {
  var items = parseRecommendations(sec.content);
  var PRIO_C = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#22c55e' };
  var STS_C  = { Open:'#f97316', 'In Progress':'#3b82f6', Fixed:'#22c55e' };
  var h = '<div class="rec-wrap" id="rec-' + sec.id + '" data-sec-id="' + sec.id + '">';

  if (!items.length) {
    h += '<div style="color:var(--t5);font-style:italic;padding:8px 0 14px">No recommendations yet.</div>';
  } else {
    h += '<table class="rec-table" style="width:100%;border-collapse:collapse;margin-bottom:12px">';
    h += '<thead><tr style="border-bottom:1px solid var(--bd)">';
    h += '<th style="text-align:left;padding:6px 10px;font-size:11px;font-weight:700;color:var(--t4);text-transform:uppercase">Title</th>';
    h += '<th style="text-align:left;padding:6px 10px;font-size:11px;font-weight:700;color:var(--t4);text-transform:uppercase;width:90px">Priority</th>';
    h += '<th style="text-align:left;padding:6px 10px;font-size:11px;font-weight:700;color:var(--t4);text-transform:uppercase;width:80px">Effort</th>';
    h += '<th style="text-align:left;padding:6px 10px;font-size:11px;font-weight:700;color:var(--t4);text-transform:uppercase;width:100px">Status</th>';
    if (canEdit) h += '<th style="width:36px"></th>';
    h += '</tr></thead><tbody>';
    items.forEach(function(item, i) {
      var pc = PRIO_C[item.priority] || '#6b7280';
      var sc = STS_C[item.status]   || '#6b7280';
      h += '<tr style="border-bottom:1px solid var(--bd)">';
      h += '<td style="padding:8px 10px">';
      h += '<div style="font-size:13px;font-weight:600;color:var(--t1)">' + esc(item.title) + '</div>';
      if (item.description) h += '<div style="font-size:11px;color:var(--t4);margin-top:2px">' + esc(item.description) + '</div>';
      h += '</td>';
      h += '<td style="padding:8px 10px"><span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:5px;background:' + pc + '20;color:' + pc + ';border:1px solid ' + pc + '40">' + esc(item.priority||'—') + '</span></td>';
      h += '<td style="padding:8px 10px;font-size:12px;color:var(--t3)">' + esc(item.effort||'—') + '</td>';
      h += '<td style="padding:8px 10px"><span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:5px;background:' + sc + '20;color:' + sc + '">' + esc(item.status||'Open') + '</span></td>';
      if (canEdit) {
        h += '<td style="padding:4px"><button type="button" class="rec-del" data-rec-idx="' + i + '" style="background:none;border:none;cursor:pointer;color:var(--red);font-size:13px;padding:2px 5px">🗑</button></td>';
      }
      h += '</tr>';
    });
    h += '</tbody></table>';
  }

  if (canEdit) {
    h += '<div class="rec-add-form" id="rec-add-' + sec.id + '" style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:14px">';
    h += '<div style="font-size:12px;font-weight:700;margin-bottom:10px;color:var(--t3)">+ Ajouter une recommandation</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">';
    h += '<div><label class="lbl">Titre *</label><input id="rec-title-' + sec.id + '" class="input" style="width:100%" placeholder="Ex: Enforce MFA on all admin accounts"></div>';
    h += '<div><label class="lbl">Description</label><input id="rec-desc-' + sec.id + '" class="input" style="width:100%" placeholder="Optional details…"></div>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">';
    h += '<div><label class="lbl">Priorité</label><select id="rec-prio-' + sec.id + '" style="width:100%"><option>Critical</option><option>High</option><option selected>Medium</option><option>Low</option></select></div>';
    h += '<div><label class="lbl">Effort</label><select id="rec-effort-' + sec.id + '" style="width:100%"><option>Low</option><option selected>Medium</option><option>High</option></select></div>';
    h += '<div><label class="lbl">Statut</label><select id="rec-sts-' + sec.id + '" style="width:100%"><option selected>Open</option><option>In Progress</option><option>Fixed</option></select></div>';
    h += '</div>';
    h += '<button type="button" class="pri btn-sm" id="rec-add-btn-' + sec.id + '" data-sec-id="' + sec.id + '">+ Ajouter</button>';
    h += '</div>';
  }
  h += '</div>';
  return h;
}

// ─── Right panel for template-based investigations ────────────────────────────
function buildRightPanelTemplate(inv) {
  var sc  = SEV_C[inv.severity] || 'var(--t4)';
  var tpl = I.templates.find(function(t) { return t.id === inv.template_id; });
  var isWriter = I.user && I.user.role !== 'viewer';
  var RATING_C = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#3b82f6' };

  var h = '';

  // Collapse toggle
  h += '<div class="inv-right-toggle" id="right-collapse-btn" title="Collapse panel" style="cursor:pointer;padding:8px 14px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px;font-size:11px;color:var(--t4);font-weight:600;text-transform:uppercase;letter-spacing:.5px">'
    + '<span>›</span><span>' + T('inv.title') + '</span></div>';

  // Metadata section
  h += '<div class="inv-right-section">';
  h += '<div class="inv-right-label">' + T('inv.title').toUpperCase() + '</div>';
  h += '<div style="display:flex;align-items:center;gap:7px;margin-bottom:6px">';
  h += '<span style="width:8px;height:8px;border-radius:50%;background:' + sc + ';flex-shrink:0"></span>';
  h += '<span style="font-size:13px;font-weight:700;color:var(--t1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">' + esc(inv.title) + '</span>';
  h += '</div>';
  if (tpl) {
    h += '<div style="font-size:11px;color:var(--t4);margin-bottom:6px">';
    h += 'Template : <span style="color:' + esc(tpl.color||'var(--t3)') + ';font-weight:700">' + esc(tpl.icon + ' ' + tpl.name) + '</span></div>';
  }
  h += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">' + stsBadge(inv.status) + ' ' + sevBadge(inv.severity) + '</div>';
  h += '<div style="font-size:12px;color:var(--t4);margin-bottom:3px">' + T('inv.field.analyst') + ' : <span style="color:var(--t2)">' + esc(inv.analyst_name || '—') + '</span></div>';
  if (inv.client_name) h += '<div style="font-size:12px;color:var(--t4);margin-bottom:3px">Client : <span style="color:var(--t2)">' + esc(inv.client_name) + '</span></div>';
  h += '<div style="font-size:12px;color:var(--t4)">Créé : <span style="color:var(--t3)">' + esc((inv.created_at||'').slice(0,10)) + '</span></div>';
  h += '</div>';

  // Status & Severity editable meta
  if (isWriter) {
    h += '<div class="inv-right-section">';
    h += '<div class="inv-right-label">STATUT / SÉVÉRITÉ</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">';
    h += '<select id="inv-status-r" style="font-size:12px;width:100%">';
    ['open','in-progress','closed'].forEach(function(s) { h += '<option value="'+s+'"'+(inv.status===s?' selected':'')+'>'+{'open':'Open','in-progress':'In Progress','closed':'Clôturé'}[s]+'</option>'; });
    h += '</select>';
    h += '<select id="inv-sev-r" style="font-size:12px;width:100%">';
    ['critical','high','medium','low','info'].forEach(function(s) { h += '<option value="'+s+'"'+(inv.severity===s?' selected':'')+'>'+s.charAt(0).toUpperCase()+s.slice(1)+'</option>'; });
    h += '</select>';
    h += '</div>';
    h += '<div style="display:flex;gap:7px;margin-top:8px">';
    h += '<input id="inv-title-r" class="input" value="' + esc(inv.title) + '" style="flex:1;font-size:12px" placeholder="Titre">';
    h += '<button class="pri btn-sm" id="btn-save-meta-r">✓</button>';
    h += '</div>';
    h += '</div>';
  }

  // Branding section
  if (isWriter) {
    h += '<div class="inv-right-section">';
    h += '<div class="inv-right-label">BRANDING CLIENT</div>';
    h += '<div style="margin-bottom:8px">';
    h += '<label class="lbl" style="font-size:10px">Nom client</label>';
    h += '<input id="brand-client-name" class="input" style="width:100%;font-size:12px" value="' + esc(inv.client_name||'') + '" placeholder="ACME Corp">';
    h += '</div>';
    h += '<div style="margin-bottom:8px">'
      + '<label class="lbl" style="font-size:10px">Logo client</label>'
      + '<div style="display:flex;align-items:center;gap:8px">';
    if (inv.client_logo) {
      h += '<img src="' + esc(inv.client_logo) + '" style="height:32px;max-width:80px;object-fit:contain;border-radius:4px;border:1px solid var(--bd)">';
      h += '<button type="button" id="brand-logo-rm" style="font-size:11px;color:var(--red);background:none;border:none;cursor:pointer">Supprimer</button>';
    } else {
      h += '<label for="brand-logo-up" style="font-size:11px;padding:4px 10px;border:1px solid var(--bd);border-radius:6px;cursor:pointer;background:var(--s2)">⬆ Logo</label>';
      h += '<input type="file" id="brand-logo-up" accept="image/png,image/jpeg" style="display:none">';
    }
    h += '</div></div>';
    h += '<div style="margin-bottom:10px">';
    h += '<label class="lbl" style="font-size:10px">Couleur accent</label>';
    h += '<div style="display:flex;gap:7px;align-items:center">';
    h += '<input type="color" id="brand-color" value="' + esc(inv.client_color||'#e63946') + '" style="width:36px;height:28px;border:1px solid var(--bd);border-radius:5px;padding:1px;cursor:pointer">';
    var presets = ['#e63946','#3b82f6','#22c55e','#f97316','#a855f7','#0d1b2a'];
    h += '<div style="display:flex;gap:4px">';
    presets.forEach(function(c) { h += '<button type="button" onclick="document.getElementById(\'brand-color\').value=\'' + c + '\'" style="width:18px;height:18px;border-radius:50%;background:' + c + ';border:2px solid transparent;cursor:pointer" title="' + c + '"></button>'; });
    h += '</div></div></div>';
    h += '<button class="btn-sm" id="btn-save-branding" style="width:100%">💾 Sauvegarder le branding</button>';
    h += '</div>';
  }

  // Completeness checker
  h += '<div class="inv-right-section" id="completeness-panel">';
  h += '<div class="inv-right-label">' + T('report.completeness').toUpperCase() + '</div>';
  h += buildCompletenessPanel();
  h += '</div>';

  return h;
}

function buildCompletenessPanel() {
  var inv = I.cur;
  var iocs = inv.iocs || [], findings = inv.findings || [];
  var checks;
  if (I.sections.length) {
    checks = I.sections.filter(function(s) { return s.type !== 'report_preview'; }).map(function(s) {
      var done = false;
      if (s.type === 'iocs')                                   done = iocs.length > 0;
      else if (s.type === 'timeline')                          done = findings.length > 0;
      else if (s.type === 'classic_summary')                   done = !!(inv.description && inv.description.trim());
      else if (s.type === 'classic_conclusion')                done = !!(inv.conclusion && inv.conclusion.trim());
      else                                                     done = !!(s.content && s.content.trim());
      return { label: s.name, done: done };
    });
  } else {
    checks = [
      { label: T('report.section_summary'),    done: !!(inv.description && inv.description.trim()) },
      { label: 'IoCs',                         done: iocs.length > 0 },
      { label: T('report.findings'),           done: findings.length > 0 },
      { label: T('report.section_conclusion'), done: !!(inv.conclusion && inv.conclusion.trim()) },
    ];
  }
  var done = checks.filter(function(c) { return c.done; }).length;
  var pct  = checks.length ? Math.round(done / checks.length * 100) : 0;
  var compColor = pct === 100 ? '#22c55e' : pct >= 50 ? '#3b82f6' : '#f97316';

  var h = '<div class="completeness-bar" style="margin-bottom:8px"><div class="completeness-fill" style="width:' + pct + '%;background:' + compColor + '"></div></div>';
  h += '<div style="font-size:12px;font-weight:800;color:' + compColor + ';margin-bottom:8px">' + pct + '% ' + T('report.completeness') + '</div>';
  h += '<div style="display:flex;flex-direction:column;gap:4px">';
  checks.forEach(function(c) {
    h += '<div style="font-size:11px;display:flex;align-items:center;gap:6px">';
    h += '<span style="font-weight:800;color:' + (c.done ? '#22c55e' : 'var(--t5)') + '">' + (c.done ? '✓' : '⊘') + '</span>';
    h += '<span style="color:' + (c.done ? 'var(--t2)' : 'var(--t5)') + ';flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(c.label) + '</span>';
    if (!c.done) h += '<span style="font-size:9px;color:var(--t5)">' + T('no_data') + '</span>';
    h += '</div>';
  });
  h += '</div>';
  return h;
}

// ─── Bind template section interactions ───────────────────────────────────────
function bindSectionInteractions() {
  var inv     = I.cur;
  if (!inv) return;
  var isWriter = I.user && I.user.role !== 'viewer';
  var isLocked = !!(inv.report_locked && I.user && I.user.role !== 'admin');
  var canEdit  = isWriter && !isLocked;

  // Section nav scroll
  document.querySelectorAll('#inv-sec-nav [data-scroll-to]').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation(); // prevent bubble to .inv-item which would re-select/re-render
      var targetId = btn.getAttribute('data-scroll-to');
      var el = document.getElementById(targetId);
      if (!el) return;
      // scroll inside the .inv-body container, not the window
      var body = document.querySelector('.inv-body');
      if (body) {
        var elTop = el.getBoundingClientRect().top;
        var bodyTop = body.getBoundingClientRect().top;
        body.scrollBy({ top: elTop - bodyTop - 16, behavior: 'smooth' });
      } else {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // RichEditor init for richtext sections
  I.sections.forEach(function(sec) {
    if ((sec.type === 'richtext' || sec.type === 'custom') && canEdit) {
      if (typeof RichEditor !== 'undefined') {
        RichEditor.create({
          containerId: 're-container-' + sec.id,
          textareaId:  'inv-sec-' + sec.id,
          label:       sec.name.toUpperCase(),
          placeholder: sec.placeholder || 'Rédigez cette section…',
          rows:        8,
          value:       sec.content || ''
        });
        // Auto-save on blur
        (function(secId) {
          setTimeout(function() {
            var ta = document.getElementById('inv-sec-' + secId);
            if (ta) {
              ta.addEventListener('blur', function() { saveSectionContent(secId, ta.value); });
            }
          }, 300);
        })(sec.id);
      }
    }
  });

  // CVSS buttons
  document.querySelectorAll('.cvss-opt-btn').forEach(function(btn) {
    if (!canEdit) return;
    btn.addEventListener('click', function() {
      var k    = btn.getAttribute('data-cvss-key');
      var v    = btn.getAttribute('data-cvss-val');
      var secId = btn.getAttribute('data-cvss-sec');
      var skey  = 'cvss_' + secId;
      if (!_cvssState[skey]) _cvssState[skey] = Object.assign({}, _cvssDefaults);
      _cvssState[skey][k] = v;
      // Update UI
      document.querySelectorAll('[data-cvss-key="'+k+'"][data-cvss-sec="'+secId+'"]').forEach(function(b) {
        b.classList.toggle('active', b.getAttribute('data-cvss-val') === v);
      });
      var res = calcCVSS31(_cvssState[skey]);
      var RATING_C = { None:'#6b7280', Low:'#22c55e', Medium:'#eab308', High:'#f97316', Critical:'#ef4444' };
      var rc = RATING_C[res.rating] || '#6b7280';
      var scoreEl = document.getElementById('cvss-score-' + secId);
      if (scoreEl) {
        scoreEl.querySelector('.cvss-score-display').textContent  = res.score.toFixed(1);
        scoreEl.querySelector('.cvss-score-display').style.color  = rc;
        scoreEl.querySelector('.cvss-rating-badge').textContent   = res.rating;
        scoreEl.querySelector('.cvss-rating-badge').style.background = rc;
        var vecEl = document.getElementById('cvss-vec-' + secId);
        if (vecEl) vecEl.textContent = res.vector;
      }
    });
  });

  // CVSS save buttons
  document.querySelectorAll('[id^="cvss-save-"]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var secId = btn.getAttribute('data-sec-id');
      var skey  = 'cvss_' + secId;
      var content = buildCVSSVector(_cvssState[skey] || _cvssDefaults);
      saveSectionContent(secId, content);
    });
  });

  // Checklist interactions
  I.sections.forEach(function(sec) {
    if (sec.type !== 'checklist' || !canEdit) return;
    var wrap = document.getElementById('chk-' + sec.id);
    if (!wrap) return;
    var items = parseChecklist(sec.content);

    wrap.addEventListener('change', function(e) {
      if (!e.target.classList.contains('chk-box')) return;
      var idx = parseInt(e.target.getAttribute('data-chk-idx'));
      if (items[idx]) { items[idx].checked = e.target.checked; saveSectionContent(sec.id, JSON.stringify(items)); }
      // Strike-through
      var label = e.target.parentElement.querySelector('span');
      if (label) label.style.textDecoration = e.target.checked ? 'line-through' : '';
    });
    wrap.addEventListener('click', function(e) {
      if (!e.target.classList.contains('chk-del')) return;
      var idx = parseInt(e.target.getAttribute('data-chk-idx'));
      items.splice(idx, 1);
      saveSectionContent(sec.id, JSON.stringify(items));
      // Re-render checklist body
      var sec2 = I.sections.find(function(s) { return s.id === sec.id; });
      if (sec2) { sec2.content = JSON.stringify(items); var body = wrap.closest('.inv-section-body'); if (body) body.innerHTML = buildSectionChecklist(sec2, inv, canEdit); bindSectionInteractions(); }
    });
    var addBtn = document.getElementById('chk-add-' + sec.id);
    var addInput = document.getElementById('chk-new-' + sec.id);
    if (addBtn && addInput) {
      addBtn.addEventListener('click', function() {
        var label = addInput.value.trim();
        if (!label) return;
        items.push({ id: 'c' + Date.now(), label, checked: false });
        saveSectionContent(sec.id, JSON.stringify(items));
        addInput.value = '';
        var sec2 = I.sections.find(function(s) { return s.id === sec.id; });
        if (sec2) { sec2.content = JSON.stringify(items); var body = addBtn.closest('.inv-section-body'); if (body) body.innerHTML = buildSectionChecklist(sec2, inv, canEdit); bindSectionInteractions(); }
      });
    }
  });

  // Recommendation interactions
  I.sections.forEach(function(sec) {
    if (sec.type !== 'recommendation' || !canEdit) return;
    var wrap = document.getElementById('rec-' + sec.id);
    if (!wrap) return;
    var items = parseRecommendations(sec.content);

    wrap.addEventListener('click', function(e) {
      if (!e.target.classList.contains('rec-del')) return;
      var idx = parseInt(e.target.getAttribute('data-rec-idx'));
      items.splice(idx, 1);
      saveSectionContent(sec.id, JSON.stringify(items));
      var sec2 = I.sections.find(function(s) { return s.id === sec.id; });
      if (sec2) { sec2.content = JSON.stringify(items); var body = wrap.closest('.inv-section-body'); if (body) body.innerHTML = buildSectionRecommendation(sec2, inv, canEdit); bindSectionInteractions(); }
    });

    var addBtn = document.getElementById('rec-add-btn-' + sec.id);
    if (addBtn) {
      addBtn.addEventListener('click', function() {
        var title = (document.getElementById('rec-title-' + sec.id)||{}).value || '';
        if (!title.trim()) return showToast(T('findings.error.title_required'), true);
        items.push({
          id:          'r' + Date.now(),
          title:       title.trim(),
          description: (document.getElementById('rec-desc-' + sec.id)||{}).value || '',
          priority:    (document.getElementById('rec-prio-' + sec.id)||{}).value || 'Medium',
          effort:      (document.getElementById('rec-effort-' + sec.id)||{}).value || 'Medium',
          status:      (document.getElementById('rec-sts-' + sec.id)||{}).value || 'Open',
        });
        saveSectionContent(sec.id, JSON.stringify(items));
        var sec2 = I.sections.find(function(s) { return s.id === sec.id; });
        if (sec2) { sec2.content = JSON.stringify(items); var body = addBtn.closest('.inv-section-body'); if (body) body.innerHTML = buildSectionRecommendation(sec2, inv, canEdit); bindSectionInteractions(); }
      });
    }
  });

}

// ─── Right panel interactive bindings (called after renderRight sets innerHTML) ─
function bindRightPanel() {
  var inv = I.cur;
  if (!inv) return;

  // Collapse toggle
  var collapseBtn = document.getElementById('right-collapse-btn');
  if (collapseBtn) {
    collapseBtn.addEventListener('click', function() {
      var rightEl = document.getElementById('inv-right');
      if (rightEl) rightEl.classList.toggle('collapsed');
    });
  }

  // Save meta from right panel (status / severity / title)
  var saveMetaBtn = document.getElementById('btn-save-meta-r');
  if (saveMetaBtn) {
    saveMetaBtn.addEventListener('click', async function() {
      var title  = (document.getElementById('inv-title-r')||{}).value || '';
      var status = (document.getElementById('inv-status-r')||{}).value || inv.status;
      var sev    = (document.getElementById('inv-sev-r')||{}).value || inv.severity;
      var d = await API.put('/investigations/' + inv.id, { title: title||inv.title, status, severity: sev, description: inv.description||'', conclusion: inv.conclusion||'' });
      if (d && d.error) return showToast(d.error, true);
      inv.title = title || inv.title;
      inv.status = status;
      inv.severity = sev;
      if (d.report_locked !== undefined) inv.report_locked = d.report_locked ? 1 : 0;
      var bc = document.getElementById('inv-breadcrumb');
      if (bc) bc.textContent = inv.title;
      await loadList();
      renderSidebar(); bindSidebar(); renderRight();
      showToast(T('source_saved'));
    });
  }

  // Branding save
  var saveBrandBtn = document.getElementById('btn-save-branding');
  if (saveBrandBtn) {
    saveBrandBtn.addEventListener('click', async function() {
      var payload = {
        client_name:  (document.getElementById('brand-client-name')||{}).value || '',
        client_color: (document.getElementById('brand-color')||{}).value || null,
      };
      if (_pendingClientLogo !== undefined) payload.client_logo = _pendingClientLogo;
      var d = await API.put('/investigations/' + inv.id + '/branding', payload);
      if (d && d.error) return showToast(d.error, true);
      inv.client_name  = payload.client_name;
      inv.client_color = payload.client_color;
      if (_pendingClientLogo !== undefined) { inv.client_logo = _pendingClientLogo; _pendingClientLogo = undefined; }
      showToast(T('source_saved'));
    });
    var logoRm = document.getElementById('brand-logo-rm');
    if (logoRm) logoRm.addEventListener('click', function() { _pendingClientLogo = ''; saveBrandBtn.click(); });
    var logoUp = document.getElementById('brand-logo-up');
    if (logoUp) logoUp.addEventListener('change', function() {
      var f = logoUp.files[0]; if (!f) return;
      var reader = new FileReader();
      reader.onload = function(e) { _pendingClientLogo = e.target.result; saveBrandBtn.click(); };
      reader.readAsDataURL(f);
    });
  }
}

// ─── Save section content to backend ─────────────────────────────────────────
async function saveSectionContent(secId, content) {
  if (!I.cur) return;
  var d = await API.put('/investigations/' + I.cur.id + '/sections/' + secId, { content });
  if (d && d.error) { showToast(d.error, true); return; }
  // Update local state
  var sec = I.sections.find(function(s) { return s.id === secId; });
  if (sec) sec.content = content;
  // Refresh completeness
  var panel = document.getElementById('completeness-panel');
  if (panel) panel.innerHTML = '<div class="inv-right-label">' + T('report.completeness').toUpperCase() + '</div>' + buildCompletenessPanel();
  // Refresh section nav dots
  var nav = document.getElementById('inv-sec-nav');
  if (nav) nav.outerHTML = renderSectionNav();
}

// ─── Theme ────────────────────────────────────────────────────
(function () { var t = localStorage.getItem('kv-theme') || 'dark'; if (t === 'light') document.body.classList.add('light'); })();

// ─── Sidebar collapse (desktop) ───────────────────────────────
function bindSidebarCollapse() {
  var sidebar   = document.getElementById('inv-sidebar');
  var shell     = document.querySelector('.inv-shell');
  var collapseBtn = document.getElementById('btn-collapse-sidebar');
  var expandTab   = document.getElementById('btn-expand-sidebar');
  if (!sidebar || !shell) return;

  var STORAGE_KEY = 'inv-sidebar-collapsed';

  function setCollapsed(collapsed) {
    sidebar.classList.toggle('inv-sidebar--collapsed', collapsed);
    shell.classList.toggle('inv-shell--sidebar-collapsed', collapsed);
    if (collapseBtn) {
      collapseBtn.style.transform = collapsed ? 'scaleX(-1)' : '';
      collapseBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    }
    try { localStorage.setItem(STORAGE_KEY, collapsed ? '1' : '0'); } catch(e) {}
  }

  // Restore from localStorage
  var stored = '';
  try { stored = localStorage.getItem(STORAGE_KEY); } catch(e) {}
  if (stored === '1') setCollapsed(true);

  if (collapseBtn) {
    collapseBtn.addEventListener('click', function () {
      setCollapsed(!sidebar.classList.contains('inv-sidebar--collapsed'));
    });
  }
  if (expandTab) {
    expandTab.addEventListener('click', function () {
      setCollapsed(false);
    });
  }
}

// ─── Right panel toggle ───────────────────────────────────────
function bindRightToggle() {
  var btn = document.getElementById('btn-toggle-right');
  var panel = document.getElementById('inv-right');
  if (!btn || !panel) return;
  var KEY = 'inv-right-open';
  var stored = '';
  try { stored = localStorage.getItem(KEY); } catch(e) {}
  if (stored === '1') panel.classList.add('inv-right--open');

  btn.addEventListener('click', function() {
    var isOpen = panel.classList.toggle('inv-right--open');
    btn.classList.toggle('active', isOpen);
    try { localStorage.setItem(KEY, isOpen ? '1' : '0'); } catch(e) {}
  });
  // Sync button active state on load
  if (panel.classList.contains('inv-right--open')) btn.classList.add('active');
}

// ─── Init ─────────────────────────────────────────────────────
async function init() {
  try {
    var me = await API.get('/auth/me');
    if (!me || !me.user) { window.location.href = '/'; return; }
    I.user = me.user;

    // Topbar user info
    var av = I.user.avatar
      ? '<img src="' + esc(I.user.avatar) + '" class="inv-topbar-avatar">'
      : '<span class="inv-topbar-avatar inv-topbar-avatar-initials">' + esc((I.user.login || '?')[0].toUpperCase()) + '</span>';
    var hr = document.getElementById('inv-topbar-actions');
    if (hr) hr.innerHTML = av
      + '<span class="inv-topbar-user">' + esc(I.user.login) + '</span>'
      + '<span class="inv-topbar-sep">·</span>'
      + '<a href="/" class="inv-topbar-back">← Vault</a>'
      + '<button class="inv-topbar-details-btn" id="btn-toggle-right" title="Toggle details panel" aria-label="Toggle details panel">'
      + '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="15" y1="3" x2="15" y2="21"/></svg>'
      + '</button>';

    // Show/hide new investigation button based on role
    var btnNew = document.getElementById('btn-new-inv');
    if (btnNew) {
      if (I.user.role === 'viewer') { btnNew.style.display = 'none'; }
      else { btnNew.addEventListener('click', function () { openNewModal(); }); }
    }

    // Status filter buttons (static HTML, bind once)
    document.querySelectorAll('#inv-filters .inv-filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        I.statusFilter = btn.getAttribute('data-status');
        renderFilters();
        renderSidebar();
        bindSidebar();
      });
    });

    // Sidebar search
    var searchEl = document.getElementById('inv-search');
    if (searchEl) {
      searchEl.addEventListener('input', function () {
        I.searchQuery = searchEl.value;
        renderSidebar();
        bindSidebar();
      });
    }

    // Mobile sidebar toggle
    var toggleBtn = document.getElementById('inv-sidebar-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', function () {
        var sb = document.querySelector('.inv-sidebar');
        if (sb) sb.classList.toggle('open');
      });
    }

    // Desktop sidebar collapse/expand
    bindSidebarCollapse();
    bindRightToggle();

    await loadReportSettings();
    await loadTemplates();
    await loadList();
    render();
    if (typeof i18n !== 'undefined' && i18n.onLangChange) {
      i18n.onLangChange(function() { render(); });
    }
  } catch (e) {
    console.error('Init error:', e);
    showToast('Loading error — restart the server and try again.', true);
  }
}

init();
