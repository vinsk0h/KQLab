// admin-templates.js — Template management admin UI

var ADM = { user: null, templates: [], editingTplId: null, editingSecTplId: null };

function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function showToast(msg, err) {
  var t = document.getElementById('toast-el');
  if (t) t.innerHTML = '<div class="toast" style="' + (err ? 'background:#450a0a;border-color:#7f1d1d;color:#fca5a5' : '') + '">' + esc(msg) + '</div>';
  setTimeout(function() { var t = document.getElementById('toast-el'); if (t) t.innerHTML = ''; }, 3000);
}

var TYPE_LABELS = {
  blueteam: '🔵 Blue Team',
  redteam:  '🔴 Red Team',
  vapt:     '🟠 VAPT',
  phishing: '🎣 Phishing',
  audit:    '✅ Audit',
  custom:   '📋 Custom',
};
var TYPE_COLORS = {
  blueteam: '#3b82f6', redteam: '#ef4444', vapt: '#f97316',
  phishing: '#a855f7', audit: '#22c55e', custom: '#6b7280',
};
var SECTION_TYPES = ['richtext','findings','iocs','cvss','checklist','timeline','recommendation','custom'];

// ─── Load templates ───────────────────────────────────────────────────────────
async function loadTemplates() {
  var d = await API.get('/templates');
  ADM.templates = Array.isArray(d) ? d : [];
  renderTemplatesGrid();
}

// ─── Render template cards ────────────────────────────────────────────────────
function renderTemplatesGrid() {
  var grid = document.getElementById('templates-grid');
  if (!grid) return;
  if (!ADM.templates.length) {
    grid.innerHTML = '<div style="padding:40px;text-align:center;color:var(--t5)">No templates yet. Create one to get started.</div>';
    return;
  }

  grid.innerHTML = ADM.templates.map(function(tpl) {
    var typeLabel = TYPE_LABELS[tpl.type] || tpl.type;
    var typeColor = TYPE_COLORS[tpl.type] || '#6b7280';
    var accentStyle = 'background:' + esc(tpl.color || '#0ea5e9') + '1a;border-color:' + esc(tpl.color || '#0ea5e9') + '44';
    return '<div class="template-card" data-id="' + tpl.id + '">'
      + '<div class="template-card-header">'
      + '<div class="template-card-icon">' + esc(tpl.icon || '📋') + '</div>'
      + '<div class="template-card-info">'
      + '<div class="template-card-name">' + esc(tpl.name) + (tpl.is_default ? ' <span style="font-size:9px;font-weight:700;padding:1px 6px;border-radius:4px;background:#e63946;color:#fff;vertical-align:middle">DEFAULT</span>' : '') + '</div>'
      + '<div class="template-card-type" style="background:' + typeColor + '20;color:' + typeColor + '">' + esc(typeLabel) + '</div>'
      + '</div></div>'
      + '<div class="template-card-desc">' + esc(tpl.description || '—') + '</div>'
      + '<div class="template-card-sections" id="tpl-secs-' + tpl.id + '">'
      + '<span style="font-size:10px;color:var(--t5)">Loading sections…</span>'
      + '</div>'
      + '<div class="template-card-actions">'
      + '<button data-edit="' + tpl.id + '" style="flex:1;font-size:12px;padding:5px 10px">✏ Edit</button>'
      + '<button data-sections="' + tpl.id + '" style="flex:1;font-size:12px;padding:5px 10px">📑 Sections</button>'
      + '<button data-dup="' + tpl.id + '" style="font-size:12px;padding:5px 8px" title="Duplicate">⎘</button>'
      + '<button data-del="' + tpl.id + '" style="font-size:12px;padding:5px 8px;color:var(--red)" title="Delete">🗑</button>'
      + '</div>'
      + '</div>';
  }).join('');

  // Load sections for each template
  ADM.templates.forEach(function(tpl) { loadTemplateSections(tpl.id); });

  // Bind actions
  document.querySelectorAll('[data-edit]').forEach(function(btn) {
    btn.addEventListener('click', function() { openEditTplModal(btn.getAttribute('data-edit')); });
  });
  document.querySelectorAll('[data-sections]').forEach(function(btn) {
    btn.addEventListener('click', function() { openSectionsModal(btn.getAttribute('data-sections')); });
  });
  document.querySelectorAll('[data-dup]').forEach(function(btn) {
    btn.addEventListener('click', async function() {
      var id = btn.getAttribute('data-dup');
      var d  = await API.post('/templates/' + id + '/duplicate');
      if (d && d.error) return showToast(d.error, true);
      showToast('Template duplicated ✓');
      await loadTemplates();
    });
  });
  document.querySelectorAll('[data-del]').forEach(function(btn) {
    btn.addEventListener('click', async function() {
      var id   = btn.getAttribute('data-del');
      var tpl  = ADM.templates.find(function(t) { return String(t.id) === String(id); });
      if (!confirm('Delete template "' + (tpl ? tpl.name : id) + '"? This cannot be undone.')) return;
      var d = await API.del('/templates/' + id);
      if (d && d.error) return showToast(d.error, true);
      showToast('Template deleted');
      await loadTemplates();
    });
  });
}

async function loadTemplateSections(tplId) {
  var d    = await API.get('/templates/' + tplId + '/sections');
  var el   = document.getElementById('tpl-secs-' + tplId);
  if (!el) return;
  if (!Array.isArray(d) || !d.length) { el.innerHTML = '<span style="font-size:10px;color:var(--t5)">No sections</span>'; return; }
  el.innerHTML = d.map(function(s) {
    return '<span class="template-card-sec-badge">' + esc(s.icon || '📝') + ' ' + esc(s.name) + '</span>';
  }).join('');
}

// ─── Create template modal ────────────────────────────────────────────────────
function openNewTplModal() {
  ADM.editingTplId = null;
  document.getElementById('tpl-modal-title').textContent = 'New template';
  document.getElementById('tpl-name').value   = '';
  document.getElementById('tpl-icon').value   = '📋';
  document.getElementById('tpl-type').value   = 'custom';
  document.getElementById('tpl-desc').value   = '';
  document.getElementById('tpl-color').value  = '#0ea5e9';
  document.getElementById('tpl-color-text').value = '#0ea5e9';
  document.getElementById('tpl-company').value = '';
  document.getElementById('tpl-default').checked = false;
  document.getElementById('tpl-modal').style.display = 'flex';
  document.getElementById('tpl-name').focus();
}

function openEditTplModal(id) {
  var tpl = ADM.templates.find(function(t) { return String(t.id) === String(id); });
  if (!tpl) return;
  ADM.editingTplId = id;
  document.getElementById('tpl-modal-title').textContent = 'Edit template';
  document.getElementById('tpl-name').value   = tpl.name || '';
  document.getElementById('tpl-icon').value   = tpl.icon || '📋';
  document.getElementById('tpl-type').value   = tpl.type || 'custom';
  document.getElementById('tpl-desc').value   = tpl.description || '';
  document.getElementById('tpl-color').value  = tpl.color || '#0ea5e9';
  document.getElementById('tpl-color-text').value = tpl.color || '#0ea5e9';
  document.getElementById('tpl-company').value = tpl.company_name || '';
  document.getElementById('tpl-default').checked = !!tpl.is_default;
  document.getElementById('tpl-modal').style.display = 'flex';
  document.getElementById('tpl-name').focus();
}

async function saveTplModal() {
  var name = (document.getElementById('tpl-name').value || '').trim();
  if (!name) return showToast('Name is required', true);

  var payload = {
    name:         name,
    icon:         document.getElementById('tpl-icon').value || '📋',
    type:         document.getElementById('tpl-type').value || 'custom',
    description:  document.getElementById('tpl-desc').value || '',
    color:        document.getElementById('tpl-color').value || '#0ea5e9',
    company_name: document.getElementById('tpl-company').value || '',
    is_default:   document.getElementById('tpl-default').checked,
  };

  var d;
  if (ADM.editingTplId) {
    d = await API.put('/templates/' + ADM.editingTplId, payload);
  } else {
    d = await API.post('/templates', payload);
  }
  if (d && d.error) return showToast(d.error, true);
  showToast(ADM.editingTplId ? 'Template updated ✓' : 'Template created ✓');
  closeTplModal();
  await loadTemplates();
}

function closeTplModal() { document.getElementById('tpl-modal').style.display = 'none'; }

// ─── Sections modal ────────────────────────────────────────────────────────────
var _tplSections = [];

async function openSectionsModal(tplId) {
  ADM.editingSecTplId = tplId;
  var tpl = ADM.templates.find(function(t) { return String(t.id) === String(tplId); });
  document.getElementById('sec-modal-title').textContent = 'Sections — ' + (tpl ? tpl.name : 'Template');
  document.getElementById('sec-modal').style.display = 'flex';
  await refreshSectionsList(tplId);
}

async function refreshSectionsList(tplId) {
  var d = await API.get('/templates/' + (tplId || ADM.editingSecTplId) + '/sections');
  _tplSections = Array.isArray(d) ? d : [];
  renderSectionsList();
}

function renderSectionsList() {
  var list = document.getElementById('sec-list');
  if (!list) return;
  if (!_tplSections.length) {
    list.innerHTML = '<div style="text-align:center;padding:24px;color:var(--t5);font-size:13px">No sections. Add one below.</div>';
    return;
  }
  list.innerHTML = _tplSections.map(function(s, i) {
    return '<div class="sec-item" data-sec-id="' + s.id + '">'
      + '<span class="sec-item-drag">⠿</span>'
      + '<div>'
      + '<div style="display:flex;align-items:center;gap:7px">'
      + '<span>' + esc(s.icon || '📝') + '</span>'
      + '<span class="sec-item-name">' + esc(s.name) + '</span>'
      + (s.required ? '<span class="sec-item-req">required</span>' : '')
      + '</div>'
      + '<div style="margin-top:2px"><span class="sec-item-type">' + esc(s.type) + '</span></div>'
      + '</div>'
      + '<button data-edit-sec="' + s.id + '" style="background:none;border:none;cursor:pointer;color:var(--t4);font-size:13px;padding:2px 5px;border-radius:4px">✏</button>'
      + '<button data-del-sec="' + s.id + '" style="background:none;border:none;cursor:pointer;color:var(--red);font-size:13px;padding:2px 5px;border-radius:4px">🗑</button>'
      + '</div>';
  }).join('');

  // Bind edit/delete for sections
  document.querySelectorAll('[data-edit-sec]').forEach(function(btn) {
    btn.addEventListener('click', function() { openSecEditInline(btn.getAttribute('data-edit-sec')); });
  });
  document.querySelectorAll('[data-del-sec]').forEach(function(btn) {
    btn.addEventListener('click', async function() {
      var id = btn.getAttribute('data-del-sec');
      if (!confirm('Delete this section?')) return;
      var d  = await API.del('/templates/' + ADM.editingSecTplId + '/sections/' + id);
      if (d && d.error) return showToast(d.error, true);
      showToast('Section deleted');
      await refreshSectionsList();
    });
  });
}

function openSecEditInline(secId) {
  var sec = _tplSections.find(function(s) { return String(s.id) === String(secId); });
  if (!sec) return;
  var ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:300;display:flex;align-items:center;justify-content:center;padding:16px';
  ov.innerHTML = '<div style="background:var(--s1);border:1px solid var(--bd);border-radius:14px;width:100%;max-width:480px;padding:22px;display:flex;flex-direction:column;gap:14px">'
    + '<h3 style="font-size:15px;margin:0">Edit section</h3>'
    + '<div style="display:grid;grid-template-columns:1fr 60px;gap:10px">'
    + '<div><label class="lbl">Name</label><input id="esec-name" class="input" style="width:100%" value="' + esc(sec.name) + '"></div>'
    + '<div><label class="lbl">Icon</label><input id="esec-icon" class="input" style="width:100%" value="' + esc(sec.icon || '📝') + '" maxlength="4"></div>'
    + '</div>'
    + '<div><label class="lbl">Type</label><select id="esec-type" style="width:100%">'
    + SECTION_TYPES.map(function(t) { return '<option value="' + t + '"' + (sec.type === t ? ' selected' : '') + '>' + t + '</option>'; }).join('')
    + '</select></div>'
    + '<div><label class="lbl">Placeholder</label><textarea id="esec-ph" class="input" style="width:100%;height:60px;resize:vertical">' + esc(sec.placeholder || '') + '</textarea></div>'
    + '<div><label style="display:flex;align-items:center;gap:7px;cursor:pointer;font-size:13px"><input type="checkbox" id="esec-req"' + (sec.required ? ' checked' : '') + '> Required</label></div>'
    + '<div style="display:flex;justify-content:flex-end;gap:8px">'
    + '<button id="esec-cancel">Cancel</button>'
    + '<button class="pri" id="esec-save">Save</button>'
    + '</div></div>';
  document.body.appendChild(ov);
  var close = function() { if (document.body.contains(ov)) document.body.removeChild(ov); };
  document.getElementById('esec-cancel').onclick = close;
  ov.onclick = function(e) { if (e.target === ov) close(); };
  document.getElementById('esec-save').onclick = async function() {
    var d = await API.put('/templates/' + ADM.editingSecTplId + '/sections/' + secId, {
      name:        document.getElementById('esec-name').value,
      icon:        document.getElementById('esec-icon').value,
      type:        document.getElementById('esec-type').value,
      placeholder: document.getElementById('esec-ph').value,
      required:    document.getElementById('esec-req').checked,
    });
    if (d && d.error) return showToast(d.error, true);
    showToast('Section updated ✓');
    close();
    await refreshSectionsList();
  };
}

async function addSection() {
  var name = prompt('Section name:');
  if (!name || !name.trim()) return;
  var type = prompt('Type (richtext / findings / iocs / cvss / checklist / recommendation / timeline / custom):', 'richtext');
  type = (SECTION_TYPES.includes(type) ? type : 'richtext');
  var d = await API.post('/templates/' + ADM.editingSecTplId + '/sections', { name: name.trim(), type });
  if (d && d.error) return showToast(d.error, true);
  showToast('Section added ✓');
  await refreshSectionsList();
}

function closeSecModal() { document.getElementById('sec-modal').style.display = 'none'; }

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  (function() { var t = localStorage.getItem('kv-theme') || 'dark'; if (t === 'light') document.body.classList.add('light'); })();

  var me = await API.get('/auth/me');
  if (!me || !me.user) { window.location.href = '/'; return; }
  ADM.user = me.user;
  if (ADM.user.role !== 'admin') { window.location.href = '/'; return; }

  var av = ADM.user.avatar
    ? '<img src="' + esc(ADM.user.avatar) + '" style="width:24px;height:24px;border-radius:50%;object-fit:cover">'
    : '<span style="width:24px;height:24px;border-radius:50%;background:var(--red);display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff">' + esc((ADM.user.login || '?')[0].toUpperCase()) + '</span>';
  var hr = document.getElementById('adm-topbar-actions');
  if (hr) hr.innerHTML = av + '<span style="font-size:13px;color:var(--t3)">' + esc(ADM.user.login) + '</span>';

  // Bind static buttons
  document.getElementById('btn-new-template').onclick = openNewTplModal;
  document.getElementById('tpl-modal-close').onclick  = closeTplModal;
  document.getElementById('tpl-modal-cancel').onclick = closeTplModal;
  document.getElementById('tpl-modal-save').onclick   = saveTplModal;
  document.getElementById('tpl-modal').onclick        = function(e) { if (e.target === this) closeTplModal(); };
  document.getElementById('sec-modal-close').onclick  = closeSecModal;
  document.getElementById('sec-modal-close2').onclick = closeSecModal;
  document.getElementById('sec-modal').onclick        = function(e) { if (e.target === this) closeSecModal(); };
  document.getElementById('btn-add-section').onclick  = addSection;

  // Color sync
  var cp = document.getElementById('tpl-color');
  var ct = document.getElementById('tpl-color-text');
  if (cp) cp.addEventListener('input', function() { if (ct) ct.value = cp.value; });
  if (ct) ct.addEventListener('input', function() { if (/^#[0-9a-f]{6}$/i.test(ct.value) && cp) cp.value = ct.value; });

  await loadTemplates();
}

init();
