// ════════════════════════════════════════════════════════════════
// KQL Vault — Admin SPA (integrated into main app)
// Loaded after app.js. Uses S, T, esc, API, render globals.
// ════════════════════════════════════════════════════════════════

// ── Admin state (lives on S) ─────────────────────────────────────────────────
// S.adminTab       = 'dashboard' | 'users' | 'teams' | 'queries' | 'folders' |
//                    'investigations' | 'audit' | 'repos' | 'watch' | 'threats' |
//                    'fingerprint' | 'settings'
// S.adminFeatures  = { repos, watch, threats, fingerprint, translations }
// S.adminData      = { [tab]: cached payload | null }
// S.adminLoading   = { [tab]: true/false }
// S.adminModal     = null | { type, data }
// S.adminAudit     = { page:0, filters:{} }
// S.adminUsers     = { search:'', sort:'created_at', dir:'desc' }
// S.adminTeamSel   = teamId | null

// Initialise sub-state on first load
(function() {
  if (!S.adminTab)      S.adminTab      = 'dashboard';
  if (!S.adminFeatures) S.adminFeatures = null;
  if (!S.adminData)     S.adminData     = {};
  if (!S.adminLoading)  S.adminLoading  = {};
  if (!S.adminModal)    S.adminModal    = null;
  if (!S.adminAudit)    S.adminAudit    = { page: 0, filters: {} };
  if (!S.adminUsers)    S.adminUsers    = { search: '', sort: 'created_at', dir: 'desc' };
  if (!S.adminTeamSel)  S.adminTeamSel  = null;
  if (!S.adminQSel)     S.adminQSel     = {};   // selected query ids for bulk
  if (!S.adminQSearch)  S.adminQSearch  = '';
  if (!S.adminInvFilter) S.adminInvFilter = 'all';
})();

// Admin i18n keys are defined in data.js LANG (loaded before this file).

// ── Helpers ───────────────────────────────────────────────────────────────────

function adminTimeAgo(dt) { return dt ? timeAgo(dt) : '\u2014'; }

function adminFmtTs(dt) {
  if (!dt) return '—';
  return dt.replace('T',' ').slice(0,19);
}

function adminAvatar(user, size) {
  size = size || 28;
  if (!user) return '<span style="width:'+size+'px;height:'+size+'px;border-radius:50%;background:var(--s3);display:inline-flex;align-items:center;justify-content:center;font-size:'+(Math.floor(size/2.8))+'px;font-weight:700;color:var(--t4)">?</span>';
  var init = (user.login || user.display_name || '?')[0].toUpperCase();
  if (user.avatar) return '<img src="'+esc(user.avatar)+'" style="width:'+size+'px;height:'+size+'px;border-radius:50%;object-fit:cover;flex-shrink:0">';
  return '<span style="width:'+size+'px;height:'+size+'px;border-radius:50%;background:var(--red3);border:1px solid var(--red);display:inline-flex;align-items:center;justify-content:center;font-size:'+(Math.floor(size/2.8))+'px;font-weight:700;color:#fca5a5;flex-shrink:0">'+esc(init)+'</span>';
}

function actionBadge(action) {
  if (!action) return '';
  var bg, color;
  if (action.indexOf('FAIL') >= 0 || action === 'ADMIN_USER_DELETE') { bg = 'var(--red)'; color = '#fff'; }
  else if (action === 'LOGIN' || action === 'LOGOUT') { bg = 'var(--blue)'; color = '#fff'; }
  else if (action.indexOf('QUERY') >= 0) { bg = '#166534'; color = '#86efac'; }
  else if (action.indexOf('FOLDER') >= 0) { bg = '#7c2d12'; color = '#fdba74'; }
  else if (action.indexOf('INVESTIGATION') >= 0) { bg = '#3b0764'; color = '#d8b4fe'; }
  else if (action.indexOf('ADMIN') >= 0) { bg = '#7f1d1d'; color = '#fca5a5'; }
  else if (action === 'REPO_SYNC' || action === 'REPO_AUTOSYNC' || action === 'WATCH_AUTO_FETCH') { bg = 'var(--s3)'; color = 'var(--t3)'; }
  else { bg = 'var(--s3)'; color = 'var(--t2)'; }
  return '<span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;background:'+bg+';color:'+color+';white-space:nowrap;font-family:var(--mono)">'+esc(action)+'</span>';
}

function adminSpinner() {
  return '<div style="text-align:center;padding:60px;color:var(--t5)"><div style="display:inline-block;width:24px;height:24px;border:2px solid var(--bd);border-top-color:var(--red);border-radius:50%;animation:spin 0.6s linear infinite"></div></div>';
}

function adminEmpty(msg) {
  return '<div style="text-align:center;padding:60px;color:var(--t5);font-size:13px">'+(msg||T('no_data'))+'</div>';
}

// ── Load admin data ───────────────────────────────────────────────────────────

async function adminLoadTab(tab) {
  if (S.adminLoading[tab]) return;
  S.adminLoading[tab] = true;
  render();
  try {
    var data;
    if (tab === 'dashboard')      data = await API.get('/admin/dashboard');
    else if (tab === 'users')     data = await API.get('/admin/users');
    else if (tab === 'teams')     data = await API.get('/admin/teams');
    else if (tab === 'queries')   data = await API.get('/admin/queries');
    else if (tab === 'folders')   data = await API.get('/admin/folders');
    else if (tab === 'investigations') data = await API.get('/admin/investigations');
    else if (tab === 'audit')     { data = await loadAuditPage(); }
    else if (tab === 'settings')  data = await API.get('/admin/settings');
    else if (tab === 'repos')     data = await API.get('/repos');
    else if (tab === 'watch') {
      var [wSources, wSettings] = await Promise.all([API.get('/watch/sources'), API.get('/admin/watch-settings')]);
      data = { sources: wSources, sync_interval_minutes: (wSettings && wSettings.sync_interval_minutes) || 15 };
    }
    S.adminData[tab] = (data && data.error) ? { _error: data.error } : data;
  } catch(e) {
    S.adminData[tab] = { _error: e.message };
  }
  S.adminLoading[tab] = false;
  render();
}

async function loadAuditPage() {
  var f = S.adminAudit.filters;
  var qs = '?limit=50&offset=' + (S.adminAudit.page * 50);
  if (f.user_id) qs += '&user_id=' + encodeURIComponent(f.user_id);
  if (f.action)  qs += '&action='  + encodeURIComponent(f.action);
  if (f.from)    qs += '&from='    + encodeURIComponent(f.from);
  if (f.to)      qs += '&to='      + encodeURIComponent(f.to);
  if (f.q)       qs += '&q='       + encodeURIComponent(f.q);
  return API.get('/admin/audit' + qs);
}

async function detectAdminFeatures() {
  if (S.adminFeatures) return;
  try { S.adminFeatures = await API.get('/admin/features'); }
  catch(e) { S.adminFeatures = {}; }
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

function renderAdminSidebar() {
  var af = S.adminFeatures || {};
  var tab = S.adminTab || 'dashboard';

  function ico(paths) {
    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">'+paths+'</svg>';
  }
  var icons = {
    dashboard:      ico('<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>'),
    users:          ico('<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>'),
    teams:          ico('<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>'),
    queries:        ico('<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>'),
    folders:        ico('<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'),
    investigations: ico('<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>'),
    audit:          ico('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>'),
    repos:          ico('<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>'),
    watch:          ico('<circle cx="12" cy="12" r="2"/><path d="M12 4C7 4 3 8 3 12s4 8 9 8 9-4 9-8-4-8-9-8"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/>'),
    threats:        ico('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
    fingerprint:    ico('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>'),
    settings:       ico('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>')
  };

  function si(id, label) {
    var active = tab === id;
    var sty = active ? 'background:var(--s3);box-shadow:inset 3px 0 0 var(--red);color:var(--t1)' : 'color:var(--t3)';
    var icoColor = active ? 'var(--t1)' : 'var(--t4)';
    return '<div class="si admin-si" data-admin-tab="'+id+'" style="display:flex;align-items:center;gap:9px;padding:8px 14px;cursor:pointer;border-radius:0;transition:all var(--tr);'+sty+'">'
      +'<span style="color:'+icoColor+';display:flex">'+icons[id]+'</span>'
      +'<span style="font-size:13px;font-weight:'+(active?'600':'400')+'">'+label+'</span>'
      +'</div>';
  }

  var h = '<div class="side" style="width:220px;flex-shrink:0;padding-top:0">';
  h += '<div style="padding:12px 14px 8px">';
  h += '<div id="btn-back-vault" style="display:flex;align-items:center;gap:7px;cursor:pointer;color:var(--t4);font-size:13px;padding:6px 0;transition:color var(--tr)" onmouseover="this.style.color=\'var(--t2)\'" onmouseout="this.style.color=\'var(--t4)\'">'
    + '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="15 18 9 12 15 6"/></svg>'
    + T('back_to_vault')+'</div>';
  h += '</div>';
  h += '<div style="padding:8px 14px 4px"><span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--t5)">'+T('admin_panel')+'</span></div>';

  h += si('dashboard',     T('admin_dashboard'));
  h += si('users',         T('admin_users'));
  h += si('teams',         T('admin_teams'));
  h += si('queries',       T('admin_queries'));
  h += si('folders',       T('admin_folders'));
  h += si('investigations',T('admin_investigations'));
  h += si('audit',         T('admin_audit'));

  var hasOptional = af.repos || af.watch || af.threats;
  if (hasOptional) {
    h += '<div style="height:1px;background:var(--bd);margin:6px 14px"></div>';
    if (af.repos)   h += si('repos',   T('admin_repos'));
    if (af.watch)   h += si('watch',   T('admin_watch'));
    if (af.threats) h += si('threats', T('admin_threats'));
  }

  h += '<div style="height:1px;background:var(--bd);margin:6px 14px"></div>';
  h += si('settings', T('admin_settings'));
  h += '</div>';
  return h;
}

// ── Main admin content dispatcher ─────────────────────────────────────────────

function renderAdminContent() {
  var tab = S.adminTab || 'dashboard';
  var h = '<div style="padding:24px 28px 60px;overflow-y:auto;height:calc(100vh - 56px)">';

  if (S.adminData[tab] === undefined && !S.adminLoading[tab]) {
    // Trigger load but return spinner immediately
    setTimeout(function() { adminLoadTab(tab); }, 0);
    h += adminSpinner();
    h += '</div>';
    return h;
  }
  if (S.adminLoading[tab]) { h += adminSpinner(); h += '</div>'; return h; }

  var data = S.adminData[tab];
  if (data && (data._error || data.error)) {
    h += '<div style="color:var(--red);padding:20px">Error: '+esc(data._error || data.error)+'</div>';
    h += '</div>';
    return h;
  }

  if (tab === 'dashboard')       h += renderAdminDashboard(data);
  else if (tab === 'users')      h += renderAdminUsers(data);
  else if (tab === 'teams')      h += renderAdminTeams(data);
  else if (tab === 'queries')    h += renderAdminQueries(data);
  else if (tab === 'folders')    h += renderAdminFolders(data);
  else if (tab === 'investigations') h += renderAdminInvestigations(data);
  else if (tab === 'audit')      h += renderAdminAudit(data);
  else if (tab === 'settings')   h += renderAdminSettings(data);
  else if (tab === 'repos')      h += renderAdminRepos(data);
  else if (tab === 'watch')      h += renderAdminWatch(data);
  else h += adminEmpty(T('admin_tab_wip'));

  h += '</div>';

  // Admin modal overlay
  if (S.adminModal) h += renderAdminModal();

  return h;
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

function formatAdminUptime(s) {
  var d = Math.floor(s/86400), hr = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  if (d>0) return d+'d '+hr+'h';
  if (hr>0) return hr+'h '+m+'m';
  return m+'m';
}

// colorKey: 'cyan'|'violet'|'teal'|'amber'|'red'|'blue'
// icon: emoji or SVG string
function _admKpi(label, value, colorKey, icon, sub) {
  var iconHtml = icon
    ? '<div class="adm-kpi-icon adm-kpi-icon--'+colorKey+'">'+icon+'</div>'
    : '<div class="adm-kpi-icon adm-kpi-icon--'+colorKey+'" style="font-size:18px">◆</div>';
  return '<div class="adm-kpi-card">'
    + iconHtml
    + '<div><div class="adm-kpi-val">'+value+'</div>'
    + '<div class="adm-kpi-label">'+label+'</div>'
    + (sub ? '<div class="adm-kpi-sub">'+sub+'</div>' : '')
    + '</div></div>';
}

function _admHealthVal(v, cls) {
  return '<span class="adm-health-val'+(cls?' '+cls:'')+'">'+(v===null||v===undefined?'—':esc(String(v)))+'</span>';
}

function _admTip(text) {
  return '<span class="adm-tip"><span class="adm-tip-icon">i</span><span class="adm-tip-bubble">'+esc(text)+'</span></span>';
}

function renderAdminDashboard(data) {
  if (!data) return adminEmpty();
  var st  = data.stats        || {};
  var sys = data.system       || data.systemHealth || {};
  var old = data.systemHealth || {};

  var h = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">';
  h += '<h1 style="font-size:20px;font-weight:800">'+T('admin_dashboard')+'</h1>';
  h += '<button id="btn-admin-refresh-dash" style="font-size:12px;padding:5px 12px">↺ Refresh</button>';
  h += '</div>';

  // ── KPI row ──────────────────────────────────────────────────────────────
  h += '<div class="adm-kpi-grid">';
  h += _admKpi('Queries',            st.queries            || 0, 'cyan',   '📄');
  h += _admKpi('Users',              st.users              || 0, 'blue',   '👥');
  h += _admKpi('Teams',              st.teams              || 0, 'violet', '🏢');
  h += _admKpi('Active sessions',    st.active_sessions    || 0, 'teal',   '🔗');
  h += _admKpi('Folders',            st.folders            || 0, 'amber',  '📁');
  h += _admKpi('Watch articles',     st.watch_articles     || 0, 'cyan',   '📰');
  h += _admKpi('Repo sources',       st.repo_sources       || 0, 'violet', '🗄️');
  h += _admKpi('Open investigations', st.investigations_open||0, 'red',    '🔍');
  h += _admKpi('Audit events (7d)',   st.audit_7d           || 0, 'blue',   '📋');
  h += '</div>';

  // ── Chart row 1: Activity (wide) + Severity donut + Env donut ───────────
  h += '<div class="adm-chart-row adm-chart-row-3">';

  h += '<div class="adm-chart-card">';
  h += '<div class="adm-chart-title">Audit activity — last 30 days'+_admTip('Daily audit event count over the last 30 days. Tracks logins, query creations, edits, and deletions across the platform.')+'</div>';
  h += '<div class="adm-chart-canvas-wrap" style="height:160px"><canvas id="chart-activity"></canvas></div>';
  h += '</div>';

  h += '<div class="adm-chart-card">';
  h += '<div class="adm-chart-title">Queries by severity'+_admTip('Distribution by severity level (critical → info). Helps assess the proportion of high-impact detection coverage.')+'</div>';
  h += '<div class="adm-chart-canvas-wrap" style="height:130px"><canvas id="chart-severity"></canvas></div>';
  var sevData = data.by_severity || {};
  var sevColors = { critical:'#dc2626', high:'#ea580c', medium:'#ca8a04', low:'#16a34a', info:'#3b82f6' };
  h += '<div class="adm-legend">';
  ['critical','high','medium','low','info'].forEach(function(k) {
    if (sevData[k]) h += '<div class="adm-legend-item"><div class="adm-legend-dot" style="background:'+sevColors[k]+'"></div>'+k+' <span class="adm-legend-val">('+sevData[k]+')</span></div>';
  });
  h += '</div></div>';

  h += '<div class="adm-chart-card">';
  h += '<div class="adm-chart-title">Queries by environment'+_admTip('Breakdown by target platform: Defender, Sentinel, or both. Use this to balance detection coverage across environments.')+'</div>';
  h += '<div class="adm-chart-canvas-wrap" style="height:130px"><canvas id="chart-env"></canvas></div>';
  var envData = data.by_environment || {};
  var envColors = { Defender:'#3b82f6', Sentinel:'#7c3aed', Both:'#06b6d4' };
  h += '<div class="adm-legend">';
  ['Defender','Sentinel','Both'].forEach(function(k) {
    if (envData[k]) h += '<div class="adm-legend-item"><div class="adm-legend-dot" style="background:'+envColors[k]+'"></div>'+k+' <span class="adm-legend-val">('+envData[k]+')</span></div>';
  });
  h += '</div></div>';

  h += '</div>'; // chart-row-3

  // ── Chart row 2: Teams bar + Language donut + Top tags ───────────────────
  h += '<div class="adm-chart-row adm-chart-row-3">';

  h += '<div class="adm-chart-card">';
  h += '<div class="adm-chart-title">Queries by team'+_admTip('Number of queries owned by each team. Identifies the most active contributors and highlights coverage gaps across teams.')+'</div>';
  h += '<div class="adm-chart-canvas-wrap" style="height:160px"><canvas id="chart-teams"></canvas></div>';
  h += '</div>';

  h += '<div class="adm-chart-card">';
  h += '<div class="adm-chart-title">Queries by language'+_admTip('Distribution by query language (KQL, SPL, SQL…). Useful to assess multi-platform detection coverage beyond Microsoft tools.')+'</div>';
  h += '<div class="adm-chart-canvas-wrap" style="height:130px"><canvas id="chart-lang"></canvas></div>';
  var langData = data.by_language || {};
  h += '<div class="adm-legend">';
  Object.keys(langData).forEach(function(k) {
    h += '<div class="adm-legend-item"><div class="adm-legend-dot" style="background:var(--blue)"></div>'+esc(k)+' <span class="adm-legend-val">('+langData[k]+')</span></div>';
  });
  h += '</div></div>';

  h += '<div class="adm-chart-card">';
  h += '<div class="adm-chart-title">Top 10 tags'+_admTip('The 10 most-used tags across all queries. Reflects dominant threat themes and detection categories in your library.')+'</div>';
  h += '<div class="adm-chart-canvas-wrap" style="height:160px"><canvas id="chart-tags"></canvas></div>';
  h += '</div>';

  h += '</div>'; // chart-row-3

  // ── Watch activity (if data available) ───────────────────────────────────
  var wa = data.watch_activity_14d || [];
  var hasWa = wa.some(function(x) { return x.articles > 0; });
  if (hasWa) {
    h += '<div class="adm-chart-row adm-chart-row-2" style="margin-bottom:16px">';
    h += '<div class="adm-chart-card">';
    h += '<div class="adm-chart-title">Cyber Watch — articles last 14 days'+_admTip('Daily count of threat intelligence articles ingested over the last 14 days, broken down by watch source.')+'</div>';
    h += '<div class="adm-chart-canvas-wrap" style="height:160px"><canvas id="chart-watch"></canvas></div>';
    h += '</div>';
    h += '<div></div>';
    h += '</div>';
  }

  // ── MITRE ATT&CK coverage heatmap ────────────────────────────────────────
  var mitreData = data.mitre_coverage || {};
  var hasMitre  = Object.keys(mitreData).length > 0;
  if (hasMitre && typeof MITRE !== 'undefined') {
    h += '<div class="adm-chart-card" style="margin-bottom:16px">';
    h += '<div class="adm-chart-title">MITRE ATT&CK Coverage'+_admTip('Query coverage mapped to MITRE ATT&CK tactics and techniques. Darker cells = more queries targeting that technique. White cells = no coverage.')+'</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:6px;padding:8px 0">';
    MITRE.forEach(function(tactic) {
      var cnt = mitreData[tactic.id] || 0;
      var hasCov = cnt > 0;
      // Also sum technique counts under this tactic
      if (!hasCov && typeof MITRE_TECHNIQUES !== 'undefined') {
        MITRE_TECHNIQUES.forEach(function(t) {
          if (t.tid === tactic.id && mitreData[t.id]) hasCov = true;
        });
      }
      var bg  = hasCov ? tactic.c + '22' : 'var(--s2)';
      var bc  = hasCov ? tactic.c + '55' : 'var(--bd)';
      var tc  = hasCov ? tactic.c : 'var(--t5)';
      h += '<div style="border:1px solid '+bc+';border-radius:6px;padding:5px 10px;min-width:100px;background:'+bg+';cursor:default" title="'+esc(tactic.id)+' — '+esc(tactic.n)+' | '+cnt+' queries">';
      h += '<div style="font-size:9px;font-weight:700;color:'+tc+';letter-spacing:0.5px">'+esc(tactic.id)+'</div>';
      h += '<div style="font-size:10px;color:'+tc+';margin-top:1px">'+esc(tactic.n)+'</div>';
      if (cnt > 0) h += '<div style="font-size:11px;font-weight:700;color:'+tactic.c+';margin-top:2px">'+cnt+' quer.</div>';
      h += '</div>';
    });
    h += '</div>';
    h += '</div>';
  }

  // ── Top queries by stars ──────────────────────────────────────────────────
  var topQ = data.top_queries || [];
  if (topQ.length) {
    h += '<div class="adm-chart-card" style="margin-bottom:16px">';
    h += '<div class="adm-chart-title">Top queries by stars ⭐</div>';
    h += '<table class="admin-table" style="font-size:12px"><thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Language</th><th>Team</th><th>Stars</th></tr></thead><tbody>';
    var sevColors = { critical:'#dc2626', high:'#ea580c', medium:'#ca8a04', low:'#16a34a', info:'#3b82f6' };
    topQ.forEach(function(q, i) {
      var sc2 = sevColors[q.severity] || 'var(--t4)';
      h += '<tr>';
      h += '<td style="color:var(--t5)">'+(i+1)+'</td>';
      h += '<td style="font-weight:600">'+esc(q.title)+'</td>';
      h += '<td><span style="color:'+sc2+';font-size:11px;font-weight:700">'+esc(q.severity||'')+'</span></td>';
      h += '<td style="color:var(--t3)">'+esc(q.language||'KQL')+'</td>';
      h += '<td style="color:var(--t4)">'+esc(q.team||'—')+'</td>';
      h += '<td style="font-weight:700;color:#f59e0b">'+(q.stars||0)+'</td>';
      h += '</tr>';
    });
    h += '</tbody></table>';
    h += '</div>';
  }

  // ── Bottom: recent activity + system health ───────────────────────────────
  h += '<div class="adm-bottom-row">';

  // Recent activity
  h += '<div class="adm-activity-panel">';
  h += '<div class="adm-activity-title">'+T('recent_activity')+'</div>';
  var acts = data.recentActivity || [];
  if (!acts.length) { h += adminEmpty(); }
  else {
    acts.forEach(function(log) {
      var user = { login: log.user_login, avatar: log.user_avatar };
      var det = '';
      try { det = log.details ? JSON.parse(log.details) : null; } catch(e) { det = log.details; }
      var detStr = det ? (typeof det === 'object' ? JSON.stringify(det).slice(0,50) : String(det).slice(0,50)) : '';
      h += '<div class="adm-act-row">';
      h += '<span class="adm-act-time">'+adminFmtTs(log.created_at).slice(11,16)+'</span>';
      h += adminAvatar(user, 22);
      h += '<span class="adm-act-login">'+esc(log.user_login||'system')+'</span>';
      h += actionBadge(log.action);
      if (detStr) h += '<span class="adm-act-det">'+esc(detStr)+'</span>';
      h += '</div>';
    });
  }
  h += '</div>';

  // System health
  var dbMb    = sys.db_size_mb   || 0;
  var dbCls   = dbMb > 500 ? 'bad' : dbMb > 100 ? 'warn' : 'ok';
  var sessCls = (sys.active_sessions || old.sessions_active || 0) > 20 ? 'warn' : 'ok';
  var failCls = (sys.failed_logins_24h || 0) > 10 ? 'bad' : (sys.failed_logins_24h || 0) > 3 ? 'warn' : 'ok';

  h += '<div class="adm-health-grid">';
  h += '<div class="adm-health-title">System Health</div>';
  h += '<div class="adm-health-row"><span class="adm-health-key">DB size</span>'+_admHealthVal(sys.db_size_human || old.db_size_human || '—', dbCls)+'</div>';
  h += '<div class="adm-health-row"><span class="adm-health-key">Active sessions</span>'+_admHealthVal(sys.active_sessions !== undefined ? sys.active_sessions : (old.sessions_active||0), sessCls)+'</div>';
  h += '<div class="adm-health-row"><span class="adm-health-key">Failed logins (24h)</span>'+_admHealthVal(sys.failed_logins_24h || 0, failCls)+'</div>';
  h += '<div class="adm-health-row"><span class="adm-health-key">Audit entries</span>'+_admHealthVal(sys.audit_entries !== undefined ? sys.audit_entries : (st.audit_7d||'—'))+'</div>';
  h += '<div class="adm-health-row"><span class="adm-health-key">Node.js</span>'+_admHealthVal(old.node_version || '—')+'</div>';
  h += '<div class="adm-health-row"><span class="adm-health-key">Uptime</span>'+_admHealthVal(old.uptime ? formatAdminUptime(old.uptime) : '—')+'</div>';
  if (sys.last_repo_sync || old.last_repo_sync)
    h += '<div class="adm-health-row"><span class="adm-health-key">Last repo sync</span>'+_admHealthVal(adminTimeAgo(sys.last_repo_sync || old.last_repo_sync))+'</div>';
  if (sys.last_watch_fetch || old.last_watch_fetch)
    h += '<div class="adm-health-row"><span class="adm-health-key">Last watch fetch</span>'+_admHealthVal(adminTimeAgo(sys.last_watch_fetch || old.last_watch_fetch))+'</div>';
  h += '</div>';

  h += '</div>'; // adm-bottom-row
  return h;
}

// ── Users ─────────────────────────────────────────────────────────────────────

function renderAdminUsers(users) {
  if (!Array.isArray(users)) return adminEmpty();

  var search = S.adminUsers.search || '';
  var sort   = S.adminUsers.sort   || 'created_at';
  var dir    = S.adminUsers.dir    || 'desc';

  var filtered = users.filter(function(u) {
    if (!search) return true;
    var s = search.toLowerCase();
    return (u.login||'').toLowerCase().indexOf(s) >= 0 || (u.display_name||'').toLowerCase().indexOf(s) >= 0;
  });

  filtered = filtered.slice().sort(function(a,b) {
    var av = a[sort]||'', bv = b[sort]||'';
    if (av < bv) return dir==='asc'?-1:1;
    if (av > bv) return dir==='asc'?1:-1;
    return 0;
  });

  var h = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap">';
  h += '<h1 style="font-size:20px;font-weight:800;margin-right:auto">'+T('admin_users')+' <span style="font-size:14px;font-weight:400;color:var(--t4)">('+users.length+')</span></h1>';
  h += '<input id="admin-user-search" placeholder="'+T('admin_search_users')+'" value="'+esc(search)+'" style="width:220px;padding:7px 12px;font-size:13px">';
  h += '<button class="pri" id="btn-admin-create-user" style="font-size:13px;padding:7px 14px">+ '+T('create_user')+'</button>';
  h += '</div>';

  h += '<div style="overflow-x:auto"><table class="admin-table">';
  h += '<thead><tr>';
  var cols = [['',''],['login',T('admin_col_login')],['display_name',T('admin_col_display')],['role',T('admin_col_role')],['team',T('admin_col_team')],['status',T('admin_col_status')],['sessions',T('admin_col_sessions')],['created_at',T('admin_col_created')]];
  cols.forEach(function(c) {
    if (!c[0]) { h += '<th style="width:32px"></th>'; return; }
    var isSort = sort === c[0];
    var arrow = isSort ? (dir==='asc'?' ↑':' ↓') : '';
    h += '<th data-admin-sort="'+c[0]+'" style="cursor:pointer">'+c[1]+arrow+'</th>';
  });
  h += '<th>'+T('admin_col_actions')+'</th></tr></thead><tbody>';

  if (!filtered.length) {
    h += '<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--t5)">'+T('no_data')+'</td></tr>';
  }
  filtered.forEach(function(u) {
    var isLocked = u.locked_until && new Date(u.locked_until) > new Date();
    var status;
    if (isLocked) {
      var remaining = Math.ceil((new Date(u.locked_until) - Date.now()) / 60000);
      status = '<span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#7c2d12;color:#fdba74">'+T('admin_status_locked',{remaining:remaining})+'</span>';
    } else if (u.must_change_password) {
      status = '<span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#713f12;color:#fde68a">'+T('admin_status_change_pw')+'</span>';
    } else {
      status = '<span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#14532d;color:#86efac">'+T('admin_status_active')+'</span>';
    }

    var roleColors = { admin:'#fca5a5;background:#7f1d1d', analyst:'#93c5fd;background:#1e3a5f', viewer:'#6ee7b7;background:#064e3b' };
    var rc = roleColors[u.role] || 'var(--t2);background:var(--s3)';

    h += '<tr>';
    h += '<td>'+adminAvatar(u, 28)+'</td>';
    h += '<td><button class="admin-user-detail" data-uid="'+u.id+'" style="background:none;border:none;color:var(--blue);cursor:pointer;font-family:var(--mono);font-size:12px;padding:0;text-decoration:underline">'+esc(u.login)+'</button></td>';
    h += '<td style="color:var(--t2)">'+esc(u.display_name||'—')+'</td>';
    h += '<td><span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:'+rc+'">'+u.role+'</span></td>';
    h += '<td style="color:var(--t3);font-size:12px">'+esc(u.team==='none'||!u.team?'—':u.team)+'</td>';
    h += '<td>'+status+'</td>';
    h += '<td style="text-align:center;color:'+(u.session_count>0?'var(--green)':'var(--t5)')+'">'+u.session_count+'</td>';
    h += '<td style="color:var(--t4);font-size:12px">'+adminTimeAgo(u.created_at)+'</td>';
    h += '<td><div class="action-menu"><button class="action-menu-btn" data-amenu="'+u.id+'">⋯</button>'
      + '<div class="action-menu-dropdown" id="amenu-'+u.id+'" style="display:none">'
      + '<button class="action-menu-item admin-user-detail" data-uid="'+u.id+'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>'+T('admin_view_detail')+'</button>'
      + '<button class="action-menu-item admin-reset-pw" data-uid="'+u.id+'" data-ulogin="'+esc(u.login)+'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>'+T('reset_password')+'</button>'
      + '<button class="action-menu-item admin-force-pw" data-uid="'+u.id+'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'+T('force_change_pw')+'</button>'
      + (isLocked ? '<button class="action-menu-item admin-unlock" data-uid="'+u.id+'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>'+T('unlock_account')+'</button>' : '')
      + '<button class="action-menu-item admin-kill-sess" data-uid="'+u.id+'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>'+T('kill_sessions')+'</button>'
      + '<button class="action-menu-item danger admin-del-user" data-uid="'+u.id+'" data-ulogin="'+esc(u.login)+'"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>'+T('delete_user')+'</button>'
      + '</div></div></td>';
    h += '</tr>';
  });

  h += '</tbody></table></div>';
  return h;
}

// ── Teams ─────────────────────────────────────────────────────────────────────

function renderAdminTeams(teams) {
  if (!Array.isArray(teams)) return adminEmpty();
  var allUsers = S.adminData['users'] || [];

  var h = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">';
  h += '<h1 style="font-size:20px;font-weight:800;margin-right:auto">'+T('admin_teams')+' <span style="font-size:14px;font-weight:400;color:var(--t4)">('+teams.length+')</span></h1>';
  h += '<button class="pri" id="btn-admin-create-team" style="font-size:13px;padding:7px 14px">+ '+T('create_team')+'</button>';
  h += '</div>';

  if (!teams.length) return h + adminEmpty(T('admin_empty_teams'));

  h += '<div class="teams-grid">';
  teams.forEach(function(t) {
    var color    = t.color || '#6366f1';
    var initials = (t.name || '?').slice(0, 2).toUpperCase();
    var notInTeam = allUsers.filter(function(u) { return u.team !== t.id; });

    h += '<div class="team-card">';

    // Header
    h += '<div class="team-card-header">';
    h += '<div class="team-avatar-wrap">';
    if (t.avatar_url) {
      h += '<img class="team-avatar-img" src="'+esc(t.avatar_url)+'" alt="'+esc(initials)+'">';
    } else {
      h += '<div class="team-avatar-initials" style="background:'+color+'22;color:'+color+'">'+initials+'</div>';
    }
    h += '</div>';
    h += '<div class="team-card-meta">';
    h += '<div class="team-card-name">'+esc(t.name)+'</div>';
    if (t.description) h += '<div class="team-card-desc">'+esc(t.description)+'</div>';
    h += '</div>';
    h += '<div style="display:flex;gap:6px;align-items:center;flex-shrink:0">';
    h += '<button class="admin-team-edit" data-tid="'+t.id+'" style="font-size:12px;padding:4px 10px;color:var(--blue);border-color:var(--blue)40">Edit</button>';
    h += '<button class="admin-del-team" data-tid="'+t.id+'" data-tname="'+esc(t.name)+'" style="font-size:12px;padding:4px 10px;color:var(--red);border-color:var(--red3)">Del</button>';
    h += '</div>';
    h += '</div>';

    // Stats bar
    h += '<div style="display:flex;gap:0;border-bottom:1px solid var(--bd)">';
    h += '<div class="team-stat"><div style="font-size:18px;font-weight:800;color:var(--blue)">'+t.member_count+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Members</div></div>';
    h += '<div class="team-stat"><div style="font-size:18px;font-weight:800;color:var(--accent)">'+t.query_count+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Queries</div></div>';
    h += '<div class="team-stat"><div style="font-size:18px;font-weight:800;color:var(--orange)">'+t.folder_count+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Folders</div></div>';
    h += '</div>';

    // Members list
    if (t.members.length) {
      h += '<div class="team-members">';
      t.members.slice(0, 5).forEach(function(m) {
        h += '<div class="team-member-row">';
        h += '<div class="team-member-avatar">'+adminAvatar(m, 26)+'</div>';
        h += '<div class="team-member-info"><div class="team-member-name">'+esc(m.login)+'</div><div class="team-member-role">'+esc(m.role)+'</div></div>';
        h += '<button class="admin-rm-member" data-tid="'+t.id+'" data-uid="'+m.id+'" style="font-size:11px;color:var(--red);border-color:var(--red3);padding:2px 7px;margin-left:auto;flex-shrink:0">×</button>';
        h += '</div>';
      });
      if (t.members.length > 5) h += '<div style="font-size:11px;color:var(--t4);padding:6px 16px">+' + (t.members.length - 5) + ' more members</div>';
      h += '</div>';
    }

    // Add member
    if (notInTeam.length) {
      h += '<div class="team-add-member">';
      h += '<select class="admin-add-member-sel" data-tid="'+t.id+'" style="flex:1;font-size:12px;padding:5px 8px"><option value="">Add member…</option>';
      notInTeam.forEach(function(u) { h += '<option value="'+u.id+'">'+esc(u.login)+' ('+esc(u.role)+')</option>'; });
      h += '</select>';
      h += '<button class="btn-admin-add-member pri" data-tid="'+t.id+'" style="font-size:12px;padding:5px 12px">+</button>';
      h += '</div>';
    }

    h += '</div>'; // team-card
  });
  h += '</div>'; // teams-grid
  return h;
}

// ── Queries ───────────────────────────────────────────────────────────────────

function renderAdminQueries(queries) {
  if (!Array.isArray(queries)) return adminEmpty();
  var search = S.adminQSearch || '';
  var sel    = S.adminQSel || {};

  var filtered = queries.filter(function(q) {
    if (!search) return true;
    var s = search.toLowerCase();
    return (q.title||'').toLowerCase().indexOf(s) >= 0 || (q.author_name||'').toLowerCase().indexOf(s) >= 0;
  });

  var selIds      = Object.keys(sel).filter(function(k) { return sel[k]; });
  var selCount    = selIds.length;
  var filteredSel = filtered.filter(function(q) { return sel[q.id]; }).length;

  var h = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">';
  h += '<h1 style="font-size:20px;font-weight:800;margin-right:auto">'+T('admin_queries')+'</h1>';
  h += '<span style="font-size:12px;color:var(--t4)">'+queries.length+' total · ';
  h += queries.filter(function(q){return (q.language||'KQL')==='KQL'&&(q.environment||'Defender')==='Defender';}).length+' Defender · ';
  h += queries.filter(function(q){return q.environment==='Sentinel';}).length+' Sentinel · ';
  h += queries.filter(function(q){return !q.folder_id;}).length+' orphaned</span>';
  h += '<input id="admin-q-search" placeholder="Search…" value="'+esc(search)+'" style="width:200px;padding:7px 12px;font-size:13px">';
  h += '</div>';

  // Sticky bulk action bar (shows above table when rows are selected)
  h += '<div class="bulk-bar'+(selCount>0?' visible':'') +'" id="admin-bulk-bar">';
  h += '<span class="bulk-count">'+selCount+' '+(selCount===1?'query':'queries')+' selected</span>';
  h += '<div class="bulk-actions">';
  h += '<select id="bulk-sev-sel" style="font-size:12px;padding:5px 8px"><option value="">Change severity…</option>';
  ['critical','high','medium','low','info'].forEach(function(s) { h += '<option value="'+s+'">'+s+'</option>'; });
  h += '</select>';
  h += '<button class="admin-bulk-act" data-bact="severity" style="font-size:12px;padding:5px 12px">Apply</button>';
  h += '<button class="admin-bulk-act" data-bact="delete" style="font-size:12px;padding:5px 12px;color:var(--red);border-color:var(--red3)">Delete selected</button>';
  h += '<button id="btn-bulk-clear" style="font-size:12px;padding:5px 12px;color:var(--t4)">Clear</button>';
  h += '</div>';
  h += '</div>';

  h += '<div style="overflow-x:auto"><table class="admin-table">';
  h += '<thead><tr>';
  h += '<th style="width:36px"><input type="checkbox" id="admin-q-selall"'+(filtered.length>0&&filteredSel===filtered.length?' checked':'')+'></th>';
  h += '<th>Title</th><th>Language</th><th>Severity</th><th>Folder</th><th>Author</th><th>Stars</th><th>Updated</th><th>Actions</th>';
  h += '</tr></thead><tbody>';

  if (!filtered.length) {
    h += '<tr><td colspan="9" style="text-align:center;padding:40px;color:var(--t5)">'+T('no_data')+'</td></tr>';
  }

  var sevColors = {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'};
  filtered.forEach(function(q) {
    var sc = sevColors[q.severity] || 'var(--t4)';
    h += '<tr>';
    h += '<td><input type="checkbox" class="admin-q-chk" data-qid="'+q.id+'"'+(sel[q.id]?' checked':'')+'></td>';
    h += '<td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><span style="font-size:13px;font-weight:500">'+esc(q.title)+'</span>'
      + (!q.folder_id?'<span style="margin-left:6px;font-size:10px;padding:1px 5px;border-radius:3px;background:var(--s3);color:var(--t4)">no folder</span>':'')
      + (q.is_repo_query?'<span style="margin-left:4px;font-size:10px;color:#6e40c9">GH</span>':'')
      + '</td>';
    h += '<td><span style="font-size:11px;color:var(--t3)">'+esc(q.language||'KQL')+'</span></td>';
    h += '<td><span style="font-size:11px;font-weight:600;color:'+sc+'">'+esc(q.severity||'')+'</span></td>';
    h += '<td style="font-size:12px;color:var(--t4)">'+esc(q.folder_name||'—')+'</td>';
    h += '<td style="font-size:12px;color:var(--t3)">'+esc(q.author_name||'—')+'</td>';
    h += '<td style="text-align:center;font-size:12px;color:var(--t4)">'+(q.stars||0)+'</td>';
    h += '<td style="font-size:12px;color:var(--t5)">'+adminTimeAgo(q.updated_at)+'</td>';
    h += '<td><button class="admin-del-query" data-qid="'+q.id+'" data-qtitle="'+esc(q.title)+'" style="font-size:11px;color:var(--red);border-color:var(--red3);padding:3px 8px">Del</button></td>';
    h += '</tr>';
  });
  h += '</tbody></table></div>';
  return h;
}

// ── Folders ───────────────────────────────────────────────────────────────────

function renderAdminFolders(folders) {
  if (!Array.isArray(folders)) return adminEmpty();
  var h = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">';
  h += '<h1 style="font-size:20px;font-weight:800;margin-right:auto">'+T('admin_folders')+' <span style="font-size:14px;font-weight:400;color:var(--t4)">('+folders.length+')</span></h1>';
  h += '</div>';
  h += '<div style="overflow-x:auto"><table class="admin-table"><thead><tr>';
  h += '<th>Icon</th><th>Name</th><th>Scope</th><th>Team</th><th>Owner</th><th>Queries</th><th>Actions</th>';
  h += '</tr></thead><tbody>';
  if (!folders.length) h += '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--t5)">'+T('no_data')+'</td></tr>';
  folders.forEach(function(f) {
    h += '<tr>';
    h += '<td><span style="width:28px;height:28px;border-radius:6px;background:'+(f.color||'var(--red)')+'1a;color:'+(f.color||'var(--red)')+';display:inline-flex;align-items:center;justify-content:center;font-size:11px">'+esc(f.icon||'FD')+'</span></td>';
    h += '<td style="font-weight:500">'+esc(f.name)+'</td>';
    h += '<td><span style="font-size:11px;padding:2px 7px;border-radius:4px;background:var(--s3);color:var(--t3)">'+esc(f.scope||'')+'</span></td>';
    h += '<td style="font-size:12px;color:var(--t4)">'+esc(f.team_name||'—')+'</td>';
    h += '<td style="font-size:12px;color:var(--t4);font-family:var(--mono)">'+esc(f.owner_login||'—')+'</td>';
    h += '<td style="text-align:center;font-size:13px;font-weight:600">'+( f.query_count||0)+'</td>';
    h += '<td><button class="admin-del-folder" data-fid="'+f.id+'" data-fname="'+esc(f.name)+'" data-qcount="'+(f.query_count||0)+'" style="font-size:11px;color:var(--red);border-color:var(--red3);padding:3px 8px">Del</button></td>';
    h += '</tr>';
  });
  h += '</tbody></table></div>';
  return h;
}

// ── Investigations ─────────────────────────────────────────────────────────────

function renderAdminInvestigations(invs) {
  if (!Array.isArray(invs)) return adminEmpty();
  var filter = S.adminInvFilter || 'all';
  var filtered = invs.filter(function(i) { return filter === 'all' || i.status === filter; });

  var h = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap">';
  h += '<h1 style="font-size:20px;font-weight:800;margin-right:auto">'+T('admin_investigations')+'</h1>';
  h += '</div>';
  ['all','open','in-progress','closed'].forEach(function(f) {
    var cnt = f==='all' ? invs.length : invs.filter(function(i){return i.status===f;}).length;
    h += '<button class="admin-inv-filter" data-invf="'+f+'" style="font-size:12px;padding:5px 12px;margin-bottom:16px;margin-right:4px;'+(filter===f?'background:var(--red);color:#fff;border-color:var(--red)':'')+'">'+(f.charAt(0).toUpperCase()+f.slice(1))+' ('+cnt+')</button>';
  });

  var sevColors = {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'};
  var statusStyles = {open:'background:#7f1d1d;color:#fca5a5',['in-progress']:'background:#7c2d12;color:#fdba74',closed:'background:#14532d;color:#86efac'};

  h += '<div style="overflow-x:auto"><table class="admin-table"><thead><tr>';
  h += '<th>Status</th><th>Title</th><th>Severity</th><th>Team</th><th>IOCs</th><th>Findings</th><th>Created</th><th>Actions</th>';
  h += '</tr></thead><tbody>';
  if (!filtered.length) h += '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--t5)">'+T('no_data')+'</td></tr>';
  filtered.forEach(function(inv) {
    var ss = statusStyles[inv.status] || 'background:var(--s3);color:var(--t3)';
    var sc = sevColors[inv.severity] || 'var(--t4)';
    var isPulse = inv.status === 'open';
    h += '<tr>';
    h += '<td><span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'+ss+'">'
      + (isPulse?'<span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--red);margin-right:4px;animation:pulse 1.5s infinite"></span>':'')
      + esc(inv.status)+'</span></td>';
    h += '<td style="font-weight:500;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(inv.title)+'</td>';
    h += '<td><span style="font-size:11px;font-weight:600;color:'+sc+'">'+esc(inv.severity||'—')+'</span></td>';
    h += '<td style="font-size:12px;color:var(--t4)">'+esc(inv.team||'—')+'</td>';
    h += '<td style="text-align:center;font-size:13px">'+( inv.ioc_count||0)+'</td>';
    h += '<td style="text-align:center;font-size:13px">'+( inv.finding_count||0)+'</td>';
    h += '<td style="font-size:12px;color:var(--t5)">'+adminTimeAgo(inv.created_at)+'</td>';
    h += '<td style="display:flex;gap:4px">';
    h += '<select class="admin-inv-status" data-invid="'+inv.id+'" style="font-size:11px;padding:3px 6px;max-width:110px">';
    ['open','in-progress','closed'].forEach(function(s) { h += '<option value="'+s+'"'+(inv.status===s?' selected':'')+'>'+s+'</option>'; });
    h += '</select>';
    h += '</td>';
    h += '</tr>';
  });
  h += '</tbody></table></div>';
  return h;
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

function renderAdminAudit(data) {
  if (!data) return adminEmpty();
  var logs = data.logs || [];
  var total = data.total || 0;
  var page  = S.adminAudit.page || 0;
  var f     = S.adminAudit.filters || {};
  var actionTypes = data.actionTypes || [];
  var allUsers = S.adminData['users'] || [];

  var h = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">';
  h += '<h1 style="font-size:20px;font-weight:800;margin-right:auto">'+T('admin_audit')+' <span style="font-size:14px;font-weight:400;color:var(--t4)">('+total+')</span></h1>';
  h += '<a href="/api/admin/audit/export?format=csv'+(f.from?'&from='+encodeURIComponent(f.from):'')+(f.to?'&to='+encodeURIComponent(f.to):'')+'" target="_blank" style="text-decoration:none"><button style="font-size:12px;padding:6px 12px">↓ '+T('export_csv')+'</button></a>';
  h += '</div>';

  // Filters
  h += '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;padding:12px 14px;background:var(--s2);border:1px solid var(--bd);border-radius:var(--r-md)">';
  h += '<select id="audit-f-user" style="font-size:12px;padding:5px 8px;min-width:140px"><option value="">All users</option>';
  allUsers.forEach(function(u) { h += '<option value="'+u.id+'"'+(f.user_id===u.id?' selected':'')+'>'+esc(u.login)+'</option>'; });
  h += '</select>';
  h += '<select id="audit-f-action" style="font-size:12px;padding:5px 8px;min-width:160px"><option value="">All actions</option>';
  actionTypes.forEach(function(a) { h += '<option value="'+esc(a)+'"'+(f.action===a?' selected':'')+'>'+esc(a)+'</option>'; });
  h += '</select>';
  h += '<input id="audit-f-from" type="date" value="'+esc(f.from||'')+'" style="font-size:12px;padding:5px 8px;width:140px" placeholder="From">';
  h += '<input id="audit-f-to" type="date" value="'+esc(f.to||'')+'" style="font-size:12px;padding:5px 8px;width:140px" placeholder="To">';
  h += '<input id="audit-f-q" placeholder="Search…" value="'+esc(f.q||'')+'" style="font-size:12px;padding:5px 8px;flex:1;min-width:160px">';
  h += '<button id="btn-audit-apply" class="pri" style="font-size:12px;padding:6px 14px">Apply</button>';
  if (Object.keys(f).some(function(k){return f[k];})) h += '<button id="btn-audit-clear" style="font-size:12px;padding:6px 12px;color:var(--red);border-color:var(--red3)">Clear</button>';
  h += '</div>';

  h += '<div style="overflow-x:auto"><table class="admin-table"><thead><tr>';
  h += '<th style="min-width:140px">Timestamp</th><th>User</th><th style="min-width:140px">Action</th><th>Target</th><th>Details</th><th>IP</th>';
  h += '</tr></thead><tbody>';
  if (!logs.length) h += '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--t5)">'+T('no_data')+'</td></tr>';
  logs.forEach(function(log) {
    var user = { login: log.user_login, avatar: log.user_avatar };
    var detStr = '';
    try { var det = log.details ? JSON.parse(log.details) : null; detStr = det ? JSON.stringify(det).slice(0,80) : ''; } catch(e) { detStr = String(log.details||'').slice(0,80); }
    h += '<tr>';
    h += '<td style="font-family:var(--mono);font-size:11px;color:var(--t4);white-space:nowrap">'+adminFmtTs(log.created_at)+'</td>';
    h += '<td><div style="display:flex;align-items:center;gap:6px">'+adminAvatar(user,20)+'<span style="font-size:12px;color:var(--t3)">'+esc(log.user_login||'system')+'</span></div></td>';
    h += '<td>'+actionBadge(log.action)+'</td>';
    h += '<td style="font-size:11px;color:var(--t4);font-family:var(--mono)">'+(log.target_type?esc(log.target_type+' '+( log.target_id||'').slice(0,12)):'—')+'</td>';
    h += '<td style="font-size:11px;color:var(--t5);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(detStr)+'">'+esc(detStr)+'</td>';
    h += '<td style="font-family:var(--mono);font-size:11px;color:var(--t5)">'+esc(log.ip_address||'—')+'</td>';
    h += '</tr>';
  });
  h += '</tbody></table></div>';

  // Pagination
  var from = page * 50 + 1, to = Math.min((page+1) * 50, total);
  h += '<div class="pagination">';
  h += '<span>Showing '+from+'–'+to+' of '+total+'</span>';
  h += '<div style="display:flex;gap:4px">';
  h += '<button id="btn-audit-prev" '+(page===0?'disabled':'')+' style="padding:6px 12px;border-radius:var(--r-sm);border:1px solid var(--bd);background:transparent;color:var(--t2);font-size:13px;cursor:pointer">Prev</button>';
  h += '<button id="btn-audit-next" '+((to>=total)?'disabled':'')+' style="padding:6px 12px;border-radius:var(--r-sm);border:1px solid var(--bd);background:transparent;color:var(--t2);font-size:13px;cursor:pointer">Next</button>';
  h += '</div></div>';

  return h;
}

// ── Settings ──────────────────────────────────────────────────────────────────

function renderAdminSettings(data) {
  if (!data) return adminEmpty();
  var inst = data.instance || {}, sec = data.security || {}, cnt = data.counts || {};

  function settingsSection(icon, title, content) {
    return '<div class="settings-section">'
      + '<div class="settings-section-header"><span class="settings-section-icon">'+icon+'</span><span class="settings-section-title">'+title+'</span></div>'
      + content
      + '</div>';
  }
  function staticRow(label, value, badge) {
    return '<div class="settings-row">'
      + '<span class="settings-label">'+label+'</span>'
      + '<span class="settings-value">'+(badge||'')+esc(String(value||'—'))+'</span>'
      + '</div>';
  }
  function editableRow(label, key, value, type, min, max) {
    var inputHtml;
    if (type === 'number') {
      inputHtml = '<input class="settings-input" id="set-'+key+'" type="number" min="'+min+'" max="'+max+'" value="'+esc(String(value))+'">';
    } else {
      inputHtml = '<input class="settings-input" id="set-'+key+'" type="text" value="'+esc(String(value||''))+'">';
    }
    return '<div class="settings-row">'
      + '<span class="settings-label">'+label+'</span>'
      + inputHtml
      + '</div>';
  }

  var encBadge = inst.encryption_active
    ? '<span style="padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;background:#14532d;color:#86efac;margin-right:6px">ACTIVE</span>'
    : '<span style="padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;background:var(--rdim);color:var(--red);margin-right:6px">NOT SET</span>';

  var h = '<h1 style="font-size:20px;font-weight:800;margin-bottom:20px">'+T('admin_settings')+'</h1>';

  h += settingsSection('🖥️', T('system_info'),
    '<div class="settings-table">'
    + staticRow('Instance name', inst.name || 'KQL Vault')
    + staticRow('DB encryption', inst.encryption_active ? 'Active' : 'NOT SET', encBadge)
    + staticRow('Node.js', inst.node_version || '—')
    + staticRow('Uptime', inst.uptime_human || '—')
    + staticRow('DB size', inst.db_size_human || '—')
    + staticRow('Environment', inst.env || '—')
    + '</div>'
  );

  h += settingsSection('🔒', T('security_settings'),
    '<div class="settings-table">'
    + editableRow('Session TTL (hours)', 'session_ttl_hours',      sec.session_ttl_hours     || 24,  'number', 1, 168)
    + editableRow('Max sessions / user', 'max_sessions_per_user',  sec.max_sessions_per_user || 5,   'number', 1, 50)
    + editableRow('Lockout after (attempts)', 'login_lockout_attempts', sec.login_lockout_attempts || 5, 'number', 1, 100)
    + editableRow('Lockout duration (min)',   'login_lockout_minutes',  sec.login_lockout_minutes  || 15,'number', 1, 1440)
    + editableRow('Audit retention (days)',   'audit_retention_days',   sec.audit_retention_days   || 365,'number',7, 3650)
    + staticRow('Auth rate limit', sec.auth_rate_limit || '30 req / 15 min')
    + '</div>'
    + '<div style="display:flex;align-items:center;gap:10px;padding:12px 0 4px">'
    + '<button class="pri" id="btn-settings-save" style="font-size:13px;padding:7px 18px">Save changes</button>'
    + '<span id="settings-save-status" style="font-size:12px;color:var(--t5)"></span>'
    + '</div>'
  );

  h += settingsSection('🔧', T('maintenance'),
    '<div class="settings-maintenance">'
    + '<div class="settings-maint-row"><div><div class="settings-maint-title">'+T('purge_sessions')+'</div><div class="settings-maint-desc">'+(cnt.expired||0)+' expired sessions</div></div>'
    + '<button id="btn-maint-purge-sess" style="font-size:12px;padding:6px 14px">Run</button></div>'
    + '<div class="settings-maint-row"><div><div class="settings-maint-title">'+T('purge_audit')+'</div><div class="settings-maint-desc">Delete logs older than '+(sec.audit_retention_days||365)+' days ('+(cnt.audit||0)+' total entries)</div></div>'
    + '<button id="btn-maint-purge-audit" style="font-size:12px;padding:6px 14px;color:var(--red);border-color:var(--red3)">Run</button></div>'
    + '<div class="settings-maint-row"><div><div class="settings-maint-title">'+T('vacuum_db')+'</div><div class="settings-maint-desc">Reclaim unused space and defragment DB</div></div>'
    + '<button id="btn-maint-vacuum" style="font-size:12px;padding:6px 14px">Run</button></div>'
    + '<div class="settings-maint-row" style="border-bottom:none"><div><div class="settings-maint-title">'+T('export_backup')+'</div><div class="settings-maint-desc">Download a copy of kqlvault.db</div></div>'
    + '<a href="/api/admin/maintenance/backup" download><button style="font-size:12px;padding:6px 14px">Download</button></a></div>'
    + '</div>'
  );

  return h;
}

// ── Repo Sources (optional) ───────────────────────────────────────────────────

function renderAdminRepos(sources) {
  if (!Array.isArray(sources)) return adminEmpty();
  var h = '<h1 style="font-size:20px;font-weight:800;margin-bottom:20px">'+T('admin_repos')+'</h1>';
  h += '<p style="color:var(--t4);font-size:13px;margin-bottom:20px">Manage GitHub repository sources. Use the Repos button in the main header for full sync controls.</p>';
  if (!sources.length) return h + adminEmpty('No repo sources configured.');
  sources.forEach(function(s) {
    h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:var(--r-md);padding:14px 16px;margin-bottom:10px;display:flex;align-items:center;gap:12px">';
    h += '<div style="flex:1"><div style="font-weight:600">'+esc(s.name)+'</div><div style="font-size:12px;color:var(--t4)">'+esc(s.github_owner)+'/'+esc(s.github_repo)+'</div></div>';
    h += '<span style="font-size:11px;color:var(--t4)">'+( s.query_count||0)+' queries</span>';
    h += '<span style="font-size:11px;padding:2px 7px;border-radius:4px;background:'+(s.last_sync_status==='ok'?'#14532d':'var(--s3)')+';color:'+(s.last_sync_status==='ok'?'#86efac':'var(--t4)')+'">'+esc(s.last_sync_status||'never')+'</span>';
    h += '</div>';
  });
  return h;
}

// ── Watch (optional) ─────────────────────────────────────────────────────────

function renderAdminWatch(data) {
  var sources = Array.isArray(data) ? data : (data && Array.isArray(data.sources) ? data.sources : null);
  var intervalMins = (data && data.sync_interval_minutes) ? data.sync_interval_minutes : 15;
  if (!sources) return adminEmpty();

  var h = '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:20px">';
  h += '<h1 style="font-size:20px;font-weight:800;margin:0">'+T('admin_watch')+'</h1>';
  h += '<button id="btn-watch-purge" style="font-size:12px;padding:6px 14px;color:var(--red);border-color:var(--red3);display:inline-flex;align-items:center;gap:6px">';
  h += '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>';
  h += 'Purge all articles</button>';
  h += '</div>';
  h += '<p style="color:var(--t4);font-size:13px;margin-bottom:20px">Manage cyber watch feed sources. Purging articles resets all sources so the next refresh re-ingests everything from scratch.</p>';

  // ── Auto-sync interval settings ─────────────────────────────────────────────
  h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:var(--r-md);padding:16px;margin-bottom:20px">';
  h += '<div style="font-weight:700;font-size:13px;margin-bottom:10px">Auto-sync interval</div>';
  h += '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">';
  h += '<label style="font-size:13px;color:var(--t3)">Fetch feeds every</label>';
  h += '<input id="watch-interval-input" type="number" min="1" max="1440" value="'+esc(String(intervalMins))+'" style="width:80px;text-align:center;font-size:13px;padding:5px 8px">';
  h += '<label style="font-size:13px;color:var(--t3)">minutes</label>';
  h += '<button id="btn-watch-interval-save" style="font-size:12px;padding:6px 14px">Save</button>';
  h += '<span id="watch-interval-status" style="font-size:12px;color:var(--t5)"></span>';
  h += '</div>';
  h += '<div style="font-size:11px;color:var(--t5);margin-top:8px">Minimum: 1 min · Maximum: 1440 min (24 h). Changes take effect immediately.</div>';
  h += '</div>';

  if (!sources.length) return h + adminEmpty('No watch sources configured.');
  sources.forEach(function(s) {
    h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:var(--r-md);padding:14px 16px;margin-bottom:10px;display:flex;align-items:center;gap:12px">';
    h += '<div style="flex:1"><div style="font-weight:600">'+esc(s.name)+'</div><div style="font-size:12px;color:var(--t4)">'+esc(s.feed_type||'rss')+' · '+esc(s.url||'')+'</div></div>';
    h += '<span style="font-size:12px;color:var(--t5)">'+(s.last_fetch_at ? adminTimeAgo(s.last_fetch_at) : T('never_synced'))+'</span>';
    h += '<span style="font-size:11px;padding:2px 7px;border-radius:4px;background:'+(s.enabled?'#14532d':'var(--s3)')+';color:'+(s.enabled?'#86efac':'var(--t4)')+'">'+( s.enabled?T('enabled_lbl'):T('disabled_lbl'))+'</span>';
    h += '</div>';
  });
  return h;
}

// ── Modals ────────────────────────────────────────────────────────────────────

function renderAdminModal() {
  var m = S.adminModal;
  if (!m) return '';
  var inner = '';

  if (m.type === 'create-user') inner = renderModalCreateUser(m.data||{});
  else if (m.type === 'user-detail') inner = renderModalUserDetail(m.data||{});
  else if (m.type === 'create-team') inner = renderModalCreateTeam();
  else if (m.type === 'edit-team') inner = renderModalEditTeam(m.data||{});
  else if (m.type === 'reset-pw-result') inner = renderModalResetPwResult(m.data||{});

  return '<div class="modal-overlay" id="admin-modal-ov">'
    + '<div class="modal-box" style="max-width:520px">'
    + inner
    + '</div></div>';
}

function renderModalCreateUser(data) {
  var teams = S.adminData['teams'] || [];
  var generatedPw = data.generatedPw || generatePassword();
  S.adminModal.data.generatedPw = generatedPw;

  var h = '<div class="modal-header"><h2>'+T('create_user')+'</h2><span id="cl-admin-modal" class="close">×</span></div>';
  h += '<div class="modal-body">';
  h += '<div style="margin-bottom:14px"><label class="lbl">Login</label><input id="acu-login" placeholder="jdoe" value="'+esc(data.login||'')+'"></div>';
  h += '<div style="margin-bottom:14px"><label class="lbl">Display name</label><input id="acu-name" placeholder="John Doe" value="'+esc(data.displayName||'')+'"></div>';
  h += '<div style="margin-bottom:14px"><label class="lbl">'+T('password_generated')+'</label>';
  h += '<div style="display:flex;gap:8px"><input id="acu-pw" value="'+esc(generatedPw)+'" readonly style="font-family:var(--mono);font-size:12px;flex:1;background:var(--s3)">';
  h += '<button id="btn-acu-copy-pw" style="font-size:12px;padding:6px 10px;flex-shrink:0">Copy</button></div></div>';
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">';
  h += '<div><label class="lbl">Role</label><select id="acu-role" style="width:100%"><option value="analyst" selected>analyst</option><option value="viewer">viewer</option><option value="admin">admin</option></select></div>';
  h += '<div><label class="lbl">Team</label><select id="acu-team" style="width:100%"><option value="none">— No team</option>';
  teams.forEach(function(t) { h += '<option value="'+t.id+'">'+esc(t.name)+'</option>'; });
  h += '</select></div></div>';
  h += '<label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer"><input type="checkbox" id="acu-force" checked style="width:15px;height:15px;accent-color:var(--red)"> Force password change on first login</label>';
  h += '<div id="acu-err" style="font-size:13px;color:var(--red);min-height:20px;margin-top:8px"></div>';
  h += '</div>';
  h += '<div class="modal-footer"><button id="cl-admin-modal2">Cancel</button><button class="pri" id="btn-acu-save" style="padding:8px 18px">Create</button></div>';
  return h;
}

function renderModalResetPwResult(data) {
  var h = '<div class="modal-header"><h2>'+T('reset_password')+'</h2><span id="cl-admin-modal" class="close">×</span></div>';
  h += '<div class="modal-body">';
  h += '<p style="font-size:13px;color:var(--t3);margin-bottom:16px">New temporary password for <strong>'+esc(data.login||'')+'</strong>:</p>';
  h += '<div style="display:flex;gap:8px"><input value="'+esc(data.password||'')+'" readonly style="font-family:var(--mono);font-size:14px;flex:1;background:var(--s3);letter-spacing:1px">';
  h += '<button id="btn-rpw-copy" style="font-size:12px;padding:6px 10px">Copy</button></div>';
  h += '<p style="font-size:12px;color:var(--t5);margin-top:12px">User will be required to change this password on next login.</p>';
  h += '</div>';
  h += '<div class="modal-footer"><button id="cl-admin-modal" class="pri">Done</button></div>';
  return h;
}

function renderModalUserDetail(data) {
  var d = data.detail;
  if (!d) return '<div class="modal-header"><h2>Loading…</h2><span id="cl-admin-modal" class="close">×</span></div><div class="modal-body">'+adminSpinner()+'</div>';
  var user = d.user || {};
  var sessions = d.sessions || [];
  var audit = d.recent_audit || [];

  var h = '<div class="modal-header"><h2>'+esc(user.login||'')+'</h2><span id="cl-admin-modal" class="close">×</span></div>';
  h += '<div class="modal-body" style="max-height:70vh;overflow-y:auto">';
  h += '<div style="display:flex;align-items:flex-start;gap:16px;margin-bottom:20px">';
  h += adminAvatar(user, 64);
  h += '<div>';
  h += '<div style="font-size:16px;font-weight:700">'+esc(user.display_name||user.login)+'</div>';
  h += '<div style="font-size:13px;color:var(--t4);font-family:var(--mono)">'+esc(user.login)+'</div>';
  h += '<div style="font-size:12px;color:var(--t3);margin-top:4px">'+user.role+' · Team: '+esc(user.team||'none')+'</div>';
  h += '<div style="font-size:12px;color:var(--t5);margin-top:2px">Created '+adminTimeAgo(user.created_at)+'</div>';
  h += '</div></div>';

  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">';
  [['Queries',d.query_count,'var(--green)'],['Comments',d.comment_count,'var(--blue)'],['Investigations',d.investigation_count,'var(--purple)']].forEach(function(c) {
    h += '<div style="background:var(--s2);border:1px solid var(--bd);border-radius:var(--r-sm);padding:10px;text-align:center">';
    h += '<div style="font-size:20px;font-weight:800;color:'+c[2]+'">'+c[1]+'</div>';
    h += '<div style="font-size:11px;color:var(--t4)">'+c[0]+'</div></div>';
  });
  h += '</div>';

  if (sessions.length) {
    h += '<div style="margin-bottom:16px"><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--t4);margin-bottom:8px">'+T('active_sessions')+' ('+sessions.length+')</div>';
    sessions.forEach(function(s) {
      h += '<div style="display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--s2);border:1px solid var(--bd);border-radius:var(--r-sm);margin-bottom:4px">';
      h += '<span style="font-family:var(--mono);font-size:11px;color:var(--t3);flex:1">'+esc(s.ip_address||'—')+'</span>';
      h += '<span style="font-size:11px;color:var(--t5)">Expires '+adminTimeAgo(s.expires_at)+'</span>';
      h += '<button class="admin-kill-single-sess" data-uid="'+user.id+'" data-shash="'+esc(s.token_hash)+'" style="font-size:11px;color:var(--red);border-color:var(--red3);padding:2px 8px">'+T('kill_session')+'</button>';
      h += '</div>';
    });
    h += '<button class="admin-kill-sess" data-uid="'+user.id+'" style="font-size:12px;color:var(--red);border-color:var(--red3);margin-top:4px;padding:5px 12px">'+T('kill_sessions')+'</button>';
    h += '</div>';
  }

  if (audit.length) {
    h += '<div><div style="font-size:12px;font-weight:700;text-transform:uppercase;color:var(--t4);margin-bottom:8px">Recent activity</div>';
    audit.forEach(function(a) {
      h += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--bd)">';
      h += '<span style="font-size:11px;color:var(--t5);min-width:90px">'+adminFmtTs(a.created_at).slice(0,16)+'</span>';
      h += actionBadge(a.action);
      h += '<span style="font-size:11px;color:var(--t4);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">'+esc((a.target_type||'')+(a.target_id?' '+a.target_id.slice(0,12):''))+'</span>';
      h += '</div>';
    });
    h += '</div>';
  }

  h += '</div>';
  h += '<div class="modal-footer"><button id="cl-admin-modal">Close</button></div>';
  return h;
}

// Renders a reusable avatar picker widget.
// prefix : 'act' (create) | 'aet' (edit)
// current: existing avatar_url or ''
// initials: 2-letter fallback
// color  : hex color for initials bg
function _renderAvatarPicker(prefix, current, initials, color) {
  var hasImg   = !!current;
  var colorId  = prefix + '-color';
  var preview  = hasImg
    ? '<img src="'+esc(current)+'" alt="" style="width:72px;height:72px;border-radius:50%;object-fit:cover;display:block">'
    : '<div style="width:72px;height:72px;border-radius:50%;background:'+(color||'#6366f1')+'22;color:'+(color||'#6366f1')+';display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800">'+(initials||'?')+'</div>';
  var h = '<div style="display:flex;align-items:center;gap:16px;margin-bottom:14px">';
  h += '<div id="'+prefix+'-av-preview" style="flex-shrink:0">'+preview+'</div>';
  h += '<div style="display:flex;flex-direction:column;gap:8px">';
  h += '<label class="lbl" style="margin:0">Avatar</label>';
  h += '<div style="display:flex;gap:6px;align-items:center">';
  h += '<button type="button" id="'+prefix+'-av-pick" onclick="_admAvPick(\''+prefix+'\')" style="font-size:12px;padding:5px 12px">📁 Upload image</button>';
  if (hasImg) h += '<button type="button" id="'+prefix+'-av-clear" onclick="_admAvClear(\''+prefix+'\',\''+colorId+'\')" style="font-size:12px;padding:5px 10px;color:var(--red);border-color:var(--red3)">Remove</button>';
  h += '</div>';
  h += '<span id="'+prefix+'-av-hint" style="font-size:11px;color:var(--t5)">JPEG, PNG, WebP — max 256 KB</span>';
  h += '</div>';
  h += '<input type="file" id="'+prefix+'-av-file" accept="image/jpeg,image/png,image/webp,image/gif" onchange="_admAvChange(\''+prefix+'\',\''+colorId+'\',this)" style="display:none">';
  h += '<input type="hidden" id="'+prefix+'-av-val" value="'+esc(current||'')+'">';
  h += '</div>';
  return h;
}

function _admAvPick(prefix) {
  var f = document.getElementById(prefix+'-av-file');
  if (f) f.click();
}

function _admAvChange(prefix, colorId, fileInp) {
  var file      = fileInp.files[0];
  var hint      = document.getElementById(prefix+'-av-hint');
  var hiddenVal = document.getElementById(prefix+'-av-val');
  var preview   = document.getElementById(prefix+'-av-preview');
  if (!file) return;
  if (file.size > 256 * 1024) {
    if (hint) { hint.textContent = '⚠ Image too large (max 256 KB)'; hint.style.color = 'var(--red)'; }
    fileInp.value = '';
    return;
  }
  var reader = new FileReader();
  reader.onload = function(ev) {
    var dataUrl = ev.target.result;
    if (hiddenVal) hiddenVal.value = dataUrl;
    if (preview)   preview.innerHTML = '<img src="'+dataUrl+'" alt="" style="width:72px;height:72px;border-radius:50%;object-fit:cover;display:block">';
    if (hint)      { hint.textContent = file.name + ' (' + (file.size/1024).toFixed(0) + ' KB)'; hint.style.color = 'var(--t5)'; }
    if (!document.getElementById(prefix+'-av-clear')) {
      var pickBtn = document.getElementById(prefix+'-av-pick');
      if (pickBtn) {
        var clr = document.createElement('button');
        clr.type = 'button'; clr.id = prefix+'-av-clear';
        clr.setAttribute('onclick', '_admAvClear("'+prefix+'","'+colorId+'")');
        clr.style.cssText = 'font-size:12px;padding:5px 10px;color:var(--red);border-color:var(--red3)';
        clr.textContent = 'Remove';
        pickBtn.parentNode.insertBefore(clr, pickBtn.nextSibling);
      }
    }
  };
  reader.readAsDataURL(file);
}

function _admAvClear(prefix, colorId) {
  var hiddenVal = document.getElementById(prefix+'-av-val');
  var preview   = document.getElementById(prefix+'-av-preview');
  var hint      = document.getElementById(prefix+'-av-hint');
  var clearBtn  = document.getElementById(prefix+'-av-clear');
  var nameInp   = document.getElementById(prefix+'-name');
  var colorInp  = document.getElementById(colorId || (prefix+'-color'));
  var fileInp   = document.getElementById(prefix+'-av-file');
  if (hiddenVal) hiddenVal.value = '';
  if (fileInp)   fileInp.value  = '';
  var initials = nameInp  ? (nameInp.value||'?').slice(0,2).toUpperCase() : '?';
  var color    = colorInp ? colorInp.value : '#6366f1';
  if (preview) preview.innerHTML = '<div style="width:72px;height:72px;border-radius:50%;background:'+color+'22;color:'+color+';display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800">'+initials+'</div>';
  if (hint) { hint.textContent = 'JPEG, PNG, WebP — max 256 KB'; hint.style.color = 'var(--t5)'; }
  if (clearBtn) clearBtn.remove();
}

function renderModalCreateTeam() {
  var h = '<div class="modal-header"><h2>'+T('create_team')+'</h2><span id="cl-admin-modal" class="close">×</span></div>';
  h += '<div class="modal-body">';
  h += '<div style="margin-bottom:14px"><label class="lbl">Team name</label><input id="act-name" placeholder="SOC Blue Team"></div>';
  h += '<div style="margin-bottom:14px"><label class="lbl">Description <span style="color:var(--t5)">(optional)</span></label><input id="act-desc" placeholder="Team description"></div>';
  h += '<div style="margin-bottom:14px"><label class="lbl">Color</label><input id="act-color" type="color" value="#6366f1" style="width:48px;height:32px;padding:2px;cursor:pointer;border-radius:6px"></div>';
  h += _renderAvatarPicker('act', '', '?', '#6366f1');
  h += '<div id="act-err" style="font-size:13px;color:var(--red);min-height:20px"></div>';
  h += '</div>';
  h += '<div class="modal-footer"><button id="cl-act-cancel">Cancel</button><button class="pri" id="btn-act-save">Create</button></div>';
  return h;
}

function renderModalEditTeam(team) {
  var color    = team.color || '#6366f1';
  var initials = (team.name||'?').slice(0,2).toUpperCase();
  var h = '<div class="modal-header"><h2>Edit team</h2><span id="cl-admin-modal" class="close">×</span></div>';
  h += '<div class="modal-body">';
  h += '<div style="margin-bottom:14px"><label class="lbl">Team name</label><input id="aet-name" value="'+esc(team.name||'')+'"></div>';
  h += '<div style="margin-bottom:14px"><label class="lbl">Description</label><input id="aet-desc" value="'+esc(team.description||'')+'"></div>';
  h += '<div style="margin-bottom:14px"><label class="lbl">Color</label><input id="aet-color" type="color" value="'+esc(color)+'" style="width:48px;height:32px;padding:2px;cursor:pointer;border-radius:6px"></div>';
  h += _renderAvatarPicker('aet', team.avatar_url||'', initials, color);
  h += '<input type="hidden" id="aet-id" value="'+esc(team.id||'')+'"><div id="aet-err" style="font-size:13px;color:var(--red);min-height:20px"></div>';
  h += '</div>';
  h += '<div class="modal-footer"><button id="cl-aet-cancel">Cancel</button><button class="pri" id="btn-aet-save">Save</button></div>';
  return h;
}

function generatePassword() {
  var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$';
  var arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(function(b) { return chars[b % chars.length]; }).join('');
}

// ── CSS for admin tables/styles injected once ────────────────────────────────

(function injectAdminCSS() {
  if (document.getElementById('admin-styles')) return;
  var s = document.createElement('style');
  s.id = 'admin-styles';
  s.textContent = `
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    .admin-table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 13px;
    }
    .admin-table th {
      text-align: left;
      padding: 10px 14px;
      font-size: 11px;
      font-weight: 600;
      color: var(--t4);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--bd);
      background: var(--s1);
      position: sticky;
      top: 0;
      z-index: 2;
      white-space: nowrap;
    }
    .admin-table td {
      padding: 11px 14px;
      border-bottom: 1px solid var(--bd);
      vertical-align: middle;
    }
    .admin-table tr:hover td { background: var(--s2); }
    .action-menu { position: relative; display: inline-block; }
    .action-menu-btn {
      width: 32px; height: 32px;
      border-radius: var(--r-sm);
      display: flex; align-items: center; justify-content: center;
      border: none; background: transparent; color: var(--t4);
      cursor: pointer; transition: all var(--tr); font-size: 18px;
    }
    .action-menu-btn:hover { background: var(--s3); color: var(--t1); }
    .action-menu-dropdown {
      position: absolute; top: 100%; right: 0; margin-top: 4px;
      background: var(--s1); border: 1px solid var(--bd);
      border-radius: var(--r-md); box-shadow: var(--sh-lg);
      min-width: 180px; padding: 4px; z-index: 60;
    }
    .action-menu-item {
      display: flex; align-items: center; gap: 8px;
      padding: 8px 12px; border-radius: var(--r-sm);
      font-size: 13px; color: var(--t2); cursor: pointer;
      border: none; background: transparent; width: 100%;
      text-align: left; transition: background var(--tr);
    }
    .action-menu-item:hover { background: var(--s3); }
    .action-menu-item.danger { color: var(--red); }
    .action-menu-item.danger:hover { background: var(--rdim); }
    .pagination {
      display: flex; align-items: center; justify-content: space-between;
      padding: 16px 0; font-size: 13px; color: var(--t4);
    }
  `;
  document.head.appendChild(s);
})();

// ── Event bindings ────────────────────────────────────────────────────────────

function bindAdminEvents() {
  if (S.view !== 'admin') return;

  // Back to vault
  var bv = document.getElementById('btn-back-vault');
  if (bv) bv.addEventListener('click', function() { S.view = 'queries'; render(); });

  // Tab navigation
  document.querySelectorAll('[data-admin-tab]').forEach(function(x) {
    x.addEventListener('click', function() {
      var tab = x.getAttribute('data-admin-tab');
      if (S.adminTab === 'dashboard' && tab !== 'dashboard') AdminCharts.destroyAll();
      S.adminTab = tab;
      S.adminTeamSel = null;
      // Load users too if switching to teams (for add-member dropdown)
      if (tab === 'teams' && !S.adminData['users']) adminLoadTab('users');
      if (!S.adminData[tab]) adminLoadTab(tab);
      else render();
    });
  });

  // Dashboard refresh
  elOn('btn-admin-refresh-dash', function() { AdminCharts.destroyAll(); delete S.adminData['dashboard']; adminLoadTab('dashboard'); });

  // ── Users ──────────────────────────────────
  var uSearch = document.getElementById('admin-user-search');
  if (uSearch) uSearch.addEventListener('input', function() { S.adminUsers.search = uSearch.value; render(); });

  document.querySelectorAll('[data-admin-sort]').forEach(function(x) {
    x.addEventListener('click', function() {
      var col = x.getAttribute('data-admin-sort');
      if (S.adminUsers.sort === col) S.adminUsers.dir = S.adminUsers.dir === 'asc' ? 'desc' : 'asc';
      else { S.adminUsers.sort = col; S.adminUsers.dir = 'asc'; }
      render();
    });
  });

  elOn('btn-admin-create-user', function() { S.adminModal = { type: 'create-user', data: {} }; render(); });

  // User detail link
  document.querySelectorAll('.admin-user-detail').forEach(function(x) {
    x.addEventListener('click', async function() {
      var uid = x.getAttribute('data-uid');
      S.adminModal = { type: 'user-detail', data: { detail: null } };
      render();
      try {
        var detail = await API.get('/admin/users/' + uid + '/detail');
        S.adminModal = { type: 'user-detail', data: { detail } };
      } catch(e) {
        S.adminModal = { type: 'user-detail', data: { detail: { user: { login: T('error')+': '+e.message }, sessions: [], recent_audit: [] } } };
      }
      render();
    });
  });

  // Action menus
  document.querySelectorAll('[data-amenu]').forEach(function(x) {
    x.addEventListener('click', function(e) {
      e.stopPropagation();
      var id = 'amenu-' + x.getAttribute('data-amenu');
      document.querySelectorAll('.action-menu-dropdown').forEach(function(d) {
        if (d.id !== id) d.style.display = 'none';
      });
      var menu = document.getElementById(id);
      if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
    });
  });
  document.addEventListener('click', function adminClickAway() {
    document.querySelectorAll('.action-menu-dropdown').forEach(function(d) { d.style.display = 'none'; });
  }, { once: true });

  document.querySelectorAll('.admin-reset-pw').forEach(function(x) {
    x.addEventListener('click', async function() {
      if (!confirm(T('confirm_delete')+'\nReset password for "'+x.getAttribute('data-ulogin')+'"?')) return;
      try {
        var r = await API.post('/admin/users/' + x.getAttribute('data-uid') + '/reset-password', {});
        if (r.error) { showToast(r.error); return; }
        S.adminModal = { type: 'reset-pw-result', data: { login: x.getAttribute('data-ulogin'), password: r.temp_password } };
        delete S.adminData['users'];
        await adminLoadTab('users');
      } catch(e) { showToast(T('error')+': '+e.message); }
    });
  });

  document.querySelectorAll('.admin-force-pw').forEach(function(x) {
    x.addEventListener('click', async function() {
      try { await API.post('/admin/users/' + x.getAttribute('data-uid') + '/force-change-pw', {}); showToast(T('admin_done')); delete S.adminData['users']; adminLoadTab('users'); }
      catch(e) { showToast(T('error')+': ' + e.message); }
    });
  });

  document.querySelectorAll('.admin-unlock').forEach(function(x) {
    x.addEventListener('click', async function() {
      try { await API.post('/admin/users/' + x.getAttribute('data-uid') + '/unlock', {}); showToast(T('admin_unlocked')); delete S.adminData['users']; adminLoadTab('users'); }
      catch(e) { showToast(T('error')+': ' + e.message); }
    });
  });

  document.querySelectorAll('.admin-kill-sess').forEach(function(x) {
    x.addEventListener('click', async function() {
      if (!confirm(T('confirm_delete')+'\nKill all sessions?')) return;
      try { var r = await API.post('/admin/users/' + x.getAttribute('data-uid') + '/kill-sessions', {}); showToast((r.killed||0)+' '+T('admin_session_killed')); delete S.adminData['users']; adminLoadTab('users'); if (S.adminModal) { S.adminModal = null; } render(); }
      catch(e) { showToast(T('error')+': ' + e.message); }
    });
  });

  document.querySelectorAll('.admin-kill-single-sess').forEach(function(x) {
    x.addEventListener('click', async function() {
      try { await API.post('/admin/users/'+x.getAttribute('data-uid')+'/kill-session/'+x.getAttribute('data-shash'), {}); showToast(T('admin_session_killed')); S.adminModal = null; delete S.adminData['users']; adminLoadTab('users'); }
      catch(e) { showToast(T('error')); }
    });
  });

  document.querySelectorAll('.admin-del-user').forEach(function(x) {
    x.addEventListener('click', async function() {
      if (!confirm(T('confirm_delete')+'\nDelete user "'+x.getAttribute('data-ulogin')+'"? This cannot be undone.')) return;
      try { await API.del('/admin/users/' + x.getAttribute('data-uid')); showToast(T('admin_user_deleted')); delete S.adminData['users']; adminLoadTab('users'); }
      catch(e) { showToast(T('error')+': ' + e.message); }
    });
  });

  // Create user save
  elOn('btn-acu-save', async function() {
    var login = (document.getElementById('acu-login')||{value:''}).value.trim();
    var name  = (document.getElementById('acu-name') ||{value:''}).value.trim();
    var pw    = (document.getElementById('acu-pw')   ||{value:''}).value;
    var role  = (document.getElementById('acu-role') ||{value:'analyst'}).value;
    var team  = (document.getElementById('acu-team') ||{value:'none'}).value;
    var force = (document.getElementById('acu-force')||{checked:true}).checked;
    var errEl = document.getElementById('acu-err');
    if (!login) { if (errEl) errEl.textContent = 'Login required'; return; }
    try {
      var r = await API.post('/admin/users', { login, display_name: name||login, password: pw, role, team, force_change: force });
      if (r.error) { if (errEl) errEl.textContent = r.error; return; }
      showToast(T('admin_user_created',{login:login}));
      S.adminModal = null;
      delete S.adminData['users'];
      adminLoadTab('users');
    } catch(e) { if (errEl) errEl.textContent = e.message; }
  });

  elOn('btn-acu-copy-pw', function() {
    var el = document.getElementById('acu-pw');
    if (el) { try { navigator.clipboard.writeText(el.value); showToast(T('copied')); } catch(e) {} }
  });

  elOn('btn-rpw-copy', function() {
    var el = document.querySelector('#admin-modal-ov input[readonly]');
    if (el) { try { navigator.clipboard.writeText(el.value); showToast(T('copied')); } catch(e) {} }
  });

  // ── Teams ──────────────────────────────────
  elOn('btn-admin-create-team', function() { S.adminModal = { type: 'create-team', data: {} }; render(); });
  elOn('cl-act-cancel', function() { S.adminModal = null; render(); });
  elOn('cl-aet-cancel', function() { S.adminModal = null; render(); });

  elOn('btn-act-save', async function() {
    var name   = (document.getElementById('act-name')  ||{value:''}).value.trim();
    var desc   = (document.getElementById('act-desc')  ||{value:''}).value.trim();
    var color  = (document.getElementById('act-color') ||{value:'#6366f1'}).value;
    var avatar = (document.getElementById('act-av-val')||{value:''}).value;
    var errEl  = document.getElementById('act-err');
    if (!name) { if (errEl) errEl.textContent = 'Name required'; return; }
    try {
      var r = await API.post('/admin/teams', { name, description: desc, color, avatar_url: avatar });
      if (r.error) { if (errEl) errEl.textContent = r.error; return; }
      showToast(T('admin_team_created'));
      S.adminModal = null;
      delete S.adminData['teams'];
      adminLoadTab('teams');
    } catch(e) { if (errEl) errEl.textContent = e.message; }
  });

  document.querySelectorAll('.admin-team-edit').forEach(function(x) {
    x.addEventListener('click', function() {
      var teams = S.adminData['teams'] || [];
      var team  = teams.find(function(t) { return t.id === x.getAttribute('data-tid'); });
      if (team) { S.adminModal = { type: 'edit-team', data: team }; render(); }
    });
  });

  elOn('btn-aet-save', async function() {
    var tid    = (document.getElementById('aet-id')    ||{value:''}).value;
    var name   = (document.getElementById('aet-name')  ||{value:''}).value.trim();
    var desc   = (document.getElementById('aet-desc')  ||{value:''}).value.trim();
    var color  = (document.getElementById('aet-color') ||{value:'#6366f1'}).value;
    var avatar = (document.getElementById('aet-av-val')||{value:''}).value;
    var errEl  = document.getElementById('aet-err');
    if (!name) { if (errEl) errEl.textContent = 'Name required'; return; }
    try {
      var r = await API.put('/admin/teams/' + tid, { name, description: desc, color, avatar_url: avatar });
      if (r.error) { if (errEl) errEl.textContent = r.error; return; }
      showToast(T('admin_done'));
      S.adminModal = null;
      delete S.adminData['teams'];
      adminLoadTab('teams');
    } catch(e) { if (errEl) errEl.textContent = e.message; }
  });

  document.querySelectorAll('.admin-del-team').forEach(function(x) {
    x.addEventListener('click', async function() {
      if (!confirm(T('confirm_delete')+'\nDelete team "'+x.getAttribute('data-tname')+'"?')) return;
      try {
        var r = await API.del('/admin/teams/' + x.getAttribute('data-tid'));
        if (r.error) { showToast(r.error); return; }
        showToast(T('admin_team_deleted'));
        delete S.adminData['teams'];
        adminLoadTab('teams');
      } catch(e) { showToast(T('error')+': '+e.message); }
    });
  });

  document.querySelectorAll('.btn-admin-add-member').forEach(function(btn) {
    btn.addEventListener('click', async function() {
      var tid = btn.getAttribute('data-tid');
      var sel = btn.closest('.team-add-member')
             && btn.closest('.team-add-member').querySelector('.admin-add-member-sel');
      var uid = sel ? sel.value : '';
      if (!uid) return;
      try {
        var r = await API.post('/admin/teams/' + tid + '/add-member', { user_id: uid });
        if (r.error) { showToast(r.error); return; }
        showToast(T('admin_member_added'));
        delete S.adminData['teams'];
        adminLoadTab('teams');
      } catch(e) { showToast(T('error')+': ' + e.message); }
    });
  });

  document.querySelectorAll('.admin-rm-member').forEach(function(x) {
    x.addEventListener('click', async function() {
      if (!confirm(T('confirm_delete')+'\nRemove this member?')) return;
      try {
        await API.post('/admin/teams/'+x.getAttribute('data-tid')+'/remove-member', { user_id: x.getAttribute('data-uid') });
        showToast(T('admin_member_removed'));
        delete S.adminData['teams'];
        adminLoadTab('teams');
      } catch(e) { showToast(T('error')+': '+e.message); }
    });
  });

  // ── Queries bulk ────────────────────────────
  var qSearch = document.getElementById('admin-q-search');
  if (qSearch) qSearch.addEventListener('input', function() { S.adminQSearch = qSearch.value; render(); });

  var qSelAll = document.getElementById('admin-q-selall');
  if (qSelAll) qSelAll.addEventListener('change', function() {
    var queries = S.adminData['queries'] || [];
    var search  = S.adminQSearch || '';
    var s = search.toLowerCase();
    var filtered = queries.filter(function(q) {
      if (!search) return true;
      return (q.title||'').toLowerCase().indexOf(s) >= 0 || (q.author_name||'').toLowerCase().indexOf(s) >= 0;
    });
    filtered.forEach(function(q) { S.adminQSel[q.id] = qSelAll.checked; });
    render();
  });

  document.querySelectorAll('.admin-q-chk').forEach(function(x) {
    x.addEventListener('change', function() { S.adminQSel[x.getAttribute('data-qid')] = x.checked; render(); });
  });

  elOn('btn-bulk-clear', function() { S.adminQSel = {}; render(); });

  document.querySelectorAll('.admin-bulk-act').forEach(function(x) {
    x.addEventListener('click', async function() {
      var action = x.getAttribute('data-bact');
      var ids    = Object.keys(S.adminQSel).filter(function(k) { return S.adminQSel[k]; });
      if (!ids.length) return;
      var value = null;
      if (action === 'delete' && !confirm(T('bulk_del_confirm',{n:ids.length}))) return;
      if (action === 'severity') {
        var sevSel = document.getElementById('bulk-sev-sel');
        value = sevSel ? sevSel.value : '';
        if (!value) { showToast(T('admin_sel_sev_first')); return; }
      }
      try {
        var r = await API.post('/admin/queries/bulk', { action, ids, value });
        if (r.error) { showToast(r.error); return; }
        showToast(T('admin_queries_updated',{n:r.affected||ids.length}));
        S.adminQSel = {};
        delete S.adminData['queries'];
        adminLoadTab('queries');
      } catch(e) { showToast(T('error')+': '+e.message); }
    });
  });

  document.querySelectorAll('.admin-del-query').forEach(function(x) {
    x.addEventListener('click', async function() {
      if (!confirm(T('confirm_delete')+'\nDelete "'+x.getAttribute('data-qtitle')+'"?')) return;
      try {
        await API.post('/admin/queries/bulk', { action: 'delete', ids: [x.getAttribute('data-qid')] });
        showToast(T('admin_query_deleted'));
        delete S.adminData['queries'];
        adminLoadTab('queries');
      } catch(e) { showToast(T('error')+': ' + e.message); }
    });
  });

  // ── Folders ────────────────────────────────
  document.querySelectorAll('.admin-del-folder').forEach(function(x) {
    x.addEventListener('click', async function() {
      var cnt = parseInt(x.getAttribute('data-qcount')) || 0;
      var msg = T('confirm_delete')+'\nDelete folder "'+x.getAttribute('data-fname')+'"?';
      if (cnt > 0) msg += '\n\n'+T('admin_folder_unlink_warn',{n:cnt});
      if (!confirm(msg)) return;
      var unlink = cnt > 0 ? '?unlink=1' : '';
      try {
        var r = await API.del('/folders/'+x.getAttribute('data-fid')+unlink);
        if (r && r.error) { showToast(r.error); return; }
        showToast(T('admin_folder_deleted'));
        delete S.adminData['folders'];
        adminLoadTab('folders');
      } catch(e) { showToast(T('error')+': '+e.message); }
    });
  });

  // ── Investigations ─────────────────────────
  document.querySelectorAll('.admin-inv-filter').forEach(function(x) {
    x.addEventListener('click', function() { S.adminInvFilter = x.getAttribute('data-invf'); render(); });
  });

  document.querySelectorAll('.admin-inv-status').forEach(function(sel) {
    sel.addEventListener('change', async function() {
      var invId = sel.getAttribute('data-invid');
      var newStatus = sel.value;
      sel.disabled = true;
      try {
        var r = await API.put('/admin/investigations/' + invId, { status: newStatus });
        if (r && r.error) { showToast(r.error); sel.disabled = false; return; }
        showToast(T('admin_done') || 'Updated');
        delete S.adminData['investigations'];
        adminLoadTab('investigations');
      } catch(e) { showToast(T('error')+': '+e.message); sel.disabled = false; }
    });
  });

  // ── Audit ──────────────────────────────────
  elOn('btn-audit-apply', async function() {
    S.adminAudit.filters = {
      user_id: (document.getElementById('audit-f-user')  ||{value:''}).value,
      action:  (document.getElementById('audit-f-action')||{value:''}).value,
      from:    (document.getElementById('audit-f-from')  ||{value:''}).value,
      to:      (document.getElementById('audit-f-to')    ||{value:''}).value,
      q:       (document.getElementById('audit-f-q')     ||{value:''}).value
    };
    S.adminAudit.page = 0;
    delete S.adminData['audit'];
    adminLoadTab('audit');
  });

  elOn('btn-audit-clear', function() { S.adminAudit.filters = {}; S.adminAudit.page = 0; delete S.adminData['audit']; adminLoadTab('audit'); });

  elOn('btn-audit-prev', function() { if (S.adminAudit.page > 0) { S.adminAudit.page--; delete S.adminData['audit']; adminLoadTab('audit'); } });
  elOn('btn-audit-next', function() { S.adminAudit.page++; delete S.adminData['audit']; adminLoadTab('audit'); });

  // ── Settings/Maintenance ───────────────────
  elOn('btn-settings-save', async function() {
    var btn    = document.getElementById('btn-settings-save');
    var status = document.getElementById('settings-save-status');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    if (status) status.textContent = '';
    var payload = {};
    ['session_ttl_hours','max_sessions_per_user','login_lockout_attempts','login_lockout_minutes','audit_retention_days'].forEach(function(k) {
      var el = document.getElementById('set-' + k);
      if (el) payload[k] = parseInt(el.value) || 0;
    });
    try {
      var r = await API.put('/admin/settings', payload);
      if (r && r.error) throw new Error(r.error);
      if (status) status.textContent = 'Saved — some settings take effect on next session';
      delete S.adminData['settings'];
      adminLoadTab('settings');
    } catch(e) {
      if (status) status.textContent = T('error')+': '+e.message;
    }
    if (btn) { btn.disabled = false; btn.textContent = 'Save changes'; }
  });

  elOn('btn-maint-purge-sess', async function() {
    if (!confirm(T('confirm_delete')+'\nPurge all expired sessions?')) return;
    try { var r = await API.post('/admin/maintenance/purge-sessions', {}); showToast(T('purge_sessions')+': '+(r.purged||0)); delete S.adminData['settings']; adminLoadTab('settings'); }
    catch(e) { showToast(T('error')+': '+e.message); }
  });

  elOn('btn-maint-purge-audit', async function() {
    var retDays = ((S.adminData['settings']||{}).security||{}).audit_retention_days || 365;
    if (!confirm(T('confirm_delete')+'\nDelete audit log entries older than '+retDays+' days? This cannot be undone.')) return;
    try { var r = await API.post('/admin/maintenance/purge-audit', { days: retDays }); showToast(T('purge_audit')+': '+(r.purged||0)); delete S.adminData['settings']; adminLoadTab('settings'); }
    catch(e) { showToast(T('error')+': '+e.message); }
  });

  elOn('btn-maint-vacuum', async function() {
    var btn = document.getElementById('btn-maint-vacuum');
    if (btn) btn.textContent = T('admin_running');
    try { await API.post('/admin/maintenance/vacuum', {}); showToast(T('admin_db_vacuumed')); delete S.adminData['settings']; adminLoadTab('settings'); }
    catch(e) { showToast(T('error')+': '+e.message); }
  });

  // ── Watch interval save ─────────────────────
  elOn('btn-watch-interval-save', async function() {
    var input = document.getElementById('watch-interval-input');
    var status = document.getElementById('watch-interval-status');
    if (!input) return;
    var mins = parseInt(input.value);
    if (!mins || mins < 1 || mins > 1440) {
      if (status) status.textContent = 'Value must be between 1 and 1440.';
      return;
    }
    var btn = document.getElementById('btn-watch-interval-save');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    if (status) status.textContent = '';
    try {
      var r = await API.put('/admin/watch-settings', { sync_interval_minutes: mins });
      if (r && r.error) throw new Error(r.error);
      if (status) status.textContent = 'Saved — next sync in ' + mins + ' min';
      if (S.adminData['watch']) S.adminData['watch'].sync_interval_minutes = mins;
    } catch(e) {
      if (status) status.textContent = T('error')+': '+e.message;
    }
    if (btn) { btn.disabled = false; btn.textContent = T('save'); }
  });

  // ── Watch purge ─────────────────────────────
  elOn('btn-watch-purge', async function() {
    if (!confirm(T('watch_purge_confirm'))) return;
    var btn = document.getElementById('btn-watch-purge');
    if (btn) { btn.disabled = true; btn.textContent = T('admin_purging'); }
    try {
      var r = await API.post('/admin/maintenance/purge-watch', {});
      if (r && r.error) throw new Error(r.error);
      showToast(T('purge')+': ' + (r.purged || 0) + ' articles');
      delete S.adminData['watch'];
      adminLoadTab('watch');
    } catch(e) { showToast(T('error')+': '+e.message); }
    if (btn) { btn.disabled = false; }
  });

  // ── Modal close ─────────────────────────────
  elOn('cl-admin-modal',  function() { S.adminModal = null; render(); });
  elOn('cl-admin-modal2', function() { S.adminModal = null; render(); });
  var ov = document.getElementById('admin-modal-ov');
  if (ov) ov.addEventListener('click', function(e) { if (e.target.id === 'admin-modal-ov') { S.adminModal = null; render(); } });

  // ── Dashboard charts (mount after paint) ────
  var _dashData = S.adminData && S.adminData['dashboard'];
  if (S.adminTab === 'dashboard' && _dashData && !_dashData._error && !_dashData.error) {
    requestAnimationFrame(function() {
      AdminCharts.mount(_dashData);
    });
  }
}

// ════════════════════════════════════════════════════════════════
// AdminCharts — Chart.js 4 UMD, loaded dynamically on demand
// ════════════════════════════════════════════════════════════════

var AdminCharts = (function() {
  var _instances = {};
  var _loaded    = typeof Chart === 'function';  // already loaded via static tag before Monaco AMD
  var _loading   = false;
  var _queue     = [];

  var LOCAL = '/js/chart.umd.min.js';
  var CDN   = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js';

  function _load(cb) {
    if (_loaded)  { cb(); return; }
    if (_loading) { _queue.push(cb); return; }
    _loading = true;

    function _inject(src, fallback) {
      var s = document.createElement('script');
      s.src = src;
      s.onload = function() {
        _loaded = true; _loading = false;
        cb();
        _queue.forEach(function(fn) { fn(); });
        _queue = [];
      };
      s.onerror = function() {
        if (fallback) {
          _inject(fallback, null);
        } else {
          _loading = false;
          _showChartFallback();
          console.warn('AdminCharts: Chart.js unavailable (local + CDN both failed)');
        }
      };
      document.head.appendChild(s);
    }

    _inject(LOCAL, CDN);
  }

  function _showChartFallback() {
    document.querySelectorAll('.adm-chart-canvas-wrap').forEach(function(wrap) {
      if (!wrap.querySelector('canvas')) return;
      wrap.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:120px;color:var(--t5);font-size:12px;text-align:center;flex-direction:column;gap:6px">'
        + '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity=".4"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>'
        + '<span>Charts unavailable<br><span style="font-size:10px;opacity:.6">Chart.js could not load</span></span>'
        + '</div>';
    });
  }

  function _dark() { return !document.body.classList.contains('light'); }

  function _th() {
    var dark = _dark();
    return {
      grid:    dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
      tick:    dark ? '#71717a' : '#64748b',
      tooltip: dark ? '#27272a' : '#f1f5f9'
    };
  }

  var SEV_COL  = { critical:'#dc2626', high:'#ea580c', medium:'#ca8a04', low:'#16a34a', info:'#3b82f6' };
  var ENV_COL  = { Defender:'#3b82f6', Sentinel:'#7c3aed', Both:'#06b6d4' };
  var LANG_PAL = ['#3b82f6','#7c3aed','#ea580c','#16a34a','#ca8a04','#06b6d4','#ec4899'];

  function _kill(id) {
    if (_instances[id]) { try { _instances[id].destroy(); } catch(e) {} delete _instances[id]; }
  }

  function _ctx(id) {
    var el = document.getElementById(id);
    return el ? el.getContext('2d') : null;
  }

  function _showEmpty(id, msg) {
    var el = document.getElementById(id);
    if (!el) return;
    var wrap = el.parentNode;
    if (!wrap) return;
    wrap.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:80px;color:var(--t5);font-size:11px;text-align:center;opacity:.55">'+(msg||'No data')+'</div>';
  }

  function _fmtDate(iso) {
    var d = new Date(iso + 'T00:00:00');
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  function _tooltipOpts(th) {
    return { backgroundColor: th.tooltip, titleColor: th.tick, bodyColor: th.tick };
  }

  // Activity line chart
  function _activity(data) {
    var c = _ctx('chart-activity'); if (!c) return; _kill('chart-activity');
    var th = _th(), arr = data.activity_30d || [];
    try {
      _instances['chart-activity'] = new Chart(c, {
        type: 'line',
        data: {
          labels: arr.map(function(x) { return _fmtDate(x.date); }),
          datasets: [{
            label: 'Events', data: arr.map(function(x) { return x.count; }),
            borderColor: '#dc2626', backgroundColor: 'rgba(220,38,38,0.12)',
            fill: true, tension: 0.35, pointRadius: 0, pointHoverRadius: 4, borderWidth: 2
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          interaction: { intersect: false, mode: 'index' },
          plugins: { legend: { display: false }, tooltip: _tooltipOpts(th) },
          scales: {
            x: { grid: { color: th.grid }, ticks: { color: th.tick, maxTicksLimit: 8, font: { size: 10 } } },
            y: { grid: { color: th.grid }, ticks: { color: th.tick, font: { size: 10 }, precision: 0 }, beginAtZero: true }
          }
        }
      });
    } catch(e) { console.error('[chart-activity]', e); _showEmpty('chart-activity', 'Chart error'); }
  }

  // Severity donut
  function _severity(data) {
    var c = _ctx('chart-severity'); if (!c) return; _kill('chart-severity');
    var th = _th(), sev = data.by_severity || {};
    var keys = ['critical','high','medium','low','info'].filter(function(k) { return sev[k] > 0; });
    if (!keys.length) { _showEmpty('chart-severity', 'No data'); return; }
    try {
      _instances['chart-severity'] = new Chart(c, {
        type: 'doughnut',
        data: { labels: keys, datasets: [{ data: keys.map(function(k) { return sev[k]; }), backgroundColor: keys.map(function(k) { return SEV_COL[k]; }), borderWidth: 0, hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '68%', plugins: { legend: { display: false }, tooltip: _tooltipOpts(th) } }
      });
    } catch(e) { console.error('[chart-severity]', e); _showEmpty('chart-severity', 'Chart error'); }
  }

  // Environment donut
  function _environment(data) {
    var c = _ctx('chart-env'); if (!c) return; _kill('chart-env');
    var th = _th(), env = data.by_environment || {};
    var keys = ['Defender','Sentinel','Both'].filter(function(k) { return env[k] > 0; });
    if (!keys.length) { _showEmpty('chart-env', 'No data'); return; }
    try {
      _instances['chart-env'] = new Chart(c, {
        type: 'doughnut',
        data: { labels: keys, datasets: [{ data: keys.map(function(k) { return env[k]; }), backgroundColor: keys.map(function(k) { return ENV_COL[k]; }), borderWidth: 0, hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '68%', plugins: { legend: { display: false }, tooltip: _tooltipOpts(th) } }
      });
    } catch(e) { console.error('[chart-env]', e); _showEmpty('chart-env', 'Chart error'); }
  }

  // Teams bar
  function _teams(data) {
    var c = _ctx('chart-teams'); if (!c) return; _kill('chart-teams');
    var th = _th(), teams = (data.by_team || []).slice(0, 8);
    if (!teams.length) { _showEmpty('chart-teams', 'No data'); return; }
    try {
      _instances['chart-teams'] = new Chart(c, {
        type: 'bar',
        data: {
          labels: teams.map(function(t) { return t.team || '—'; }),
          datasets: [{ label: 'Queries', data: teams.map(function(t) { return t.count; }), backgroundColor: 'rgba(59,130,246,0.7)', borderColor: '#3b82f6', borderWidth: 1, borderRadius: 3 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: _tooltipOpts(th) },
          scales: {
            x: { grid: { color: th.grid }, ticks: { color: th.tick, font: { size: 10 } } },
            y: { grid: { color: th.grid }, ticks: { color: th.tick, font: { size: 10 }, precision: 0 }, beginAtZero: true }
          }
        }
      });
    } catch(e) { console.error('[chart-teams]', e); _showEmpty('chart-teams', 'Chart error'); }
  }

  // Language donut
  function _language(data) {
    var c = _ctx('chart-lang'); if (!c) return; _kill('chart-lang');
    var th = _th(), lang = data.by_language || {};
    var keys = Object.keys(lang).filter(function(k) { return lang[k] > 0; });
    if (!keys.length) { _showEmpty('chart-lang', 'No data'); return; }
    try {
      _instances['chart-lang'] = new Chart(c, {
        type: 'doughnut',
        data: { labels: keys, datasets: [{ data: keys.map(function(k) { return lang[k]; }), backgroundColor: keys.map(function(k, i) { return LANG_PAL[i % LANG_PAL.length]; }), borderWidth: 0, hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '68%', plugins: { legend: { display: false }, tooltip: _tooltipOpts(th) } }
      });
    } catch(e) { console.error('[chart-lang]', e); _showEmpty('chart-lang', 'Chart error'); }
  }

  // Top tags horizontal bar
  function _topTags(data) {
    var c = _ctx('chart-tags'); if (!c) return; _kill('chart-tags');
    var th = _th(), tags = (data.top_tags || []).slice(0, 10);
    if (!tags.length) { _showEmpty('chart-tags', 'No data'); return; }
    try {
      _instances['chart-tags'] = new Chart(c, {
        type: 'bar',
        data: {
          labels: tags.map(function(t) { return t.tag; }),
          datasets: [{ label: 'Queries', data: tags.map(function(t) { return t.count; }), backgroundColor: 'rgba(124,58,237,0.7)', borderColor: '#7c3aed', borderWidth: 1, borderRadius: 3 }]
        },
        options: {
          indexAxis: 'y',
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: _tooltipOpts(th) },
          scales: {
            x: { grid: { color: th.grid }, ticks: { color: th.tick, font: { size: 10 }, precision: 0 }, beginAtZero: true },
            y: { grid: { display: false }, ticks: { color: th.tick, font: { size: 10 } } }
          }
        }
      });
    } catch(e) { console.error('[chart-tags]', e); _showEmpty('chart-tags', 'Chart error'); }
  }

  // Watch activity stacked bar
  function _watchActivity(data) {
    var c = _ctx('chart-watch'); if (!c) return; _kill('chart-watch');
    var th = _th(), arr = data.watch_activity_14d || [];
    if (!arr.some(function(x) { return x.articles > 0; })) return;
    try {
      _instances['chart-watch'] = new Chart(c, {
        type: 'bar',
        data: {
          labels: arr.map(function(x) { return _fmtDate(x.date); }),
          datasets: [
            { label: 'Articles', data: arr.map(function(x) { return x.articles; }), backgroundColor: 'rgba(59,130,246,0.55)', borderColor: '#3b82f6', borderWidth: 1, borderRadius: 2 },
            { label: 'Critical',  data: arr.map(function(x) { return x.critical;  }), backgroundColor: 'rgba(220,38,38,0.7)',  borderColor: '#dc2626', borderWidth: 1, borderRadius: 2 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { labels: { color: th.tick, font: { size: 10 }, boxWidth: 10 } }, tooltip: _tooltipOpts(th) },
          scales: {
            x: { grid: { color: th.grid }, ticks: { color: th.tick, font: { size: 10 } } },
            y: { grid: { color: th.grid }, ticks: { color: th.tick, font: { size: 10 }, precision: 0 }, beginAtZero: true }
          }
        }
      });
    } catch(e) { console.error('[chart-watch]', e); }
  }

  function refreshThemes() {
    var th = _th();
    Object.keys(_instances).forEach(function(id) {
      var ch = _instances[id]; if (!ch) return;
      if (ch.options.scales) {
        Object.keys(ch.options.scales).forEach(function(k) {
          var sc = ch.options.scales[k];
          if (sc.grid)  sc.grid.color  = th.grid;
          if (sc.ticks) sc.ticks.color = th.tick;
        });
      }
      if (ch.options.plugins && ch.options.plugins.tooltip) {
        ch.options.plugins.tooltip.backgroundColor = th.tooltip;
        ch.options.plugins.tooltip.titleColor = th.tick;
        ch.options.plugins.tooltip.bodyColor   = th.tick;
      }
      ch.update('none');
    });
  }

  function mount(data) {
    if (!data) return;
    _load(function() {
      // setTimeout gives the browser one more tick to finalize canvas layout
      // so offsetWidth/offsetHeight are non-zero when Chart.js reads them
      setTimeout(function() {
        _activity(data);
        _severity(data);
        _environment(data);
        _teams(data);
        _language(data);
        _topTags(data);
        _watchActivity(data);
      }, 0);
    });
  }

  function destroyAll() {
    Object.keys(_instances).forEach(function(id) { _kill(id); });
  }

  return { mount: mount, destroyAll: destroyAll, refreshThemes: refreshThemes };
})();
