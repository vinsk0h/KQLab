// KQLab v3 - Main Application
var S = {user:null,queries:[],folders:[],search:"",selQ:null,showCreate:false,showNewFolder:false,showImport:false,showProfile:false,showUserDropdown:false,showVarPanel:false,activeFolder:null,lang:null,fm:[],fs:[],fe:[],starOnly:false,queryView:'grid',cf:null,toast:null,regStep:null,mustChangePw:false,showChangePw:false,comments:{},globalVars:{},uiLang:'en',compat:{},compatDetail:{},showEnvModal:false,envProfiles:[],envEdit:null,showRepoModal:false,repoSources:[],repoShowForm:false,repoEdit:null,repoQueryMap:{},repoSyncing:{},repoLastSync:null,view:'queries',watchSummary:null,watchArticles:[],watchFilter:{days:7,source:'all',severity:'all',unread_only:false,matched_only:false},watchSelArticle:null,watchLoading:false,watchSources:[],watchShowSourceForm:false,watchView:'list',watchTableSort:{col:'date',dir:'desc'},watchTestResult:null,watchEditSrc:null,adminTab:'dashboard',adminFeatures:null,adminData:{},adminLoading:{},adminModal:null,adminAudit:{page:0,filters:{}},adminUsers:{search:'',sort:'created_at',dir:'desc'},adminTeamSel:null,adminQSel:{},adminQSearch:'',detailFullscreen:false,loading:false,showShortcuts:false,offline:false};
var _st = null;

function _sideToggle(){
  var collapsed=localStorage.getItem('kv-side-collapsed')==='1';
  collapsed=!collapsed;
  localStorage.setItem('kv-side-collapsed',collapsed?'1':'0');
  var side=document.querySelector('.side');
  var expandBtn=document.getElementById('btn-side-expand');
  if(side){
    if(collapsed)side.classList.add('side--collapsed');
    else side.classList.remove('side--collapsed');
  }
  if(expandBtn){
    if(collapsed)expandBtn.classList.remove('hidden');
    else expandBtn.classList.add('hidden');
  }
}

function initLang(){
  // Synchronise S.uiLang depuis i18n (déjà initialisé au chargement de i18n.js)
  S.uiLang = (typeof i18n !== 'undefined' ? i18n.getLang() : null) || localStorage.getItem('kv-lang') || 'en';
}
function pTip(p){var fr=(typeof i18n!=='undefined'?i18n.getLang():S.uiLang)==='fr';var name=fr?(p.nFr||p.n):p.n;var desc=fr?(p.dFr||p.d):p.d;return p.id+' \u2014 '+name+'&#10;'+(desc||'').replace(/\n/g,'&#10;');}

var ENV_DEF_LICENSES=[
  {id:'mde',           lbl:'Microsoft Defender for Endpoint (MDE)'},
  {id:'mde_p2',        lbl:'MDE Plan 2 (TVM, advanced hunting)'},
  {id:'mdi',           lbl:'Microsoft Defender for Identity (MDI)'},
  {id:'mdo',           lbl:'Microsoft Defender for Office 365 (MDO)'},
  {id:'mda',           lbl:'Microsoft Defender for Cloud Apps (MDA)'},
  {id:'m365_defender', lbl:'Microsoft 365 Defender (Alerts, Incidents)'}
];
var ENV_SENT_CONNECTORS=[
  {id:'AzureActiveDirectory',      lbl:'Azure Active Directory (Entra ID)'},
  {id:'MicrosoftThreatProtection', lbl:'Microsoft Threat Protection (Defender XDR tables in Sentinel)'},
  {id:'Office365',                 lbl:'Office 365'},
  {id:'SecurityEvents',            lbl:'Security Events (Windows)'},
  {id:'Syslog',                    lbl:'Syslog (Linux/CEF)'},
  {id:'DNS',                       lbl:'DNS'},
  {id:'AzureActivity',             lbl:'Azure Activity'},
  {id:'AzureMonitor',              lbl:'Azure Monitor (Heartbeat, Perf)'}
];

// P1 — Reuse a single element instead of allocating on every call
var _escEl = document.createElement("div");
function esc(s) { if (typeof s !== "string") return ""; _escEl.textContent = s; return _escEl.innerHTML; }
function escAttr(s) { return esc(s).replace(/"/g, '&quot;'); }
function safeHref(url) { return typeof url === 'string' && /^https?:\/\//i.test(url) ? url : null; }
// Global image-error handler (replaces inline onerror= attributes, avoids unsafe-inline CSP)
document.addEventListener('error', function(e) {
  if (e.target.tagName !== 'IMG') return;
  var act = e.target.dataset.imgErr;
  if (act === 'hide') { e.target.style.display = 'none'; }
  else if (act === 'removeParent') { if (e.target.parentElement) e.target.parentElement.removeChild(e.target); }
  else if (act === 'hideSibShow') { e.target.style.display = 'none'; if (e.target.nextElementSibling) e.target.nextElementSibling.style.display = 'flex'; }
}, true);
// P2 — Static lookup maps built once from immutable data (MITRE/PICERL/LANGUAGES come from data.js)
var _mitreMap = {};
MITRE.forEach(function(m) { _mitreMap[m.id] = m; });
// Extend map with techniques — inherit tactic color
if (typeof MITRE_TECHNIQUES !== 'undefined') {
  MITRE_TECHNIQUES.forEach(function(t) {
    var tactic = _mitreMap[t.tid];
    _mitreMap[t.id] = { id: t.id, n: t.n, c: tactic ? tactic.c : '#6e40c9', tid: t.tid, p: t.p };
  });
}
var _picerlMap = {}; PICERL.forEach(function(p) { _picerlMap[p.id] = p; });
var _langMap = {}; LANGUAGES.forEach(function(l) { _langMap[l.id] = l; });
var _tacticIdSet = new Set(MITRE.map(function(m) { return m.id; }));
// Map technique ID → tactic ID (for coverage counting)
var _techTacticMap = {};
if (typeof MITRE_TECHNIQUES !== 'undefined') {
  MITRE_TECHNIQUES.forEach(function(t) { _techTacticMap[t.id] = t.tid; });
}
// Map tactic ID → sorted techniques (for picker)
var _tacticTechniques = {};
if (typeof MITRE_TECHNIQUES !== 'undefined') {
  MITRE_TECHNIQUES.forEach(function(t) {
    if (!_tacticTechniques[t.tid]) _tacticTechniques[t.tid] = [];
    _tacticTechniques[t.tid].push(t);
  });
}

// P3 — Dynamic lookup maps rebuilt whenever queries/folders change
var _folderMap = {};
var _folderQueryCounts = {};
var _langQueryCounts = {};
function rebuildMaps() {
  _folderMap = {};
  S.folders.forEach(function(f) { _folderMap[f.id] = f; });
  _folderQueryCounts = {};
  _langQueryCounts = {};
  S.queries.forEach(function(q) {
    if (q.folder_id) _folderQueryCounts[q.folder_id] = (_folderQueryCounts[q.folder_id] || 0) + 1;
    var lang = q.language || "KQL";
    _langQueryCounts[lang] = (_langQueryCounts[lang] || 0) + 1;
  });
}

function detectVars(k) { return VARS.filter(function(v) { return k.indexOf(v.key) >= 0; }); }
function resolveKql(k, vs) { var r = k; VARS.forEach(function(v) { if (vs[v.id]) r = r.split(v.key).join(vs[v.id]); }); return r; }

function toggleArr(a, v) { var i = a.indexOf(v); return i >= 0 ? a.filter(function(x) { return x !== v; }) : a.concat([v]); }
function elOn(id, fn) { var x = document.getElementById(id); if (x) x.addEventListener("click", fn); }

// ═══ TOAST SYSTEM ═══
var Toast = {
  _container: null,
  _init: function() {
    if (!this._container) {
      this._container = document.createElement('div');
      this._container.className = 'toast-container';
      document.body.appendChild(this._container);
    }
  },
  show: function(msg, type, duration) {
    type = type || 'info'; duration = duration !== undefined ? duration : 3500;
    this._init();
    var icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
    var el = document.createElement('div');
    el.className = 'toast-item ' + type;
    el.innerHTML = '<span class="toast-item-icon">' + (icons[type] || icons.info) + '</span>'
      + '<span class="toast-item-msg">' + esc(String(msg)) + '</span>'
      + '<button class="toast-item-close">×</button>';
    el.querySelector('.toast-item-close').addEventListener('click', function() { el.remove(); });
    this._container.appendChild(el);
    if (duration > 0) setTimeout(function() { if (el.parentNode) el.remove(); }, duration);
    return el;
  },
  success: function(msg, d) { return Toast.show(msg, 'success', d); },
  error:   function(msg, d) { return Toast.show(msg, 'error', d); },
  warning: function(msg, d) { return Toast.show(msg, 'warning', d); },
  info:    function(msg, d) { return Toast.show(msg, 'info', d); }
};

function showToast(msg, type) {
  // Détection automatique du type selon le contenu si non précisé
  if (!type) {
    var m = String(msg).toLowerCase();
    if (m.indexOf('error') >= 0 || m.indexOf('erreur') >= 0 || m.indexOf('invalid') >= 0 || m.indexOf('failed') >= 0 || m.indexOf('échec') >= 0) {
      type = 'error';
    } else if (m.indexOf('warn') >= 0 || m.indexOf('attention') >= 0) {
      type = 'warning';
    } else {
      type = 'success';
    }
  }
  Toast.show(msg, type);
}
function val(id) { var x = document.getElementById(id); return x ? x.value.trim() : ""; }

async function boot() {
  // Sync S.uiLang with i18n engine (i18n.js loaded before this file)
  initLang();

  // Register language change listener — re-render entire UI on lang switch
  if (typeof i18n !== 'undefined') {
    i18n.onLangChange(function(lang) {
      S.uiLang = lang;
      render();
    });
  }

  try {
    var _gv = localStorage.getItem('kv-gvars');
    if (_gv) S.globalVars = JSON.parse(_gv);
  } catch(e) {}
  try {
    var _wv = localStorage.getItem('kqlab_watch_view');
    if (_wv && ['list','compact','mosaic'].includes(_wv)) S.watchView = _wv;
  } catch(e) {}
  try {
    var _qvs = localStorage.getItem('kv-query-view');
    if (_qvs && ['grid','list','table'].includes(_qvs)) S.queryView = _qvs;
  } catch(e) {}
  // Offline detection
  S.offline = !navigator.onLine;
  if (S.offline) _showOfflineBanner();
  window.addEventListener('offline', function() {
    S.offline = true; _showOfflineBanner();
    showToast('Connection lost — read-only mode', 'warning');
  });
  window.addEventListener('online', function() {
    S.offline = false; _hideOfflineBanner();
    showToast('Back online', 'success');
    API.invalidateQueries();
    loadData().then(function() { render(); });
  });

  // Global keyboard shortcut system
  document.addEventListener("keydown", function(e){
    var tag = (e.target&&e.target.tagName||'').toLowerCase();
    var isInput = tag==='input'||tag==='textarea'||tag==='select'||(e.target&&e.target.isContentEditable);
    if (e.key === "Escape") {
      if (S.showShortcuts) { S.showShortcuts=false; render(); return; }
      if (S.watchSelArticle) { S.watchSelArticle=null; render(); return; }
      if (S.showCreate) { S.showCreate=false; S.cf=null; render(); return; }
      if (S.showImport) { S.showImport=false; render(); return; }
      if (S.showNewFolder) { S.showNewFolder=false; render(); return; }
      if (S.showVarPanel) { S.showVarPanel=false; render(); return; }
      if (S.showEnvModal) { S.showEnvModal=false; render(); return; }
      if (S.showRepoModal) { S.showRepoModal=false; render(); return; }
      if (S.selQ) { S.selQ=null; S.detailFullscreen=false; render(); return; }
      return;
    }
    if (e.key==='?' && !isInput) {
      e.preventDefault();
      S.showShortcuts=!S.showShortcuts; render(); return;
    }
    if (isInput) return;
    if (e.key==='/' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      var sb=document.getElementById('sbox');
      if (sb) { sb.focus(); sb.select(); } return;
    }
    if (e.key==='n' && !S.showCreate && !S.selQ && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      S.showCreate=true;
      S.cf={title:'',desc:'',kql:'',lang:S.lang||'KQL',severity:'medium',env:'Defender',playbook:'',folder:'',mitre:[],picerl:[],tags:[]};
      render(); return;
    }
    if (e.key==='e' && S.selQ && !S.showCreate) {
      e.preventDefault();
      var q=S.selQ;
      S.cf={editId:q.id,title:q.title,desc:q.description||'',kql:q.kql,lang:q.language||'KQL',severity:q.severity||'medium',env:q.environment||'Defender',playbook:q.playbook||'',folder:q.folder_id||'',mitre:q.mitre||[],picerl:q.picerl||[],tags:q.tags||[]};
      S.selQ=null; S.showCreate=true; render(); return;
    }
    if (e.key==='f' && !S.showCreate && !S.selQ) {
      S.starOnly=!S.starOnly; render(); return;
    }
  });
  try {
    S.user = await Auth.me(); // null si non connecté
    if (S.user) await loadData();
  } catch (e) {
    S.user = null;
  }
  render();
}

async function loadData() {
  S.loading = true;
  try {
    var results = await Promise.all([API.get("/queries"), API.get("/folders")]);
    S.queries = Array.isArray(results[0]) ? results[0] : [];
    S.folders = Array.isArray(results[1]) ? results[1] : [];
  } catch(e) { S.queries = []; S.folders = []; }
  S.loading = false;
  // Restore saved folder order
  try {
    var _fo = localStorage.getItem('kv-folder-order');
    if (_fo) {
      var _order = JSON.parse(_fo);
      S.folders.sort(function(a, b){ var ai=_order.indexOf(a.id), bi=_order.indexOf(b.id); return (ai<0?999:ai)-(bi<0?999:bi); });
    }
  } catch(e) {}
  rebuildMaps();
  setTimeout(loadCompatibility, 0);
  setTimeout(loadRepoMeta, 0);
  setTimeout(loadWatchSummary, 0);
}

async function loadWatchSummary() {
  try {
    var s = await API.get("/watch/summary");
    S.watchSummary = s;
    render();
  } catch(e) { S.watchSummary = null; }
}

async function loadWatchFeed() {
  S.watchLoading = true; render();
  try {
    var f = S.watchFilter;
    var qs = "?days=" + f.days + "&source=" + encodeURIComponent(f.source) + "&severity=" + encodeURIComponent(f.severity);
    if (f.unread_only) qs += "&unread=1";
    if (f.matched_only) qs += "&matched_only=1";
    var arts = await API.get("/watch/feed" + qs);
    S.watchArticles = Array.isArray(arts) ? arts : [];
  } catch(e) { S.watchArticles = []; }
  S.watchLoading = false; render();
}

async function loadRepoMeta() {
  try {
    // P9 — Fetch last-sync and (for admin) sources list in parallel; then fan-out file fetches in parallel
    var isAdmin = S.user && S.user.role === 'admin';
    var baseRequests = [API.get('/repos/last-sync')];
    if (isAdmin) baseRequests.push(API.get('/repos'));
    var baseResults = await Promise.all(baseRequests);
    var ls = baseResults[0];
    var sources = isAdmin ? (Array.isArray(baseResults[1]) ? baseResults[1] : []) : [];

    if (ls) {
      S.repoLastSync = ls;
      S.repoFolderIds = {};
      if (Array.isArray(ls.sources)) {
        ls.sources.forEach(function(s) { if (s.target_folder_id) S.repoFolderIds[s.target_folder_id] = { name: s.name, github_owner: s.github_owner }; });
      }
    }

    if (isAdmin) {
      S.repoSources = sources;
      var filesArr = await Promise.all(sources.map(function(src) {
        return API.get('/repos/' + src.id + '/files').catch(function() { return []; });
      }));
      var map = {};
      sources.forEach(function(src, i) {
        var files = Array.isArray(filesArr[i]) ? filesArr[i] : [];
        files.forEach(function(f) {
          map[f.query_id] = { repo_id: src.id, repo_name: src.name, github_owner: src.github_owner, github_repo: src.github_repo, file_path: f.file_path, last_synced_at: f.last_synced_at, local_modified: f.local_modified };
        });
      });
      S.repoQueryMap = map;
    }
  } catch(e) {}
}

async function loadCompatibility() {
  try {
    var r = await API.get('/env/compatibility');
    if (r && typeof r === 'object' && !r.error) { S.compat = r; render(); }
  } catch(e) { S.compat = {}; }
}

function render() {
  rebuildMaps(); // P3 — keep folder/lang maps fresh after any mutation
  var app = document.getElementById("app");
  if (!S.user) app.innerHTML = renderLogin();
  else app.innerHTML = renderApp();
  if (S.regStep) app.innerHTML += renderRegModal();
  if (S.mustChangePw || S.showChangePw) app.innerHTML += renderChangePwModal(S.mustChangePw);
  if (S.showProfile) app.innerHTML += renderProfileModal();
  if (S.showShortcuts) app.innerHTML += renderShortcutsOverlay();
  bindEvents();
  // ── Monaco: formulaire create/edit (progressive enhancement) ───────────────
  // #ck (textarea) toujours visible en fallback.
  // setTimeout(0) : attend que le browser ait peint AVANT monaco.editor.create()
  //   → container a des dimensions réelles → coloration correcte.
  // ed.onDidChangeModelContent → S.cf.kql en sync → chip clicks préservent le contenu.
  if (S.showCreate && S.cf && (S.cf.lang || 'KQL') === 'KQL') {
    KQLMonaco.init(function (ok) {
      if (!ok) return;
      setTimeout(function () {
        var container = document.getElementById('monaco-container');
        var ta        = document.getElementById('ck');
        if (!container || !ta) return; // form fermé ou re-rendu entre-temps
        var ed = KQLMonaco.mountForm('monaco-container', 'ck', ta.value);
        if (ed) {
          ed.onDidChangeModelContent(function () {
            // Garder S.cf.kql en sync : sans ça, chaque re-render (chip click, etc.)
            // reconstruit le textarea depuis S.cf.kql stale et Monaco perd le contenu.
            if (S.cf) S.cf.kql = ed.getValue();
          });
        }
      }, 0);
    });
  } else if (!S.showCreate) {
    KQLMonaco.unmountForm('monaco-container', 'ck');
  }
  // ── Monaco: détail read-only (progressive enhancement) ──────────────────
  // <pre id="ko"> toujours visible en fallback.
  // Container affiché AVANT mountDetail() (dans le setTimeout) → coloration correcte.
  if (S.selQ) {
    KQLMonaco.init(function (ok) {
      if (!ok) return;
      setTimeout(function () {
        var container = document.getElementById('monaco-detail-container');
        var pre       = document.getElementById('ko');
        if (!container || !pre) return; // détail fermé ou re-rendu entre-temps
        container.style.display = '';   // rendre visible AVANT create()
        var ed = KQLMonaco.mountDetail('monaco-detail-container', pre.textContent);
        if (ed) {
          pre.style.display = 'none';
        } else {
          container.style.display = 'none'; // fallback : <pre> reste visible
        }
      }, 0);
    });
  } else if (!S.selQ) {
    KQLMonaco.unmountDetail();
  }
}

// ═══ LOGIN ═══
function renderLogin() {
  var _isEn=S.uiLang==='en';
  var _flagFR='<svg width="20" height="14" viewBox="0 0 20 14" style="display:block;border-radius:2px"><rect width="7" height="14" fill="#002395"/><rect x="7" width="6" height="14" fill="#fff"/><rect x="13" width="7" height="14" fill="#ED2939"/></svg>';
  var _flagGB='<svg width="20" height="14" viewBox="0 0 20 14" style="display:block;border-radius:2px"><rect width="20" height="14" fill="#012169"/><path d="M0,0L20,14M20,0L0,14" stroke="#fff" stroke-width="3.5"/><path d="M0,0L20,14M20,0L0,14" stroke="#C8102E" stroke-width="2"/><path d="M10,0V14M0,7H20" stroke="#fff" stroke-width="4.5"/><path d="M10,0V14M0,7H20" stroke="#C8102E" stroke-width="2.8"/></svg>';
  var h = '<div class="login-wrap"><div class="login-box">';
  h += '<div class="login-logo">';
  h += '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 140" style="width:100%;max-width:340px;display:block;margin:0 auto 6px">';
  h += '<defs><linearGradient id="lgShield" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#0ea5e9"/><stop offset="100%" stop-color="#3b82f6"/></linearGradient></defs>';
  h += '<g transform="translate(40,20) scale(0.39)">';
  h += '<path d="M128 16 L216 56 L216 120 C216 184 128 240 128 240 C128 240 40 184 40 120 L40 56 Z" fill="none" stroke="url(#lgShield)" stroke-width="18" stroke-linejoin="round"/>';
  h += '<polyline points="88,104 120,128 88,152" fill="none" stroke="#0ea5e9" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>';
  h += '<line x1="128" y1="152" x2="168" y2="152" stroke="#0ea5e9" stroke-width="18" stroke-linecap="round"/>';
  h += '</g>';
  h += '<text x="160" y="85" font-family="Inter,-apple-system,sans-serif" font-size="68" fill="currentColor">';
  h += '<tspan font-weight="800">KQL</tspan><tspan font-weight="300" fill="#0ea5e9">ab</tspan>';
  h += '</text>';
  h += '<text x="165" y="115" font-family="JetBrains Mono,monospace" font-size="13" font-weight="600" fill="#64748b" letter-spacing="3">THE BLUE TEAM QUERY VAULT</text>';
  h += '</svg>';
  h += '<p style="margin:2px 0 0;font-size:13px;color:var(--t4);text-align:center">'+T('login_subtitle')+'</p></div>';
  h += '<div class="login-form">';
  h += '<div class="field"><label class="lbl">'+T('login_label')+'</label><input id="lg-login" placeholder="jdoe" autocomplete="username"></div>';
  h += '<div class="field"><label class="lbl">'+T('passphrase')+'</label><input id="lg-pw" type="password" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" autocomplete="current-password"></div>';
  h += '<div id="login-err" style="min-height:14px;font-size:12px;color:#fca5a5;margin-bottom:6px"></div>';
  h += '<button class="pri full" id="btn-signin" style="margin-bottom:10px">'+T('signin_btn')+'</button>';
  h += '<div class="sep">'+T('no_account')+'</div>';
  h += '<button class="full outline-red" id="btn-newacct">'+T('create_account')+'</button>';
  h += '<div style="border-top:1px solid var(--bd);margin-top:14px;padding-top:14px;display:flex;align-items:center;justify-content:center;gap:10px">';
  h += '<button id="btn-demo" class="btn-ghost" style="font-size:12px">'+T('demo_btn')+'</button>';
  h += '<button class="hdr-btn-lang" id="btn-lang" title="'+T('switch_lang_tip')+'">'+(_isEn?_flagGB:_flagFR)+'</button>';
  h += '</div></div></div></div>';
  return h;
}

// ═══ REGISTER MODAL ═══
function renderRegModal() {
  var h = '<div class="modal-overlay" id="reg-ov">';
  h += '<div class="modal-box narrow">';
  h += '<div class="modal-header"><h2 style="color:var(--red)">'+T('reg_title')+'</h2></div>';
  h += '<div class="modal-body">';
  h += '<p class="sub" style="margin-bottom:16px">'+T('reg_subtitle')+'</p>';
  h += '<div class="field"><label class="lbl">'+T('login_label')+'</label><input id="reg-login" value="' + esc(S.regStep.login || "") + '" placeholder="jdoe" autocomplete="username"></div>';
  h += '<p class="hint" style="margin-bottom:12px">'+T('reg_login_hint')+'</p>';
  h += '<div class="field"><label class="lbl">'+T('passphrase')+'</label><input id="reg-pw" type="password" placeholder="'+T('cpw_min8')+'" autocomplete="new-password"></div>';
  h += '<div class="field"><label class="lbl">'+T('reg_confirm_pw')+'</label><input id="reg-pw2" type="password" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" autocomplete="new-password"></div>';
  h += '<div id="reg-err"></div>';
  h += '</div>';
  h += '<div class="modal-footer"><button id="reg-cancel">'+T('cancel')+'</button><button class="pri" id="reg-confirm">'+T('reg_create_btn')+'</button></div>';
  h += '</div></div>';
  return h;
}

// ═══ CHANGE PASSWORD MODAL ═══
function renderChangePwModal(forced) {
  var h = '<div class="modal-overlay" id="cpw-ov">';
  h += '<div class="modal-box narrow" style="border-color:#991b1b">';
  h += '<div class="modal-header">';
  if (forced) {
    h += '<h2 style="color:var(--red)">'+T('cpw_forced_title')+'</h2>';
  } else {
    h += '<h2>'+T('cpw_title')+'</h2>';
  }
  h += '</div>';
  h += '<div class="modal-body">';
  if (forced) {
    h += '<p style="font-size:13px;color:var(--t3);margin-bottom:20px">'+T('cpw_forced_desc')+'</p>';
  } else {
    h += '<div style="margin-bottom:14px"><label class="lbl">'+T('cpw_current')+'</label><input id="cpw-cur" type="password" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" autocomplete="current-password"></div>';
  }
  h += '<div style="margin-bottom:14px"><label class="lbl">'+T('cpw_new')+'</label><input id="cpw-new" type="password" placeholder="'+T('cpw_min8')+'" autocomplete="new-password"></div>';
  h += '<div style="margin-bottom:6px"><label class="lbl">'+T('cpw_confirm_lbl')+'</label><input id="cpw-new2" type="password" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" autocomplete="new-password"></div>';
  h += '<div id="cpw-err" style="font-size:13px;color:#fca5a5;min-height:20px"></div>';
  h += '</div>';
  h += '<div class="modal-footer">';
  if (!forced) h += '<button id="cpw-cancel">'+T('cancel')+'</button>';
  h += '<button class="pri" id="cpw-confirm">'+T('cpw_save')+'</button>';
  h += '</div></div></div>';
  return h;
}

// ═══ PROFILE MODAL ═══
function renderProfileModal() {
  var h = '<div class="modal-overlay" id="prof-ov">';
  h += '<div class="modal-box narrow">';
  var activeEnv = S.envProfiles ? S.envProfiles.find(function(p) { return p.is_active === 1; }) : null;
  var roleColors = { admin: '#ef4444', analyst: '#0ea5e9', viewer: '#64748b' };
  var rc = roleColors[S.user.role] || '#64748b';
  var _avBig = S.user.avatar
    ? '<img id="prof-av-preview" src="'+esc(S.user.avatar)+'" style="width:72px;height:72px;border-radius:50%;object-fit:cover;display:block;flex-shrink:0">'
    : '<span id="prof-av-preview" style="display:none"></span>';
  var _avInit = '<div id="prof-av-init" style="width:72px;height:72px;border-radius:50%;background:var(--red);display:'+(S.user.avatar?'none':'flex')+';align-items:center;justify-content:center;font-size:26px;font-weight:800;color:#fff;flex-shrink:0">'+esc((S.user.login||"?")[0].toUpperCase())+'</div>';
  var _icoCamera = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg>';
  var _icoFingerprint = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 018 4"/><path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M12 10a2 2 0 00-2 2c0 1.02-.1 2.51-.26 4"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M9 6.8a6 6 0 019 5.2c0 .47 0 1.17-.02 2"/></svg>';
  var _icoKey = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>';
  h += '<div class="modal-header" style="padding:14px 20px;border-bottom:1px solid var(--bd)">';
  h += '<h2 style="font-size:14px;font-weight:600;letter-spacing:-.01em">'+T('prof_title')+'</h2>';
  h += '<span id="cl-prof" class="close">\u00d7</span>';
  h += '</div>';
  h += '<div class="prof-body">';
  // \u2460 Identity
  h += '<div class="prof-identity">';
  h += '<div class="prof-av-wrap">'+_avBig+_avInit;
  h += '<button class="prof-av-overlay" id="btn-pick-avatar" title="'+T('prof_choose')+'">'+_icoCamera+'</button>';
  h += '</div>';
  h += '<input type="file" id="prof-file" accept="image/jpeg,image/png,image/webp,image/gif" style="display:none">';
  h += '<div class="prof-identity-info">';
  h += '<span class="prof-username">'+esc(S.user.login)+'</span>';
  h += '<div style="display:flex;align-items:center;gap:6px;margin-top:5px">';
  h += '<span class="prof-role-badge" style="background:'+rc+'18;color:'+rc+';border:1px solid '+rc+'30">'+esc(S.user.role)+'</span>';
  if (S.user.team && S.user.team !== 'none') h += '<span class="prof-team-chip">'+esc(S.user.team)+'</span>';
  h += '</div>';
  if (S.user.avatar) h += '<button id="btn-clear-avatar" class="prof-del-photo">'+T('prof_delete_photo')+'</button>';
  h += '</div></div>';
  h += '<input id="prof-avatar" value="'+esc(S.user.avatar||'')+'" style="display:none">';
  // \u2461 Informations
  h += '<div class="prof-section">';
  h += '<div class="prof-section-label">'+T('prof_section_info')+'</div>';
  h += '<div class="prof-row"><span class="prof-row-key">'+T('login_label')+'</span><span class="prof-row-val">'+esc(S.user.login)+'</span></div>';
  h += '<div class="prof-row"><span class="prof-row-key">'+T('prof_role')+'</span><span class="prof-role-badge" style="background:'+rc+'18;color:'+rc+';border:1px solid '+rc+'30">'+esc(S.user.role)+'</span></div>';
  h += '<div class="prof-row"><span class="prof-row-key">'+T('prof_team')+'</span><div style="display:flex;align-items:center;gap:8px"><span class="prof-row-val">'+esc(S.user.team === 'none' ? '\u2014' : S.user.team)+'</span><button id="btn-leave-team" class="prof-danger-btn">'+T('prof_leave_team')+'</button></div></div>';
  h += '</div>';
  // \u2462 Environnement
  h += '<div class="prof-section">';
  h += '<div class="prof-section-label">'+T('prof_section_env')+'</div>';
  h += '<div class="prof-row"><div style="display:flex;align-items:center;gap:8px"><span class="prof-env-dot'+(activeEnv?' prof-env-dot--active':'')+'"></span><span class="prof-row-val">'+(activeEnv ? esc(activeEnv.name) : T('prof_env_none'))+'</span></div>';
  h += '<button class="prof-link-btn" id="btn-prof-env">'+T('prof_env_manage')+'</button></div>';
  h += '</div>';
  // \u2463 Securite
  h += '<div class="prof-section prof-section--last">';
  h += '<div class="prof-section-label">'+T('prof_section_security')+'</div>';
  h += '<div class="prof-row"><div class="prof-sec-item"><span class="prof-sec-ico">'+_icoFingerprint+'</span><div><div class="prof-sec-sub">'+T('prof_passkey_sub')+'</div></div></div>';
  h += '<button class="prof-action-btn" id="btn-add-passkey">'+T('prof_add_passkey')+'</button></div>';
  h += '<div class="prof-row"><div class="prof-sec-item"><span class="prof-sec-ico">'+_icoKey+'</span><div><div class="prof-sec-label">'+T('prof_passphrase_label')+'</div><div class="prof-sec-sub">'+T('prof_passphrase_sub')+'</div></div></div>';
  h += '<button class="prof-action-btn" id="btn-change-pw">'+T('prof_modify')+'</button></div>';
  h += '</div>';
  h += '</div>';
  h += '<div class="modal-footer"><button id="cl-prof2">'+T('cancel')+'</button><button class="pri" id="btn-save-prof">'+T('prof_save')+'</button></div>';
  h += '</div></div>';
  return h;
}

// ═══ USER DROPDOWN ═══
function renderUserDropdown() {
  var _isLight = document.body.classList.contains('light');
  var _avLg = S.user.avatar
    ? '<img src="'+esc(S.user.avatar)+'" style="width:36px;height:36px;border-radius:50%;object-fit:cover;flex-shrink:0">'
    : '<span style="width:36px;height:36px;border-radius:50%;background:var(--red);display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0">'+esc((S.user.login||"?")[0].toUpperCase())+'</span>';
  var _icoPerson = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>';
  var _icoThemeDD = _isLight
    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
  var _icoLogoutDD = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
  var h = '<div class="hdr-dropdown" id="hdr-user-dd">';
  h += '<div class="hdr-dd-hdr">';
  h += _avLg;
  h += '<div class="hdr-dd-user"><span class="hdr-dd-name">'+esc(S.user.login)+'</span><span class="hdr-dd-role">'+esc(S.user.role)+'</span></div>';
  h += '</div>';
  h += '<div class="hdr-dd-sep"></div>';
  h += '<button class="hdr-dd-item" id="btn-dd-profile">'+_icoPerson+'<span>'+T('prof_title')+'</span></button>';
  h += '<div class="hdr-dd-sep"></div>';
  h += '<button class="hdr-dd-item" id="btn-dd-theme">'+_icoThemeDD+'<span>'+T(_isLight?'switch_theme_dark':'switch_theme_light')+'</span></button>';
  h += '<div class="hdr-dd-sep"></div>';
  h += '<button class="hdr-dd-item hdr-dd-item--danger" id="btn-dd-logout">'+_icoLogoutDD+'<span>'+T('logout')+'</span></button>';
  h += '</div>';
  return h;
}

// ═══ MAIN APP ═══
function renderApp() {
  var fq = getFiltered(); var af = S.folders.find(function(f) { return f.id === S.activeFolder; }); var h = '';

  // Header
  var _gvFilled=VARS.filter(function(v){return S.globalVars[v.id]&&S.globalVars[v.id].trim();}).length;
  var _icoPlus='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>';
  var _icoDown='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
  var _icoUp='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>';
  var _icoSliders='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="4" y1="6" x2="20" y2="6"/><line x1="8" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="16" y2="18"/><circle cx="7" cy="6" r="2.5" fill="currentColor" stroke="none"/><circle cx="17" cy="12" r="2.5" fill="currentColor" stroke="none"/></svg>';
  var _icoSearch='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
  var _icoShield='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
  var _icoLogout='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
  var _icoEnv='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>';
  var _hasFp=Object.keys(S.compat).length>0;
  var _fpDef=S.envProfiles.length>0&&S.envProfiles.some(function(p){return p.is_active===1;});
  var _isLight=document.body.classList.contains('light');
  var _icoTheme=_isLight?'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>':'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
  var _isEn=S.uiLang==='en';
  var _flagFR='<svg width="20" height="14" viewBox="0 0 20 14" style="display:block;border-radius:2px"><rect width="7" height="14" fill="#002395"/><rect x="7" width="6" height="14" fill="#fff"/><rect x="13" width="7" height="14" fill="#ED2939"/></svg>';
  var _flagGB='<svg width="20" height="14" viewBox="0 0 20 14" style="display:block;border-radius:2px"><rect width="20" height="14" fill="#012169"/><path d="M0,0L20,14M20,0L0,14" stroke="#fff" stroke-width="3.5"/><path d="M0,0L20,14M20,0L0,14" stroke="#C8102E" stroke-width="2"/><path d="M10,0V14M0,7H20" stroke="#fff" stroke-width="4.5"/><path d="M10,0V14M0,7H20" stroke="#C8102E" stroke-width="2.8"/></svg>';
  var _avSm=S.user.avatar?'<img src="'+esc(S.user.avatar)+'" style="width:24px;height:24px;border-radius:50%;object-fit:cover;flex-shrink:0">':'<span style="width:24px;height:24px;border-radius:50%;background:var(--red);display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0">'+esc((S.user.login||"?")[0].toUpperCase())+'</span>';
  h += '<div class="hdr">';
  h += '<button class="hdr-hamburger" id="btn-sidebar-toggle" aria-label="Menu"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg></button>';
  // Left: logo + brand
  h += '<a href="/" class="hdr-left" style="display:flex;align-items:center;gap:8px;text-decoration:none;color:inherit;cursor:pointer">';
  h += '<svg width="28" height="28" viewBox="40 16 176 228" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0">';
  h += '<defs><linearGradient id="hdrG" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#0ea5e9"/><stop offset="100%" stop-color="#3b82f6"/></linearGradient></defs>';
  h += '<path d="M128 16 L216 56 L216 120 C216 184 128 240 128 240 C128 240 40 184 40 120 L40 56 Z" fill="none" stroke="url(#hdrG)" stroke-width="18" stroke-linejoin="round"/>';
  h += '<polyline points="88,104 120,128 88,152" fill="none" stroke="#0ea5e9" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>';
  h += '<line x1="128" y1="152" x2="168" y2="152" stroke="#0ea5e9" stroke-width="18" stroke-linecap="round"/>';
  h += '</svg>';
  h += '<span style="font-size:15px;font-weight:800;letter-spacing:-.01em">KQL<span style="color:#0ea5e9">ab</span></span>';
  h += '</a>';
  // Center: search bar
  h += '<div class="hdr-center"><div class="header-search"><svg class="search-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input id="sbox" placeholder="'+T('search')+'" style="color:var(--t1)"></div></div>';
  // Right: actions + nav + user
  var _icoGH='<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.341-3.369-1.341-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0 1 12 6.836c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/></svg>';
  var _repoNew=S.repoLastSync&&S.repoLastSync.total_new>0?'<span class="hdr-badge hdr-badge--green">+'+S.repoLastSync.total_new+'</span>':'';
  var _varBadge=_gvFilled>0?'<span class="hdr-badge hdr-badge--violet">'+_gvFilled+'</span>':'';
  var _watchUnread=S.watchSummary&&S.watchSummary.unread_count>0;
  var _watchCrit=S.watchSummary&&S.watchSummary.critical_count>0;
  var _watchBadge=_watchUnread?'<span class="hdr-badge'+(_watchCrit?' hdr-badge--red':' hdr-badge--orange')+'">'+S.watchSummary.unread_count+'</span>':'';
  var _icoWatch='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M12 4c-4 0-8 4-8 8s4 8 8 8 8-4 8-8-4-8-8-8"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>';
  var _icoChevron='<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="6 9 12 15 18 9"/></svg>';
  var _avSm=S.user.avatar?'<img src="'+esc(S.user.avatar)+'" style="width:26px;height:26px;border-radius:50%;object-fit:cover;flex-shrink:0">':'<span style="width:26px;height:26px;border-radius:50%;background:var(--red);display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0">'+esc((S.user.login||"?")[0].toUpperCase())+'</span>';
  h += '<div class="hdr-right">';
  h += '<button class="hdr-btn-new" id="btn-cr">'+_icoPlus+T('new_query')+'</button>';
  h += '<div class="hdr-sep"></div>';
  h += '<button class="hdr-btn-icon" id="btn-imp" aria-label="'+T('import')+'" title="'+T('import')+'">'+_icoDown+'</button>';
  h += '<button class="hdr-btn-icon" id="btn-exp" aria-label="'+T('export')+'" title="'+T('export')+'">'+_icoUp+'</button>';
  h += '<button class="hdr-btn-icon" id="btn-vp" aria-label="'+T('variables')+'" title="'+T('variables')+'" style="position:relative">'+_icoSliders+_varBadge+'</button>';
  if(S.user.role==='admin')h+='<button class="hdr-btn-icon" id="btn-repos" aria-label="'+T('repos')+'" title="'+T('repos')+'" style="position:relative">'+_icoGH+_repoNew+'</button>';
  h += '<div class="hdr-sep"></div>';
  h += '<a href="/investigations.html" class="hdr-btn-nav" style="text-decoration:none" aria-label="'+T('investigations')+'">'+_icoSearch+T('investigations')+'</a>';
  h += '<button class="hdr-btn-nav'+(S.view==="watch"?" active":"")+'" id="btn-watch" style="position:relative'+(_watchCrit?';color:#ef4444':_watchUnread?';color:#f97316':'')+'" aria-label="'+T('watch')+'">'+ _icoWatch+T('watch')+_watchBadge+'</button>';
  if(S.user.role==="admin")h+='<button class="hdr-btn-admin'+(S.view==="admin"?" active":"")+'" id="btn-admin">'+_icoShield+T('admin')+'</button>';
  h += '<div class="hdr-sep"></div>';
  h += '<button class="hdr-btn-lang" id="btn-lang" title="'+T('switch_lang_tip')+'" aria-label="'+T('switch_lang_tip')+'">'+(_isEn?_flagGB:_flagFR)+'</button>';
  h += '<div class="hdr-user-wrap" style="position:relative">';
  h += '<button class="hdr-profile-btn" id="btn-profile" aria-label="'+T('prof_title')+'">'+_avSm+_icoChevron+'</button>';
  if(S.showUserDropdown) h += renderUserDropdown();
  h += '</div>';
  h += '</div></div>';

  h += '<div class="main-layout">';
  h += renderSidebar();
  var _sc=localStorage.getItem('kv-side-collapsed')==='1';
  h += '<button class="btn-side-expand'+(_sc?'':' hidden')+'" id="btn-side-expand" data-action="side-toggle" title="Expand sidebar">\u276F</button>';
  h += '<div class="side-overlay" id="sidebar-overlay"></div>';
  h += '<div class="content">';

  if (S.view === 'watch') {
    h += renderWatchView();
    h += '</div></div>';
    if(S.watchShowSourceForm)h+=renderWatchSourcesModal();
    h+=renderWatchSlidein(S.watchSelArticle);
    if(S.selQ)h+=renderDetail(S.selQ);
    if(S.showCreate)h+=renderCreateModal();
    if(S.showImport)h+=renderImportModal();
    if(S.showNewFolder)h+=renderFolderModal();
    if(S.showVarPanel)h+=renderVarPanel();
    if(S.showEnvModal)h+=renderEnvModal();
    if(S.showRepoModal)h+=renderRepoModal();
    return h;
  }

  if (S.view === 'admin') {
    h += typeof renderAdminContent==='function' ? renderAdminContent() : '<div style="padding:40px;color:var(--t3)">Loading admin…</div>';
    h += '</div></div>';
    if(S.adminModal && typeof renderAdminModal==='function') h += renderAdminModal();
    return h;
  }

  // Stats — P4: single pass over fq instead of 3 separate passes; P2: reuse _tacticIdSet
  var ms = new Set();
  var _sevColors={critical:'var(--sev-critical)',high:'var(--sev-high)',medium:'var(--sev-medium)',low:'var(--sev-low)',info:'var(--sev-info)'};
  var _sevMap={critical:0,high:0,medium:0,low:0,info:0};
  var _defC=0,_senC=0,_botC=0;
  var _langC={};LANGUAGES.forEach(function(l){_langC[l.id]=0;});
  fq.forEach(function(q){
    (q.mitre||[]).forEach(function(m){
      if(_tacticIdSet.has(m)) ms.add(m);
      else if(_techTacticMap[m]) ms.add(_techTacticMap[m]);
    });
    if(_sevMap[q.severity]!==undefined)_sevMap[q.severity]++;
    var e=q.environment||"Defender";if(e==="Defender")_defC++;else if(e==="Sentinel")_senC++;else _botC++;
    var lang=q.language||"KQL";if(_langC[lang]!==undefined)_langC[lang]++;
  });
  // ── Stat icon SVGs ───────────────────────────────────────
  var _icoDb='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4.03 3-9 3S3 13.66 3 12"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/></svg>';
  var _icoTarget='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>';
  var _icoServer='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="6" cy="18" r="1" fill="currentColor" stroke="none"/></svg>';
  var _icoShieldSt='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';

  h+='<div class="stats">';
  // Card 1 — Queries + language bar
  h+='<div class="stat">';
  h+='<div class="stat-hd"><span class="stat-ico stat-ico-red">'+_icoDb+'</span><span class="stat-lbl-hd">'+T('queries_label')+'</span></div>';
  h+='<div class="stat-main"><span class="stat-val" style="color:var(--primary)">'+fq.length+'</span></div>';
  h+='<div class="stat-bar-wrap">';
  if(fq.length){LANGUAGES.forEach(function(l){if(_langC[l.id]>0)h+='<div class="stat-bar-seg" style="flex:'+_langC[l.id]+';background:'+l.color+'"></div>';});}
  else{h+='<div class="stat-bar-seg stat-bar-empty"></div>';}
  h+='</div>';
  h+='<div class="stat-chips">';
  LANGUAGES.forEach(function(l){if(_langC[l.id]>0)h+='<span class="stat-chip" style="color:'+l.color+';background:'+l.color+'18">'+_langC[l.id]+'\u00a0'+l.name+'</span>';});
  h+='</div></div>';
  // Card 2 — MITRE coverage + dot grid
  h+='<div class="stat">';
  h+='<div class="stat-hd"><span class="stat-ico stat-ico-orange">'+_icoTarget+'</span><span class="stat-lbl-hd">'+T('mitre_label')+'</span></div>';
  h+='<div class="stat-main"><span class="stat-val" style="color:var(--sev-critical)">'+ms.size+'</span><span class="stat-denom"> / '+MITRE.length+'</span></div>';
  h+='<div class="stat-dot-grid">';
  MITRE.forEach(function(m){var cov=ms.has(m.id);h+='<div class="stat-dot" data-tip="'+m.id+' \u2014 '+m.n+'" style="background:'+(cov?m.c+'cc':'var(--border-medium)')+'"></div>';});
  h+='</div></div>';
  // Card 3 — Platforms
  h+='<div class="stat">';
  h+='<div class="stat-hd"><span class="stat-ico stat-ico-blue">'+_icoServer+'</span><span class="stat-lbl-hd">'+T('platforms_label')+'</span></div>';
  h+='<div class="stat-main"><span class="stat-val" style="color:#f59e0b">'+(_defC+_senC+_botC)+'</span><span class="stat-unit">total</span></div>';
  h+='<div class="stat-bar-wrap">';
  if(_defC>0)h+='<div class="stat-bar-seg" style="flex:'+_defC+';background:#f59e0b"></div>';
  if(_senC>0)h+='<div class="stat-bar-seg" style="flex:'+_senC+';background:#38bdf8"></div>';
  if(_botC>0)h+='<div class="stat-bar-seg" style="flex:'+_botC+';background:var(--intel)"></div>';
  if(!_defC&&!_senC&&!_botC)h+='<div class="stat-bar-seg stat-bar-empty"></div>';
  h+='</div>';
  h+='<div class="stat-chips">';
  if(_defC>0)h+='<span class="stat-chip" style="color:#f59e0b;background:rgba(245,158,11,.12)">'+_defC+'\u00a0Defender</span>';
  if(_senC>0)h+='<span class="stat-chip" style="color:#38bdf8;background:rgba(56,189,248,.12)">'+_senC+'\u00a0Sentinel</span>';
  if(_botC>0)h+='<span class="stat-chip" style="color:var(--intel);background:var(--intel-dim)">'+_botC+'\u00a0Both</span>';
  h+='</div></div>';
  // Card 4 — Severity
  h+='<div class="stat">';
  h+='<div class="stat-hd"><span class="stat-ico stat-ico-red2">'+_icoShieldSt+'</span><span class="stat-lbl-hd">'+T('severity_label')+'</span></div>';
  h+='<div class="stat-main"><span class="stat-val" style="color:var(--sev-critical)">'+(_sevMap.critical||0)+'</span><span class="stat-unit">critical</span></div>';
  h+='<div class="stat-bar-wrap">';
  ['critical','high','medium','low','info'].forEach(function(s){if(_sevMap[s]>0)h+='<div class="stat-bar-seg" style="flex:'+_sevMap[s]+';background:'+_sevColors[s]+'"></div>';});
  if(!fq.length)h+='<div class="stat-bar-seg stat-bar-empty"></div>';
  h+='</div>';
  h+='<div class="stat-chips">';
  ['critical','high','medium','low','info'].forEach(function(s){if(_sevMap[s]>0)h+='<span class="stat-chip" style="color:'+_sevColors[s]+';background:'+_sevColors[s]+'18">'+_sevMap[s]+'\u00a0'+s+'</span>';});
  h+='</div></div>';
  h+='</div>'; // end stats grid

  // Watch alert banner
  if (S.watchSummary && S.watchSummary.unread_count > 0) {
    var _wCritical = S.watchSummary.critical_count > 0;
    h += '<div class="watch-banner" id="btn-watch-banner">';
    h += '<svg class="watch-banner-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="2"/><path d="M12 4c-4 0-8 4-8 8s4 8 8 8 8-4 8-8-4-8-8-8"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>';
    h += '<span class="watch-banner-txt"><span class="watch-banner-count'+(_wCritical?' watch-banner-crit':'')+'">'+S.watchSummary.unread_count+'</span> '+T('watch_banner')+'</span>';
    h += '<button class="pri watch-banner-btn">'+T('watch')+'</button>';
    h += '</div>';
  }

  // Toolbar: view mode toggle + star filter
  h += '<div class="qv-toolbar">';
  h += '<div class="qv-view-toggle">';
  h += '<button class="qv-vbtn'+(S.queryView==='grid'?' active':'')+'" id="btn-qv-grid" title="Grid view">';
  h += '<svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor"><rect x="0" y="0" width="6" height="6" rx="1.5"/><rect x="8" y="0" width="6" height="6" rx="1.5"/><rect x="0" y="8" width="6" height="6" rx="1.5"/><rect x="8" y="8" width="6" height="6" rx="1.5"/></svg>';
  h += '<span>Grid</span></button>';
  h += '<button class="qv-vbtn'+(S.queryView==='list'?' active':'')+'" id="btn-qv-list" title="List view">';
  h += '<svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor"><rect x="0" y="1" width="14" height="2" rx="1"/><rect x="0" y="6" width="14" height="2" rx="1"/><rect x="0" y="11" width="14" height="2" rx="1"/></svg>';
  h += '<span>List</span></button>';
  h += '<button class="qv-vbtn'+(S.queryView==='table'?' active':'')+'" id="btn-qv-table" title="Table view">';
  h += '<svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor"><rect x="0" y="0" width="14" height="2" rx="0.5"/><rect x="0" y="4" width="14" height="1.5" rx="0.5" opacity=".6"/><rect x="0" y="7" width="14" height="1.5" rx="0.5" opacity=".6"/><rect x="0" y="10" width="14" height="1.5" rx="0.5" opacity=".6"/><rect x="0" y="13" width="14" height="1" rx="0.5" opacity=".4"/></svg>';
  h += '<span>Table</span></button>';
  h += '</div>';
  h += '<button id="btn-sf" style="font-size:15px;'+(S.starOnly?'background:var(--primary-dim);color:#fca5a5;border-color:var(--primary-border)':'')+'">'+(S.starOnly?T('starred_on'):T('starred_off'))+'</button>';
  h += '</div>';


  if(af){h+='<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:12px 14px;background:'+af.color+'12;border:1px solid '+af.color+'25;border-radius:8px"><span class="fic" style="width:30px;height:30px;font-size:12px;background:'+af.color+'20;color:'+af.color+'">'+esc(af.icon)+'</span><div><div style="font-size:15px;font-weight:600;color:'+af.color+'">'+esc(af.name)+'</div><div style="font-size:12px;color:var(--t4)">'+fq.length+' '+T('queries_label').toLowerCase()+'</div></div><span id="btn-cfld" style="margin-left:auto;cursor:pointer;color:var(--t4);font-size:18px">x</span></div>';}

  if(S.loading){h+=renderSkeletonGrid();}
  else if(!fq.length){h+=renderEmptyState(af);}
  else if(S.queryView==='list'){h+=renderQueryList(fq);}
  else if(S.queryView==='table'){h+=renderQueryTable(fq);}
  else{h+='<div class="qgrid">';fq.forEach(function(q){h+=renderCard(q);});h+='</div>';}
  h+='</div></div>';

  if(S.selQ)h+=renderDetail(S.selQ);
  if(S.showCreate)h+=renderCreateModal();
  if(S.showImport)h+=renderImportModal();
  if(S.showNewFolder)h+=renderFolderModal();
  if(S.showVarPanel)h+=renderVarPanel();
  if(S.showEnvModal)h+=renderEnvModal();
  if(S.showRepoModal)h+=renderRepoModal();
  return h;
}

function renderSkeletonGrid() {
  var sk = '';
  for (var i = 0; i < 6; i++) {
    sk += '<div class="skeleton-card">'
      + '<div style="display:flex;gap:8px;margin-bottom:6px"><div class="sk-line skeleton" style="width:52px;height:20px;border-radius:4px"></div><div class="sk-line skeleton" style="width:36px;height:20px;border-radius:4px"></div></div>'
      + '<div class="sk-line sk-title skeleton"></div>'
      + '<div class="sk-line sk-short skeleton" style="margin-top:4px"></div>'
      + '<div class="sk-line sk-bar skeleton" style="margin-top:10px"></div>'
      + '</div>';
  }
  return '<div class="skeleton-grid">' + sk + '</div>';
}

function renderEmptyState(af) {
  var hasSearch = S.search.trim();
  var hasFilters = S.fm.length || S.fs.length || S.fe.length;
  var _icoSearch = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
  var _icoStar   = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>';
  var _icoFolder = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>';
  var _icoVault  = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>';
  if (hasSearch || hasFilters) {
    return '<div class="empty-state">'
      + '<div class="empty-state-icon">' + _icoSearch + '</div>'
      + '<div class="empty-state-title">' + T('no_queries') + '</div>'
      + '<div class="empty-state-desc">Try different keywords or clear active filters</div>'
      + '<div class="empty-state-actions"><button id="btn-clf-es" class="pri">Clear filters</button></div>'
      + '</div>';
  }
  if (S.starOnly) {
    return '<div class="empty-state">'
      + '<div class="empty-state-icon">' + _icoStar + '</div>'
      + '<div class="empty-state-title">No starred queries</div>'
      + '<div class="empty-state-desc">Star queries you use frequently — click the ★ on any card</div>'
      + '</div>';
  }
  if (af) {
    return '<div class="empty-state">'
      + '<div class="empty-state-icon" style="background:' + af.color + '18;border-color:' + af.color + '30">' + esc(af.icon) + '</div>'
      + '<div class="empty-state-title">' + esc(af.name) + ' is empty</div>'
      + '<div class="empty-state-desc">Move existing queries here or create a new one</div>'
      + '<div class="empty-state-actions"><button class="pri" id="btn-cr2">' + T('create') + '</button></div>'
      + '</div>';
  }
  return '<div class="empty-state">'
    + '<div class="empty-state-icon">' + _icoVault + '</div>'
    + '<div class="empty-state-title">Your vault is empty</div>'
    + '<div class="empty-state-desc">Start by creating your first KQL query or importing an existing library</div>'
    + '<div class="empty-state-actions"><button class="pri" id="btn-cr2">' + T('create') + '</button><button id="btn-imp2">Import JSON</button></div>'
    + '<div class="empty-state-hint"><kbd class="kbd">n</kbd> to create · <kbd class="kbd">/</kbd> to search · <kbd class="kbd">?</kbd> shortcuts</div>'
    + '</div>';
}

function renderShortcutsOverlay() {
  var shortcuts = [
    ['/','Focus search'],['n','New query'],['e','Edit selected query'],
    ['f','Toggle starred filter'],['Esc','Close / dismiss'],['?','Show this overlay'],
  ];
  var h = '<div class="ov-shortcuts" id="ov-shortcuts"><div class="shortcuts-box">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">';
  h += '<span style="font-size:15px;font-weight:700;color:var(--text-primary)">Keyboard Shortcuts</span>';
  h += '<button id="cl-shortcuts" style="background:none;border:none;cursor:pointer;color:var(--text-tertiary);font-size:20px;line-height:1;padding:0">×</button>';
  h += '</div><div class="shortcuts-list">';
  shortcuts.forEach(function(s){
    h += '<div class="shortcut-row"><kbd class="kbd">' + s[0] + '</kbd><span>' + s[1] + '</span></div>';
  });
  h += '</div></div></div>';
  return h;
}

function renderSidebar(){
  if(S.view==='admin') return typeof renderAdminSidebar==='function' ? renderAdminSidebar() : '';
  var collapsed=localStorage.getItem('kv-side-collapsed')==='1';
  var h='<div class="side'+(collapsed?' side--collapsed':'')+'">';
  // ── Collapse toggle (always visible at top) ───
  h+='<div class="side-collapse-hdr"><button class="btn-side-collapse" data-action="side-toggle" title="Collapse sidebar">\u276E</button></div>';

  // ── Language tab cards ────────────────────────
  h+='<div class="lang-tabs">';
  LANGUAGES.forEach(function(l){
    var active=S.lang===l.id;
    var cnt=_langQueryCounts[l.id]||0; // P7
    var tabSty=active?'border-color:'+l.color+';background:'+l.color+'12':'';
    var cntSty=active?'background:'+l.color+'28;color:'+l.color:'';
    h+='<div class="lang-tab" data-lang="'+l.id+'" style="'+tabSty+'">'
      +'<div class="lang-tab-icon" style="background:'+l.color+(active?'28':'18')+'">'+l.logo+'</div>'
      +'<span class="lang-tab-name" style="color:'+(active?l.color:'var(--t2)')+'">'+l.name+'</span>'
      +'<span class="lang-tab-count" style="'+cntSty+'">'+cnt+'</span>'
      +'</div>';
  });
  h+='</div>';

  // ── Inline filter sections ────────────────────
  h+='<div class="side-sep"></div>';
  h+='<div class="side-filters">';

  // MITRE ATT&CK Coverage — first, primary dimension
  var _tCnts={};MITRE.forEach(function(m){_tCnts[m.id]=0;});
  S.queries.forEach(function(q){var _cv={};(Array.isArray(q.mitre)?q.mitre:[]).forEach(function(id){if(_tacticIdSet.has(id))_cv[id]=1;else if(_techTacticMap[id])_cv[_techTacticMap[id]]=1;});Object.keys(_cv).forEach(function(tid){if(_tCnts[tid]!==undefined)_tCnts[tid]++;});});
  h+='<div class="fsec"><div class="fsec-lbl"><span>'+T('mitre_label')+'</span></div><div class="mitre-fchips">';
  MITRE.forEach(function(m){
    var on=S.fm.indexOf(m.id)>=0;
    var cnt=_tCnts[m.id]||0;
    var aStyle=on?'background:'+m.c+'1a;color:'+m.c+';border-color:'+m.c+'40;':'';
    var dotC=on?m.c:(cnt>0?m.c+'99':'var(--border-medium)');
    h+='<button class="mitre-fchip'+(on?' mitre-fchip--on':'')+(cnt===0?' mitre-fchip--zero':'')+'" data-fmt="'+m.id+'"'+(cnt===0?' disabled':'')+' style="'+aStyle+'">'
      +'<span class="mitre-fchip-dot" style="background:'+dotC+'"></span>'
      +'<span class="mitre-fchip-name">'+m.n+'</span>'
      +(cnt>0?'<span class="mitre-fchip-cnt">'+cnt+'</span>':'')
      +'</button>';
  });
  h+='</div></div>';

  // Severity
  var sevDots={critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'};
  h+='<div class="fsec"><div class="fsec-lbl"><span>'+T('severity_label')+'</span></div><div class="fchips">';
  SEVKEYS.forEach(function(s){
    var on=S.fs.indexOf(s)>=0;
    h+='<button class="fchip'+(on?' sev-on-'+s:'')+'" data-fsv="'+s+'">'
      +'<span style="width:6px;height:6px;border-radius:50%;background:'+(sevDots[s]||'var(--t4)')+';flex-shrink:0;'+(on?'':'opacity:.35')+'"></span>'
      +s+'</button>';
  });
  h+='</div></div>';

  // Environment — only for KQL or no language filter
  if(!S.lang||S.lang==="KQL"){
    var envMeta={Defender:["#38bdf8","#0c3a52"],Sentinel:["#0ea5e9","#0c2d48"],Both:["#a78bfa","#2e1065"]};
    h+='<div class="fsec"><div class="fsec-lbl"><span>'+T('platform_label')+'</span></div><div class="fchips">';
    ENVS.forEach(function(e){
      var on=S.fe.indexOf(e)>=0;
      var em=envMeta[e]||["var(--t2)","var(--s2)"];
      h+='<button class="fchip" data-fe="'+e+'" style="'+(on?'background:'+em[1]+';color:'+em[0]+';border-color:'+em[1]+';':'')+'">'
        +(e==="Defender"?'<svg width="9" height="10" viewBox="0 0 20 22" fill="none" style="flex-shrink:0"><path d="M10 1L2 4.5v7c0 5 3.5 9 8 10 4.5-1 8-5 8-10v-7z" fill="'+(on?em[0]:'var(--t5)')+'"/></svg>'
        :e==="Sentinel"?'<svg width="9" height="9" viewBox="0 0 20 20" fill="none" style="flex-shrink:0"><circle cx="10" cy="10" r="8" stroke="'+(on?em[0]:'var(--t5)')+'" stroke-width="2"/><path d="M7 10l2 2 4-4" stroke="'+(on?em[0]:'var(--t5)')+'\" stroke-width="1.8" stroke-linecap="round"/></svg>'
        :'<svg width="9" height="9" viewBox="0 0 20 20" fill="none" style="flex-shrink:0"><rect x="2" y="2" width="7" height="7" rx="1" fill="'+(on?em[0]:'var(--t5)')+'"/><rect x="11" y="2" width="7" height="7" rx="1" fill="'+(on?em[0]:'var(--t5)')+'"/><rect x="2" y="11" width="7" height="7" rx="1" fill="'+(on?em[0]:'var(--t5)')+'"/><rect x="11" y="11" width="7" height="7" rx="1" fill="'+(on?em[0]:'var(--t5)')+'"/></svg>')
        +e+'</button>';
    });
    h+='</div></div>';
  }

  // Clear filters
  if(S.fm.length||S.fs.length||S.fe.length){
    h+='<button id="btn-clf" style="width:100%;font-size:11px;color:var(--red);border-color:var(--red3);background:rgba(220,38,38,.05);padding:5px;border-radius:5px;margin-top:2px">'+T('clear_filters')+'</button>';
  }

  h+='</div>';

  // ── Separator + folders ───────────────────────
  h+='<div class="side-sep"></div>';

  var allActive=!S.activeFolder;
  var visibleCount=S.lang?S.queries.filter(function(q){return (q.language||"KQL")===S.lang;}).length:S.queries.length;
  h+='<div class="si'+(allActive?' active':'')+'" data-fld="all" style="'+(allActive?'box-shadow:inset 2px 0 0 var(--red);background:rgba(220,38,38,.07)':'')+'">'
    +'<span class="fic" style="background:var(--s3);color:var(--t4);font-size:14px;letter-spacing:0">≡</span>'
    +'<span class="si-name" style="font-weight:'+(allActive?'700':'500')+'">'+T('all_queries')+'</span>'
    +'<span class="si-count"'+(allActive?' style="background:rgba(220,38,38,.18);color:#f87171"':'')+'>'+visibleCount+'</span>'
    +'</div>';

  var repoFIds=S.repoFolderIds||{};
  var pers=S.folders.filter(function(f){return f.scope==="personal";});
  var tmap={},tnames={};
  var repoFolders=[];
  S.folders.filter(function(f){return f.scope==="team";}).forEach(function(f){
    if(repoFIds[f.id]){repoFolders.push(f);return;}
    var t=f.team_id||"none";
    if(!tmap[t]){tmap[t]=[];tnames[t]=f.team_name||t;}
    tmap[t].push(f);
  });
  if(pers.length){
    h+='<div class="si-group"><div class="si-group-lbl"><span>'+T('personal_folders')+'</span></div>';
    pers.forEach(function(f){h+=sideItem(f);});
    h+='</div>';
  }
  Object.keys(tmap).forEach(function(t){
    h+='<div class="si-group"><div class="si-group-lbl"><span>'+esc(tnames[t])+'</span></div>';
    tmap[t].forEach(function(f){h+=sideItem(f);});
    h+='</div>';
  });
  if(repoFolders.length){
    h+='<div class="si-group"><div class="si-group-lbl"><span>'+T('side_collections')+'</span></div>';
    repoFolders.forEach(function(f){h+=sideItem(f);});
    h+='</div>';
  }
  h+='<button id="btn-nf" style="width:100%;margin-top:16px;border-style:dashed;font-size:12px;color:var(--t5)">'+T('new_folder')+'</button>';
  h+='</div>';
  return h;
}

function sideItem(f){
  var c=_folderQueryCounts[f.id]||0; // P7
  var a=S.activeFolder===f.id;
  var sty=a?'box-shadow:inset 2px 0 0 '+f.color+';background:'+f.color+'12':'';
  var cntSty=c>0?'background:'+f.color+'22;color:'+f.color:'';
  var isAdmin=S.user&&S.user.role==='admin';
  var repoMeta=S.repoFolderIds&&S.repoFolderIds[f.id];
  var iconHtml;
  if(repoMeta&&repoMeta.github_owner){
    var av='https://github.com/'+encodeURIComponent(repoMeta.github_owner)+'.png?size=32';
    iconHtml='<span class="fic" style="background:'+f.color+'1a;padding:0;overflow:hidden"><img src="'+av+'" width="24" height="24" style="display:block;border-radius:4px" data-icon-fb="'+esc(f.icon)+'" data-icon-color="'+esc(f.color)+'"></span>';
  } else {
    iconHtml='<span class="fic" style="background:'+f.color+'1a;color:'+f.color+'">'+esc(f.icon)+'</span>';
  }
  return '<div class="si'+(a?' active':'')+'" data-fld="'+f.id+'" data-drag-folder="'+f.id+'" draggable="true" style="'+sty+'">'
    +iconHtml
    +'<span class="si-name" data-rename-folder="'+f.id+'" style="color:'+(a?f.color:'var(--t2)')+';font-weight:'+(a?'600':'400')+';cursor:text" title="Double-click to rename">'+esc(f.name)+'</span>'
    +'<span class="si-count" style="'+cntSty+'">'+c+'</span>'
    +(isAdmin?'<button class="si-del-folder" data-del-folder="'+f.id+'" title="Delete folder" style="margin-left:4px;flex-shrink:0;opacity:0;background:none;border:none;cursor:pointer;color:var(--red);font-size:14px;line-height:1;padding:0 2px;border-radius:3px">\u00d7</button>':'')
    +'</div>';
}

function renderCard(q){
  var env=q.environment||"Defender";
  var vs=detectVars(q.kql);
  var ql=q.language||"KQL";
  var langDef=_langMap[ql]||LANGUAGES[0]; // P5
  var sev=(q.severity||'info').toLowerCase();
  // Severity bar colors for border-left (kept for ::before pseudo-element matching)
  var sevC={critical:'#ff2d55',high:'#ff6b35',medium:'#ffd60a',low:'#2dd4bf',info:'#6366f1'};
  var sc=sevC[sev]||'var(--text-tertiary)';
  var kqlFirst=q.kql.split('\n').map(function(l){return l.trim();}).filter(Boolean)[0]||'';
  if(kqlFirst.length>68)kqlFirst=kqlFirst.slice(0,68)+'\u2026';
  var envColor={Defender:'#f59e0b',Sentinel:'#38bdf8',Both:'#a78bfa'};
  var ec=envColor[env]||'var(--text-tertiary)';

  var h='<div class="card" data-qid="'+q.id+'" style="border-left:3px solid '+sc+'">';

  // ── Indicateurs absolus (repo + watch) ──────────
  var _rqm=S.repoQueryMap&&S.repoQueryMap[q.id];
  if(_rqm){
    var _ini=(_rqm.github_owner||_rqm.repo_name||"?").slice(0,2).toUpperCase();
    var _rTip='Source: '+esc(_rqm.repo_name||'')+' | Synced: '+esc((_rqm.last_synced_at||'').slice(0,10));
    h+='<div style="position:absolute;bottom:9px;right:11px;width:16px;height:16px;border-radius:50%;background:var(--intel);display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:800;color:#fff;letter-spacing:-.5px;cursor:default" data-tip="'+_rTip+'">'+esc(_ini)+'</div>';
  }
  var _wm=S.watchSummary&&S.watchSummary.matched_queries&&S.watchSummary.matched_queries[q.id];
  if(_wm){
    var _wTip='Matched by: '+_wm.map(function(t){return t.slice(0,50);}).join(', ');
    h+='<div style="position:absolute;top:9px;right:11px;width:7px;height:7px;border-radius:50%;background:var(--accent);border:2px solid var(--bg-surface)" data-tip="'+esc(_wTip)+'"></div>';
  }

  // ── Head: badges + star ──────────────────────────
  h+='<div class="card-row-head">';
  h+='<div class="card-badges-row">';
  h+='<span class="cb-sev cb-sev-'+sev+'"><span class="cb-dot"></span>'+sev+'</span>';
  h+='<span class="cb-lang" style="color:'+langDef.color+';background:'+langDef.color+'18;border-color:'+langDef.color+'30">'+langDef.logo+'<span>'+langDef.name+'</span></span>';
  if(ql==="KQL")h+='<span class="cb-env" style="color:'+ec+';background:'+ec+'14">'+env+'</span>';
  h+='</div>';
  // Compat dot + star
  var _cs=S.compat[q.id];
  var _fpC=_cs==='compatible'?'var(--sev-low)':_cs==='partial'?'var(--sev-medium)':_cs==='incompatible'?'var(--sev-critical)':null;
  var _fpT=_cs==='compatible'?T('compatible'):_cs==='partial'?T('partial_compat'):_cs==='incompatible'?T('incompatible'):null;
  h+='<div style="display:flex;align-items:center;gap:5px">';
  if(_fpC)h+='<span class="fp-dot" style="background:'+_fpC+'" title="'+_fpT+'"></span>';
  h+='<button class="card-star-btn'+(q.starred?' starred':'')+'" data-st="'+q.id+'">'+(q.starred?'\u2605':'\u2606')+'</button>';
  h+='</div>';
  h+='</div>';

  // ── Title ────────────────────────────────────────
  h+='<div class="card-title-text">'+esc(q.title)+'</div>';

  // ── Description ──────────────────────────────────
  if(q.description)h+='<div class="card-desc-text">'+esc(q.description)+'</div>';

  // ── KQL Preview ──────────────────────────────────
  if(kqlFirst)h+='<div class="card-kql-prev">'+esc(kqlFirst)+'</div>';

  // ── Meta: MITRE + PICERL + techniques + vars ─────
  var techTags=(q.tags||[]).filter(function(t){return /^T\d{4}(\.\d{3})?$/.test(t);});
  var hasMitre=(q.mitre||[]).length>0, hasTech=techTags.length>0;
  if(hasMitre||hasTech||vs.length){
    h+='<div class="card-meta-row">';
    if(hasMitre){
      (q.mitre||[]).slice(0,4).forEach(function(id){
        var m=_mitreMap[id]; // P5
        if(m) h+='<span class="cmtag" style="color:'+m.c+';background:'+m.c+'18;border-color:'+m.c+'30" data-tip="'+m.id+' \u2014 '+m.n+'">'+id+'</span>';
        else if(/^T\d{4}/.test(id)) h+='<span class="cmtag" style="color:var(--intel);background:var(--intel-dim);border-color:var(--intel-border)" data-tip="ATT&amp;CK Technique">'+esc(id)+'</span>';
      });
      if((q.mitre||[]).length>4)h+='<span class="cmtag-more">+'+(((q.mitre||[]).length-4))+'</span>';
    }
    if(hasTech){
      if(hasMitre)h+='<span class="card-meta-sep"></span>';
      techTags.slice(0,3).forEach(function(t){h+='<span class="cmtag" style="color:var(--intel);background:var(--intel-dim);border-color:var(--intel-border)" data-tip="ATT&amp;CK Technique">'+esc(t)+'</span>';});
      if(techTags.length>3)h+='<span class="cmtag-more">+'+(techTags.length-3)+'</span>';
    }
    if(vs.length)h+='<span class="card-var-ind">'+vs.length+' var</span>';
    h+='</div>';
  }

  // ── Footer: folder + tags + author ────────────────────
  h+='<div class="card-footer-row">';
  h+='<div class="card-ctags">';
  if(q.folder_id){
    var _cf=_folderMap[q.folder_id]; // P5
    if(_cf)h+='<span class="ctag">'+esc(_cf.icon||'')+(_cf.icon?' ':'')+esc(_cf.name)+'</span>';
  }
  (q.tags||[]).slice(0,3).forEach(function(t){h+='<span class="ctag">'+esc(t)+'</span>';});
  if((q.tags||[]).length>3)h+='<span class="ctag-more">+'+(q.tags.length-3)+'</span>';
  h+='</div>';
  h+='<span class="card-auth">'+esc(q.author_name)+'</span>';
  h+='</div>';

  h+='</div>';
  return h;
}

function renderQueryList(fq){
  var sevC={critical:'#ff2d55',high:'#ff6b35',medium:'#ffd60a',low:'#2dd4bf',info:'#6366f1'};
  var envColor={Defender:'#f59e0b',Sentinel:'#38bdf8',Both:'#a78bfa'};
  var h='<div class="qlist">';
  fq.forEach(function(q,idx){
    var sev=(q.severity||'info').toLowerCase();
    var sc=sevC[sev]||'var(--t5)';
    var env=q.environment||'Defender';
    var ec=envColor[env]||'var(--t5)';
    var ql=q.language||'KQL';
    var mitreSlice=(q.mitre||[]).slice(0,3);
    var _cs=S.compat[q.id];
    var _fpC=_cs==='compatible'?'var(--sev-low)':_cs==='partial'?'var(--sev-medium)':_cs==='incompatible'?'var(--sev-critical)':null;
    h+='<div class="qlist-row" data-qid="'+q.id+'" style="animation-delay:'+(idx*15)+'ms">';
    h+='<span class="ql-sev-dot" style="background:'+sc+'"></span>';
    h+='<div class="ql-body"><span class="ql-title">'+esc(q.title)+'</span>';
    if(q.description)h+='<span class="ql-desc">'+esc(q.description)+'</span>';
    h+='</div>';
    if(mitreSlice.length){
      h+='<div class="ql-tags">';
      mitreSlice.forEach(function(id){var m=_mitreMap[id];if(m)h+='<span class="ql-tag" style="color:'+m.c+';background:'+m.c+'18">'+esc(id)+'</span>';else h+='<span class="ql-tag">'+esc(id)+'</span>';});
      if((q.mitre||[]).length>3)h+='<span class="ql-tag-more">+'+(q.mitre.length-3)+'</span>';
      h+='</div>';
    }
    if(ql==='KQL')h+='<span class="ql-env" style="color:'+ec+';background:'+ec+'14">'+env+'</span>';
    if(_fpC)h+='<span class="fp-dot" style="background:'+_fpC+'" title="'+(_cs||'')+'"></span>';
    h+='<button class="card-star-btn'+(q.starred?' starred':'')+'" data-st="'+q.id+'">'+(q.starred?'★':'☆')+'</button>';
    h+='</div>';
  });
  h+='</div>';
  return h;
}

function renderQueryTable(fq){
  var sevC={critical:'#ff2d55',high:'#ff6b35',medium:'#ffd60a',low:'#2dd4bf',info:'#6366f1'};
  var envColor={Defender:'#f59e0b',Sentinel:'#38bdf8',Both:'#a78bfa'};
  var h='<div class="qtable-wrap"><table class="qtable"><thead><tr>';
  h+='<th style="width:10px"></th>';
  h+='<th>Title</th>';
  h+='<th style="width:96px">Platform</th>';
  h+='<th style="width:160px">MITRE</th>';
  h+='<th style="width:96px">Author</th>';
  h+='<th style="width:30px"></th>';
  h+='</tr></thead><tbody>';
  fq.forEach(function(q,idx){
    var sev=(q.severity||'info').toLowerCase();
    var sc=sevC[sev]||'var(--t5)';
    var env=q.environment||'Defender';
    var ec=envColor[env]||'var(--t5)';
    var ql=q.language||'KQL';
    var mitreSlice=(q.mitre||[]).slice(0,4);
    h+='<tr class="qtable-row" data-qid="'+q.id+'" style="animation-delay:'+(idx*12)+'ms">';
    h+='<td style="padding-right:0"><span class="ql-sev-dot" style="background:'+sc+'"></span></td>';
    h+='<td><span class="qt-title">'+esc(q.title)+'</span>';
    if(q.description)h+='<span class="qt-desc">'+esc(q.description)+'</span>';
    h+='</td>';
    h+='<td>';
    if(ql==='KQL')h+='<span class="ql-env" style="color:'+ec+';background:'+ec+'14">'+env+'</span>';
    else h+='<span class="ql-env" style="color:var(--t3);background:var(--bg-raised)">'+esc(ql)+'</span>';
    h+='</td>';
    h+='<td class="qt-mitre">';
    mitreSlice.forEach(function(id){var m=_mitreMap[id];if(m)h+='<span class="ql-tag" style="color:'+m.c+';background:'+m.c+'18">'+esc(id)+'</span>';else h+='<span class="ql-tag">'+esc(id)+'</span>';});
    if((q.mitre||[]).length>4)h+='<span class="ql-tag-more">+'+(q.mitre.length-4)+'</span>';
    h+='</td>';
    h+='<td class="qt-author">'+esc(q.author_name)+'</td>';
    h+='<td><button class="card-star-btn'+(q.starred?' starred':'')+'" data-st="'+q.id+'">'+(q.starred?'★':'☆')+'</button></td>';
    h+='</tr>';
  });
  h+='</tbody></table></div>';
  return h;
}


// ═══ WATCH VIEW ═══
var WATCH_SOURCE_COLORS  = { ws_bleeping:'#f97316', ws_hackernews:'#22c55e', ws_cisa_kev:'#dc2626', ws_msrc:'#3b82f6' };
var WATCH_SOURCE_DOMAINS = { ws_bleeping:'bleepingcomputer.com', ws_hackernews:'thehackernews.com', ws_cisa_kev:'cisa.gov', ws_msrc:'msrc.microsoft.com' };
var WATCH_SEV_COLORS = { critical:'var(--sev-critical)', high:'var(--sev-high)', medium:'var(--sev-medium)', low:'var(--sev-low)', info:'var(--sev-info)' };

function watchSourceColor(sid) {
  return WATCH_SOURCE_COLORS[sid] || '#6b7280';
}

function watchSourceName(sid) {
  var dyn = S.watchSources.find(function(s){ return s.id===sid; });
  if (dyn) return dyn.name;
  var names = { ws_bleeping:'BleepingComputer', ws_hackernews:'TheHackerNews', ws_cisa_kev:'CISA KEV', ws_msrc:'MSRC' };
  return names[sid] || sid;
}

function watchFaviconUrl(sid) {
  var domain = '';
  var dyn = S.watchSources.find(function(s){ return s.id===sid; });
  if (dyn && dyn.url) {
    try { domain = new URL(dyn.url).hostname; } catch(e) {}
  }
  if (!domain) domain = WATCH_SOURCE_DOMAINS[sid] || '';
  if (!domain) return '';
  return 'https://www.google.com/s2/favicons?domain=' + domain + '&sz=16';
}

function watchTimeAgo(dt) {
  if (!dt) return '';
  var diff = Date.now() - new Date(dt).getTime();
  var mins = Math.floor(diff / 60000);
  if (mins < 60) return mins + 'm ago';
  var hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  return Math.floor(hrs / 24) + 'd ago';
}

function renderWatchView() {
  var h = '';
  var ws = S.watchSummary || { unread_count:0, critical_count:0, total_matches:0, last_fetch_at:null };
  var f  = S.watchFilter;
  var wv = S.watchView || 'list';

  // ── Stats bar (horizontal) ───────────────────────────────
  h += '<div class="wa-statsbar">';

  // Unread counter
  var uActive = f.unread_only;
  h += '<div class="wa-statbar-item'+(uActive?' active':'')+'" id="btn-stat-unread" title="'+T('wv_unread_btn')+'">';
  h += '<div class="wa-statbar-lbl">'+T('unread_alerts')+'</div>';
  h += '<div class="wa-statbar-val wa-statbar-val--'+(ws.unread_count>0?'unread':'neutral')+'">'+ws.unread_count+'</div>';
  h += '</div>';

  // Critical counter
  var cActive = f.severity === 'critical';
  h += '<div class="wa-statbar-item'+(cActive?' active':'')+'" id="btn-stat-critical" title="'+T('critical_alerts')+'">';
  h += '<div class="wa-statbar-lbl">'+T('critical_alerts')+'</div>';
  h += '<div class="wa-statbar-val wa-statbar-val--'+(ws.critical_count>0?'critical':'neutral')+'">'+ws.critical_count+'</div>';
  h += '</div>';

  // Matched counter
  var mActive = f.matched_only;
  h += '<div class="wa-statbar-item'+(mActive?' active':'')+'" id="btn-stat-matched" title="'+T('matching_queries')+'">';
  h += '<div class="wa-statbar-lbl">'+T('matching_queries')+'</div>';
  h += '<div class="wa-statbar-val wa-statbar-val--'+(ws.total_matches>0?'matched':'neutral')+'">'+ws.total_matches+'</div>';
  h += '</div>';

  // Controls on right
  h += '<div class="wa-statbar-controls">';

  // Day selector
  h += '<div class="wa-filter-seg" style="flex-shrink:0">';
  [7,14,30].forEach(function(d) {
    h += '<button class="wa-seg-btn'+(f.days===d?' active':'')+'" data-wdays="'+d+'">'+d+'d</button>';
  });
  h += '</div>';

  // View toggle (icon + text label; padding:0 set in CSS to avoid global button padding collision)
  h += '<div class="wa-view-toggle">';
  h += '<button class="wa-vbtn'+(wv==='list'?' active':'')+'" id="btn-wv-list" title="List view" aria-label="List view">';
  h += '<svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="1" width="14" height="2" rx="1"/><rect x="0" y="6" width="14" height="2" rx="1"/><rect x="0" y="11" width="14" height="2" rx="1"/></svg>';
  h += '<span>List</span></button>';
  h += '<button class="wa-vbtn'+(wv==='compact'?' active':'')+'" id="btn-wv-compact" title="Compact view" aria-label="Compact view">';
  h += '<svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0.5" width="14" height="1.5" rx="0.75"/><rect x="0" y="3.5" width="14" height="1.5" rx="0.75"/><rect x="0" y="6.5" width="14" height="1.5" rx="0.75"/><rect x="0" y="9.5" width="14" height="1.5" rx="0.75"/><rect x="0" y="12.5" width="14" height="1.5" rx="0.75"/></svg>';
  h += '<span>Compact</span></button>';
  h += '<button class="wa-vbtn'+(wv==='mosaic'?' active':'')+'" id="btn-wv-mosaic" title="Vue mosaïque" aria-label="Vue mosaïque">';
  h += '<svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0" width="6" height="6" rx="1.5"/><rect x="8" y="0" width="6" height="6" rx="1.5"/><rect x="0" y="8" width="6" height="6" rx="1.5"/><rect x="8" y="8" width="6" height="6" rx="1.5"/></svg>';
  h += '<span>Mosa\u00efque</span></button>';
  h += '</div>';

  if (S.user && S.user.role === 'admin') {
    h += '<button id="btn-watch-sources" class="wa-btn-sec" title="'+T('watch_sources')+'">'+T('watch_sources')+'</button>';
    h += '<button id="btn-watch-refresh" class="pri wa-btn-refresh" title="'+T('refresh_feeds')+'">';
    h += '<svg class="wa-spin-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-6.22-8.56"/></svg>';
    h += T('refresh_feeds')+'</button>';
  }
  h += '</div>'; // end controls
  h += '</div>'; // end statsbar

  // ── Filter bar ───────────────────────────────────────────
  h += '<div class="wa-filter-bar">';

  // Source chips with favicons
  var _srcList = [{ id:'all', name:T('all_sources'), color:'var(--t3)', url:'' }];
  if (S.watchSources.length) {
    S.watchSources.forEach(function(s){ _srcList.push({ id:s.id, name:s.name, color:watchSourceColor(s.id), url:s.url||'' }); });
  } else {
    _srcList = _srcList.concat([
      {id:'ws_bleeping',   name:'BleepingComputer', color:'#f97316', url:'https://www.bleepingcomputer.com'},
      {id:'ws_hackernews', name:'TheHackerNews',    color:'#22c55e', url:'https://thehackernews.com'},
      {id:'ws_cisa_kev',   name:'CISA KEV',         color:'#dc2626', url:'https://cisa.gov'},
      {id:'ws_msrc',       name:'MSRC',             color:'#3b82f6', url:'https://msrc.microsoft.com'}
    ]);
  }
  h += '<div class="wa-filter-chips">';
  _srcList.forEach(function(src) {
    var on = f.source === src.id;
    var favUrl = src.id === 'all' ? '' : watchFaviconUrl(src.id);
    h += '<button class="wa-chip'+(on?' active':'')+'" data-wsrc="'+src.id+'"'+(on?' style="--chip-c:'+src.color+'"':'')+' title="'+esc(src.name)+'">';
    if (favUrl) h += '<img src="'+esc(favUrl)+'" width="14" height="14" style="border-radius:2px;flex-shrink:0" alt="" data-img-err="hide">';
    else h += '<span class="wa-chip-dot" style="background:'+src.color+'"></span>';
    h += esc(src.name)+'</button>';
  });
  h += '</div>';
  h += '<div class="wa-filter-sep"></div>';

  h += '<div class="wa-filter-chips">';
  ['critical','high','medium'].forEach(function(s) {
    var on = f.severity === s;
    var c = WATCH_SEV_COLORS[s];
    h += '<button class="wa-chip'+(on?' active':'')+'" data-wsev="'+s+'"'+(on?' style="--chip-c:'+c+'"':'')+'>'+
         '<span class="wa-chip-dot" style="background:'+c+'"></span>'+s+'</button>';
  });
  if (f.severity !== 'all') h += '<button class="wa-chip" data-wsev="all">\u00d7 sev</button>';
  h += '</div>';
  h += '<div class="wa-filter-sep"></div>';

  h += '<div class="wa-filter-chips">';
  h += '<button class="wa-chip'+(f.unread_only?' active':'')+'" id="btn-wf-unread"'+(f.unread_only?' style="--chip-c:#f97316"':'')+'>'+T('wv_unread_btn')+'</button>';
  h += '<button class="wa-chip'+(f.matched_only?' active':'')+'" id="btn-wf-matched"'+(f.matched_only?' style="--chip-c:#7c3aed"':'')+'>'+T('with_matches')+'</button>';
  if (ws.last_fetch_at) h += '<span class="wa-topbar-ts" style="margin-left:4px">'+T('last_fetched')+': '+watchTimeAgo(ws.last_fetch_at)+'</span>';
  h += '</div>';
  h += '</div>';

  // ── Loading skeleton ─────────────────────────────────────
  if (S.watchLoading) {
    h += '<div class="wa-list">';
    for (var si = 0; si < 5; si++) {
      h += '<div class="wa-card wa-skeleton" style="--i:'+si+'">';
      h += '<div class="wa-sk-row"><div class="wa-sk-pill"></div><div class="wa-sk-pill"></div><div class="wa-sk-line wa-sk-line--title"></div></div>';
      h += '<div class="wa-sk-line wa-sk-line--sm"></div>';
      h += '<div class="wa-sk-line wa-sk-line--xs"></div>';
      h += '</div>';
    }
    h += '</div>';
    return h;
  }

  // ── Empty state ──────────────────────────────────────────
  if (!S.watchArticles.length) {
    h += '<div class="wa-empty">';
    h += '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity=".35"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>';
    h += '<div class="wa-empty-txt">'+T('no_articles')+'</div>';
    h += '</div>';
    return h;
  }

  // ── Article views ────────────────────────────────────────
  if (wv === 'compact') h += renderWatchCompact();
  else if (wv === 'mosaic') h += renderWatchMosaic();
  else h += renderWatchList();

  return h;
}

// ── Render: List view ───────────────────────────────────────────────────────
function renderWatchList() {
  var h = '<div class="wa-list">';
  S.watchArticles.forEach(function(a, idx) {
    var srcColor = watchSourceColor(a.source_id);
    var srcName  = watchSourceName(a.source_id);
    var favUrl   = watchFaviconUrl(a.source_id);
    var kws  = []; try { kws  = JSON.parse(a.keywords || '[]'); } catch(e) {}
    var cves = []; try { cves = JSON.parse(a.cves     || '[]'); } catch(e) {}
    var isUnread = !a.is_read;
    var isCrit   = a.severity === 'critical';

    h += '<div class="wa-card watch-article'+(isUnread?' wa-card--unread':'')+(isCrit?' wa-card--crit':'')+'" data-waid="'+esc(a.id)+'" style="--i:'+idx+'">';
    h += '<div class="wa-card-layout">';
    if (a.image_url) {
      h += '<img class="wa-card-thumb" src="'+esc(a.image_url)+'" alt="" loading="lazy" data-img-err="removeParent">';
    }
    h += '<div class="wa-card-body">';
    h += '<div class="wa-card-head">';
    if (favUrl) h += '<img class="wa-src-fav" src="'+esc(favUrl)+'" alt="" width="16" height="16" style="border-radius:3px;flex-shrink:0" data-img-err="hide">';
    h += '<span class="wa-src-pill" style="--src-c:'+srcColor+'">'+esc(srcName)+'</span>';
    h += '<span class="wa-sev-pill wa-sev-'+esc(a.severity)+'">'+esc(a.severity)+'</span>';
    if (kws.length) kws.slice(0,2).forEach(function(k){ h += '<span class="wa-tag wa-tag-kw" style="font-size:10px;padding:1px 5px">'+esc(k)+'</span>'; });
    if (cves.length) cves.slice(0,1).forEach(function(c){ h += '<span class="wa-tag wa-tag-cve" style="font-size:10px;padding:1px 5px">'+esc(c)+'</span>'; });
    if (a.match_count > 0) h += '<span class="wa-match-pill">'+a.match_count+' queries</span>';
    h += '<span class="wa-card-time">'+watchTimeAgo(a.published_at)+'</span>';
    var _cardHref=safeHref(a.url);if(_cardHref)h+='<a class="wa-card-ext" href="'+esc(_cardHref)+'" target="_blank" rel="noopener noreferrer" title="'+T('read_full')+'"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>';
    h += '<button class="wa-card-read-btn watch-read-btn" data-waid="'+esc(a.id)+'" title="'+T('mark_read')+'" aria-label="'+T('mark_read')+'">';
    h += '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>';
    h += '</button>';
    h += '</div>';
    h += '<div class="wa-card-title'+(isUnread?' wa-card-title--unread':'')+'">'+esc(a.title)+'</div>';
    if (a.summary) h += '<div class="wa-card-desc">'+esc(a.summary)+'</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
  });
  h += '</div>';
  return h;
}

// ── Render: Compact view ────────────────────────────────────────────────────
function renderWatchCompact() {
  var h = '<div class="wa-compact-list">';
  S.watchArticles.forEach(function(a, idx) {
    var srcName  = watchSourceName(a.source_id);
    var favUrl   = watchFaviconUrl(a.source_id);
    var kws  = []; try { kws = JSON.parse(a.keywords || '[]'); } catch(e) {}
    var cves = []; try { cves= JSON.parse(a.cves     || '[]'); } catch(e) {}
    var isUnread = !a.is_read;
    var sevColor = WATCH_SEV_COLORS[a.severity] || 'var(--text-tertiary)';
    var titleAttr = esc((a.summary||'') + (kws.length?' | '+kws.join(', '):'') + (cves.length?' | '+cves.join(', '):''));

    h += '<div class="wa-compact-item'+(isUnread?' unread':'')+' watch-article" data-waid="'+esc(a.id)+'" title="'+titleAttr+'" style="--i:'+idx+'">';
    h += '<span class="wa-compact-dot" style="background:'+sevColor+'"></span>';
    if (favUrl) h += '<img class="wa-compact-fav" src="'+esc(favUrl)+'" alt="" data-img-err="hide">';
    h += '<span class="wa-compact-src">'+esc(srcName)+'</span>';
    h += '<span class="wa-compact-title">'+esc(a.title)+'</span>';
    h += '<span class="wa-compact-sev" style="color:'+sevColor+'">'+esc(a.severity)+'</span>';
    if (a.match_count > 0) h += '<span class="wa-compact-qcount">'+a.match_count+'q</span>';
    h += '<span class="wa-compact-time">'+watchTimeAgo(a.published_at)+'</span>';
    var _compactHref=safeHref(a.url);if(_compactHref)h+='<a class="wa-compact-ext" href="'+esc(_compactHref)+'" target="_blank" rel="noopener noreferrer" title="'+T('read_full')+'"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>';
    h += '<button class="wa-compact-read-btn watch-read-btn" data-waid="'+esc(a.id)+'" title="'+T('mark_read')+'" aria-label="'+T('mark_read')+'">';
    h += '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>';
    h += '</button>';
    h += '</div>';
  });
  h += '</div>';
  return h;
}

// ── Render: Table view ──────────────────────────────────────────────────────
function renderWatchMosaic() {
  var h = '<div class="wa-mosaic-grid">';
  S.watchArticles.forEach(function(a, idx) {
    var srcColor = watchSourceColor(a.source_id);
    var srcName  = watchSourceName(a.source_id);
    var favUrl   = watchFaviconUrl(a.source_id);
    var isUnread = !a.is_read;
    var isCrit   = a.severity === 'critical';
    var sevColor = WATCH_SEV_COLORS[a.severity] || 'var(--text-tertiary)';

    h += '<div class="wa-mosaic-card watch-article'+(isUnread?' wa-mosaic-card--unread':'')+(isCrit?' wa-mosaic-card--crit':'')+'" data-waid="'+esc(a.id)+'" style="--i:'+idx+(isUnread?';--sev-c:'+sevColor:'')+'">';

    // Image or gradient fallback
    if (a.image_url) {
      h += '<img class="wa-mosaic-img" src="'+esc(a.image_url)+'" alt="" loading="lazy" data-img-err="hideSibShow">';
      h += '<div class="wa-mosaic-img-fallback" style="display:none;background:linear-gradient(135deg,'+sevColor+'18,'+sevColor+'06)">';
      if (favUrl) h += '<img src="'+esc(favUrl)+'" width="28" height="28" style="border-radius:6px;opacity:.6" alt="" data-img-err="hide">';
      h += '</div>';
    } else {
      h += '<div class="wa-mosaic-img-fallback" style="background:linear-gradient(135deg,'+sevColor+'18,'+sevColor+'06)">';
      if (favUrl) h += '<img src="'+esc(favUrl)+'" width="28" height="28" style="border-radius:6px;opacity:.6" alt="" data-img-err="hide">';
      h += '</div>';
    }

    // Card body
    h += '<div class="wa-mosaic-body">';

    // Badges row
    h += '<div class="wa-mosaic-badges">';
    h += '<span class="wa-mosaic-sev" style="background:'+sevColor+'20;color:'+sevColor+';border:1px solid '+sevColor+'40">'+esc(a.severity.toUpperCase())+'</span>';
    h += '<span class="wa-mosaic-src">';
    if (favUrl) h += '<img src="'+esc(favUrl)+'" width="12" height="12" style="border-radius:2px;flex-shrink:0" alt="" data-img-err="hide">';
    h += '<span>'+esc(srcName)+'</span></span>';
    if (a.match_count > 0) h += '<span class="wa-mosaic-match" style="margin-left:auto">'+a.match_count+' q</span>';
    h += '</div>';

    // Title
    h += '<div class="wa-mosaic-title">'+esc(a.title)+'</div>';

    // Summary
    if (a.summary) h += '<div class="wa-mosaic-summary">'+esc(a.summary.slice(0, 120))+'</div>';

    // Footer
    h += '<div class="wa-mosaic-footer">';
    h += '<span class="wa-mosaic-time">'+watchTimeAgo(a.published_at)+'</span>';
    h += '<div class="wa-mosaic-actions">';
    var _mosaicHref=safeHref(a.url);if(_mosaicHref)h+='<a class="wa-mosaic-action-btn" href="'+esc(_mosaicHref)+'" target="_blank" rel="noopener noreferrer" title="'+T('read_full')+'"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>';
    h += '<button class="wa-mosaic-action-btn watch-read-btn" data-waid="'+esc(a.id)+'" title="'+T('mark_read')+'" aria-label="'+T('mark_read')+'"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg></button>';
    h += '</div>';
    h += '</div>'; // footer

    h += '</div>'; // body
    h += '</div>'; // card
  });
  h += '</div>';
  return h;
}

// ═══ WATCH SOURCES MODAL (redesigned) ═══
function renderWatchSourcesModal() {
  var h = '<div class="modal-overlay top" id="ov-wsrc">';
  h += '<div class="modal-box" style="max-width:680px">';
  h += '<div class="modal-header">';
  h += '<h2>'+T('watch_sources')+'</h2>';
  h += '<span id="cl-wsrc" class="close">\u00d7</span>';
  h += '</div>';
  h += '<div class="modal-body wsrc-modal-body">';

  // ── Section: Active sources ───────────────────────────────
  h += '<div class="wsrc-section-hdr">'+T('watch_sources')+'</div>';

  if (S.watchSources.length) {
    S.watchSources.forEach(function(src) {
      var favUrl = watchFaviconUrl(src.id);
      var hasError = src.last_error || (src.last_fetch_status && src.last_fetch_status.startsWith('error'));
      var statusColor = src.enabled ? (hasError ? 'var(--sev-high)' : '#22c55e') : 'var(--text-tertiary)';
      var metaText = '';
      if (hasError) metaText = T('error')+': '+esc(src.last_error || src.last_fetch_status || '?');
      else if (src.last_fetch_at) metaText = T('det_last_synced')+': '+watchTimeAgo(src.last_fetch_at);
      else metaText = T('never_synced');

      var typeLabel = { rss:'RSS', atom:'ATOM', rss_auto:'AUTO', msrc:'MSRC', json_cisa:'CISA', cisa_kev:'CISA' }[src.feed_type] || esc(src.feed_type).toUpperCase();

      // Inline edit form mode
      if (S.watchEditSrc === src.id) {
        h += '<div class="wsrc-edit-form">';
        h += '<div class="wsrc-edit-form-row">';
        h += '<input id="wsrc-edit-name" placeholder="Name" value="'+esc(src.name||'')+'" style="flex:2">';
        h += '<input id="wsrc-edit-url" placeholder="https://..." value="'+esc(src.url||'')+'" style="flex:3">';
        h += '<select id="wsrc-edit-type" style="flex:1;font-size:12px;padding:6px 8px;background:var(--bg-input);border:1px solid var(--border-medium);color:var(--text-primary);border-radius:6px">';
        [['rss','RSS'],['atom','Atom'],['rss_auto','Auto'],['msrc','MSRC'],['json_cisa','CISA']].forEach(function(o) {
          h += '<option value="'+o[0]+'"'+(src.feed_type===o[0]?' selected':'')+'>'+o[1]+'</option>';
        });
        h += '</select>';
        h += '</div>';
        h += '<div class="wsrc-edit-form-actions">';
        h += '<button data-wsrc-editcancel="'+esc(src.id)+'" style="font-size:12px;padding:5px 14px">'+T('cancel')+'</button>';
        h += '<button class="pri" data-wsrc-save="'+esc(src.id)+'" style="font-size:12px;padding:5px 14px">'+T('save')+'</button>';
        h += '</div>';
        h += '</div>';
        return;
      }

      h += '<div class="wsrc-source-row">';
      h += '<span class="wsrc-status-dot" style="background:'+statusColor+'" title="'+(src.enabled?'Enabled':'Disabled')+'"></span>';
      if (favUrl) h += '<img class="wsrc-favicon" src="'+esc(favUrl)+'" alt="" data-img-err="hide">';
      h += '<div class="wsrc-info">';
      h += '<div class="wsrc-name">'+esc(src.name)+'</div>';
      h += '<div class="wsrc-meta'+(hasError?' wsrc-meta-err':'')+'">'+metaText+'</div>';
      h += '</div>';
      h += '<span class="wsrc-type-pill">'+typeLabel+'</span>';
      h += '<div class="wsrc-actions">';
      h += '<button class="wsrc-toggle-btn" data-wsrc-toggle2="'+esc(src.id)+'" title="'+(src.enabled?'Disable':'Enable')+'">'+(src.enabled?'Disable':'Enable')+'</button>';
      h += '<button class="wsrc-edit-btn" data-wsrc-edit="'+esc(src.id)+'" title="Edit source">Edit</button>';
      h += '<button class="wsrc-del-btn" data-wsrc-del="'+esc(src.id)+'" title="'+T('wsrc_del')+'" aria-label="'+T('wsrc_del')+'">'+T('wsrc_del')+'</button>';
      h += '</div>';
      h += '</div>';
    });
  } else {
    h += '<div style="text-align:center;padding:20px;color:var(--t5);font-size:13px">'+T('wsrc_no_sources')+'</div>';
  }

  // ── Section: Add a source ─────────────────────────────────
  h += '<div style="border-top:1px solid var(--bd);padding-top:16px;margin-top:16px">';
  h += '<div class="wsrc-section-hdr">'+T('wsrc_add_title')+'</div>';

  // URL + Test row
  h += '<div style="display:flex;gap:8px;margin-bottom:10px">';
  h += '<input id="wsrc-url" placeholder="https://feeds.example.com/rss" style="flex:1" value="'+(S.watchTestResult&&S.watchTestResult._url?esc(S.watchTestResult._url):'')+'">';
  h += '<button id="btn-wsrc-test" style="flex-shrink:0;font-size:12px;padding:8px 14px;white-space:nowrap">'+T('wsrc_test_btn')+'</button>';
  h += '</div>';

  // Test result box
  if (S.watchTestResult) {
    var tr = S.watchTestResult;
    if (tr.loading) {
      h += '<div class="wsrc-test-result" style="color:var(--t4);font-size:13px">Testing feed…</div>';
    } else if (tr.ok) {
      h += '<div class="wsrc-test-result wsrc-test-result--ok">';
      h += '<div class="wsrc-test-status wsrc-test-status--ok">&#10003; Format détecté : '+esc((tr.format||'').toUpperCase())+' &middot; '+tr.count+' articles disponibles</div>';
      if (tr.finalUrl && tr.finalUrl !== tr._url) h += '<div style="font-size:11px;color:var(--t4);margin-top:3px">&#8594; '+esc(tr.finalUrl)+'</div>';
      if (tr.sample && tr.sample.length) {
        h += '<ul class="wsrc-test-sample">';
        tr.sample.forEach(function(s) {
          h += '<li><a href="'+esc(s.url)+'" target="_blank" rel="noopener noreferrer" title="'+esc(s.url)+'">'+esc(s.title.slice(0,80))+'</a> <span style="color:var(--t5)">('+(s.published_at?watchTimeAgo(s.published_at):'')+' )</span></li>';
        });
        h += '</ul>';
      }
      h += '</div>';
    } else {
      h += '<div class="wsrc-test-result wsrc-test-result--err">';
      h += '<div class="wsrc-test-status wsrc-test-status--err">&#10007; '+esc(tr.error||'Feed test failed')+'</div>';
      if (tr.hint) h += '<div style="font-size:11px;color:var(--t4);margin-top:3px">&#8594; '+esc(tr.hint)+'</div>';
      h += '</div>';
    }
  }

  // Name + type row
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">';
  h += '<div><label class="lbl">'+T('wsrc_name_lbl')+'</label>';
  h += '<input id="wsrc-name" placeholder="My Feed" value="'+(S.watchTestResult&&S.watchTestResult.feedTitle?esc(S.watchTestResult.feedTitle):'')+'">';
  h += '</div>';
  h += '<div><label class="lbl">'+T('feed_type')+'</label>';
  h += '<select id="wsrc-type" style="background:var(--bg);border:1px solid var(--bd);color:var(--t1);border-radius:6px;padding:8px 10px;width:100%;font-size:13px">';
  var ftSelected = S.watchTestResult && S.watchTestResult.format || 'rss';
  if (ftSelected === 'unknown') ftSelected = 'rss';
  [['rss','RSS 2.0'],['atom','Atom 1.0'],['rss_auto','Auto-detect'],['msrc','Microsoft MSRC'],['json_cisa','CISA KEV']].forEach(function(o) {
    h += '<option value="'+o[0]+'"'+(ftSelected===o[0]?' selected':'')+'>'+o[1]+'</option>';
  });
  h += '</select></div>';
  h += '</div>';

  // Popular feeds suggestions
  var _existingUrls = S.watchSources.map(function(s){ return s.url; });
  var _popularFeeds = [
    { name:'BleepingComputer',  url:'https://www.bleepingcomputer.com/feed/',                                         type:'rss'      },
    { name:'The Hacker News',   url:'https://feeds.feedburner.com/TheHackersNews',                                    type:'rss'      },
    { name:'Krebs on Security', url:'https://krebsonsecurity.com/feed/',                                              type:'rss'      },
    { name:'Dark Reading',      url:'https://www.darkreading.com/rss.xml',                                            type:'rss'      },
    { name:'SecurityWeek',      url:'https://www.securityweek.com/feed/',                                             type:'rss'      },
    { name:'SANS ISC',          url:'https://isc.sans.edu/rssfeed_full.xml',                                          type:'rss'      },
    { name:'Securelist',        url:'https://securelist.com/feed/',                                                   type:'rss'      },
    { name:'NCSC UK',           url:'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml',                 type:'rss'      },
    { name:'Microsoft MSRC',    url:'https://api.msrc.microsoft.com/update-guide/rss',                               type:'msrc'     },
    { name:'CISA KEV',          url:'https://www.cisa.gov/sites/default/feeds/known_exploited_vulnerabilities.json', type:'json_cisa'}
  ];
  var _available = _popularFeeds.filter(function(f){ return _existingUrls.indexOf(f.url) < 0; });
  h += '<details style="margin-bottom:12px"><summary class="wsrc-popular-summary">&#9776; Sources populaires '+'('+_available.length+' disponibles)</summary>';
  if (!_available.length) {
    h += '<div style="padding:8px 0;font-size:12px;color:var(--t5)">'+T('watch_all_popular_added')+'</div>';
  } else {
    h += '<div class="wsrc-popular-list">';
    _available.forEach(function(f) {
      var favDomain = ''; try { favDomain = new URL(f.url).hostname; } catch(e) {}
      var favSrc = favDomain ? 'https://www.google.com/s2/favicons?sz=32&domain='+favDomain : '';
      var typeLabel = { rss:'RSS', atom:'ATOM', msrc:'MSRC', json_cisa:'CISA' }[f.type] || f.type.toUpperCase();
      h += '<div class="wsrc-popular-row" data-suggest-url="'+esc(f.url)+'" data-suggest-name="'+esc(f.name)+'" data-suggest-type="'+esc(f.type)+'" title="'+esc(f.url)+'">';
      if (favSrc) h += '<img class="wsrc-popular-fav" src="'+esc(favSrc)+'" alt="" data-img-err="hide">';
      else h += '<span class="wsrc-popular-fav-fallback"></span>';
      h += '<span class="wsrc-popular-name">'+esc(f.name)+'</span>';
      h += '<span class="wsrc-popular-type">'+typeLabel+'</span>';
      h += '<button class="wsrc-popular-add-btn">+ Ajouter</button>';
      h += '</div>';
    });
    h += '</div>';
  }
  h += '</details>';

  h += '<div style="display:flex;justify-content:flex-end;gap:8px">';
  h += '<button id="btn-wsrc-cancel" style="font-size:13px;padding:8px 16px">'+T('cancel')+'</button>';
  h += '<button class="pri" id="btn-wsrc-add" style="font-size:13px;padding:8px 18px">'+T('wsrc_add_save')+'</button>';
  h += '</div>';
  h += '</div>'; // end add section

  h += '</div></div></div>';
  return h;
}

// ═══ WATCH SLIDE-IN ═══
function renderWatchSlidein(article) {
  var isOpen = !!article;
  document.body.style.overflow = isOpen ? 'hidden' : '';

  var h = '<div class="ws-overlay'+(isOpen?' open':'')+'" id="ov-watch-detail"></div>';
  h += '<div class="ws-panel'+(isOpen?' open':'')+'" id="watch-slidein-panel" role="dialog" aria-modal="true">';

  if (!isOpen) { h += '</div>'; return h; }

  var srcColor = watchSourceColor(article.source_id);
  var srcName  = watchSourceName(article.source_id);
  var kws  = []; try { kws  = JSON.parse(article.keywords || '[]'); } catch(e) {}
  var cves = []; try { cves = JSON.parse(article.cves     || '[]'); } catch(e) {}
  var prods= []; try { prods= JSON.parse(article.products || '[]'); } catch(e) {}
  var matches = article.matches || [];
  var favUrl = watchFaviconUrl(article.source_id);
  var domain = '';
  try { domain = article.url ? new URL(article.url).hostname : ''; } catch(e) {}

  // ── Fixed header ─────────────────────────────────────────
  h += '<div class="ws-header">';
  h += '<div class="ws-header-left">';
  if (favUrl) h += '<img src="'+esc(favUrl)+'" width="16" height="16" alt="" class="ws-fav" data-img-err="hide">';
  h += '<span class="ws-src-name" style="--src-c:'+srcColor+'">'+esc(srcName)+'</span>';
  h += '<span class="ws-sev-pill ws-sev-'+esc(article.severity)+'">'+esc(article.severity)+'</span>';
  h += '</div>';
  h += '<div class="ws-header-right">';
  h += '<button id="btn-watch-dismiss" data-waid="'+esc(article.id)+'" class="ws-dismiss-btn">'+T('ws_dismiss')+'</button>';
  var _artHref=safeHref(article.url);if(_artHref)h+='<a href="'+esc(_artHref)+'" target="_blank" rel="noopener noreferrer" class="ws-read-btn">'+T('ws_read_article')+'</a>';
  h += '<button id="cl-watch-detail" class="ws-close" title="'+T('ws_close')+'" aria-label="'+T('ws_close')+'">\u00d7</button>';
  h += '</div>';
  h += '</div>';

  // ── Scrollable body ──────────────────────────────────────
  h += '<div class="ws-body">';

  if (article.image_url) {
    h += '<img class="ws-og-img" src="'+esc(article.image_url)+'" alt="" loading="lazy" data-img-err="hide">';
  }

  h += '<div class="ws-content">';
  h += '<h2 class="ws-title">'+esc(article.title)+'</h2>';
  h += '<div class="ws-meta">';
  h += '<span class="ws-ts">'+watchTimeAgo(article.published_at)+'</span>';
  if (domain) h += '<span class="ws-sep">&middot;</span><span class="ws-domain">'+esc(domain)+'</span>';
  h += '</div>';

  if (article.summary) {
    h += '<p class="ws-summary">'+esc(article.summary)+'</p>';
  }

  // CVE chips
  if (cves.length) {
    h += '<div class="ws-chips-row">';
    cves.forEach(function(c) {
      h += '<a class="ws-chip ws-chip-cve" href="https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(c)+'" target="_blank" rel="noopener noreferrer">'+esc(c)+'</a>';
    });
    h += '</div>';
  }

  // Keyword chips
  if (kws.length) {
    h += '<div class="ws-section-label">'+T('extracted_keywords')+'</div>';
    h += '<div class="ws-chips-row">';
    kws.forEach(function(k){ h += '<span class="ws-chip ws-chip-kw">'+esc(k)+'</span>'; });
    h += '</div>';
  }

  // Product chips
  if (prods.length) {
    h += '<div class="ws-section-label">'+T('wdet_products')+'</div>';
    h += '<div class="ws-chips-row">';
    prods.forEach(function(p){ h += '<span class="ws-chip ws-chip-prod">'+esc(p)+'</span>'; });
    h += '</div>';
  }

  // ── Matching queries ─────────────────────────────────────
  h += '<div class="ws-matches-section">';
  h += '<div class="ws-section-label">'+T('matching_queries')+(matches.length?' ('+matches.length+')':'')+'</div>';

  if (matches.length) {
    var envC = { Defender:'#f59e0b', Sentinel:'#38bdf8', Both:'#a78bfa' };
    matches.slice(0, 5).forEach(function(m) {
      var mReasons=[]; try{mReasons=JSON.parse(m.match_reasons||'[]');}catch(e){}
      var sc = m.match_score || 0;
      var barColor = sc < 30 ? 'var(--t5)' : sc < 60 ? '#eab308' : '#22c55e';
      h += '<div class="ws-match-row" data-wq-open="'+esc(m.id)+'">';
      h += '<div class="ws-match-top">';
      h += '<span class="cb-sev cb-sev-'+esc(m.severity)+'"><span class="cb-dot"></span>'+esc(m.severity)+'</span>';
      h += '<span class="ws-match-lang">'+(m.language||'KQL')+'</span>';
      if (m.environment) {
        var ec=envC[m.environment]||'var(--t4)';
        h += '<span class="ws-match-env" style="color:'+ec+';background:'+ec+'14;border-color:'+ec+'25">'+esc(m.environment)+'</span>';
      }
      h += '<span class="ws-match-title">'+esc(m.title)+'</span>';
      h += '<span class="ws-match-score">'+sc+'</span>';
      h += '</div>';
      h += '<div class="ws-score-track"><div class="ws-score-fill" style="width:'+sc+'%;background:'+barColor+'"></div></div>';
      if (mReasons.length) {
        h += '<div class="ws-reasons">';
        mReasons.forEach(function(r){
          var rp=r.split(':'); var rtype=rp[0];
          var rColor=rtype==='cve'?'#fca5a5':rtype==='tag'?'#c4b5fd':rtype==='kql'?'#93c5fd':rtype==='env'?'#86efac':'var(--t4)';
          var rBg=rtype==='cve'?'#7f1d1d18':rtype==='tag'?'#7c3aed18':rtype==='kql'?'#1d4ed818':rtype==='env'?'#14532d18':'var(--s3)';
          h += '<span class="ws-reason-chip" style="color:'+rColor+';background:'+rBg+'">'+esc(r)+'</span>';
        });
        h += '</div>';
      }
      h += '</div>';
    });
    if (matches.length > 5) {
      h += '<button class="ws-viewall-btn" id="btn-wsi-viewall">'+T('with_matches')+' ('+matches.length+') \u2192</button>';
    }
  } else {
    h += '<div class="ws-empty-state">';
    h += '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v3M11 14h.01"/></svg>';
    h += '<div class="ws-empty-title">'+T('ws_no_matches')+'</div>';
    h += '<div class="ws-empty-sub">'+T('ws_no_matches_sub')+'</div>';
    h += '</div>';
  }

  h += '</div>'; // end ws-matches-section
  h += '</div>'; // end ws-content
  h += '</div>'; // end ws-body
  h += '</div>'; // end ws-panel
  return h;
}

// Render a single tag badge — CVE tags become clickable red NVD links.
function renderTagBadge(t) {
  var isCVE = /^CVE-\d{4}-\d{4,7}$/i.test(t);
  if (isCVE) {
    var nvdUrl = 'https://nvd.nist.gov/vuln/detail/' + t.toUpperCase();
    return '<a href="'+nvdUrl+'" target="_blank" rel="noopener noreferrer" class="det-tag det-tag-cve" title="View '+esc(t)+' on NVD">'+esc(t.toUpperCase())+' \u2197</a>';
  }
  return '<span class="det-tag">'+esc(t)+'</span>';
}

// Render repo-parsed hyperlinks above the comments section.
function renderRepoRefs(refs) {
  if (!refs || !refs.length) return '';
  var h = '<div class="repo-refs-block">';
  h += '<div class="repo-refs-label">RÉFÉRENCES</div>';
  refs.forEach(function(r) {
    var url = r.url || '';
    var note = r.note || '';
    var display;
    try { var u = new URL(url); display = (u.hostname + u.pathname).replace(/\/$/, '').slice(0, 60); } catch(e) { display = url.slice(0, 60); }
    if (display.length === 60) display += '…';
    h += '<div class="repo-ref-row">';
    if (note) h += '<span class="repo-ref-note">' + esc(note) + '</span>';
    h += '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer" class="repo-ref-url" title="' + esc(url) + '">' + esc(display) + ' \u2197</a>';
    h += '</div>';
  });
  h += '</div>';
  return h;
}

// Render the CVE references block shown above the comments section.
function renderCVERefs(cves) {
  if (!cves || !cves.length) return '';
  var h = '<div class="cve-refs-block">';
  h += '<div class="cve-refs-label">CVEs R\u00c9F\u00c9RENC\u00c9S</div>';
  cves.forEach(function(cve) {
    var nvd   = 'https://nvd.nist.gov/vuln/detail/' + cve.toUpperCase();
    var mitre = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve.toUpperCase();
    h += '<div class="cve-ref-row">';
    h += '<span class="cve-ref-id">'+esc(cve.toUpperCase())+'</span>';
    h += '<div class="cve-ref-links">';
    h += '<a href="'+nvd+'"   target="_blank" rel="noopener" class="cve-ref-link">NVD \u2197</a>';
    h += '<a href="'+mitre+'" target="_blank" rel="noopener" class="cve-ref-link">MITRE \u2197</a>';
    h += '</div></div>';
  });
  h += '</div>';
  return h;
}

function renderDetail(q){
  var vs=detectVars(q.kql);
  var env=q.environment||"Defender";
  var ec=env==="Defender"?"env-defender":(env==="Sentinel"?"env-sentinel":"env-both");
  var ql=q.language||"KQL";
  var sevC={critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'};
  var sc=sevC[q.severity]||'var(--t4)';
  var langDef=_langMap[ql]||LANGUAGES[0]; // P6
  var _cmts=S.comments[q.id];
  var isWriter=S.user.role!=='viewer';
  var canDel=q.author_id===S.user.id||S.user.role==='admin';

  // Slide panel structure
  var h='<div class="detail-backdrop" id="ov-d"></div>';
  h+='<div class="detail-panel'+(S.detailFullscreen?' detail-panel--fullscreen':'')+'">';

  // ── Panel header ─────────────────────────────────────────────────
  h+='<div class="det-header" style="background:var(--s2)">';
  h+='<div style="display:flex;align-items:center;gap:6px;flex-shrink:0">';
  h+='<span class="cb-sev cb-sev-'+q.severity+'"><span class="cb-dot"></span>'+q.severity+'</span>';
  h+='<span class="cb-lang" style="color:'+langDef.color+';background:'+langDef.color+'14;border-color:'+langDef.color+'30">'+langDef.logo+'<span>'+langDef.name+'</span></span>';
  if(ql==="KQL"){var _ec={Defender:'#f59e0b',Sentinel:'#38bdf8',Both:'#a78bfa'};var _ecc=_ec[env]||'var(--t4)';h+='<span class="cb-env" style="color:'+_ecc+';background:'+_ecc+'14">'+env+'</span>';}
  h+='</div>';
  h+='<h2 style="font-size:15px;font-weight:700;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:0 8px">'+esc(q.title)+'</h2>';
  h+='<div style="display:flex;gap:5px;flex-shrink:0">';
  h+='<button id="btn-e1" style="font-size:12px;padding:5px 10px">'+T('det_export_btn')+'</button>';
  h+='<button id="btn-export-pdf" style="font-size:12px;padding:5px 10px" title="Export as PDF reference sheet">PDF</button>';
  if(isWriter)h+='<button id="btn-ed-q" style="font-size:12px;padding:5px 10px;font-weight:600">'+T('det_edit_btn')+'</button>';
  if(isWriter&&canDel)h+='<button id="btn-del-q" style="font-size:12px;padding:5px 10px;color:var(--red);border-color:var(--red3)">'+T('det_delete_btn')+'</button>';
  var _fsIcon=S.detailFullscreen
    ?'<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4.5 1H1v3.5M7.5 1H11v3.5M4.5 11H1V7.5M7.5 11H11V7.5"/></svg>'
    :'<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M1 4.5V1h3.5M11 4.5V1H7.5M1 7.5V11h3.5M11 7.5V11H7.5"/></svg>';
  h+='<button class="btn-det-expand" id="btn-det-expand" title="'+(S.detailFullscreen?'Exit fullscreen':'Fullscreen')+'">'+_fsIcon+'</button>';
  h+='<button id="cl-d" class="close" style="font-size:20px">\u00d7</button>';
  h+='</div></div>';
  // Sub-header: meta info
  h+='<div style="padding:8px 18px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;flex-wrap:wrap;flex-shrink:0;background:var(--bg)">';
  h+='<span style="font-size:12px;color:var(--t4)">'+esc(q.author_name)+' <span style="color:var(--t5)">·</span> '+(q.updated_at||"").slice(0,10)+'</span>';
  if(q.playbook)h+='<span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t5)">'+esc(q.playbook)+'</span>';
  if(q.folder_id){var _df=_folderMap[q.folder_id];if(_df)h+='<span class="det-tag" style="font-size:11px;padding:2px 9px;cursor:default">'+esc(_df.icon||'')+(_df.icon?' ':'')+esc(_df.name)+'</span>';} // P6
  h+='<select id="move-folder" style="padding:3px 7px;font-size:11px;background:var(--bg);border:1px solid var(--bd);color:var(--t3);border-radius:4px;margin-left:auto"><option value="">'+T('det_move_to')+'</option>';
  S.folders.forEach(function(f){h+='<option value="'+f.id+'"'+(q.folder_id===f.id?' selected':'')+'>'+esc(f.icon)+' '+esc(f.name)+'</option>';});
  h+='<option value="__none">'+T('det_no_folder')+'</option></select>';
  h+='</div>';

  // ── Scrollable body ──────────────────────────────────────────────
  h+='<div class="det-scroll" style="padding:18px 20px">';

  // Description
  if(q.description)h+='<p style="font-size:13px;color:var(--t2);line-height:1.7;margin:0 0 20px;white-space:pre-wrap">'+esc(q.description)+'</p>';

  // Variables resolver
  if(vs.length){
    h+='<div style="background:#0d0a0a;border:1px solid var(--red3);border-radius:10px;padding:16px;margin-bottom:18px">';
    var _vFilled=vs.filter(function(v){return !!(S.globalVars[v.id]&&S.globalVars[v.id].trim());}).length;
    h+='<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">';
    h+='<div style="font-size:13px;font-weight:700;color:#ef4444">\u2699 '+T('det_vars_title')+'</div>';
    h+='<div style="font-size:11px;color:'+(_vFilled===vs.length?'#22c55e':'#fbbf24')+'">'+_vFilled+' / '+vs.length+'</div>';
    h+='</div>';
    h+='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px">';
    vs.forEach(function(v){
      h+='<div style="display:flex;align-items:center;gap:8px">';
      h+='<code style="font-size:11px;color:#ef4444;background:#7f1d1d;padding:3px 8px;border-radius:4px;font-family:var(--mono);border:1px solid #991b1b;min-width:95px;text-align:center">'+v.key+'</code>';
      h+='<span style="font-size:12px;color:var(--t4);min-width:50px">'+esc(v.lbl)+'</span>';
      if(v.tp==="s"){h+='<select data-vid="'+v.id+'" style="flex:1;padding:8px;font-size:13px;background:var(--s1);border:1px solid var(--bd);color:var(--t1);border-radius:6px"><option value="">...</option>';v.opts.forEach(function(o){h+='<option value="'+o+'"'+((S.globalVars[v.id]||'')=== o?' selected':'')+'>'+o+'</option>';});h+='</select>';}
      else{h+='<input data-vid="'+v.id+'" type="'+(v.tp==="n"?"number":"text")+'" value="'+esc(S.globalVars[v.id]||'')+'" placeholder="'+v.ph+'" style="flex:1;padding:8px;font-size:13px;font-family:var(--mono);background:var(--s1);border:1px solid var(--bd);color:var(--t1);border-radius:6px">';}
      h+='</div>';
    });
    h+='</div>';
    h+='<div id="vw" style="margin-top:10px;font-size:12px;color:#fbbf24">'+T('det_var_not_filled',{n:vs.length})+'</div>';
    h+='</div>';
  }

  // KQL code block
  h+='<div style="margin-bottom:22px">';
  h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
  h+='<span class="lbl" style="margin:0" id="kl">'+T('det_query_lbl',{lang:ql})+'</span>';
  h+='<button class="pri" id="btn-cp" style="padding:7px 18px;font-size:13px;font-weight:700">'+T('det_copy_lang',{lang:ql})+'</button>';
  h+='</div>';
  h+='<pre class="kql" id="ko">'+esc(q.kql)+'</pre>';
  h+='<div id="monaco-detail-container" style="display:none;border:1px solid var(--bd);border-radius:8px;overflow:hidden;min-height:100px"></div>';
  h+='</div>';

  // ── Compatibility section ─────────────────────────────────────────
  var _cst=S.compat[q.id];
  if(_cst&&_cst!=='unknown'){
    var _cstC=_cst==='compatible'?'#22c55e':_cst==='partial'?'#f59e0b':'#ef4444';
    var _cstL=_cst==='compatible'?T('compatible'):_cst==='partial'?T('partial_compat'):T('incompatible');
    var _det=S.compatDetail[q.id];
    h+='<div style="margin-bottom:22px;padding:14px 16px;background:var(--s2);border:1px solid var(--bd);border-radius:10px">';
    h+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">';
    h+='<span style="width:8px;height:8px;border-radius:50%;background:'+_cstC+';flex-shrink:0"></span>';
    h+='<span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t4)">'+T('env_check')+'</span>';
    h+='<span style="font-size:12px;font-weight:700;color:'+_cstC+';margin-left:4px">'+_cstL+'</span>';
    h+='<span style="margin-left:auto;font-size:11px;cursor:pointer;color:var(--blue);background:none;border:none;padding:0" id="btn-open-env">'+T('configure_env')+' ›</span>';
    h+='</div>';
    if(_det===undefined){
      h+='<div style="font-size:12px;color:var(--t5)">'+T('loading')+'</div>';
    }else if(_det===null){
      h+='<div style="font-size:12px;color:var(--t5)">No detail available.</div>';
    }else{
      var _allT=(_det.tables_ok||[]).concat(_det.tables_missing||[]);
      if(_allT.length){
        h+='<div style="display:flex;flex-wrap:wrap;gap:5px">';
        _allT.forEach(function(t){
          var tName=typeof t==='string'?t:(t.table||t);
          var tStatus=typeof t==='object'?t.status:'ok';
          var tDetail=typeof t==='object'?t.detail:'';
          var sc2=tStatus==='ok'?'#22c55e':tStatus==='missing_license'?'#f97316':tStatus==='missing_connector'?'#f59e0b':'#ef4444';
          var sl=tStatus==='ok'?'\u2713':tStatus==='missing_license'?T('missing_license'):tStatus==='missing_connector'?T('missing_connector'):T('wrong_platform');
          h+='<span class="det-tag" style="color:'+sc2+';background:'+sc2+'13;border-color:'+sc2+'28" data-tip="'+esc(tName+(tDetail?' \u2014 '+tDetail:''))+'">'+esc(tName)+'<span style="font-size:9px;margin-left:4px;opacity:.8">'+esc(sl)+'</span></span>';
        });
        h+='</div>';
      }else if(_cst==='compatible'){
        h+='<div style="font-size:12px;color:var(--t5)">No known tables detected \u2014 assumed compatible.</div>';
      }
    }
    h+='</div>';
  }else{
    h+='<div style="margin-bottom:22px;padding:12px 14px;background:var(--s2);border:1px solid var(--bd);border-radius:10px;display:flex;align-items:center;gap:8px">';
    h+='<span style="width:8px;height:8px;border-radius:50%;background:var(--t5);flex-shrink:0"></span>';
    h+='<span style="font-size:12px;color:var(--t5)">'+(_cst==='unknown'?T('unknown_compat')+' (SPL/ELK)':T('no_env_profile'))+'</span>';
    h+='<button id="btn-open-env" style="margin-left:auto;font-size:12px;color:var(--blue);background:none;border:none;cursor:pointer;padding:0">'+T('configure_env')+' ›</button>';
    h+='</div>';
  }

  // ── Source (repo) section ────────────────────────────────────────
  var _rqmD=S.repoQueryMap&&S.repoQueryMap[q.id];
  if(_rqmD){
    var _ghUrl='https://github.com/'+esc(_rqmD.github_owner)+'/'+esc(_rqmD.github_repo)+'/blob/HEAD/'+esc(_rqmD.file_path||'');
    h+='<div style="margin-bottom:22px;padding:14px 16px;background:var(--s2);border:1px solid var(--bd);border-radius:10px">';
    h+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">';
    h+='<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor" style="color:var(--t4)"><path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.341-3.369-1.341-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0 1 12 6.836c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/></svg>';
    h+='<span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t4)">'+T('imported_from')+'</span>';
    h+='<span style="font-size:12px;font-weight:600;color:#6e40c9">'+esc(_rqmD.repo_name||'')+'</span>';
    if(_rqmD.local_modified)h+='<span style="font-size:10px;padding:2px 7px;border-radius:3px;background:#f59e0b1a;color:#f59e0b;border:1px solid #f59e0b40;font-weight:700">'+T('locally_modified')+'</span>';
    h+='</div>';
    h+='<div style="font-size:12px;color:var(--t4);margin-bottom:4px"><a href="'+_ghUrl+'" target="_blank" rel="noopener noreferrer" style="color:#60a5fa;text-decoration:none;word-break:break-all">'+esc(_rqmD.file_path||'')+'</a></div>';
    h+='<div style="font-size:11px;color:var(--t5)">'+T('det_last_synced')+': '+esc((_rqmD.last_synced_at||'').slice(0,10))+'</div>';
    if(S.user.role==='admin')h+='<button data-reset-upstream="'+q.id+'" style="margin-top:10px;font-size:12px;color:#f59e0b;border-color:#f59e0b40;padding:4px 10px">'+T('reset_upstream')+'</button>';
    h+='</div>';
  }

  // ── Metadata panel ───────────────────────────────────────────────
  h+='<div class="det-meta-panel">';
  // MITRE ATT&CK
  h+='<div class="det-meta-sec">';
  h+='<div class="det-meta-lbl"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>MITRE ATT&CK</div>';
  h+='<div class="det-meta-items">';
  if((q.mitre||[]).length){
    q.mitre.forEach(function(id){
      var m=_mitreMap[id]; // P6
      if(m) h+='<span class="det-mtag" style="color:'+m.c+';background:'+m.c+'13;border-color:'+m.c+'28"><span class="det-mtag-id">'+m.id+'</span><span class="det-mtag-name">'+esc(m.n)+'</span></span>';
      else if(/^T\d{4}/.test(id)) h+='<span class="det-mtag" style="color:#6e40c9;background:#6e40c913;border-color:#6e40c928"><span class="det-mtag-id">'+esc(id)+'</span></span>';
    });
  }else{h+='<span class="det-meta-empty">—</span>';}
  h+='</div></div>';
  // Tags
  h+='<div class="det-meta-sec">';
  h+='<div class="det-meta-lbl"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 01-2.83 0L2 12V2h10l8.59 8.59a2 2 0 010 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>Tags</div>';
  h+='<div class="det-meta-items">';
  if((q.tags||[]).length){
    (q.tags||[]).forEach(function(t){h+=renderTagBadge(t);});
  }else{h+='<span class="det-meta-empty">—</span>';}
  h+='</div></div>';
  // Folder
  if(q.folder_id){var _fmeta=_folderMap[q.folder_id];if(_fmeta){ // P6
    h+='<div class="det-meta-sec">';
    h+='<div class="det-meta-lbl"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>'+T('lbl_folder')+'</div>';
    h+='<div class="det-meta-items"><span class="det-tag det-tag-folder">'+esc(_fmeta.icon||'')+(_fmeta.icon?' ':'')+esc(_fmeta.name)+'</span></div>';
    h+='</div>';
  }}
  h+='</div>'; // end meta panel

  // CVE references block (auto-generated from CVE tags)
  var _cves=(q.tags||[]).filter(function(t){return /^CVE-\d{4}-\d{4,7}$/i.test(t);});
  if(_cves.length) h+=renderCVERefs(_cves);

  // Repo-parsed references (URLs extracted from GitHub Markdown)
  var _prefs=[];try{_prefs=JSON.parse(q.parsed_references||'[]');}catch(e){}
  if(_prefs.length) h+=renderRepoRefs(_prefs);

  // Comments
  h+='<div style="border-top:1px solid var(--bd);padding-top:18px">';
  h+='<div class="lbl" style="margin-bottom:12px">'+T('det_comments_title')+'</div>';
  if(_cmts===undefined){h+='<div style="font-size:13px;color:var(--t5);padding:8px 0">'+T('det_loading_comments')+'</div>';}
  else if(!_cmts.length){h+='<div style="font-size:13px;color:var(--t5);margin-bottom:12px">'+T('det_no_comments')+'</div>';}
  else{_cmts.forEach(function(c){
    h+='<div data-cmt-container="'+c.id+'" style="display:flex;gap:10px;padding:12px 0;border-bottom:1px solid '+sc+'18">';
    h+=c.author_avatar?'<img src="'+esc(c.author_avatar)+'" style="width:30px;height:30px;border-radius:50%;object-fit:cover;flex-shrink:0;border:1px solid var(--bd)">':'<div style="width:30px;height:30px;border-radius:50%;background:var(--red3);border:1px solid var(--red);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fca5a5;flex-shrink:0">'+esc((c.author_name||"?")[0].toUpperCase())+'</div>';
    h+='<div style="flex:1;min-width:0">';
    h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">';
    h+='<span style="font-size:12px;font-weight:600;color:var(--t2)">'+esc(c.author_name)+'</span>';
    h+='<div style="display:flex;align-items:center;gap:8px"><span style="font-size:11px;color:var(--t5)">'+(c.created_at||"").slice(0,10)+'</span>';
    if(c.user_id===S.user.id)h+='<button data-ecmt="'+c.id+'" style="font-size:12px;color:var(--t4);background:none;border:none;cursor:pointer;padding:2px 5px;border-radius:4px" title="'+T('det_edit_btn')+'">\u270e</button>';
    if(c.user_id===S.user.id||S.user.role==='admin')h+='<button data-dcmt="'+c.id+'" style="font-size:13px;color:var(--t4);background:none;border:none;cursor:pointer;padding:2px 4px;border-radius:4px" title="'+T('det_delete_btn')+'">\u00d7</button>';
    h+='</div></div>';
    h+='<div style="font-size:13px;color:var(--t2);line-height:1.5;word-break:break-word">'+esc(c.content)+'</div>';
    if(c.url)h+='<a href="'+esc(c.url)+'" target="_blank" rel="noopener noreferrer" style="font-size:12px;color:#60a5fa;display:inline-flex;align-items:center;gap:4px;text-decoration:none;margin-top:4px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\ud83d\udd17 '+esc(c.url.replace(/^https?:\/\//,'').slice(0,60))+(c.url.replace(/^https?:\/\//,'').length>60?'\u2026':'')+'</a>';
    h+='</div></div>';
  });}
  if(isWriter){
    h+='<div style="display:flex;flex-direction:column;gap:6px;margin-top:14px">';
    h+='<textarea id="cmt-txt" rows="2" placeholder="'+T('det_cmt_placeholder')+'" style="font-family:var(--sans);font-size:13px;resize:vertical"></textarea>';
    h+='<input id="cmt-url" placeholder="'+T('det_cmt_url')+'" style="font-size:13px">';
    h+='<div style="display:flex;justify-content:flex-end;margin-top:2px"><button class="pri" id="btn-add-cmt" style="padding:7px 16px;font-size:13px">'+T('det_cmt_add')+'</button></div>';
    h+='</div>';
  }
  h+='</div>'; // end comments

  h+='</div>'; // end det-scroll

  // Footer
  h+='<div class="det-footer">';
  h+='<button id="cl-d2">'+T('close')+'</button>';
  h+='</div>';

  h+='</div>'; // end detail-panel
  return h;
}

function _buildMitrePicker(selected) {
  var h = '<div style="border:1px solid var(--bd);border-radius:8px;overflow:hidden">';
  MITRE.forEach(function(tactic) {
    var techniques = _tacticTechniques[tactic.id] || [];
    var topLevel = techniques.filter(function(t) { return !t.p; });
    var tacticOn = selected.indexOf(tactic.id) >= 0;
    var tacticHasSel = !tacticOn && techniques.some(function(t) { return selected.indexOf(t.id) >= 0; });
    h += '<div style="border-bottom:1px solid var(--bd)">';
    // Tactic header row
    h += '<div style="display:flex;align-items:center;gap:6px;padding:5px 8px;background:' + (tacticOn ? tactic.c + '18' : 'var(--s2)') + '">';
    h += '<button class="tchip" data-cm="' + tactic.id + '" style="font-size:10px;flex-shrink:0;' + (tacticOn ? 'background:' + tactic.c + '25;color:' + tactic.c + ';border-color:' + tactic.c + '50' : '') + '">' + tactic.id + '</button>';
    h += '<span style="font-size:11px;font-weight:600;color:' + (tacticOn ? tactic.c : 'var(--t3)') + '">' + esc(tactic.n) + '</span>';
    if (tacticHasSel) h += '<span style="font-size:10px;color:' + tactic.c + ';margin-left:auto">✓ technique</span>';
    h += '</div>';
    if (topLevel.length) {
      h += '<div style="padding:4px 8px 6px 8px;display:flex;flex-wrap:wrap;gap:3px">';
      topLevel.forEach(function(tech) {
        var techOn = selected.indexOf(tech.id) >= 0;
        var subs = techniques.filter(function(t) { return t.p === tech.id; });
        h += '<div style="display:inline-flex;flex-direction:column;gap:2px;margin-bottom:2px">';
        h += '<button class="tchip" data-cm="' + tech.id + '" style="font-size:10px;' + (techOn ? 'background:' + tactic.c + '20;color:' + tactic.c + ';border-color:' + tactic.c + '40' : '') + '" title="' + esc(tech.id) + '">' + esc(tech.n.length > 22 ? tech.n.slice(0,20)+'…' : tech.n) + '</button>';
        if (subs.length) {
          h += '<div style="display:flex;flex-wrap:wrap;gap:2px;padding-left:8px">';
          subs.forEach(function(sub) {
            var subOn = selected.indexOf(sub.id) >= 0;
            h += '<button class="tchip" data-cm="' + sub.id + '" style="font-size:9px;opacity:0.85;' + (subOn ? 'background:' + tactic.c + '20;color:' + tactic.c + ';border-color:' + tactic.c + '40' : '') + '" title="' + esc(sub.id) + '">' + esc(sub.n.length > 20 ? sub.n.slice(0,18)+'…' : sub.n) + '</button>';
          });
          h += '</div>';
        }
        h += '</div>';
      });
      h += '</div>';
    }
    h += '</div>';
  });
  h += '</div>';
  return h;
}

function renderCreateModal(){var f=S.cf||{};var vs=detectVars(f.kql||"");var curLang=f.lang||"KQL";var h='<div class="modal-overlay top" id="ov-c"><div class="modal-box wide"><div class="modal-header"><h2>'+(S.cf&&S.cf.editId?T('cr_edit_title'):T('cr_new_title'))+'</h2><span id="cl-c" class="close">\u00d7</span></div><div class="mdl-scroll">';
h+='<div style="margin-bottom:16px"><label class="lbl">'+T('cr_language')+'</label><div style="display:flex;gap:6px">';
LANGUAGES.forEach(function(l){var on=curLang===l.id;h+='<button class="tchip" data-cl="'+l.id+'" style="display:inline-flex;align-items:center;gap:5px;'+(on?'background:'+l.color+'20;color:'+l.color+';border-color:'+l.color+'50':'')+'">'+'<span style="display:flex;align-items:center">'+l.logo+'</span>'+l.name+'</button>';});
h+='</div></div>';
h+='<div style="margin-bottom:16px"><label class="lbl">'+T('cr_title_lbl')+'</label><input id="ct" placeholder="Suspicious process" value="'+esc(f.title||"")+'"></div>';h+='<div style="margin-bottom:16px"><label class="lbl">'+T('cr_description')+'</label><textarea id="cd" rows="2" placeholder="What does this detect..." style="font-family:var(--sans);font-size:14px">'+esc(f.desc||"")+'</textarea></div>';
var qLabel=_langMap[curLang]||LANGUAGES[0]; // P6
h+='<div style="margin-bottom:16px"><label class="lbl">'+curLang+' Query</label>';
if(curLang==="KQL"){
  h+='<textarea id="ck" rows="8" placeholder="DeviceProcessEvents\n| where Timestamp > ago(7d)\n| where FileName =~ \"cmd.exe\"">'+esc(f.kql||"")+'</textarea>';
  h+='<div id="monaco-container" style="display:none;height:300px;border:1px solid var(--bd);border-radius:6px;overflow:hidden"></div>';
}else{
  h+='<textarea id="ck" rows="8" placeholder="'+(curLang==="ELK"?"process where process.name == ...":"index=* sourcetype=...")+'">'+esc(f.kql||"")+'</textarea>';
}
if(vs.length)h+='<div style="margin-top:6px;font-size:12px;color:#22c55e">'+T('cr_detected')+vs.map(function(v){return v.key;}).join(", ")+'</div>';h+='</div>';
h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">';
if(curLang==="KQL"){h+='<div><label class="lbl">'+T('cr_env')+'</label><div style="display:flex;gap:6px">';ENVS.forEach(function(e){var cls=e==="Defender"?"env-defender":(e==="Sentinel"?"env-sentinel":"env-both");h+='<button class="tchip '+((f.env||"Defender")===e?cls:'')+'" data-ce="'+e+'">'+e+'</button>';});h+='</div></div>';}
h+='<div><label class="lbl">'+T('cr_severity')+'</label><div style="display:flex;gap:5px;flex-wrap:wrap">';SEVKEYS.forEach(function(s){h+='<button class="tchip '+((f.severity||"medium")===s?'sev-'+s:'')+'" data-cs="'+s+'" style="text-transform:capitalize">'+s+'</button>';});h+='</div></div></div>';h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px"><div><label class="lbl">'+T('cr_folder')+'</label><select id="cfl"><option value="">'+T('cr_none_folder')+'</option>';S.folders.forEach(function(fd){h+='<option value="'+fd.id+'">'+esc(fd.icon)+' '+esc(fd.name)+'</option>';});h+='</select></div><div><label class="lbl">'+T('cr_playbook')+'</label><input id="cpb" placeholder="Malware" value="'+esc(f.playbook||"")+'"></div></div>';h+='<div style="margin-bottom:16px"><label class="lbl">'+T('cr_mitre')+'</label>';h+=_buildMitrePicker(f.mitre||[]);h+='</div>';h+='<div style="margin-bottom:16px"><label class="lbl">'+T('cr_tags')+'</label><div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">';(f.tags||[]).forEach(function(t,i){h+='<span class="tag">'+esc(t)+' <span data-rt="'+i+'" style="cursor:pointer;color:var(--red)">x</span></span>';});h+='<input id="cnt" placeholder="'+T('cr_tags_ph')+'" style="width:130px;padding:6px 10px;font-size:13px"></div></div></div>';h+='</div><div class="modal-footer"><button id="cl-c2">'+T('cancel')+'</button><button class="pri" id="btn-sq">'+(S.cf&&S.cf.editId?T('cr_save_changes'):T('cr_save_query'))+'</button></div></div></div>';return h;}

function renderImportModal(){return'<div class="modal-overlay" id="ov-i"><div class="modal-box narrow"><div class="modal-header"><h2>'+T('import')+'</h2><span id="cl-i" class="close">\u00d7</span></div><div class="modal-body"><p style="font-size:14px;color:var(--t3);margin-bottom:16px">'+T('imp_upload_desc')+'</p><input type="file" id="if" accept=".json" style="padding:12px"><div id="ist" style="margin-top:12px"></div></div><div class="modal-footer"><button id="cl-i2">'+T('cancel')+'</button><button class="pri" id="btn-di" disabled>'+T('import')+'</button></div></div></div>';}

function renderFolderModal(){return'<div class="modal-overlay" id="ov-f"><div class="modal-box narrow"><div class="modal-header"><h2>'+T('fld_new_title')+'</h2><span id="cl-f" class="close">\u00d7</span></div><div class="modal-body"><div style="margin-bottom:16px"><label class="lbl">'+T('fld_name')+'</label><input id="fn" placeholder="Incident Response"></div><div style="margin-bottom:16px"><label class="lbl">'+T('fld_icon')+'</label><input id="fi" placeholder="IR" maxlength="2" style="width:80px"></div></div><div class="modal-footer"><button id="cl-f2">'+T('cancel')+'</button><button class="pri" id="btn-svf">'+T('fld_create')+'</button></div></div></div>';}

function renderVarPanel(){
  var filled=VARS.filter(function(v){return S.globalVars[v.id]&&S.globalVars[v.id].trim();}).length;
  var pct=Math.round(filled/VARS.length*100);
  var pctColor=pct===100?'#22c55e':pct>50?'#3b82f6':'#a855f7';

  var h='<div class="modal-overlay top" id="ov-vp">';
  h+='<div class="modal-box" style="max-width:860px">';

  // Header
  h+='<div style="padding:18px 24px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between">';
  h+='<div>';
  h+='<div style="display:flex;align-items:center;gap:10px;margin-bottom:5px">';
  h+='<div style="width:34px;height:34px;border-radius:8px;background:#3b076422;border:1px solid #7c3aed55;display:flex;align-items:center;justify-content:center;flex-shrink:0">';
  h+='<svg width="18" height="18" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="3" fill="#a855f7"/><path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.9 4.9l1.4 1.4M13.7 13.7l1.4 1.4M4.9 15.1l1.4-1.4M13.7 6.3l1.4-1.4" stroke="#a855f7" stroke-width="1.5" stroke-linecap="round"/></svg>';
  h+='</div>';
  h+='<h2 style="font-size:18px;font-weight:800;margin:0">'+T('vp_title')+'</h2>';
  h+='</div>';
  h+='<p style="font-size:13px;color:var(--t4);margin:0">'+T('vp_desc')+'</p>';
  h+='</div>';
  h+='<span id="cl-vp" style="cursor:pointer;color:var(--t4);font-size:26px;line-height:1;flex-shrink:0;margin-left:16px">\u00d7</span>';
  h+='</div>';

  // Progress bar
  h+='<div style="padding:12px 24px;border-bottom:1px solid var(--bd);background:var(--s2)">';
  h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">';
  h+='<span style="font-size:12px;font-weight:600;color:var(--t3)">'+T('vp_filled_count',{n:filled,total:VARS.length})+'</span>';
  h+='<div style="display:flex;gap:8px">';
  if(filled>0)h+='<button id="btn-vp-clr" style="font-size:11px;color:var(--red);border-color:var(--red3);padding:4px 10px;border-radius:5px">'+T('vp_clear_all')+'</button>';
  h+='</div></div>';
  h+='<div style="height:5px;border-radius:3px;background:var(--bd);overflow:hidden">';
  h+='<div style="height:100%;width:'+pct+'%;background:'+pctColor+';border-radius:3px;transition:width .4s"></div>';
  h+='</div></div>';

  // Variables by category
  h+='<div style="padding:20px 24px">';
  Object.keys(VAR_CATS).forEach(function(catKey){
    var cat=VAR_CATS[catKey];
    var catVars=VARS.filter(function(v){return v.cat===catKey;});
    if(!catVars.length)return;
    var catFilled=catVars.filter(function(v){return S.globalVars[v.id]&&S.globalVars[v.id].trim();}).length;
    h+='<div style="margin-bottom:20px">';
    h+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">';
    h+='<span style="width:10px;height:10px;border-radius:50%;background:'+cat.c+';flex-shrink:0"></span>';
    h+='<span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:'+cat.c+'">'+(T('vars.group.'+catKey)||cat.lbl)+'</span>';
    h+='<span style="font-size:10px;color:var(--t5);margin-left:2px">'+catFilled+'/'+catVars.length+'</span>';
    h+='<div style="flex:1;height:1px;background:'+cat.c+'28"></div>';
    h+='</div>';
    h+='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:8px">';
    catVars.forEach(function(v){
      var curVal=S.globalVars[v.id]||'';
      var hasVal=!!curVal.trim();
      h+='<div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--s2);border:1px solid '+(hasVal?cat.c+'44':'var(--bd)')+';border-radius:9px">';
      h+='<code style="font-size:9px;color:'+cat.c+';background:'+cat.c+'18;padding:3px 7px;border-radius:4px;font-family:var(--mono);border:1px solid '+cat.c+'30;min-width:120px;text-align:center;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+v.key+'</code>';
      h+='<span style="font-size:11px;color:var(--t4);min-width:90px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+(T('var.'+v.key.replace(/[{}]/g,''))||v.lbl)+'</span>';
      if(v.tp==="s"){
        h+='<select data-gv="'+v.id+'" style="flex:1;padding:7px 8px;font-size:12px;background:var(--s1);border:1px solid var(--bd);color:var(--t1);border-radius:6px;min-width:0"><option value="">'+v.ph+'...</option>';
        v.opts.forEach(function(o){h+='<option value="'+o+'"'+(curVal===o?' selected':'')+'>'+o+'</option>';});
        h+='</select>';
      }else{
        h+='<input data-gv="'+v.id+'" type="'+(v.tp==="n"?"number":"text")+'" value="'+esc(curVal)+'" placeholder="'+v.ph+'" style="flex:1;padding:7px 8px;font-size:12px;font-family:var(--mono);background:var(--s1);border:1px solid var(--bd);color:var(--t1);border-radius:6px;min-width:0">';
      }
      if(hasVal)h+='<button data-gvcl="'+v.id+'" style="background:none;border:none;color:var(--t5);cursor:pointer;padding:3px 5px;font-size:15px;line-height:1;flex-shrink:0" title="'+T('close')+'">\u00d7</button>';
      h+='</div>';
    });
    h+='</div></div>';
  });
  h+='</div>'; // end padding

  // Footer
  h+='<div style="padding:14px 24px;border-top:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">';
  h+='<span style="font-size:12px;color:var(--t5)">'+T('vp_footer_hint')+'</span>';
  h+='<div style="display:flex;gap:8px"><button id="cl-vp2">'+T('close_nosave')+'</button><button id="btn-vp-save" style="background:#7c3aed;border-color:#7c3aed;color:#fff;font-weight:600">'+T('vp_save_btn')+'</button></div>';
  h+='</div>';

  h+='</div></div>';
  return h;
}

function buildCorpus(q){
  var tags=Array.isArray(q.tags)?q.tags:(typeof q.tags==='string'?JSON.parse(q.tags||'[]'):[]);
  var mitre=Array.isArray(q.mitre)?q.mitre:(typeof q.mitre==='string'?JSON.parse(q.mitre||'[]'):[]);
  var mitreParts=mitre.map(function(id){
    var m=_mitreMap[id]; // P6
    return m?id+' '+m.n:'';
  });
  // Also add all MITRE tactic names to corpus so searching "persistence" works
  var tacticNames=MITRE.map(function(m){return m.n;}).join(' ');
  var cmtParts=(S.comments[q.id]||[]).map(function(c){return c.content||'';});
  return [
    q.title,
    q.description||'',
    q.kql,
    q.playbook||'',
    q.author_name||'',
    q.severity||'',
    (q.environment||''),
    (q.language||''),
    tags.join(' '),
    mitreParts.join(' '),
    cmtParts.join(' ')
  ].join(' ').toLowerCase();
}
function matchQ(q,raw){
  var terms=raw.toLowerCase().split(/\s+/).filter(Boolean);
  if(!terms.length)return true;
  var corpus=buildCorpus(q);
  return terms.every(function(t){return corpus.indexOf(t)>=0;});
}
function getFiltered(){return S.queries.filter(function(q){
  if(S.lang&&(q.language||"KQL")!==S.lang)return false;
  if(S.activeFolder&&q.folder_id!==S.activeFolder)return false;
  if(S.starOnly&&!q.starred)return false;
  if(S.search&&!matchQ(q,S.search))return false;
  if(S.fm.length){var _qm=Array.isArray(q.mitre)?q.mitre:(typeof q.mitre==='string'?JSON.parse(q.mitre||'[]'):[]);var _qt=_qm.map(function(id){return _tacticIdSet.has(id)?id:(_techTacticMap[id]||null);}).filter(Boolean);if(!S.fm.some(function(tid){return _qt.indexOf(tid)>=0;}))return false;}
  if(S.fs.length&&S.fs.indexOf(q.severity)<0)return false;
  if(S.fe.length&&S.fe.indexOf(q.environment||"Defender")<0)return false;
  return true;
});}

// ═══ ENV FINGERPRINT MODAL ═══
function renderEnvModal(){
  var h='<div class="modal-overlay top" id="ov-env">';
  h+='<div class="modal-box" style="max-width:580px">';
  h+='<div class="modal-header">';
  h+='<h2>'+T('env_profile')+'</h2>';
  h+='<span id="cl-env" class="close">\u00d7</span>';
  h+='</div>';
  h+=S.envEdit?renderEnvForm():renderEnvList();
  h+='</div></div>';
  return h;
}

function renderEnvList(){
  var h='<div style="padding:18px 22px">';
  if(!S.envProfiles.length){
    h+='<div style="text-align:center;padding:24px 0 12px;color:var(--t5);font-size:14px">'+T('no_env_profile')+'</div>';
    h+='<div style="font-size:13px;color:var(--t4);text-align:center;margin-bottom:18px">'+T('select_platform')+'</div>';
    h+='<div style="display:flex;gap:8px;margin-bottom:4px">';
    h+='<button id="btn-env-plat-def" style="flex:1;padding:14px 10px;font-weight:700;border-radius:8px;border:2px solid #f59e0b40;color:#f59e0b;background:#f59e0b10;font-size:13px">'+T('defender_xdr')+'</button>';
    h+='<button id="btn-env-plat-sen" style="flex:1;padding:14px 10px;font-weight:700;border-radius:8px;border:2px solid #38bdf840;color:#38bdf8;background:#38bdf810;font-size:13px">'+T('sentinel')+'</button>';
    h+='</div>';
  }else{
    S.envProfiles.forEach(function(p){
      var isAct=p.is_active===1;
      var cfg={}; try{cfg=(typeof p.config==='string')?JSON.parse(p.config):(p.config||{});}catch(e){}
      var platC=p.platform==='defender_xdr'?'#f59e0b':'#38bdf8';
      var platL=p.platform==='defender_xdr'?T('defender_xdr'):T('sentinel');
      h+='<div style="padding:12px 14px;background:var(--s2);border:1px solid '+(isAct?platC+'55':'var(--bd)')+';border-radius:10px;margin-bottom:8px">';
      h+='<div style="display:flex;align-items:center;gap:8px">';
      h+='<span style="width:8px;height:8px;border-radius:50%;background:'+(isAct?platC:'var(--t5)')+';flex-shrink:0"></span>';
      h+='<span style="font-size:13px;font-weight:700;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(p.name)+'</span>';
      h+='<span style="font-size:11px;font-weight:600;color:'+platC+';background:'+platC+'18;padding:2px 7px;border-radius:4px;flex-shrink:0">'+platL+'</span>';
      if(isAct)h+='<span style="font-size:10px;font-weight:700;color:#22c55e;background:#22c55e18;padding:2px 7px;border-radius:4px;flex-shrink:0">ACTIVE</span>';
      h+='<button data-env-edit="'+esc(p.id)+'" style="font-size:11px;padding:4px 9px;border-radius:5px;flex-shrink:0">\u270e '+T('det_edit_btn').replace('\u270e ','')+'</button>';
      if(!isAct)h+='<button data-env-activate="'+esc(p.id)+'" style="font-size:11px;padding:4px 9px;border-radius:5px;color:'+platC+';border-color:'+platC+'44;flex-shrink:0">'+T('env_activate')+'</button>';
      h+='<button data-env-del="'+esc(p.id)+'" style="font-size:11px;padding:4px 9px;border-radius:5px;color:var(--red);border-color:var(--red3);flex-shrink:0">\u00d7</button>';
      h+='</div>';
      var infoItems=[];
      if(p.platform==='defender_xdr'){
        if(cfg.mde)infoItems.push('MDE');if(cfg.mde_p2)infoItems.push('MDE P2');
        if(cfg.mdi)infoItems.push('MDI');if(cfg.mdo)infoItems.push('MDO');
        if(cfg.mda)infoItems.push('MDA');if(cfg.m365_defender)infoItems.push('M365 Defender');
      }else if(p.platform==='sentinel'){
        if(Array.isArray(cfg.connectors))infoItems=infoItems.concat(cfg.connectors.slice(0,4));
        if(Array.isArray(cfg.custom_tables)&&cfg.custom_tables.length)infoItems.push(cfg.custom_tables.length+' custom table'+(cfg.custom_tables.length>1?'s':''));
      }
      if(infoItems.length)h+='<div style="font-size:11px;color:var(--t5);margin-top:6px">'+esc(infoItems.join(' \u00b7 '))+'</div>';
      h+='</div>';
    });
    h+='<div style="padding-top:8px">';
    h+='<button class="pri" id="btn-env-new" style="padding:8px 18px;font-size:13px">'+T('env_new_profile')+'</button>';
    h+='</div>';
  }
  h+='</div>';
  return h;
}

function renderEnvForm(){
  var e=S.envEdit;
  var isDef=e.platform==='defender_xdr';
  var defC='#f59e0b',senC='#38bdf8';
  var cfg=e.config||{};
  var h='<div style="padding:22px;max-height:70vh;overflow-y:auto">';
  h+='<div style="margin-bottom:16px"><label class="lbl">'+T('name_lbl')+'</label><input id="env-name" value="'+esc(e.name||'')+'" placeholder="My SOC Environment"></div>';
  h+='<div style="margin-bottom:20px"><label class="lbl">'+T('platform_label')+'</label><div style="display:flex;gap:6px">';
  h+='<button id="env-plat-def" style="flex:1;padding:10px;font-weight:700;'+(isDef?'background:'+defC+'18;color:'+defC+';border-color:'+defC+'40':'')+'">'+(T('defender_xdr'))+'</button>';
  h+='<button id="env-plat-sen" style="flex:1;padding:10px;font-weight:700;'+(!isDef?'background:'+senC+'18;color:'+senC+';border-color:'+senC+'40':'')+'">'+(T('sentinel'))+'</button>';
  h+='</div></div>';
  if(isDef){
    h+='<div style="margin-bottom:20px"><label class="lbl">'+T('your_licenses')+'</label>';
    h+='<div style="padding:9px 12px;background:var(--s2);border:1px solid var(--bd);border-radius:7px;margin-bottom:8px;font-size:11px;color:var(--t5)">'+T('env_mde_note')+'</div>';
    h+='<div style="display:flex;flex-direction:column;gap:5px">';
    ENV_DEF_LICENSES.forEach(function(lic){
      var on=cfg[lic.id]===true;
      h+='<label style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--s2);border:1px solid '+(on?defC+'44':'var(--bd)')+';border-radius:7px;cursor:pointer">';
      h+='<input type="checkbox" data-lic="'+esc(lic.id)+'" '+(on?'checked':'')+' style="width:15px;height:15px;accent-color:'+defC+';cursor:pointer;flex-shrink:0">';
      h+='<span style="font-size:13px;font-weight:600;color:'+(on?defC:'var(--t2)')+'">'+esc(lic.lbl)+'</span>';
      h+='</label>';
    });
    h+='</div></div>';
  }else{
    var conList=Array.isArray(cfg.connectors)?cfg.connectors:[];
    h+='<div style="margin-bottom:20px"><label class="lbl">'+T('your_connectors')+'</label>';
    h+='<div style="padding:9px 12px;background:var(--s2);border:1px solid var(--bd);border-radius:7px;margin-bottom:8px;font-size:11px;color:var(--t5)">'+T('env_sent_note')+'</div>';
    h+='<div style="display:flex;flex-direction:column;gap:5px">';
    ENV_SENT_CONNECTORS.forEach(function(con){
      var on=conList.indexOf(con.id)>=0;
      h+='<label style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--s2);border:1px solid '+(on?senC+'44':'var(--bd)')+';border-radius:7px;cursor:pointer">';
      h+='<input type="checkbox" data-con="'+esc(con.id)+'" '+(on?'checked':'')+' style="width:15px;height:15px;accent-color:'+senC+';cursor:pointer;flex-shrink:0">';
      h+='<span style="font-size:13px;font-weight:600;color:'+(on?senC:'var(--t2)')+'">'+esc(con.lbl)+'</span>';
      h+='</label>';
    });
    h+='</div></div>';
    h+='<div style="margin-bottom:4px"><label class="lbl">'+T('custom_tables')+' <span style="text-transform:none;font-weight:400;color:var(--t5)">(optional)</span></label>';
    var customTbl=Array.isArray(cfg.custom_tables)?cfg.custom_tables:[];
    h+='<textarea id="env-custom" rows="2" placeholder="CustomTable1_CL, CustomTable2_CL" style="font-family:var(--sans);font-size:13px;resize:vertical">'+esc(customTbl.join(', '))+'</textarea>';
    h+='<div style="font-size:11px;color:var(--t5);margin-top:4px">'+T('env_custom_desc')+'</div>';
    h+='</div>';
  }
  h+='</div>';
  h+='<div style="padding:14px 22px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end;gap:8px">';
  h+='<button id="btn-env-cancel">'+T('cancel')+'</button>';
  h+='<button class="pri" id="btn-env-save" style="padding:8px 18px;font-size:13px">'+T('save_and_check')+'</button>';
  h+='</div>';
  return h;
}

// ═══ REPO MODAL ═══
function renderRepoModal(){
  var h='<div class="modal-overlay top" id="ov-repo">';
  h+='<div class="modal-box" style="max-width:750px">';
  h+='<div class="modal-header">';
  h+='<h2>'+T('repo_sources')+'</h2>';
  h+='<span id="cl-repo" class="close">\u00d7</span>';
  h+='</div>';
  h+=S.repoShowForm?renderRepoForm():renderRepoList();
  h+='</div></div>';
  return h;
}

function formatRepoName(name, owner, repo) {
  // If name looks like a URL or is empty, derive from owner/repo
  if (!name || name.startsWith('http') || name.startsWith('github.com')) {
    name = owner + '/' + repo;
  }
  // Convert kebab-case / snake_case to Title Case
  return name.replace(/[-_]+/g, ' ').replace(/\b\w/g, function(c){ return c.toUpperCase(); });
}

function renderRepoList(){
  var h='<div style="padding:18px 22px">';
  // Summary bar
  if(S.repoSources.length){
    var totalQ=S.repoSources.reduce(function(a,s){return a+(s.query_count||0);},0);
    var lastSync=S.repoSources.filter(function(s){return s.last_sync_at;}).sort(function(a,b){return b.last_sync_at.localeCompare(a.last_sync_at);})[0];
    var agoStr='';
    if(lastSync&&lastSync.last_sync_at){var diffH=Math.round((Date.now()-new Date(lastSync.last_sync_at))/3600000);agoStr=T('synced_ago')+': '+(diffH<1?'<1h':diffH+'h');}
    h+='<div style="padding:10px 14px;background:var(--bg-raised);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;font-size:12px;color:var(--text-secondary);display:flex;gap:16px;flex-wrap:wrap;align-items:center">';
    if(agoStr)h+='<span>'+esc(agoStr)+'</span>';
    h+='<span>'+totalQ+' '+T('queries_imported')+' — '+S.repoSources.length+' sources</span>';
    h+='<div style="margin-left:auto;display:flex;gap:6px">';
    h+='<button id="btn-purge-imported" style="font-size:11px;padding:4px 10px;color:var(--primary);border-color:var(--primary-border)">'+T('repo_purge_imported')+'</button>';
    h+='<button id="btn-reparse-all" style="font-size:11px;padding:4px 10px;color:var(--sev-high);border-color:var(--sev-high-border)" title="'+T('repo_reparse_tip')+'">'+T('repo_reparse')+'</button>';
    h+='<button id="btn-sync-all" style="font-size:11px;padding:4px 10px;color:var(--intel);border-color:var(--intel-border)">'+T('repo_sync_all')+'</button>';
    h+='</div></div>';
  }
  var fmtC={yaml:'#3b82f6',md:'#22c55e',kql:'#f97316',auto:'var(--text-tertiary)'};
  S.repoSources.forEach(function(src){
    var isSyncing=S.repoSyncing&&S.repoSyncing[src.id];
    var statusC=src.last_sync_status==='never'||!src.last_sync_at?'var(--text-tertiary)':src.last_sync_status==='ok'?'#22c55e':src.last_sync_status.startsWith('error')?'var(--primary)':'var(--sev-high)';
    var statusTxt=!src.last_sync_at?T('never_synced'):src.last_sync_status==='ok'?(function(){var dh=Math.round((Date.now()-new Date(src.last_sync_at))/3600000);return T('synced_ago')+' '+(dh<1?'<1h':dh+'h');})():src.last_sync_status.slice(0,60);
    if(isSyncing)statusTxt=T('syncing');
    var displayName = formatRepoName(src.name, src.github_owner, src.github_repo);
    h+='<div style="padding:14px 16px;background:var(--bg-raised);border:1px solid var(--border);border-radius:10px;margin-bottom:8px">';
    h+='<div style="display:flex;align-items:center;gap:12px">';
    h+='<div style="flex:1;min-width:0">';
    h+='<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;flex-wrap:wrap">';
    h+='<span style="font-size:13px;font-weight:700;color:var(--text-primary)">'+esc(displayName)+'</span>';
    h+='<span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px;color:'+(fmtC[src.file_format]||'var(--text-tertiary)')+';background:'+(fmtC[src.file_format]||'#888')+'20;border:1px solid '+(fmtC[src.file_format]||'#888')+'40">'+src.file_format.toUpperCase()+'</span>';
    h+='<span style="font-size:11px;color:'+statusC+';font-weight:600">'+esc(statusTxt)+(isSyncing?' \u23f3':'')+'</span>';
    if(!src.enabled)h+='<span style="font-size:10px;padding:2px 6px;border-radius:3px;background:var(--bg-surface);border:1px solid var(--border);color:var(--text-tertiary)">'+T('disabled_lbl')+'</span>';
    h+='</div>';
    h+='<a href="https://github.com/'+esc(src.github_owner)+'/'+esc(src.github_repo)+'" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--accent);text-decoration:none;display:inline-flex;align-items:center;gap:3px">';
    h+='<svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>';
    h+=esc(src.github_owner)+'/'+esc(src.github_repo)+'</a>';
    if(src.last_sync_at&&src.last_sync_status==='ok'){
      h+='<div style="margin-top:6px;font-size:11px;color:var(--text-tertiary);display:flex;gap:10px">';
      if(src.last_sync_new)h+='<span style="color:#22c55e">+'+src.last_sync_new+' '+T('new_queries')+'</span>';
      if(src.last_sync_updated)h+='<span style="color:#3b82f6">~'+src.last_sync_updated+' '+T('updated_queries')+'</span>';
      if(src.last_sync_errors)h+='<span style="color:var(--primary)">'+src.last_sync_errors+' '+T('repo_errors')+'</span>';
      h+='<span>'+esc(src.query_count||0)+' '+T('queries_imported')+'</span>';
      h+='</div>';
    }
    h+='</div>';
    h+='<div class="repo-row-actions">';
    h+='<label class="toggle-switch" title="'+(src.enabled?'Disable':'Enable')+'">';
    h+='<input type="checkbox" data-repo-toggle="'+src.id+'" '+(src.enabled?'checked':'')+' style="display:none">';
    h+='<span class="toggle-slider"></span></label>';
    h+='<div class="repo-btn-group">';
    h+='<button class="repo-btn-sync" data-repo-sync="'+src.id+'" title="'+T('sync_now')+'">'+(isSyncing?'\u23f3':'\u21bb')+' '+T('sync_now')+'</button>';
    h+='<button class="repo-btn-purge" data-repo-purge="'+src.id+'" title="Delete all imported queries for this repo">\u21ba '+T('purge')+'</button>';
    h+='<button class="repo-btn-del" data-repo-del="'+src.id+'" title="'+T('delete')+'">\u00d7 '+T('delete')+'</button>';
    h+='</div>';
    h+='</div></div></div>';
  });
  if(!S.repoSources.length)h+='<div style="text-align:center;padding:32px;color:var(--text-tertiary);font-size:14px">'+T('repo_no_repos')+'</div>';
  h+='</div>';
  h+='<div style="padding:14px 22px;border-top:1px solid var(--border);display:flex;justify-content:flex-end">';
  h+='<button class="pri" id="btn-repo-new" style="padding:8px 18px;font-size:13px">'+T('add_repo')+'</button>';
  h+='</div>';
  return h;
}

function parseGithubUrl(url) {
  if (!url) return null;
  var s = url.trim().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/^github\.com\//, '');
  var parts = s.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  var owner = parts[0];
  var repo = parts[1].replace(/\.git$/, '');
  if (!owner || !repo) return null;
  var branch = (parts[2] === 'tree' && parts[3]) ? parts[3] : null;
  return { owner: owner, repo: repo, name: repo, branch: branch };
}

function renderRepoForm(){
  var e=S.repoEdit||{};
  var showAdv=!!(e.path_filter||(e.branch&&e.branch!=='main')||e.target_folder_id);
  var h='<div style="padding:22px;max-height:70vh;overflow-y:auto">';
  h+='<div style="margin-bottom:16px">';
  h+='<label class="lbl">GitHub Repository URL</label>';
  h+='<input id="rp-url" value="'+esc(e.url||'')+'" placeholder="https://github.com/owner/repo" style="font-family:monospace;font-size:13px">';
  h+='<div id="rp-url-preview" style="margin-top:5px;font-size:12px;min-height:16px"></div>';
  h+='</div>';
  h+='<details'+(showAdv?' open':'')+' style="margin-bottom:4px">';
  h+='<summary style="cursor:pointer;font-size:11px;font-weight:700;color:var(--t4);text-transform:uppercase;letter-spacing:.06em;user-select:none;padding:2px 0">Advanced</summary>';
  h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px">';
  h+='<div><label class="lbl">'+T('repo_branch')+'</label><input id="rp-branch" value="'+esc(e.branch||'main')+'" placeholder="main"></div>';
  h+='<div><label class="lbl">'+T('path_filter')+' <span style="font-weight:400;text-transform:none;color:var(--t5)">(optional)</span></label><input id="rp-pf" value="'+esc(e.path_filter||'')+'" placeholder="Hunting Queries"></div>';
  h+='</div>';
  h+='<div style="margin-top:14px"><label class="lbl">'+T('file_format')+'</label><div style="display:flex;gap:6px">';
  ['auto','yaml','md','kql'].forEach(function(f){var on=(e.file_format||'auto')===f;var fC={auto:'var(--t3)',yaml:'#3b82f6',md:'#22c55e',kql:'#f97316'}[f];h+='<button class="tchip" data-rp-fmt="'+f+'" style="'+(on?'background:'+fC+'18;color:'+fC+';border-color:'+fC+'40':'')+'">'+f.toUpperCase()+'</button>';});
  h+='</div></div>';
  h+='<div style="margin-top:14px"><label class="lbl">'+T('repo_target_folder')+'</label><select id="rp-folder" style="width:100%"><option value="">'+T('repo_none_folder')+'</option>';
  S.folders.forEach(function(f){h+='<option value="'+f.id+'"'+(e.target_folder_id===f.id?' selected':'')+'>'+esc(f.icon)+' '+esc(f.name)+'</option>';});
  h+='</select></div>';
  h+='</details>';
  h+='</div>';
  h+='<div style="padding:14px 22px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end;gap:8px">';
  h+='<button id="btn-repo-cancel">'+T('cancel')+'</button>';
  h+='<button class="pri" id="btn-repo-save" style="padding:8px 18px;font-size:13px">'+T('add_and_sync')+'</button>';
  h+='</div>';
  return h;
}

// ═══ EVENTS ═══
function bindEvents(){
  // Auth
  elOn("btn-signin",async function(){
    var login=val("lg-login"),pw=val("lg-pw");
    var errEl=document.getElementById("login-err");
    if(errEl)errEl.textContent="";
    if(!login||!pw){if(errEl)errEl.textContent=T('login_pw_required');return;}
    try{
      var result=await Auth.login(login,pw);
      S.user=result.user;
      await loadData();
      if(result.must_change_password)S.mustChangePw=true;
      render();
    }catch(e){if(errEl)errEl.textContent=e.message;}
  });
  elOn("btn-demo",async function(){
    try{var result=await Auth.demo();S.user=result.user;await loadData();render();}
    catch(e){var errEl=document.getElementById("login-err");if(errEl)errEl.textContent=e.message;}
  });
  elOn("btn-newacct",function(){S.regStep={login:val("lg-login")||""};render();});
  elOn("reg-cancel",function(){S.regStep=null;render();});
  elOn("reg-confirm",async function(){
    var login=val("reg-login"),pw=val("reg-pw"),pw2=val("reg-pw2");
    var errEl=document.getElementById("reg-err");
    if(errEl)errEl.innerHTML="";
    function regErr(msg){if(errEl)errEl.innerHTML='<div style="margin-top:12px;padding:10px;border-radius:6px;background:#7f1d1d;color:#fca5a5;font-size:13px">'+esc(msg)+'</div>';}
    if(!login||login.length<2){regErr(T('login_min2'));return;}
    if(!/^[a-zA-Z0-9_.-]+$/.test(login)){regErr(T('login_invalid_chars'));return;}
    if(!pw||pw.length<8){regErr(T('pw_min8_err'));return;}
    if(pw!==pw2){regErr(T('pw_mismatch'));return;}
    try{
      var result=await Auth.register(login,pw);
      S.user=result.user;S.regStep=null;await loadData();showToast(T('welcome_user',{name:login}));
    }catch(e){regErr(e.message);}
  });
  elOn("btn-lang",function(){
    var newLang = (typeof i18n !== 'undefined' ? i18n.getLang() : S.uiLang) === 'en' ? 'fr' : 'en';
    if (typeof i18n !== 'undefined') { i18n.setLang(newLang); } else { S.uiLang = newLang; localStorage.setItem('kv-lang', newLang); }
    render();
  });
  // User dropdown
  elOn("btn-profile",function(e){e.stopPropagation();S.showUserDropdown=!S.showUserDropdown;render();});
  elOn("btn-dd-profile",function(){S.showUserDropdown=false;S.showProfile=true;render();});
  elOn("btn-dd-theme",function(){document.body.classList.toggle('light');localStorage.setItem('kv-theme',document.body.classList.contains('light')?'light':'dark');S.showUserDropdown=false;render();});
  elOn("btn-dd-logout",async function(){await Auth.logout();S.user=null;render();});
  // Close dropdown on outside click
  (function(){var dd=document.getElementById("hdr-user-dd");if(dd){var close=function(e){if(!dd.contains(e.target)&&e.target.id!=="btn-profile"){S.showUserDropdown=false;render();}};document.addEventListener("click",close,{once:true});}})();

  // Change password modal
  elOn("cpw-cancel",function(){S.showChangePw=false;S.mustChangePw=false;render();});
  elOn("cpw-confirm",async function(){
    var forced=S.mustChangePw;
    var cur=forced?"":val("cpw-cur");
    var nw=val("cpw-new"),nw2=val("cpw-new2");
    var errEl=document.getElementById("cpw-err");
    if(errEl)errEl.textContent="";
    if(!nw||nw.length<8){if(errEl)errEl.textContent=T('pw_min8_err');return;}
    if(nw!==nw2){if(errEl)errEl.textContent=T('pw_mismatch');return;}
    if(!forced&&!cur){if(errEl)errEl.textContent=T('pw_current_required');return;}
    try{
      await Auth.changePassword(cur,nw);
      S.mustChangePw=false;S.showChangePw=false;
      render();
      showToast(T('pw_updated'));
    }catch(e){if(errEl)errEl.textContent=e.message;}
  });

  // Profile modal
  elOn("cl-prof",function(){S.showProfile=false;render();});
  elOn("cl-prof2",function(){S.showProfile=false;render();});
  elOn("prof-ov",function(e){if(e.target.id==="prof-ov"){S.showProfile=false;render();}});
  elOn("btn-prof-env",function(){S.showProfile=false;openEnvModal();});
  elOn("btn-add-passkey",async function(){
    var btn=document.getElementById("btn-add-passkey");
    if(btn){btn.disabled=true;btn.textContent="...";}
    try{
      await Auth.addPasskey(S.user.login);
      showToast(T('prof_passkey_added'));
    }catch(e){
      showToast(e.message||T('error'));
    }finally{
      if(btn){btn.disabled=false;btn.textContent=T('prof_add_passkey');}
    }
  });
  elOn("btn-save-prof",async function(){var avatar=val("prof-avatar");try{await API.put("/auth/profile",{avatar:avatar});}catch(e){showToast(e.message||T('error'));return;}S.user.avatar=avatar||null;S.showProfile=false;showToast(T('prof_updated'));});
  elOn("btn-pick-avatar",function(){var fi=document.getElementById("prof-file");if(fi)fi.click();});
  var _profFile=document.getElementById("prof-file");
  if(_profFile){_profFile.addEventListener("change",function(e){
    var f=e.target.files[0];if(!f)return;
    if(!["image/jpeg","image/png","image/webp","image/gif"].includes(f.type)){showToast(T('img_format_err'));return;}
    if(f.size>150*1024){showToast(T('img_size_err'));return;}
    var r=new FileReader();
    r.onload=function(ev){
      var dataUrl=ev.target.result;
      var inp=document.getElementById("prof-avatar");if(inp)inp.value=dataUrl;
      var prev=document.getElementById("prof-av-preview");if(prev){prev.src=dataUrl;prev.style.display="block";}
      var init=document.getElementById("prof-av-init");if(init)init.style.display="none";
      var lbl=document.getElementById("prof-file-lbl");if(lbl)lbl.textContent=esc(f.name);
    };r.readAsDataURL(f);
  });}
  elOn("btn-clear-avatar",function(){
    var inp=document.getElementById("prof-avatar");if(inp)inp.value="";
    var prev=document.getElementById("prof-av-preview");if(prev){prev.src="";prev.style.display="none";}
    var init=document.getElementById("prof-av-init");if(init)init.style.display="inline-flex";
    var lbl=document.getElementById("prof-file-lbl");if(lbl)lbl.textContent=T('prof_no_image');
    var cb=document.getElementById("btn-clear-avatar");if(cb)cb.style.display="none";
  });
  elOn("btn-leave-team",async function(){if(!confirm(T('leave_team_confirm')))return;await API.post("/auth/leave-team",{});S.user.team="none";S.showProfile=false;await loadData();showToast(T('left_team'));});
  elOn("btn-change-pw",function(){S.showChangePw=true;S.showProfile=false;render();});

  // Search
  var sb=document.getElementById("sbox");if(sb){sb.value=S.search;sb.addEventListener("input",function(){S.search=sb.value;clearTimeout(_st);_st=setTimeout(function(){var g=document.querySelector(".qgrid,.query-grid");if(!g){render();return;}var fq=getFiltered();g.innerHTML=fq.length?fq.map(renderCard).join(''):'<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--t5)">'+T('no_queries')+'</div>';bindCardEvents();},150);});}

  // Filters
  elOn("btn-sf",function(){S.starOnly=!S.starOnly;render();});elOn("btn-clf",function(){S.fm=[];S.fs=[];S.fe=[];render();});elOn("btn-cfld",function(){S.activeFolder=null;render();});
  document.querySelectorAll("[data-fe]").forEach(function(x){x.addEventListener("click",function(){S.fe=toggleArr(S.fe,x.getAttribute("data-fe"));render();});});
  document.querySelectorAll("[data-fmt]").forEach(function(x){x.addEventListener("click",function(){S.fm=toggleArr(S.fm,x.getAttribute("data-fmt"));render();});});
  document.querySelectorAll("[data-fsv]").forEach(function(x){x.addEventListener("click",function(){S.fs=toggleArr(S.fs,x.getAttribute("data-fsv"));render();});});
  document.querySelectorAll("[data-lang]").forEach(function(x){x.addEventListener("click",function(){var l=x.getAttribute("data-lang");S.lang=S.lang===l?null:l;if(S.lang&&S.lang!=="KQL")S.fe=[];S.view='queries';render();});});
  document.querySelectorAll("[data-fld]").forEach(function(x){x.addEventListener("click",function(e){if(e.target.closest("[data-del-folder]"))return;var f=x.getAttribute("data-fld");S.activeFolder=f==="all"?null:(S.activeFolder===f?null:f);S.view='queries';render();});});
  document.querySelectorAll("img[data-icon-fb]").forEach(function(img){img.addEventListener("error",function(){var span=img.parentNode;span.style.color=img.getAttribute("data-icon-color");span.style.padding='';span.textContent=img.getAttribute("data-icon-fb");});});
  document.querySelectorAll("[data-del-folder]").forEach(function(x){x.addEventListener("click",async function(e){e.stopPropagation();var fid=x.getAttribute("data-del-folder");var folder=S.folders.find(function(f){return f.id===fid;});if(!folder)return;var cnt=S.queries.filter(function(q){return q.folder_id===fid;}).length;var msg=T('del_folder_confirm',{name:folder.name})+(cnt?' '+T('del_folder_keep_queries',{n:cnt}):'');if(!confirm(msg))return;try{var r=await API.del('/folders/'+fid);if(!r.ok&&!r.id){showToast(r.error||T('error'));return;}S.folders=S.folders.filter(function(f){return f.id!==fid;});S.queries=S.queries.map(function(q){return q.folder_id===fid?Object.assign({},q,{folder_id:null}):q;});if(S.activeFolder===fid)S.activeFolder=null;showToast(T('folder_deleted'));render();}catch(err){showToast(T('error')+': '+err.message);}});});
  bindCardEvents();

  // Shortcuts overlay close
  elOn('cl-shortcuts', function(){ S.showShortcuts=false; render(); });
  elOn('ov-shortcuts', function(e){ if(e.target.id==='ov-shortcuts'){ S.showShortcuts=false; render(); } });

  // Empty state import button
  elOn('btn-imp2', function(){ S.showImport=true; render(); });
  // Empty state clear filters
  elOn('btn-clf-es', function(){ S.fm=[]; S.fs=[]; S.fe=[]; S.search=''; var sb=document.getElementById('sbox'); if(sb) sb.value=''; render(); });

  // Drag & drop folder reorder (localStorage-based, visual only)
  (function(){
    var _dragId = null;
    document.querySelectorAll('[data-drag-folder]').forEach(function(el){
      el.addEventListener('dragstart', function(e){
        _dragId = el.getAttribute('data-drag-folder');
        el.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', _dragId);
      });
      el.addEventListener('dragend', function(){
        el.classList.remove('dragging');
        document.querySelectorAll('.si.drag-over').forEach(function(x){ x.classList.remove('drag-over'); });
      });
      el.addEventListener('dragover', function(e){
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        document.querySelectorAll('.si.drag-over').forEach(function(x){ x.classList.remove('drag-over'); });
        if (el.getAttribute('data-drag-folder') !== _dragId) el.classList.add('drag-over');
      });
      el.addEventListener('dragleave', function(){ el.classList.remove('drag-over'); });
      el.addEventListener('drop', function(e){
        e.preventDefault();
        el.classList.remove('drag-over');
        var targetId = el.getAttribute('data-drag-folder');
        if (!_dragId || _dragId === targetId) return;
        // Reorder S.folders array
        var dragIdx = S.folders.findIndex(function(f){ return f.id === _dragId; });
        var targetIdx = S.folders.findIndex(function(f){ return f.id === targetId; });
        if (dragIdx < 0 || targetIdx < 0) return;
        var moved = S.folders.splice(dragIdx, 1)[0];
        S.folders.splice(targetIdx, 0, moved);
        // Persist order
        try { localStorage.setItem('kv-folder-order', JSON.stringify(S.folders.map(function(f){ return f.id; }))); } catch(e) {}
        render();
      });
    });
  })();

  // Folder rename (double-click on folder name in sidebar)
  document.querySelectorAll("[data-rename-folder]").forEach(function(span){span.addEventListener("dblclick",function(e){e.stopPropagation();var fid=span.getAttribute("data-rename-folder");var folder=S.folders.find(function(f){return f.id===fid;});if(!folder)return;var inp=document.createElement("input");inp.value=folder.name;inp.style.cssText="flex:1;font-size:13px;background:var(--bg);border:1px solid var(--red);border-radius:4px;padding:2px 6px;color:var(--t1);min-width:0;max-width:120px";span.parentNode.replaceChild(inp,span);inp.focus();inp.select();var _done=false;async function _save(){if(_done)return;_done=true;var nm=inp.value.trim();if(!nm||nm===folder.name){render();return;}try{var r=await API.put("/folders/"+fid,{name:nm,icon:folder.icon,color:folder.color});if(r&&r.error){showToast(r.error);render();return;}S.folders=S.folders.map(function(f){return f.id===fid?Object.assign({},f,{name:nm}):f;});showToast(T('folder_renamed'));}catch(err){showToast(T('error'));}render();}inp.addEventListener("keydown",function(e){if(e.key==="Enter"){e.preventDefault();_save();}if(e.key==="Escape"){_done=true;render();}});inp.addEventListener("blur",function(){setTimeout(_save,100);});});});

  // Detail
  elOn("ov-d",function(e){if(e.target.id==="ov-d"){S.selQ=null;S.detailFullscreen=false;render();}});elOn("cl-d",function(){S.selQ=null;S.detailFullscreen=false;render();});elOn("cl-d2",function(){S.selQ=null;S.detailFullscreen=false;render();});
  elOn("btn-det-expand",function(){S.detailFullscreen=!S.detailFullscreen;render();});
  document.querySelectorAll("[data-vid]").forEach(function(x){x.addEventListener("input",updateResolved);});
  if(S.selQ&&detectVars(S.selQ.kql).length)setTimeout(updateResolved,0);
  elOn("btn-cp",function(){var kqlToCopy=(document.getElementById("ko")||{textContent:""}).textContent||"";try{navigator.clipboard.writeText(kqlToCopy);}catch(e){}var b=document.getElementById("btn-cp");if(b){var qlCp=S.selQ?S.selQ.language||"KQL":"KQL";b.textContent=T('copied');b.style.background="#22c55e";setTimeout(function(){b.textContent=T('det_copy_lang',{lang:qlCp});b.style.background="";},1500);}});
  elOn("btn-e1",function(){if(S.selQ)exportQueries([S.selQ]);});
  elOn("btn-export-pdf",function(){if(!S.selQ)return;var a=document.createElement("a");a.href="/api/queries/"+S.selQ.id+"/export?format=pdf";a.download="";a.click();});
  elOn("btn-del-q",async function(){if(!S.selQ)return;if(!confirm(T('del_query_confirm',{title:S.selQ.title})))return;try{var r=await fetch("/api/queries/"+S.selQ.id,{method:"DELETE",credentials:"same-origin"});var d=await r.json();if(!r.ok){showToast(d.error||T('error'));return;}S.queries=S.queries.filter(function(q){return q.id!==S.selQ.id;});S.selQ=null;API.invalidateQueries();showToast(T('query_deleted'));}catch(e){showToast(T('error'));}});
  elOn("btn-ed-q",function(){if(!S.selQ)return;var q=S.selQ;S.cf={editId:q.id,title:q.title,desc:q.description||"",kql:q.kql,lang:q.language||"KQL",severity:q.severity||"medium",env:q.environment||"Defender",playbook:q.playbook||"",folder:q.folder_id||"",mitre:q.mitre||[],picerl:q.picerl||[],tags:q.tags||[]};S.selQ=null;S.showCreate=true;render();});
  elOn("btn-add-cmt",async function(){if(!S.selQ)return;var txt=(document.getElementById("cmt-txt")||{value:""}).value.trim();var url=(document.getElementById("cmt-url")||{value:""}).value.trim();if(!txt){showToast(T('cmt_empty'));return;}try{var r=await fetch("/api/comments/"+S.selQ.id,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({content:txt,url:url||null})});var d=await r.json();if(!r.ok){showToast(d.error||T('error'));return;}if(!S.comments[S.selQ.id])S.comments[S.selQ.id]=[];S.comments[S.selQ.id].push(d);render();}catch(e){showToast(T('error'));}});
  document.querySelectorAll("[data-dcmt]").forEach(function(x){x.addEventListener("click",async function(){var cid=x.getAttribute("data-dcmt");if(!confirm(T('del_cmt_confirm')))return;try{var r=await fetch("/api/comments/"+cid,{method:"DELETE",credentials:"same-origin"});if(!r.ok){var d=await r.json();showToast(d.error||T('error'));return;}if(S.selQ&&S.comments[S.selQ.id])S.comments[S.selQ.id]=S.comments[S.selQ.id].filter(function(c){return c.id!==cid;});render();}catch(e){showToast(T('error'));}});});
  document.querySelectorAll("[data-ecmt]").forEach(function(x){x.addEventListener("click",function(){var cid=x.getAttribute("data-ecmt");var cmt=S.selQ&&S.comments[S.selQ.id]&&S.comments[S.selQ.id].find(function(c){return c.id===cid;});if(!cmt)return;var container=document.querySelector('[data-cmt-container="'+cid+'"]');if(!container)return;container.innerHTML='<div style="display:flex;flex-direction:column;gap:6px"><textarea id="ecmt-txt" rows="2" style="font-family:var(--sans);font-size:13px;resize:vertical">'+esc(cmt.content)+'</textarea><input id="ecmt-url" placeholder="'+T('det_cmt_url')+'" value="'+escAttr(cmt.url||'')+'" style="font-size:13px"><div style="display:flex;justify-content:flex-end;gap:6px;margin-top:2px"><button id="ecmt-cancel">'+T('cancel')+'</button><button class="pri" id="ecmt-save" style="padding:5px 12px;font-size:13px">'+T('save')+'</button></div></div>';document.getElementById('ecmt-cancel').onclick=function(){render();};document.getElementById('ecmt-save').onclick=async function(){var content=(document.getElementById('ecmt-txt')||{value:''}).value.trim();var url=(document.getElementById('ecmt-url')||{value:''}).value.trim();if(!content){showToast(T('cmt_empty'),true);return;}try{var r=await fetch('/api/comments/'+cid,{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:content,url:url||null})});var d=await r.json();if(!r.ok){showToast(d.error||T('error'),true);return;}if(S.selQ&&S.comments[S.selQ.id]){var idx=S.comments[S.selQ.id].findIndex(function(c){return c.id===cid;});if(idx>=0){S.comments[S.selQ.id][idx].content=content;S.comments[S.selQ.id][idx].url=url||null;}}showToast(T('cmt_updated'));render();}catch(e){showToast(T('error'),true);}};});});
  var mf=document.getElementById("move-folder");if(mf&&S.selQ){mf.addEventListener("change",async function(){var fid=mf.value==="__none"?null:mf.value;if(!fid&&mf.value!=="__none")return;var prevFid=S.selQ.folder_id;S.selQ.folder_id=fid;var idx=S.queries.findIndex(function(q){return q.id===S.selQ.id;});if(idx>=0)S.queries[idx].folder_id=fid;rebuildMaps();showToast(T('query_updated'));fetch("/api/queries/"+S.selQ.id+"/move",{method:"PUT",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({folder_id:fid})}).then(function(r){return r.json();}).then(function(d){if(d.error){S.selQ.folder_id=prevFid;if(idx>=0)S.queries[idx].folder_id=prevFid;rebuildMaps();showToast(d.error,'error');}}).catch(function(){S.selQ.folder_id=prevFid;if(idx>=0)S.queries[idx].folder_id=prevFid;rebuildMaps();showToast(T('error'),'error');});});}

  // Variables panel
  elOn("btn-vp",function(){S.showVarPanel=true;render();});
  elOn("ov-vp",function(e){if(e.target.id==="ov-vp"){S.showVarPanel=false;render();}});
  elOn("cl-vp",function(){S.showVarPanel=false;render();});
  elOn("cl-vp2",function(){S.showVarPanel=false;render();});
  elOn("btn-vp-save",function(){
    document.querySelectorAll("[data-gv]").forEach(function(x){
      var v=x.getAttribute("data-gv"),val=x.value.trim();
      if(val)S.globalVars[v]=val;else delete S.globalVars[v];
    });
    try{localStorage.setItem('kv-gvars',JSON.stringify(S.globalVars));}catch(e){}
    S.showVarPanel=false;
    var savedCount=Object.keys(S.globalVars).length;
    render();
    showToast(T('vp_saved',{n:savedCount}));
  });
  elOn("btn-vp-clr",function(){
    S.globalVars={};
    try{localStorage.removeItem('kv-gvars');}catch(e){}
    render();
    showToast(T('vars_cleared'));
  });
  document.querySelectorAll("[data-gvcl]").forEach(function(x){
    x.addEventListener("click",function(){
      delete S.globalVars[x.getAttribute("data-gvcl")];
      try{localStorage.setItem('kv-gvars',JSON.stringify(S.globalVars));}catch(e){}
      render();
    });
  });

  // Create
  elOn("btn-cr",function(){S.showCreate=true;S.cf={title:"",desc:"",kql:"",lang:S.lang||"KQL",severity:"medium",env:"Defender",playbook:"",folder:"",mitre:[],picerl:[],tags:[]};render();});
  elOn("btn-cr2",function(){S.showCreate=true;S.cf={title:"",desc:"",kql:"",lang:S.lang||"KQL",severity:"medium",env:"Defender",playbook:"",folder:"",mitre:[],picerl:[],tags:[]};render();});
  elOn("ov-c",function(e){if(e.target.id==="ov-c"){S.showCreate=false;render();}});elOn("cl-c",function(){S.showCreate=false;render();});elOn("cl-c2",function(){S.showCreate=false;render();});
  document.querySelectorAll("[data-cl]").forEach(function(x){x.addEventListener("click",function(){if(S.cf){S.cf.lang=x.getAttribute("data-cl");render();}});});
  document.querySelectorAll("[data-ce]").forEach(function(x){x.addEventListener("click",function(){if(S.cf)S.cf.env=x.getAttribute("data-ce");render();});});
  document.querySelectorAll("[data-cs]").forEach(function(x){x.addEventListener("click",function(){if(S.cf)S.cf.severity=x.getAttribute("data-cs");render();});});
  document.querySelectorAll("[data-cm]").forEach(function(x){x.addEventListener("click",function(){if(S.cf){S.cf.mitre=toggleArr(S.cf.mitre,x.getAttribute("data-cm"));render();}});});
  document.querySelectorAll("[data-rt]").forEach(function(x){x.addEventListener("click",function(){if(S.cf){S.cf.tags.splice(parseInt(x.getAttribute("data-rt")),1);render();}});});
  var nt=document.getElementById("cnt");if(nt)nt.addEventListener("keydown",function(e){if(e.key==="Enter"&&nt.value.trim()&&S.cf){S.cf.tags.push(esc(nt.value.trim()));render();}});
  ["ct","cd","ck","cpb","cfl"].forEach(function(id){var x=document.getElementById(id);if(x&&S.cf)x.addEventListener("input",function(){var map={ct:"title",cd:"desc",ck:"kql",cpb:"playbook",cfl:"folder"};if(map[id])S.cf[map[id]]=x.value;});});
  elOn("btn-sq",async function(){if(!S.cf)return;var t=val("ct"),k=val("ck");if(!t||!k)return;var payload={title:t,description:val("cd"),kql:k,language:S.cf.lang||"KQL",environment:S.cf.env,severity:S.cf.severity,playbook:val("cpb")||"Uncategorized",folder_id:val("cfl")||null,mitre:S.cf.mitre,picerl:S.cf.picerl,tags:S.cf.tags};try{if(S.cf.editId){var er=await fetch("/api/queries/"+S.cf.editId,{method:"PUT",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});if(!er.ok){var ed=await er.json();showToast(ed.error||T('error'));return;}var idx=S.queries.findIndex(function(q){return q.id===S.cf.editId;});if(idx>=0)S.queries[idx]=Object.assign({},S.queries[idx],payload);S.showCreate=false;S.cf=null;API.invalidateQueries();showToast(T('query_updated'));}else{var r=await fetch("/api/queries",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});var d=await r.json();if(d.id)S.queries.unshift(d);S.showCreate=false;S.cf=null;API.invalidateQueries();showToast(T('query_created'));}}catch(e){}});

  // Import
  elOn("btn-imp",function(){S.showImport=true;render();});elOn("ov-i",function(e){if(e.target.id==="ov-i"){S.showImport=false;render();}});elOn("cl-i",function(){S.showImport=false;render();});elOn("cl-i2",function(){S.showImport=false;render();});
  var impF=document.getElementById("if");if(impF)impF.addEventListener("change",function(){if(impF.files.length){var st=document.getElementById("ist");if(st)st.innerHTML='<span style="color:#6ee7b7">'+esc(impF.files[0].name)+'</span>';var b=document.getElementById("btn-di");if(b)b.disabled=false;}});
  elOn("btn-di",async function(){var f=document.getElementById("if");if(!f||!f.files.length)return;var reader=new FileReader();reader.onload=async function(e){try{var data=JSON.parse(e.target.result);if(!Array.isArray(data))throw new Error("Expected array");var r=await fetch("/api/queries/import",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({queries:data})});var d=await r.json();S.showImport=false;API.invalidateQueries();await loadData();showToast(T('import_ok',{n:d.imported||0}));}catch(err){var st=document.getElementById("ist");if(st)st.innerHTML='<span style="color:#fca5a5">'+esc(err.message)+'</span>';}};reader.readAsText(f.files[0]);});
  elOn("btn-exp",function(){exportQueries(S.queries);});

  // Folder
  elOn("btn-nf",function(){S.showNewFolder=true;render();});elOn("ov-f",function(e){if(e.target.id==="ov-f"){S.showNewFolder=false;render();}});elOn("cl-f",function(){S.showNewFolder=false;render();});elOn("cl-f2",function(){S.showNewFolder=false;render();});
  elOn("btn-svf",async function(){var n=val("fn");if(!n)return;try{var r=await fetch("/api/folders",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:n,icon:(val("fi")||"FD").toUpperCase().slice(0,2),scope:"personal",color:"#dc2626"})});var d=await r.json();if(d.id)S.folders.push(d);S.showNewFolder=false;render();}catch(e){}});

  // Env Fingerprint Modal
  async function openEnvModal(){S.showEnvModal=true;S.envEdit=null;render();try{var profiles=await API.get('/env');S.envProfiles=Array.isArray(profiles)?profiles:[];render();}catch(e){S.envProfiles=[];render();}}
  elOn("btn-env",openEnvModal);
  elOn("btn-open-env",openEnvModal);
  elOn("cl-env",function(){S.showEnvModal=false;S.envEdit=null;render();});
  elOn("ov-env",function(e){if(e.target.id==="ov-env"){S.showEnvModal=false;S.envEdit=null;render();}});
  elOn("btn-env-plat-def",function(){S.envEdit={isNew:true,name:'',platform:'defender_xdr',config:{mde:true,mde_p2:false,mdi:false,mdo:false,mda:false,m365_defender:true}};render();});
  elOn("btn-env-plat-sen",function(){S.envEdit={isNew:true,name:'',platform:'sentinel',config:{connectors:[],custom_tables:[]}};render();});
  elOn("btn-env-new",function(){S.envEdit={isNew:true,name:'',platform:'defender_xdr',config:{mde:true,mde_p2:false,mdi:false,mdo:false,mda:false,m365_defender:true}};render();});
  elOn("btn-env-cancel",function(){S.envEdit=null;render();});
  var _envNameEl=document.getElementById("env-name");
  if(_envNameEl)_envNameEl.addEventListener("input",function(){if(S.envEdit)S.envEdit.name=_envNameEl.value;});
  elOn("env-plat-def",function(){if(S.envEdit){S.envEdit.platform='defender_xdr';S.envEdit.config={mde:true,mde_p2:false,mdi:false,mdo:false,mda:false,m365_defender:true};render();}});
  elOn("env-plat-sen",function(){if(S.envEdit){S.envEdit.platform='sentinel';S.envEdit.config={connectors:[],custom_tables:[]};render();}});
  document.querySelectorAll("[data-lic]").forEach(function(x){x.addEventListener("change",function(){if(!S.envEdit||!S.envEdit.config)return;var lic=x.getAttribute("data-lic");S.envEdit.config[lic]=x.checked;render();});});
  document.querySelectorAll("[data-con]").forEach(function(x){x.addEventListener("change",function(){if(!S.envEdit||!S.envEdit.config)return;var con=x.getAttribute("data-con");var cl=S.envEdit.config.connectors||[];if(x.checked){if(cl.indexOf(con)<0)cl.push(con);}else{cl=cl.filter(function(c){return c!==con;});}S.envEdit.config.connectors=cl;render();});});
  document.querySelectorAll("[data-env-edit]").forEach(function(x){x.addEventListener("click",function(){var p=S.envProfiles.find(function(p){return p.id===x.getAttribute("data-env-edit");});if(p){var cfg={}; try{cfg=(typeof p.config==='string')?JSON.parse(p.config):(p.config||{});}catch(e){} S.envEdit={id:p.id,name:p.name,platform:p.platform,config:Object.assign({},cfg)};render();}});});
  document.querySelectorAll("[data-env-del]").forEach(function(x){x.addEventListener("click",async function(){if(!confirm(T('del_env_confirm')))return;var pid=x.getAttribute("data-env-del");try{await API.del("/env/"+pid);S.envProfiles=S.envProfiles.filter(function(p){return p.id!==pid;});S.compat={};S.compatDetail={};render();loadCompatibility();}catch(e){showToast(T('error'));}});});
  document.querySelectorAll("[data-env-activate]").forEach(function(x){x.addEventListener("click",async function(){var pid=x.getAttribute("data-env-activate");try{var r=await API.post("/env/"+pid+"/activate",{});S.envProfiles=S.envProfiles.map(function(p){return Object.assign({},p,{is_active:p.id===pid?1:0});});S.compat={};S.compatDetail={};render();if(r&&r.stats)showToast(T('env_check_result')+': '+r.stats.compatible+' '+T('compatible')+', '+r.stats.partial+' '+T('partial')+', '+r.stats.incompatible+' '+T('incompatible'));loadCompatibility();}catch(e){showToast(T('error'));}});});
  elOn("btn-env-save",async function(){
    if(!S.envEdit)return;
    var name=(document.getElementById("env-name")||{value:""}).value.trim();
    if(!name){showToast(T('name_required'));return;}
    var config=Object.assign({},S.envEdit.config||{});
    if(S.envEdit.platform==='sentinel'){
      var customRaw=(document.getElementById("env-custom")||{value:""}).value.trim();
      config.custom_tables=customRaw?customRaw.split(",").map(function(t){return t.trim();}).filter(Boolean):[];
    }
    var payload={name:name,platform:S.envEdit.platform,config:config};
    try{
      var r;
      if(S.envEdit.id){r=await API.put("/env/"+S.envEdit.id,payload);}
      else{r=await API.post("/env",payload);}
      if(r&&r.error){showToast(T('error')+': '+r.error);return;}
      S.envEdit=null;S.compat={};S.compatDetail={};
      var profiles=await API.get('/env');S.envProfiles=Array.isArray(profiles)?profiles:[];
      render();
      var stats=r&&r.stats?r.stats:null;
      if(stats)showToast(T('env_check_result')+': '+stats.compatible+' '+T('compatible')+', '+stats.partial+' '+T('partial')+', '+stats.incompatible+' '+T('incompatible'));
      else showToast(T('profile_saved'));
      loadCompatibility();
    }catch(e){showToast(T('error')+': '+(e.message||''));}
  });

  // ── Repo modal events ──────────────────────────────────────────
  async function openRepoModal(){
    S.showRepoModal=true;S.repoShowForm=false;S.repoEdit=null;render();
    try{var s=await API.get('/repos');S.repoSources=Array.isArray(s)?s:[];render();}catch(e){}
  }
  elOn("btn-repos",openRepoModal);
  elOn("cl-repo",function(){S.showRepoModal=false;S.repoShowForm=false;render();});
  elOn("ov-repo",function(e){if(e.target.id==="ov-repo"){S.showRepoModal=false;S.repoShowForm=false;render();}});
  elOn("btn-repo-new",function(){S.repoEdit={file_format:'auto',url:''};S.repoShowForm=true;render();});
  elOn("btn-repo-cancel",function(){S.repoShowForm=false;S.repoEdit=null;render();});
  (function(){
    var urlInput=document.getElementById("rp-url");
    if(!urlInput)return;
    function updatePreview(){
      var prev=document.getElementById("rp-url-preview");
      if(!prev)return;
      var parsed=parseGithubUrl(urlInput.value);
      if(parsed){
        prev.innerHTML='<span style="color:#22c55e">✓</span> <strong>'+esc(parsed.owner)+'/'+esc(parsed.repo)+'</strong>'+(parsed.branch?' &middot; branch: '+esc(parsed.branch):'');
      } else if(urlInput.value.trim()){
        prev.innerHTML='<span style="color:#ef4444">Invalid GitHub URL</span>';
      } else {
        prev.textContent='';
      }
    }
    urlInput.addEventListener("input",updatePreview);
    updatePreview();
  })();
  document.querySelectorAll("[data-rp-fmt]").forEach(function(x){x.addEventListener("click",function(){
    if(S.repoEdit){
      var _u=document.getElementById("rp-url"),_b=document.getElementById("rp-branch");
      var _pf=document.getElementById("rp-pf"),_fl=document.getElementById("rp-folder");
      if(_u)S.repoEdit.url=_u.value;
      if(_b)S.repoEdit.branch=_b.value;
      if(_pf)S.repoEdit.path_filter=_pf.value;
      if(_fl)S.repoEdit.target_folder_id=_fl.value||null;
      S.repoEdit.file_format=x.getAttribute("data-rp-fmt");
    }
    render();
  });});
  elOn("btn-repo-save",async function(){
    var urlVal=(document.getElementById("rp-url")||{value:""}).value.trim();
    var parsed=parseGithubUrl(urlVal);
    if(!parsed){showToast('Invalid GitHub URL — expected https://github.com/owner/repo');return;}
    var name=parsed.name;
    var owner=parsed.owner;
    var repo=parsed.repo;
    var branchInput=(document.getElementById("rp-branch")||{value:""}).value.trim();
    var branch=branchInput||parsed.branch||"main";
    var pf=(document.getElementById("rp-pf")||{value:""}).value.trim();
    var folder=(document.getElementById("rp-folder")||{value:""}).value||null;
    var fmt=(S.repoEdit&&S.repoEdit.file_format)||"auto";
    try{
      var created=await API.post('/repos',{name:name,github_owner:owner,github_repo:repo,branch:branch,path_filter:pf,file_format:fmt,target_folder_id:folder});
      S.repoSources.push(created);S.repoShowForm=false;S.repoEdit=null;render();
      S.repoSyncing[created.id]=true;render();
      try{
        var stats=await API.post('/repos/'+created.id+'/sync',{});
        S.repoSources=S.repoSources.map(function(s){return s.id===created.id?Object.assign({},s,{last_sync_status:'ok',last_sync_new:stats.new,last_sync_updated:stats.updated,last_sync_errors:stats.errors,query_count:(s.query_count||0)+stats.new}):s;});
        showToast(T('sync_success')+': +'+stats.new+' '+T('new_queries'));
        await loadRepoMeta();
      }catch(e){showToast(T('sync_error')+': '+(e.message||''));}
      delete S.repoSyncing[created.id];render();
    }catch(e){showToast(T('error')+': '+e.message);}
  });
  elOn("btn-purge-imported",async function(){
    if(!confirm(T('repo_purge_all_confirm')))return;
    try{
      var r=await API.post('/repos/purge-imported',{});
      if(r&&r.error){showToast(T('error')+': '+r.error);return;}
      S.repoSources=S.repoSources.map(function(s){return Object.assign({},s,{last_sync_at:null,last_sync_status:'never',last_sync_new:0,last_sync_updated:0,last_sync_errors:0,query_count:0});});
      await loadRepoMeta();
      showToast(T('purge_result',{n:r.deleted||0}));
      render();
    }catch(e){showToast(T('error')+': '+e.message);}
  });
  elOn("btn-reparse-all",async function(){
    if(!confirm(T('repo_reparse_confirm')))return;
    S.repoSources.forEach(function(s){S.repoSyncing[s.id]=true;});render();
    try{
      var res=await API.post('/repos/reparse',{});
      var sources=await API.get('/repos');S.repoSources=Array.isArray(sources)?sources:[];
      await loadRepoMeta();
      var tot=(res.results||[]).reduce(function(a,r){return a+(r.updated||0);},0);
      showToast(T('repo_reparse_done',{n:tot}));
    }catch(e){showToast(T('error')+': '+e.message);}
    S.repoSyncing={};render();
  });
  elOn("btn-sync-all",async function(){
    S.repoSources.forEach(function(s){S.repoSyncing[s.id]=true;});render();
    try{
      var res=await API.post('/repos/sync-all',{});
      var sources=await API.get('/repos');S.repoSources=Array.isArray(sources)?sources:[];
      await loadRepoMeta();showToast(T('sync_success'));
    }catch(e){showToast(T('sync_error')+': '+e.message);}
    S.repoSyncing={};render();
  });
  document.querySelectorAll("[data-repo-sync]").forEach(function(x){x.addEventListener("click",async function(){
    var sid=x.getAttribute("data-repo-sync");
    S.repoSyncing[sid]=true;render();
    try{
      var stats=await API.post('/repos/'+sid+'/sync',{});
      S.repoSources=S.repoSources.map(function(s){return s.id===sid?Object.assign({},s,{last_sync_status:'ok',last_sync_new:stats.new,last_sync_updated:stats.updated,last_sync_errors:stats.errors}):s;});
      await loadRepoMeta();showToast(T('sync_success')+': +'+stats.new+' '+T('new_queries'));
    }catch(e){showToast(T('sync_error')+': '+e.message);}
    delete S.repoSyncing[sid];render();
  });});
  document.querySelectorAll("[data-repo-purge]").forEach(function(x){x.addEventListener("click",async function(){
    var sid=x.getAttribute("data-repo-purge");
    var src=S.repoSources.find(function(s){return s.id===sid;});
    if(!src)return;
    if(!confirm(T('repo_purge_src_confirm',{name:src.name})))return;
    try{
      var resp=await fetch('/api/repos/purge/'+sid,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:'{}'});
      var text=await resp.text();
      var r;
      try{r=JSON.parse(text);}catch(e){showToast(T('error_http',{status:resp.status,text:text.slice(0,200)}));return;}
      if(r&&r.error){showToast(T('error')+': '+r.error);return;}
      S.repoSources=S.repoSources.map(function(s){return s.id===sid?Object.assign({},s,{last_sync_at:null,last_sync_status:'never',last_sync_new:0,last_sync_updated:0,last_sync_errors:0,query_count:0}):s;});
      S.queries=S.queries.filter(function(q){return !(S.repoQueryMap&&S.repoQueryMap[q.id]&&S.repoQueryMap[q.id].repo_id===sid);});
      await loadRepoMeta();
      showToast(T('queries_deleted_from',{n:r.deleted||0,name:src.name}));
      render();
    }catch(e){showToast(T('error')+': '+e.message);}
  });});
  document.querySelectorAll("[data-repo-del]").forEach(function(x){x.addEventListener("click",async function(){
    var sid=x.getAttribute("data-repo-del");
    if(!confirm(T('repo_del_confirm')))return;
    try{await API.del('/repos/'+sid);S.repoSources=S.repoSources.filter(function(s){return s.id!==sid;});await loadRepoMeta();render();}
    catch(e){showToast(T('error')+': '+e.message);}
  });});
  document.querySelectorAll("[data-repo-toggle]").forEach(function(x){x.addEventListener("change",async function(){
    var sid=x.getAttribute("data-repo-toggle");
    try{await API.put('/repos/'+sid,{enabled:x.checked});S.repoSources=S.repoSources.map(function(s){return s.id===sid?Object.assign({},s,{enabled:x.checked}):s;});}
    catch(e){showToast(T('error'));x.checked=!x.checked;}
  });});
  document.querySelectorAll("[data-reset-upstream]").forEach(function(x){x.addEventListener("click",async function(){
    var qid=x.getAttribute("data-reset-upstream");
    var rqm=S.repoQueryMap&&S.repoQueryMap[qid];
    if(!rqm)return;
    if(!confirm(T('reset_upstream_confirm')))return;
    try{
      await API.post('/repos/'+rqm.repo_id+'/reset-file',{file_path:rqm.file_path});
      if(S.repoQueryMap[qid])S.repoQueryMap[qid].local_modified=0;
      showToast(T('reset_upstream_done'));await loadData();render();
    }catch(e){showToast(T('error')+': '+e.message);}
  });});

  // ── Watch view events ────────────────────────────────────────────
  elOn("btn-watch", function(){
    S.view = 'watch';
    if (!S.watchArticles.length && !S.watchLoading) loadWatchFeed();
    else render();
    if (!S.watchSources.length) API.get("/watch/sources").then(function(srcs){ if(Array.isArray(srcs)){ S.watchSources=srcs; render(); } });
  });
  elOn("btn-watch-banner", function(){ S.view='watch'; loadWatchFeed(); });

  // Watch stats bar — clickable counters
  elOn("btn-stat-unread", function(){
    S.watchFilter.unread_only = !S.watchFilter.unread_only;
    loadWatchFeed();
  });
  elOn("btn-stat-critical", function(){
    S.watchFilter.severity = S.watchFilter.severity === 'critical' ? 'all' : 'critical';
    loadWatchFeed();
  });
  elOn("btn-stat-matched", function(){
    S.watchFilter.matched_only = !S.watchFilter.matched_only;
    loadWatchFeed();
  });

  // Query view mode toggle (grid/list/table)
  elOn("btn-qv-grid",  function(){ S.queryView='grid';  try{localStorage.setItem('kv-query-view','grid');}catch(e){}  render(); });
  elOn("btn-qv-list",  function(){ S.queryView='list';  try{localStorage.setItem('kv-query-view','list');}catch(e){}  render(); });
  elOn("btn-qv-table", function(){ S.queryView='table'; try{localStorage.setItem('kv-query-view','table');}catch(e){} render(); });

  // Watch view toggle (compact/list/table)
  elOn("btn-wv-compact", function(){ S.watchView='compact'; try{localStorage.setItem('kqlab_watch_view','compact');}catch(e){} render(); });
  elOn("btn-wv-list",    function(){ S.watchView='list';    try{localStorage.setItem('kqlab_watch_view','list');}catch(e){}    render(); });
  elOn("btn-wv-mosaic",  function(){ S.watchView='mosaic';  try{localStorage.setItem('kqlab_watch_view','mosaic');}catch(e){}  render(); });

  // Watch filter chips
  document.querySelectorAll("[data-wdays]").forEach(function(x){x.addEventListener("click",function(){ S.watchFilter.days=parseInt(x.getAttribute("data-wdays")); loadWatchFeed(); });});
  document.querySelectorAll("[data-wsev]").forEach(function(x){x.addEventListener("click",function(){ S.watchFilter.severity=x.getAttribute("data-wsev"); loadWatchFeed(); });});
  document.querySelectorAll("[data-wsrc]").forEach(function(x){x.addEventListener("click",function(){ S.watchFilter.source=x.getAttribute("data-wsrc"); loadWatchFeed(); });});
  elOn("btn-wf-unread",function(){ S.watchFilter.unread_only=!S.watchFilter.unread_only; loadWatchFeed(); });
  elOn("btn-wf-matched",function(){ S.watchFilter.matched_only=!S.watchFilter.matched_only; loadWatchFeed(); });

  // Watch: table sort columns
  document.querySelectorAll("[data-wsort]").forEach(function(x){
    x.addEventListener("click", function(){
      var col = x.getAttribute("data-wsort");
      if (S.watchTableSort.col === col) {
        S.watchTableSort.dir = S.watchTableSort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        S.watchTableSort = { col: col, dir: col === 'date' ? 'desc' : 'asc' };
      }
      render();
    });
  });

  // Watch: mark read button (inline ✓ button)
  document.querySelectorAll(".watch-read-btn").forEach(function(x){
    x.addEventListener("click", async function(e){
      e.stopPropagation();
      var aid = x.getAttribute("data-waid");
      if (!aid) return;
      try {
        await API.post("/watch/feed/"+aid+"/read",{});
        S.watchArticles = S.watchArticles.map(function(a){ return a.id===aid ? Object.assign({},a,{is_read:1}) : a; });
        if (S.watchSummary) {
          S.watchSummary = Object.assign({},S.watchSummary,{
            unread_count: Math.max(0,(S.watchSummary.unread_count||1)-1)
          });
        }
        render();
      } catch(e2){ /* silent */ }
    });
  });

  // Watch: click an article row → open slide-in
  document.querySelectorAll(".watch-article[data-waid]").forEach(function(x){
    x.addEventListener("click", async function(e){
      if (e.target.closest('a,button')) return;
      var aid = x.getAttribute("data-waid");
      try {
        var detail = await API.get("/watch/feed/"+aid);
        if (!detail || detail.error) { showToast(T('error')); return; }
        S.watchSelArticle = detail;
        API.post("/watch/feed/"+aid+"/read",{}).catch(function(){});
        S.watchArticles = S.watchArticles.map(function(a){ return a.id===aid ? Object.assign({},a,{is_read:1}) : a; });
        if (S.watchSummary && !detail.is_read) {
          S.watchSummary = Object.assign({},S.watchSummary,{
            unread_count: Math.max(0,(S.watchSummary.unread_count||1)-1)
          });
        }
        render();
      } catch(e){ showToast(T('error')); }
    });
  });

  // Watch slide-in close (overlay click + × button)
  elOn("cl-watch-detail", function(){ S.watchSelArticle=null; render(); });
  elOn("ov-watch-detail", function(e){ if(e.target.id==="ov-watch-detail"){ S.watchSelArticle=null; render(); } });

  // (Escape key is handled via the persistent listener registered in boot)

  // Watch detail: dismiss button
  elOn("btn-watch-dismiss", async function(){
    var aid = (document.getElementById("btn-watch-dismiss")||{}).getAttribute("data-waid");
    if(!aid) return;
    try {
      await API.post("/watch/feed/"+aid+"/dismiss",{});
      S.watchArticles = S.watchArticles.filter(function(a){ return a.id !== aid; });
      S.watchSelArticle = null;
      await loadWatchSummary();
      render();
    } catch(e){ showToast(T('error')); }
  });

  // Watch detail: open query from match list
  document.querySelectorAll("[data-wq-open]").forEach(function(x){
    x.addEventListener("click", function(){
      var qid = x.getAttribute("data-wq-open");
      var q = S.queries.find(function(z){ return z.id===qid; });
      if (q) {
        S.watchSelArticle = null;
        S.selQ = q;
        S.comments[q.id] = undefined;
        if(S.compat[q.id]&&S.compat[q.id]!=='unknown')S.compatDetail[q.id]=undefined;
        render();
        fetch("/api/comments/"+q.id,{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(data){S.comments[q.id]=data;if(S.selQ&&S.selQ.id===q.id)render();}).catch(function(){S.comments[q.id]=[];});
        if(S.compat[q.id]&&S.compat[q.id]!=='unknown'){fetch("/api/env/compatibility/"+q.id,{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(data){S.compatDetail[q.id]=data;if(S.selQ&&S.selQ.id===q.id)render();}).catch(function(){S.compatDetail[q.id]=null;});}
      }
    });
  });

  // "View all matches" in slide-in
  elOn("btn-wsi-viewall", function(){
    S.watchFilter.matched_only = true;
    S.watchSelArticle = null;
    loadWatchFeed();
  });

  // Watch: refresh feeds (admin)
  elOn("btn-watch-refresh", async function(){
    var btn = document.getElementById("btn-watch-refresh");
    if(btn) { btn.disabled = true; btn.classList.add('spinning'); }
    try {
      var r = await API.post("/watch/refresh",{});
      if (r && r.error) { showToast(T('error')+': '+r.error, 'error'); }
      else {
        await loadWatchSummary();
        loadWatchFeed();
        showToast(T('watch_refresh_result',{'new':r.new_articles||0,matched:r.matched||0})+(r.errors&&r.errors.length?" ("+r.errors.length+" "+T('repo_errors')+")":""));
      }
    } catch(e){ showToast(T('error')+': '+e.message); }
    if(btn) { btn.disabled = false; btn.classList.remove('spinning'); }
  });

  // Watch: sources modal (admin)
  elOn("btn-watch-sources", async function(){
    S.watchShowSourceForm = true;
    S.watchTestResult = null;
    render();
    try { var srcs = await API.get("/watch/sources"); S.watchSources = Array.isArray(srcs) ? srcs : []; render(); } catch(e) {}
  });
  elOn("cl-wsrc", function(){ S.watchShowSourceForm = false; S.watchTestResult = null; S.watchEditSrc = null; render(); });
  elOn("btn-wsrc-cancel", function(){ S.watchShowSourceForm = false; S.watchTestResult = null; S.watchEditSrc = null; render(); });
  elOn("ov-wsrc", function(e){ if(e.target.id==="ov-wsrc"){ S.watchShowSourceForm=false; S.watchTestResult=null; S.watchEditSrc=null; render(); } });

  // Feed test button
  elOn("btn-wsrc-test", async function(){
    var url = (document.getElementById("wsrc-url")||{value:""}).value.trim();
    if (!url) { showToast(T('error_enter_url')); return; }
    S.watchTestResult = { loading: true, _url: url };
    render();
    try {
      var r = await API.post("/watch/test-feed", { url: url });
      S.watchTestResult = Object.assign({ _url: url }, r);
    } catch(e) {
      S.watchTestResult = { ok: false, error: e.message, _url: url };
    }
    render();
  });

  // Popular feed suggestions — fill URL/Name/Type then auto-test
  document.querySelectorAll("[data-suggest-url]").forEach(function(x){
    x.addEventListener("click", async function(e){
      // Don't trigger if the "+ Ajouter" button itself was clicked inside the row
      if (e.target && e.target.classList.contains('wsrc-popular-add-btn')) {
        // fall through to same logic (the row click = add button click)
      }
      var u  = x.getAttribute("data-suggest-url");
      var n  = x.getAttribute("data-suggest-name");
      var ft = x.getAttribute("data-suggest-type") || "rss";
      var urlEl   = document.getElementById("wsrc-url");
      var nameEl  = document.getElementById("wsrc-name");
      var typeEl  = document.getElementById("wsrc-type");
      if (urlEl)  urlEl.value  = u;
      if (nameEl) nameEl.value = n;
      if (typeEl) typeEl.value = ft;
      // Auto-test the feed
      S.watchTestResult = { loading: true, _url: u };
      render();
      try {
        var r = await API.post("/watch/test-feed", { url: u });
        S.watchTestResult = Object.assign({ _url: u }, r);
        // Pre-fill name from feedTitle if available
        if (r.ok && r.feedTitle) {
          var ne2 = document.getElementById("wsrc-name");
          if (ne2 && !ne2.value) ne2.value = r.feedTitle;
        }
      } catch(e2) {
        S.watchTestResult = { ok: false, error: e2.message, _url: u };
      }
      render();
    });
  });

  // Watch sources: save (add)
  elOn("btn-wsrc-add", async function(){
    var name = (document.getElementById("wsrc-name")||{value:""}).value.trim();
    var url  = (document.getElementById("wsrc-url") ||{value:""}).value.trim();
    var ft   = (document.getElementById("wsrc-type")||{value:"rss"}).value;
    if (!name || !url) { showToast(T('name_url_required')); return; }
    var created = await API.post("/watch/sources", { name: name, url: url, feed_type: ft });
    if (!created || created.error) { showToast(created ? created.error : T('error')); return; }
    S.watchSources.push(created);
    S.watchTestResult = null;
    render();
    showToast(T('source_added'));
  });

  // Sources: toggle enable/disable (redesigned button)
  document.querySelectorAll("[data-wsrc-toggle2]").forEach(function(x){
    x.addEventListener("click", async function(){
      var sid = x.getAttribute("data-wsrc-toggle2");
      var src = S.watchSources.find(function(s){ return s.id===sid; });
      if (!src) return;
      var newState = !src.enabled;
      var r = await API.put("/watch/sources/"+sid, { enabled: newState });
      if (r && r.error) { showToast(r.error); return; }
      S.watchSources = S.watchSources.map(function(s){ return s.id===sid ? Object.assign({},s,{enabled:newState}) : s; });
      render();
    });
  });

  document.querySelectorAll("[data-wsrc-del]").forEach(function(x){
    x.addEventListener("click", async function(){
      var sid = x.getAttribute("data-wsrc-del");
      var src = S.watchSources.find(function(s){ return s.id===sid; });
      if (!confirm(T('del_source_confirm',{name:src?src.name:sid}))) return;
      var r = await API.del("/watch/sources/"+sid);
      if (r && r.error) { showToast(r.error); return; }
      S.watchSources = S.watchSources.filter(function(s){ return s.id!==sid; });
      render();
      showToast(T('source_deleted'));
    });
  });

  // Edit feed source — open inline form
  document.querySelectorAll("[data-wsrc-edit]").forEach(function(x){
    x.addEventListener("click", function(){
      S.watchEditSrc = x.getAttribute("data-wsrc-edit");
      render();
    });
  });

  // Edit feed source — cancel
  document.querySelectorAll("[data-wsrc-editcancel]").forEach(function(x){
    x.addEventListener("click", function(){ S.watchEditSrc = null; render(); });
  });

  // Edit feed source — save
  document.querySelectorAll("[data-wsrc-save]").forEach(function(x){
    x.addEventListener("click", async function(){
      var sid  = x.getAttribute("data-wsrc-save");
      var name = (document.getElementById("wsrc-edit-name")||{value:""}).value.trim();
      var url  = (document.getElementById("wsrc-edit-url") ||{value:""}).value.trim();
      var ft   = (document.getElementById("wsrc-edit-type")||{value:"rss"}).value;
      if (!name || !url) { showToast(T('name_url_required')); return; }
      var r = await API.put("/watch/sources/"+sid, { name: name, url: url, feed_type: ft });
      if (!r || r.error) { showToast(r ? r.error : T('error')); return; }
      S.watchSources = S.watchSources.map(function(s){ return s.id===sid ? Object.assign({},s,r) : s; });
      S.watchEditSrc = null;
      render();
      showToast(T('source_saved') || 'Source updated');
    });
  });
  elOn("btn-admin", function(){
    S.view = 'admin';
    S.adminTab = S.adminTab || 'dashboard';
    if (!S.adminFeatures && typeof detectAdminFeatures === 'function') detectAdminFeatures();
    render();
  });
  // ── Mobile sidebar toggle ──────────────────────────────
  elOn('btn-sidebar-toggle', function() {
    var side = document.querySelector('.side');
    var ov   = document.getElementById('sidebar-overlay');
    if (side) side.classList.toggle('side--open');
    if (ov)   ov.classList.toggle('active');
  });
  elOn('sidebar-overlay', function() {
    var side = document.querySelector('.side');
    var ov   = document.getElementById('sidebar-overlay');
    if (side) side.classList.remove('side--open');
    if (ov)   ov.classList.remove('active');
  });
  document.querySelectorAll('[data-action="side-toggle"]').forEach(function(b) {
    b.addEventListener('click', _sideToggle);
  });
  if (typeof bindAdminEvents === 'function') bindAdminEvents();
}

function bindCardEvents(){document.querySelectorAll(".card[data-qid],.qlist-row[data-qid],.qtable-row[data-qid]").forEach(function(x){x.addEventListener("click",function(e){if(e.target.closest("[data-st]"))return;var q=S.queries.find(function(z){return z.id===x.getAttribute("data-qid");});if(q){S.selQ=q;S.comments[q.id]=undefined;if(S.compat[q.id]&&S.compat[q.id]!=='unknown')S.compatDetail[q.id]=undefined;render();fetch("/api/comments/"+q.id,{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(data){S.comments[q.id]=data;if(S.selQ&&S.selQ.id===q.id)render();}).catch(function(){S.comments[q.id]=[];});if(S.compat[q.id]&&S.compat[q.id]!=='unknown'){fetch("/api/env/compatibility/"+q.id,{credentials:"same-origin"}).then(function(r){return r.json();}).then(function(data){S.compatDetail[q.id]=data;if(S.selQ&&S.selQ.id===q.id)render();}).catch(function(){S.compatDetail[q.id]=null;});}}});});document.querySelectorAll("[data-st]").forEach(function(x){x.addEventListener("click",async function(e){e.stopPropagation();var qid=x.getAttribute("data-st");var q=S.queries.find(function(z){return z.id===qid;});if(!q)return;var was=q.starred;q.starred=!was;x.textContent=q.starred?'★':'☆';x.classList.toggle('starred',q.starred);try{var r=await fetch("/api/queries/"+qid+"/star",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:"{}"});var d=await r.json();if(d.error){throw new Error(d.error);}/* server confirmed — no re-render needed */}catch(err){q.starred=was;x.textContent=was?'★':'☆';x.classList.toggle('starred',was);showToast(T('error'),'error');}});});}

function updateResolved(){if(!S.selQ)return;var vs={},filled=0,total=0;document.querySelectorAll("[data-vid]").forEach(function(x){total++;var val=x.value.trim();if(val){vs[x.getAttribute("data-vid")]=val;filled++;S.globalVars[x.getAttribute("data-vid")]=val;}});try{localStorage.setItem('kv-gvars',JSON.stringify(S.globalVars));}catch(e){}var resolvedKql=resolveKql(S.selQ.kql,vs);var o=document.getElementById("ko");if(o)o.textContent=resolvedKql;KQLMonaco.setDetailValue(resolvedKql);var w=document.getElementById("vw"),l=document.getElementById("kl"),miss=total-filled;if(w){w.style.display=miss>0?"block":"none";w.textContent=T('det_var_not_filled',{n:miss});}var qlUpd=S.selQ?S.selQ.language||"KQL":"KQL";if(l)l.innerHTML=(miss===0&&total>0)?T('det_query_lbl',{lang:qlUpd})+' <span style="font-size:10px;padding:3px 8px;border-radius:4px;background:#064e3b;color:#6ee7b7;font-weight:700">'+T('det_resolved_ready')+'</span>':T('det_query_lbl',{lang:qlUpd});var cp=document.getElementById("btn-cp");if(cp){cp.textContent=(miss===0&&total>0)?T('det_copy_resolved',{lang:qlUpd}):T('det_copy_lang',{lang:qlUpd});}}

function exportQueries(qs){var b=new Blob([JSON.stringify(qs,null,2)],{type:"application/json"});var u=URL.createObjectURL(b);var a=document.createElement("a");a.href=u;a.download="kqlab-export.json";a.click();URL.revokeObjectURL(u);}

function initTheme(){var t=localStorage.getItem('kv-theme')||'dark';if(t==='light')document.body.classList.add('light');}

// ═══ JS TOOLTIP (viewport-aware) ═══
(function(){
  var tip=document.createElement('div');
  tip.id='kv-tip';tip.className='kv-tip';
  document.body.appendChild(tip);
  document.addEventListener('mouseover',function(e){
    var el=e.target&&e.target.closest?e.target.closest('[data-tip]'):null;
    if(!el)return;
    var text=(el.getAttribute('data-tip')||'').replace(/&#10;/g,'\n');
    if(!text)return;
    tip.textContent=text;
    tip.style.display='block';
    var r=el.getBoundingClientRect();
    var tw=tip.offsetWidth, th=tip.offsetHeight;
    var left=r.left+r.width/2-tw/2;
    var top=r.top-th-10;
    left=Math.max(8,Math.min(left,window.innerWidth-tw-8));
    if(top<8)top=r.bottom+8;
    tip.style.left=left+'px';
    tip.style.top=top+'px';
  });
  document.addEventListener('mouseout',function(e){
    var el=e.target&&e.target.closest?e.target.closest('[data-tip]'):null;
    if(el&&!el.contains(e.relatedTarget))tip.style.display='none';
  });
})();

// ─── Offline banner (DOM-level — no full re-render) ───────────
function _showOfflineBanner() {
  if (document.getElementById('kv-offline-banner')) return;
  var el = document.createElement('div');
  el.id = 'kv-offline-banner';
  el.className = 'kv-offline-banner';
  el.innerHTML = '<span>⚡ Offline — read-only until reconnected</span>';
  document.body.prepend(el);
  document.body.classList.add('kv-is-offline');
}
function _hideOfflineBanner() {
  var el = document.getElementById('kv-offline-banner');
  if (el) el.remove();
  document.body.classList.remove('kv-is-offline');
}

initTheme();
initLang();
boot();
