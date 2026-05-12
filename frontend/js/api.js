// ─── CSRF: inject X-Requested-With on all same-origin API mutations ──────────
(function() {
  var _orig = window.fetch;
  window.fetch = function(url, opts) {
    if (typeof url === 'string' && url.startsWith('/api')) {
      opts = opts ? Object.assign({}, opts) : {};
      var m = (opts.method || 'GET').toUpperCase();
      if (m === 'POST' || m === 'PUT' || m === 'DELETE' || m === 'PATCH') {
        opts.headers = Object.assign({ 'X-Requested-With': 'XMLHttpRequest' }, opts.headers);
      }
    }
    return _orig.call(this, url, opts);
  };
})();

// ─── In-memory GET cache (TTL = 30s) ──────────────────────────
var _cache = new Map(); // path → { data, ts }
var _CACHE_TTL = 30000;

function _cacheGet(path) {
  var entry = _cache.get(path);
  return entry && Date.now() - entry.ts < _CACHE_TTL ? entry.data : null;
}
function _cacheSet(path, data) { _cache.set(path, { data: data, ts: Date.now() }); }

function apiFetch(url, options) {
  var ctrl = new AbortController();
  var timer = setTimeout(function() { ctrl.abort(); }, 15000);
  return fetch(url, Object.assign({}, options, { signal: ctrl.signal }))
    .finally(function() { clearTimeout(timer); });
}

var API = {
  // opts: { fresh: true } to bypass cache, { noCache: true } to skip writing to cache
  async get(path, opts) {
    var fresh   = opts && opts.fresh;
    var noCache = opts && opts.noCache;
    if (!fresh && !noCache) {
      var hit = _cacheGet(path);
      if (hit !== null) return hit;
    }
    try {
      var res = await apiFetch("/api" + path, { credentials: "same-origin" });
      if (res.status === 401) { if (path !== '/auth/me') window.location.replace('/'); return null; }
      if (!res.ok) return { error: "Erreur serveur" };
      var data = await res.json();
      if (!noCache) _cacheSet(path, data);
      return data;
    } catch (e) {
      return { error: e.message };
    }
  },

  async post(path, body) {
    if (!navigator.onLine) return { error: 'Offline — reconnect and retry' };
    try {
      var res = await apiFetch("/api" + path, {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
        body: JSON.stringify(body),
      });
      return await res.json();
    } catch (e) { return { error: e.message }; }
  },

  async put(path, body) {
    if (!navigator.onLine) return { error: 'Offline — reconnect and retry' };
    try {
      var res = await apiFetch("/api" + path, {
        method: "PUT", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
        body: JSON.stringify(body),
      });
      return await res.json();
    } catch (e) { return { error: e.message }; }
  },

  async del(path, body) {
    if (!navigator.onLine) return { error: 'Offline — reconnect and retry' };
    try {
      var opts = { method: "DELETE", credentials: "same-origin", headers: { "X-Requested-With": "XMLHttpRequest" } };
      if (body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      }
      var res = await apiFetch("/api" + path, opts);
      return await res.json();
    } catch (e) { return { error: e.message }; }
  },

  // Cache invalidation helpers
  invalidate: function(path) { if (path) _cache.delete(path); else _cache.clear(); },
  invalidateQueries: function() { _cache.delete('/queries'); _cache.delete('/folders'); },
};
