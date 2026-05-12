// KQL Vault — Cyber Watch Engine
// Ingestion, keyword extraction, and query matching for cyber news feeds.
var crypto = require("crypto");
var https  = require("https");
var http   = require("http");
var zlib   = require("zlib");

var DEBUG = process.env.WATCH_DEBUG === "true";
function dbg() { if (DEBUG) console.log.apply(console, ["[Watch]"].concat(Array.prototype.slice.call(arguments))); }

// ─── OG image fetch ──────────────────────────────────────────────────────────

async function fetchOgImage(url) {
  if (!url) return null;
  try {
    var resp = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; KQLVault/2.1; +https://github.com/kqlvault)" },
      signal: AbortSignal.timeout(5000)
    });
    if (!resp.ok) return null;
    var html = await resp.text();
    var m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
          || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i)
          || html.match(/<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']/i)
          || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter:image["']/i);
    if (!m) return null;
    var imgUrl = m[1];
    return imgUrl.startsWith("https://") ? imgUrl : null;
  } catch(e) { return null; }
}

// ─── XML helpers ─────────────────────────────────────────────────────────────

function extractTag(xml, tag) {
  var re = new RegExp("<" + tag + "[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?<\\/" + tag + ">", "i");
  var m = xml.match(re);
  return m ? m[1] : null;
}

function extractXmlAttr(xml, tag, attr) {
  var re = new RegExp("<" + tag + "[^>]+\\s" + attr + "=[\"']([^\"']+)[\"']", "i");
  var m = xml.match(re);
  return m ? m[1] : null;
}

function stripHtml(s) {
  if (!s) return "";
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function decodeEntities(s) {
  if (!s) return "";
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&nbsp;/g, " ");
}

function cleanField(s) {
  return decodeEntities(stripHtml(s || "")).trim();
}

function extractRssImage(block, rawDesc) {
  var mc = block.match(/<media:content[^>]+url="([^"]+)"[^>]*medium="image"/i)
        || block.match(/<media:content[^>]+medium="image"[^>]*url="([^"]+)"/i)
        || block.match(/<media:content[^>]+url="([^"]+)"/i);
  if (mc) return mc[1];
  var mt = block.match(/<media:thumbnail[^>]+url="([^"]+)"/i);
  if (mt) return mt[1];
  var enc = block.match(/<enclosure[^>]+url="([^"]+)"[^>]*type="image\/[^"]*"/i)
          || block.match(/<enclosure[^>]+type="image\/[^"]*"[^>]*url="([^"]+)"/i);
  if (enc) return enc[1];
  if (rawDesc) {
    var img = rawDesc.match(/<img[^>]+src="([^"]+)"/i);
    if (img) return img[1];
  }
  return null;
}

// ─── Feed format detection ────────────────────────────────────────────────────

function detectFeedFormat(text, contentType) {
  var ct = (contentType || "").toLowerCase();
  if (ct.includes("atom") || text.includes('<feed ') || text.includes('xmlns="http://www.w3.org/2005/Atom"')) return "atom";
  if (text.includes('<rdf:RDF') || text.includes('xmlns:rdf=')) return "rdf";
  if (text.includes('<rss') || text.includes('<channel>') || text.includes('<item>')) return "rss";
  return "unknown";
}

// ─── FEED_HEADERS — browser-like UA to avoid Cloudflare/CDN blocks ──────────

var FEED_HEADERS = {
  "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Accept":          "application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.8",
  "Accept-Language": "en-US,en;q=0.9",
  "Accept-Encoding": "gzip, deflate",
  "Cache-Control":   "no-cache"
};

// ─── Error hint for actionable user messages ──────────────────────────────────

function getErrorHint(msg) {
  if (!msg) return "";
  if (msg.includes("ENOTFOUND"))              return "Domaine introuvable — vérifier l'URL";
  if (msg.includes("ECONNREFUSED"))           return "Connexion refusée par le serveur";
  if (msg.includes("Timeout") || msg.includes("timeout") || msg.includes("ETIMEDOUT")) return "Délai dépassé — serveur trop lent ou inaccessible";
  if (msg.includes("403"))                    return "Accès refusé (HTTP 403) — feed privé ou bloqué";
  if (msg.includes("404"))                    return "Feed introuvable (HTTP 404) — URL incorrecte";
  if (msg.includes("certificate") || msg.includes("SSL") || msg.includes("CERT_")) return "Certificat SSL invalide";
  if (msg.includes("Format") || msg.includes("non reconnu")) return "Le contenu n'est pas un flux RSS/Atom valide";
  if (msg.includes("Too many redirects"))     return "Trop de redirections — URL incorrecte ou boucle";
  return "Vérifier que l'URL pointe vers un flux RSS ou Atom valide";
}

// ─── http/https module fallback (bypasses Node.js fetch quirks, handles gzip)

function fetchViaHttpModule(url, headers, maxRedirects, timeoutMs) {
  return new Promise(function(resolve, reject) {
    var redirects = 0;
    function doRequest(currentUrl) {
      var parsed;
      try { parsed = new URL(currentUrl); } catch(e) { return reject(e); }
      var lib = parsed.protocol === "https:" ? https : http;
      var req = lib.request({
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   "GET",
        headers:  headers,
        timeout:  timeoutMs
      }, function(res) {
        if ([301,302,303,307,308].indexOf(res.statusCode) >= 0 && res.headers.location) {
          if (++redirects > maxRedirects) return reject(new Error("Too many redirects"));
          var next = res.headers.location;
          if (!next.startsWith("http")) next = parsed.protocol + "//" + parsed.host + next;
          res.resume();
          return doRequest(next);
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error("HTTP " + res.statusCode + " " + currentUrl));
        }
        var chunks = [];
        var totalBytes = 0;
        var MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
        res.on("data", function(c) {
          totalBytes += c.length;
          if (totalBytes > MAX_RESPONSE_BYTES) { req.destroy(); return reject(new Error("Response too large: " + currentUrl)); }
          chunks.push(c);
        });
        res.on("error", reject);
        res.on("end", function() {
          var buf = Buffer.concat(chunks);
          var enc = (res.headers["content-encoding"] || "").toLowerCase();
          try {
            var text = enc.includes("gzip")    ? zlib.gunzipSync(buf).toString("utf8")
                     : enc.includes("deflate") ? zlib.inflateSync(buf).toString("utf8")
                     : buf.toString("utf8");
            resolve({ text: text, finalUrl: currentUrl, contentType: res.headers["content-type"] || "" });
          } catch(e) {
            resolve({ text: buf.toString("utf8"), finalUrl: currentUrl, contentType: res.headers["content-type"] || "" });
          }
        });
      });
      req.on("timeout", function() { req.destroy(); reject(new Error("Timeout: " + currentUrl)); });
      req.on("error", reject);
      req.end();
    }
    doRequest(url);
  });
}

// ─── Robust fetch: native fetch first, http module fallback ─────────────────

async function fetchFeedRobust(url) {
  var TIMEOUT_MS = 20000;

  // Attempt 1: native fetch (fast path)
  try {
    var ctrl  = new AbortController();
    var timer = setTimeout(function() { ctrl.abort(); }, TIMEOUT_MS);
    var res   = await fetch(url, { headers: FEED_HEADERS, redirect: "follow", signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error("HTTP " + res.status + " " + res.statusText);
    var text = await res.text();
    return { text: text, finalUrl: res.url, contentType: res.headers.get("content-type") || "" };
  } catch(err) {
    if (DEBUG) console.warn("[WatchEngine] fetch() failed, trying http module:", url, err.cause ? err.cause.code : err.message);
  }

  // Attempt 2: http/https module (handles gzip, custom redirects, avoids Node fetch quirks)
  return fetchViaHttpModule(url, FEED_HEADERS, 5, TIMEOUT_MS);
}

// ─── RSS 2.0 parser ──────────────────────────────────────────────────────────

function parseRSSFeed(xml, source) {
  var items = [];
  var feedTitle = extractTag(xml, "title") || (source && source.name) || "";

  var itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  var match;
  while ((match = itemRegex.exec(xml)) !== null) {
    var block = match[1];
    var title   = extractTag(block, "title");
    var link    = extractTag(block, "link");
    var desc    = extractTag(block, "description");
    var pubDate = extractTag(block, "pubDate") || extractTag(block, "dc:date");
    if (title) {
      items.push({
        title:        cleanField(title).slice(0, 300),
        url:          link ? link.trim() : "",
        summary:      desc ? cleanField(desc).slice(0, 1000) : "",
        published_at: pubDate ? new Date(pubDate).toISOString() : new Date().toISOString(),
        image_url:    extractRssImage(block, desc)
      });
    }
  }
  return { articles: items, format: "rss", feedTitle: cleanField(feedTitle) };
}

// ─── Atom 1.0 parser ─────────────────────────────────────────────────────────

function parseAtomFeed(xml, source) {
  var articles = [];
  var feedTitle = extractTag(xml, "title") || (source && source.name) || "";

  var entries = xml.match(/<entry[\s\S]*?<\/entry>/gi) || [];
  entries.forEach(function(entry) {
    var title   = extractTag(entry, "title");
    var link    = extractXmlAttr(entry, "link", "href") || extractTag(entry, "link");
    var summary = extractTag(entry, "summary") || extractTag(entry, "content");
    var date    = extractTag(entry, "published") || extractTag(entry, "updated");
    if (title) {
      articles.push({
        title:        cleanField(title).slice(0, 300),
        url:          link ? link.trim() : "",
        summary:      summary ? cleanField(summary).slice(0, 1000) : "",
        published_at: date ? new Date(date).toISOString() : new Date().toISOString(),
        image_url:    null
      });
    }
  });
  return { articles: articles, format: "atom", feedTitle: cleanField(feedTitle) };
}

// ─── RDF/RSS 1.0 parser ───────────────────────────────────────────────────────

function parseRDFFeed(xml, source) {
  var articles = [];
  var feedTitle = extractTag(xml, "title") || (source && source.name) || "";

  var items = xml.match(/<item[\s\S]*?<\/item>/gi) || [];
  items.forEach(function(item) {
    var title = extractTag(item, "title");
    var link  = extractTag(item, "link") || extractXmlAttr(item, "item", "rdf:about");
    var desc  = extractTag(item, "description") || extractTag(item, "content:encoded");
    var date  = extractTag(item, "dc:date") || extractTag(item, "pubDate");
    if (title) {
      articles.push({
        title:        cleanField(title).slice(0, 300),
        url:          link ? link.trim() : "",
        summary:      desc ? cleanField(desc).slice(0, 1000) : "",
        published_at: date ? new Date(date).toISOString() : new Date().toISOString(),
        image_url:    null
      });
    }
  });
  return { articles: articles, format: "rdf", feedTitle: cleanField(feedTitle) };
}

// ─── Unified feed fetcher ─────────────────────────────────────────────────────

async function fetchFeed(source) {
  var url = source.url || source;
  var sourceObj = (typeof source === "object") ? source : { url: source, name: "" };

  dbg("Fetching", sourceObj.name || url, url);

  var fetched;
  try {
    fetched = await fetchFeedRobust(url);
  } catch(err) {
    if (DEBUG) console.error("[WatchEngine] fetch error:", err.name, err.message, err.cause);
    return { error: "Connexion échouée : " + err.message, articles: [], format: null, hint: getErrorHint(err.message) };
  }

  var text        = fetched.text;
  var contentType = fetched.contentType || "";
  var format      = detectFeedFormat(text, contentType);

  dbg("Format détecté:", format, "finalUrl:", fetched.finalUrl);

  var result;
  switch (format) {
    case "atom":   result = parseAtomFeed(text, sourceObj); break;
    case "rdf":    result = parseRDFFeed(text, sourceObj);  break;
    case "rss":    result = parseRSSFeed(text, sourceObj);  break;
    default:       return { error: "Format non reconnu (" + contentType + ")", articles: [], format: "unknown", hint: getErrorHint("Format non reconnu") };
  }

  result.finalUrl = fetched.finalUrl;
  dbg("Articles parsés:", result.articles.length);
  return result;
}

// ─── Legacy wrappers (for backward compatibility) ─────────────────────────────

async function fetchRSS(url) {
  var result = await fetchFeed({ url: url, name: "" });
  if (result.error) throw new Error(result.error);
  return result.articles;
}

async function fetchCISA(url) {
  var fetched = await fetchFeedRobust(url);
  if (!fetched.text) throw new Error("Empty response");
  var data = JSON.parse(fetched.text);

  var cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
  return (data.vulnerabilities || [])
    .filter(function(v) { return v.dateAdded >= cutoff; })
    .map(function(v) {
      return {
        title:        v.cveID + " - " + v.vulnerabilityName,
        url:          "https://nvd.nist.gov/vuln/detail/" + v.cveID,
        summary:      (v.shortDescription || "") + (v.knownRansomwareCampaignUse === "Known" ? " [RANSOMWARE]" : ""),
        published_at: new Date(v.dateAdded).toISOString(),
        external_id:  v.cveID,
        cves:         [v.cveID],
        products:     [(v.vendorProject || "") + " " + (v.product || "")],
        severity:     v.knownRansomwareCampaignUse === "Known" ? "critical" : "high"
      };
    });
}

// ─── Keyword extraction ──────────────────────────────────────────────────────

var MALWARE_DICT = [
  "lumma","vidar","redline","raccoon","asyncrat","cobalt strike","metasploit",
  "emotet","trickbot","qakbot","icedid","bumblebee","pikabot","darkgate",
  "lockbit","blackcat","alphv","clop","akira","rhysida","play","medusa",
  "lazarus","apt29","apt28","volt typhoon","midnight blizzard","scattered spider",
  "sandworm","kimsuky","turla","fancy bear","cozy bear","hafnium",
  "mimikatz","impacket","bloodhound","certutil","psexec","wmic","ntds",
  "phishing","ransomware","infostealer","info-stealer","credential-theft",
  "zero-day","0-day","rce","remote code execution","privilege escalation",
  "lateral movement","brute force","mfa bypass","session hijacking",
  "supply chain","living off the land","lolbin","dll sideloading",
  "webshell","web shell","credential dumping","pass-the-hash","kerberoasting",
  "spearphishing","typosquatting","malvertising","drive-by"
];

var PRODUCT_DICT = [
  "exchange","outlook","sharepoint","teams","onedrive","azure","entra",
  "active directory","defender","sentinel","intune","office 365","microsoft 365",
  "windows","iis","sql server","power automate","power bi",
  "palo alto","pan-os","fortinet","fortigate","citrix","ivanti","vmware",
  "cisco","sophos","crowdstrike","okta","duo","lastpass","juniper","f5","bigip",
  "confluence","jira","atlassian","jenkins","gitlab","github actions"
];

function extractKeywords(title, summary) {
  var text = (title + " " + summary).toLowerCase();
  var keywords = [];
  var cves = [];
  var products = [];

  var cveMatches = text.match(/cve-\d{4}-\d{4,}/gi);
  if (cveMatches) {
    cves = Array.from(new Set(cveMatches.map(function(c) { return c.toUpperCase(); })));
  }

  MALWARE_DICT.forEach(function(term) {
    if (text.indexOf(term) >= 0) keywords.push(term);
  });

  PRODUCT_DICT.forEach(function(p) {
    if (text.indexOf(p) >= 0) products.push(p);
  });

  return { keywords: keywords, cves: cves, products: products };
}

// ─── Article → Query matching ─────────────────────────────────────────────

function matchArticleToQueries(article, queries) {
  var artKeywords = JSON.parse(article.keywords || "[]");
  var artCves     = JSON.parse(article.cves     || "[]");
  var artProducts = JSON.parse(article.products || "[]");
  var matches = [];

  queries.forEach(function(q) {
    var score   = 0;
    var reasons = [];
    var qTags   = JSON.parse(q.tags || "[]").map(function(t) { return t.toLowerCase(); });
    var qKql    = (q.kql || "").toLowerCase();
    var qTitle  = (q.title || "").toLowerCase();

    artKeywords.forEach(function(kw) {
      if (qTags.some(function(t) { return t.indexOf(kw) >= 0 || kw.indexOf(t) >= 0; })) {
        if (!reasons.includes("tag:" + kw)) { score += 25; reasons.push("tag:" + kw); }
      }
    });

    artKeywords.forEach(function(kw) {
      if (qTitle.indexOf(kw) >= 0 && !reasons.includes("tag:" + kw)) {
        if (!reasons.includes("title:" + kw)) { score += 15; reasons.push("title:" + kw); }
      }
    });

    artKeywords.forEach(function(kw) {
      if (qKql.indexOf(kw) >= 0 && !reasons.some(function(r) { return r.endsWith(":" + kw); })) {
        score += 10; reasons.push("kql:" + kw);
      }
    });

    artProducts.forEach(function(p) {
      var pl = p.toLowerCase();
      if ((pl.indexOf("defender") >= 0 || pl.indexOf("windows") >= 0) && q.environment === "Defender") {
        if (!reasons.includes("env:" + p)) { score += 10; reasons.push("env:" + p); }
      }
      if ((pl.indexOf("sentinel") >= 0 || pl.indexOf("azure") >= 0 || pl.indexOf("entra") >= 0) && q.environment === "Sentinel") {
        if (!reasons.includes("env:" + p)) { score += 10; reasons.push("env:" + p); }
      }
    });

    artCves.forEach(function(cve) {
      var cveLow = cve.toLowerCase();
      if (qKql.indexOf(cveLow) >= 0 || qTags.indexOf(cveLow) >= 0) {
        score += 30; reasons.push("cve:" + cve);
      }
    });

    if (score > 100) score = 100;
    if (score >= 15) {
      matches.push({ query_id: q.id, match_score: score, match_reasons: reasons });
    }
  });

  return matches.sort(function(a, b) { return b.match_score - a.match_score; }).slice(0, 20);
}

// ─── Main cycle ──────────────────────────────────────────────────────────────

async function runWatchCycle(db) {
  var sources    = db.prepare("SELECT * FROM watch_sources WHERE enabled = 1").all();
  var allQueries = db.prepare("SELECT id, title, kql, tags, environment FROM queries").all();
  var results    = { fetched: 0, new_articles: 0, matched: 0, errors: [] };

  for (var i = 0; i < sources.length; i++) {
    var src = sources[i];
    dbg("Processing source:", src.name, "type:", src.feed_type);
    try {
      var items = [];

      if (src.feed_type === "json_cisa") {
        items = await fetchCISA(src.url);
      } else {
        // rss, atom, rss_auto, msrc — all handled via fetchFeed
        var feedResult = await fetchFeed(src);
        if (feedResult.error) throw new Error(feedResult.error);
        items = feedResult.articles;
      }

      dbg(src.name + ": fetched", items.length, "items");
      results.fetched += items.length;

      var insertMatch = db.prepare(
        "INSERT OR REPLACE INTO watch_article_matches (article_id, query_id, match_score, match_reasons) VALUES (?,?,?,?)"
      );

      for (var j = 0; j < items.length; j++) {
        var item  = items[j];
        var extId = item.external_id || item.url || item.title;
        if (!extId) continue;

        var existing = db.prepare("SELECT id FROM watch_articles WHERE source_id = ? AND external_id = ?").get(src.id, extId);
        if (existing) continue;

        var extracted = extractKeywords(item.title, item.summary || "");
        var cves      = (item.cves     && item.cves.length)     ? item.cves     : extracted.cves;
        var products  = (item.products && item.products.length) ? item.products : extracted.products;
        var keywords  = extracted.keywords;

        var sev = item.severity || "medium";
        if (cves.length > 0 && sev === "medium") sev = "high";
        if (keywords.some(function(k) { return k === "ransomware" || k === "zero-day" || k === "0-day"; })) sev = "critical";

        var imgUrl = item.image_url || null;
        if (!imgUrl && item.url) {
          imgUrl = await fetchOgImage(item.url);
        }

        var articleId = "wa_" + crypto.randomBytes(8).toString("hex");
        db.prepare(
          "INSERT INTO watch_articles (id, source_id, external_id, title, summary, url, published_at, keywords, cves, products, severity, image_url) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        ).run(
          articleId, src.id, extId,
          item.title.slice(0, 300),
          (item.summary || "").slice(0, 1000),
          item.url || "",
          item.published_at || new Date().toISOString(),
          JSON.stringify(keywords),
          JSON.stringify(cves),
          JSON.stringify(products),
          sev,
          imgUrl
        );
        results.new_articles++;

        var matches = matchArticleToQueries(
          { keywords: JSON.stringify(keywords), cves: JSON.stringify(cves), products: JSON.stringify(products) },
          allQueries
        );
        matches.forEach(function(m) {
          insertMatch.run(articleId, m.query_id, m.match_score, JSON.stringify(m.match_reasons));
          results.matched++;
        });
      }

      // Update source status — try last_success_at/article_count if columns exist
      try {
        db.prepare(
          "UPDATE watch_sources SET last_fetch_at = datetime('now'), last_fetch_status = 'success', fetch_count = fetch_count + ?, last_error = NULL, last_success_at = strftime('%s','now'), article_count = ? WHERE id = ?"
        ).run(items.length, items.length, src.id);
      } catch(e2) {
        db.prepare(
          "UPDATE watch_sources SET last_fetch_at = datetime('now'), last_fetch_status = 'success', fetch_count = fetch_count + ? WHERE id = ?"
        ).run(items.length, src.id);
      }

    } catch(e) {
      dbg("Error on", src.name + ":", e.message);
      results.errors.push(src.name + ": " + e.message);
      try {
        db.prepare(
          "UPDATE watch_sources SET last_fetch_at = datetime('now'), last_fetch_status = ?, last_error = ? WHERE id = ?"
        ).run("error: " + e.message.slice(0, 200), e.message.slice(0, 500), src.id);
      } catch(e2) {
        db.prepare(
          "UPDATE watch_sources SET last_fetch_at = datetime('now'), last_fetch_status = ? WHERE id = ?"
        ).run("error: " + e.message.slice(0, 200), src.id);
      }
    }
  }

  // Cleanup: delete articles older than 90 days
  db.prepare("DELETE FROM watch_articles WHERE fetched_at < datetime('now', '-90 days')").run();

  return results;
}

module.exports = { runWatchCycle, fetchRSS, fetchCISA, fetchFeed, fetchFeedRobust, detectFeedFormat, extractKeywords, matchArticleToQueries, getErrorHint };
