#!/usr/bin/env node
// i18n audit — KQL Vault
// Usage: node scripts/i18n-audit.js

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const FRONTEND = path.join(ROOT, 'frontend', 'js');

// ── 1. Extract DICTS keys from i18n.js ───────────────────────────────────────
function flattenDict(obj, prefix) {
  const out = {};
  for (const k of Object.keys(obj)) {
    const full = prefix ? prefix + '.' + k : k;
    if (obj[k] !== null && typeof obj[k] === 'object' && !Array.isArray(obj[k])) {
      Object.assign(out, flattenDict(obj[k], full));
    } else {
      out[full] = obj[k];
    }
  }
  return out;
}

function extractDicts() {
  const src = fs.readFileSync(path.join(FRONTEND, 'i18n.js'), 'utf8');
  // Expose window stub so the IIFE runs
  const window = {};
  const navigator = { language: 'fr' };
  const localStorage = { getItem: () => null, setItem: () => {} };
  const document = {
    documentElement: { lang: '' },
    readyState: 'complete',
    querySelectorAll: () => []
  };
  try {
    // eslint-disable-next-line no-new-func
    new Function('window', 'navigator', 'localStorage', 'document', src)(
      window, navigator, localStorage, document
    );
  } catch (e) {
    console.error('ERROR loading i18n.js:', e.message);
    process.exit(1);
  }
  // DICTS is declared as const inside the file but not on window — eval it
  const dictsMatch = src.match(/^const DICTS\s*=\s*(\{[\s\S]*?\n\};)/m);
  if (!dictsMatch) {
    console.error('Could not locate DICTS in i18n.js');
    process.exit(1);
  }
  let DICTS;
  try {
    // eslint-disable-next-line no-eval
    DICTS = eval('(' + dictsMatch[1].replace(/\};$/, '}') + ')');
  } catch (e) {
    // Try full assignment eval
    try {
      // eslint-disable-next-line no-eval
      eval('DICTS = ' + dictsMatch[1].replace(/\};$/, '}'));
    } catch(e2) {
      console.error('ERROR parsing DICTS:', e2.message);
      process.exit(1);
    }
  }
  return {
    fr: flattenDict(DICTS.fr || {}, ''),
    en: flattenDict(DICTS.en || {}, ''),
  };
}

// ── 2. Extract LANG keys from data.js ────────────────────────────────────────
function extractLang() {
  const src = fs.readFileSync(path.join(FRONTEND, 'data.js'), 'utf8');
  const match = src.match(/var LANG\s*=\s*(\{[\s\S]*?\n\};)/m);
  if (!match) return { fr: {}, en: {} };
  let LANG;
  try {
    // eslint-disable-next-line no-eval
    eval('LANG = ' + match[1].replace(/\};$/, '}'));
    return { fr: LANG.fr || {}, en: LANG.en || {} };
  } catch(e) {
    return { fr: {}, en: {} };
  }
}

// ── 3. Extract all T('key') calls from JS files ───────────────────────────────
function extractTCalls() {
  const files = [
    'app.js', 'admin.js', 'admin-templates.js',
    'auth.js', 'investigations.js', 'data.js'
  ];
  const keys = new Set();
  const keysByFile = {};

  for (const f of files) {
    const fpath = path.join(FRONTEND, f);
    if (!fs.existsSync(fpath)) continue;
    const src = fs.readFileSync(fpath, 'utf8');
    const found = [];
    // Match T('key') and T("key")
    const re = /\bT\(\s*['"]([^'"]+)['"]/g;
    let m;
    while ((m = re.exec(src)) !== null) {
      keys.add(m[1]);
      found.push(m[1]);
    }
    keysByFile[f] = [...new Set(found)];
  }
  return { all: keys, byFile: keysByFile };
}

// ── 4. Run audit ──────────────────────────────────────────────────────────────
const dicts = extractDicts();
const lang  = extractLang();
const tcalls = extractTCalls();

const frKeys = new Set(Object.keys(dicts.fr));
const enKeys = new Set(Object.keys(dicts.en));
const allDictKeys = new Set([...frKeys, ...enKeys]);
const langFrKeys = new Set(Object.keys(lang.fr));
const langEnKeys = new Set(Object.keys(lang.en));
const usedKeys = tcalls.all;

// Missing from DICTS entirely (T() call but no key in FR or EN)
const missingBoth = [...usedKeys].filter(k => !frKeys.has(k) && !enKeys.has(k));

// In EN but missing from FR
const missingFr = [...enKeys].filter(k => !frKeys.has(k));

// In FR but missing from EN
const missingEn = [...frKeys].filter(k => !enKeys.has(k));

// Orphaned: in DICTS but never called by T()
const orphaned = [...allDictKeys].filter(k => !usedKeys.has(k));

// In LANG but not in DICTS (legacy only)
const langOnlyFr = [...langFrKeys].filter(k => !frKeys.has(k));
const langOnlyEn = [...langEnKeys].filter(k => !enKeys.has(k));

// Coverage
const covered = [...usedKeys].filter(k => frKeys.has(k) || enKeys.has(k));
const coveragePct = ((covered.length / usedKeys.size) * 100).toFixed(1);

// ── 5. Group missing by prefix ────────────────────────────────────────────────
function groupByPrefix(keys) {
  const groups = {};
  for (const k of keys) {
    const prefix = k.includes('.') ? k.split('.')[0] : '_root';
    if (!groups[prefix]) groups[prefix] = [];
    groups[prefix].push(k);
  }
  return groups;
}

// ── 6. Build full translation table ───────────────────────────────────────────
function buildTable() {
  const allKeys = new Set([...frKeys, ...enKeys, ...usedKeys]);
  const rows = [];
  for (const k of [...allKeys].sort()) {
    const fr = dicts.fr[k] || '';
    const en = dicts.en[k] || '';
    const used = usedKeys.has(k);
    const status = !fr && !en ? 'MISSING_BOTH'
      : !fr ? 'MISSING_FR'
      : !en ? 'MISSING_EN'
      : !used ? 'ORPHAN'
      : 'OK';
    rows.push({ key: k, fr, en, status, used });
  }
  return rows;
}

// ── 7. Output ──────────────────────────────────────────────────────────────────
const lines = [];
const hr = '═'.repeat(72);

lines.push(hr);
lines.push('KQL VAULT — i18n AUDIT REPORT');
lines.push(new Date().toISOString());
lines.push(hr);
lines.push('');

lines.push('## COVERAGE SUMMARY');
lines.push(`  T() calls (unique)     : ${usedKeys.size}`);
lines.push(`  DICTS.fr keys          : ${frKeys.size}`);
lines.push(`  DICTS.en keys          : ${enKeys.size}`);
lines.push(`  LANG.fr keys (legacy)  : ${langFrKeys.size}`);
lines.push(`  LANG.en keys (legacy)  : ${langEnKeys.size}`);
lines.push(`  T() covered by DICTS   : ${covered.length} / ${usedKeys.size} (${coveragePct}%)`);
lines.push(`  Missing from DICTS     : ${missingBoth.length}`);
lines.push(`  Missing FR only        : ${missingFr.length}`);
lines.push(`  Missing EN only        : ${missingEn.length}`);
lines.push(`  Orphaned (unused)      : ${orphaned.length}`);
lines.push(`  LANG-only (not DICTS)  : FR=${langOnlyFr.length}, EN=${langOnlyEn.length}`);
lines.push('');

// Missing from both
lines.push('## MISSING FROM DICTS (T() called but no FR+EN key)');
if (missingBoth.length === 0) {
  lines.push('  ✓ None');
} else {
  const groups = groupByPrefix(missingBoth);
  for (const [prefix, keys] of Object.entries(groups).sort()) {
    lines.push(`  [${prefix}] (${keys.length} keys)`);
    for (const k of keys.sort()) lines.push(`    - ${k}`);
  }
}
lines.push('');

// Missing FR
lines.push('## MISSING FROM FR (exists in EN, absent in FR)');
if (missingFr.length === 0) {
  lines.push('  ✓ None');
} else {
  for (const k of missingFr.sort()) {
    lines.push(`  - ${k}  [EN: "${dicts.en[k]}"]`);
  }
}
lines.push('');

// Missing EN
lines.push('## MISSING FROM EN (exists in FR, absent in EN)');
if (missingEn.length === 0) {
  lines.push('  ✓ None');
} else {
  for (const k of missingEn.sort()) {
    lines.push(`  - ${k}  [FR: "${dicts.fr[k]}"]`);
  }
}
lines.push('');

// Orphaned
lines.push('## ORPHANED KEYS (in DICTS but never called by T())');
if (orphaned.length === 0) {
  lines.push('  ✓ None');
} else {
  for (const k of orphaned.sort()) {
    lines.push(`  - ${k}`);
  }
}
lines.push('');

// By file
lines.push('## T() CALLS BY FILE');
for (const [f, keys] of Object.entries(tcalls.byFile)) {
  lines.push(`  ${f}: ${keys.length} unique keys`);
}
lines.push('');

// Full translation table
lines.push('## FULL TRANSLATION TABLE');
lines.push('  ' + ['STATUS'.padEnd(14), 'KEY'.padEnd(50), 'FR'.padEnd(40), 'EN'].join(' | '));
lines.push('  ' + '-'.repeat(150));
const table = buildTable();
const statusOrder = { MISSING_BOTH: 0, MISSING_FR: 1, MISSING_EN: 2, ORPHAN: 3, OK: 4 };
table.sort((a, b) => (statusOrder[a.status] - statusOrder[b.status]) || a.key.localeCompare(b.key));
for (const row of table) {
  const fr = (row.fr || '').substring(0, 38).replace(/\n/g, '\\n');
  const en = (row.en || '').substring(0, 38).replace(/\n/g, '\\n');
  lines.push('  ' + [
    row.status.padEnd(14),
    row.key.padEnd(50),
    fr.padEnd(40),
    en
  ].join(' | '));
}
lines.push('');
lines.push(hr);

const report = lines.join('\n');
const outPath = path.join(ROOT, 'scripts', 'i18n-audit-report.txt');
fs.writeFileSync(outPath, report, 'utf8');
console.log(report);
console.log('\nReport saved to:', outPath);
