'use strict';

const PDFDocument = require('pdfkit');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  ImageRun, Header, Footer, PageNumber, AlignmentType, WidthType,
  BorderStyle, ShadingType,
} = require('docx');

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires partagés
// ─────────────────────────────────────────────────────────────────────────────
function safe(s) { return String(s || ''); }

function safeFilename(t) {
  return safe(t).replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').slice(0, 60) || 'report';
}

function hex2rgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex || '#e63946');
  return r ? [parseInt(r[1], 16), parseInt(r[2], 16), parseInt(r[3], 16)] : [230, 57, 70];
}

function clamp(v) { return Math.max(0, Math.min(255, Math.round(v))); }
function darker(rgb, a) { return [clamp(rgb[0]-a), clamp(rgb[1]-a), clamp(rgb[2]-a)]; }
function lighter(rgb, a) { return [clamp(rgb[0]+a), clamp(rgb[1]+a), clamp(rgb[2]+a)]; }
function rgb2hex([r, g, b]) { return '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join(''); }

// ─────────────────────────────────────────────────────────────────────────────
// Palette couleurs
// ─────────────────────────────────────────────────────────────────────────────
const C = {
  dark:     '#0d1117',
  surface:  '#161b22',
  surfaceMid: '#1e293b',
  text:     '#111827',
  muted:    '#6b7280',
  subtle:   '#94a3b8',
  slate:    '#64748b',
  white:    '#ffffff',
  lightBg:  '#f8fafc',
  lightBg2: '#f1f5f9',
  border:   '#e5e7eb',
  borderDark: '#1e293b',
  codeBg:   '#0d1117',
  codeText: '#e6edf3',
  sev: {
    critical: '#dc2626', high: '#ea580c',
    medium:   '#d97706', low:  '#059669', info:  '#4f46e5',
  },
};

function sevColor(s) { return C.sev[(s || 'medium').toLowerCase()] || C.sev.medium; }

// ─────────────────────────────────────────────────────────────────────────────
// Dictionnaire backend — chaînes du rapport (FR + EN)
// N'importe jamais i18n.js (module browser). rs() est le seul point d'accès.
// ─────────────────────────────────────────────────────────────────────────────
const RS = {
  fr: {
    confidential:           'CONFIDENTIEL — Usage interne uniquement',
    confidential_docx:      'CONFIDENTIEL  ·  Usage interne uniquement  |  Page ',
    cover_type:             "RAPPORT D'INVESTIGATION DE SÉCURITÉ",
    toc_title:              'Table des matières',
    sec_01:                 'Résumé exécutif',
    sec_02:                 'Indicateurs de Compromission',
    sec_03:                 'Timeline des événements',
    sec_04:                 'Conclusion & Recommandations',
    toc_sub_01:             "Contexte et résumé de l'investigation",
    toc_sub_02_n:           'indicateur(s) identifié(s)',
    toc_sub_03_n:           'événement(s) documenté(s)',
    toc_sub_04:             "Analyse de l'incident et recommandations",
    fiche_label:            'FICHE INVESTIGATION',
    analyst_label:          'Analyste',
    severity_label:         'Sévérité',
    status_label:           'Statut',
    created_label:          'Créé le',
    updated_label:          'Mise à jour',
    meta_analyst:           'ANALYSTE',
    meta_date:              'DATE',
    meta_severity:          'SÉVÉRITÉ',
    meta_status:            'STATUT',
    meta_created:           'CRÉÉ LE',
    meta_classification:    'CLASSIFICATION',
    meta_classification_v:  'CONFIDENTIEL',
    col_type:               'TYPE',
    col_indicator:          'INDICATEUR',
    col_severity:           'SÉVÉRITÉ',
    col_context:            'CONTEXTE',
    no_summary:             '_Aucun résumé rédigé._',
    no_conclusion:          '_Aucune conclusion rédigée._',
    no_summary_plain:       'Aucun résumé rédigé.',
    no_conclusion_plain:    'Aucune conclusion rédigée.',
    status_open:            'Ouvert',
    status_in_progress:     'En cours',
    status_closed:          'Clôturé',
    event_finding:          'Finding',
    event_initial_access:   'Accès initial',
    event_lateral_movement: 'Mouvement latéral',
    event_ioc_detected:     'IOC détecté',
    event_exfiltration:     'Exfiltration',
    event_custom:           'Événement personnalisé',
    event_custom_short:     'Événement',
    date_unknown:           'Date inconnue',
    no_title:               'Sans titre',
    analyst_role:           'Analyste SOC',
    ioc_total:              'Total',
    ioc_critical_high:      'Critique/Haute sévérité',
    ioc_others:             'Autres',
    locale:                 'fr-FR',
  },
  en: {
    confidential:           'CONFIDENTIAL — Internal use only',
    confidential_docx:      'CONFIDENTIAL  ·  Internal use only  |  Page ',
    cover_type:             'SECURITY INVESTIGATION REPORT',
    toc_title:              'Table of Contents',
    sec_01:                 'Executive Summary',
    sec_02:                 'Indicators of Compromise',
    sec_03:                 'Event Timeline',
    sec_04:                 'Conclusion & Recommendations',
    toc_sub_01:             'Context and investigation summary',
    toc_sub_02_n:           'indicator(s) identified',
    toc_sub_03_n:           'event(s) documented',
    toc_sub_04:             'Incident analysis and recommendations',
    fiche_label:            'INVESTIGATION CARD',
    analyst_label:          'Analyst',
    severity_label:         'Severity',
    status_label:           'Status',
    created_label:          'Created',
    updated_label:          'Updated',
    meta_analyst:           'ANALYST',
    meta_date:              'DATE',
    meta_severity:          'SEVERITY',
    meta_status:            'STATUS',
    meta_created:           'CREATED',
    meta_classification:    'CLASSIFICATION',
    meta_classification_v:  'CONFIDENTIAL',
    col_type:               'TYPE',
    col_indicator:          'INDICATOR',
    col_severity:           'SEVERITY',
    col_context:            'CONTEXT',
    no_summary:             '_No summary written._',
    no_conclusion:          '_No conclusion written._',
    no_summary_plain:       'No summary written.',
    no_conclusion_plain:    'No conclusion written.',
    status_open:            'Open',
    status_in_progress:     'In Progress',
    status_closed:          'Closed',
    event_finding:          'Finding',
    event_initial_access:   'Initial Access',
    event_lateral_movement: 'Lateral Movement',
    event_ioc_detected:     'IOC Detected',
    event_exfiltration:     'Exfiltration',
    event_custom:           'Custom Event',
    event_custom_short:     'Event',
    date_unknown:           'Unknown date',
    no_title:               'Untitled',
    analyst_role:           'SOC Analyst',
    ioc_total:              'Total',
    ioc_critical_high:      'Critical/High severity',
    ioc_others:             'Others',
    locale:                 'en-US',
  },
};

function rs(key, lang) {
  const d = RS[lang] || RS.fr;
  return Object.prototype.hasOwnProperty.call(d, key) ? d[key] : (RS.fr[key] || key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Dates & statut
// ─────────────────────────────────────────────────────────────────────────────
function fmtDate(ts, lang) {
  if (!ts) return 'N/A';
  const d = new Date(typeof ts === 'number' ? ts : ts);
  return isNaN(d) ? safe(ts).slice(0, 10)
    : d.toLocaleDateString(rs('locale', lang || 'fr'), { day: '2-digit', month: 'long', year: 'numeric' });
}

function fmtDateShort(ts, lang) {
  if (!ts) return 'N/A';
  const d = new Date(ts);
  return isNaN(d) ? safe(ts).slice(0, 10)
    : d.toLocaleDateString(rs('locale', lang || 'fr'), { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function formatStatus(s, lang) {
  const l = lang || 'fr';
  return {
    open:          rs('status_open', l),
    'in-progress': rs('status_in_progress', l),
    in_progress:   rs('status_in_progress', l),
    closed:        rs('status_closed', l),
  }[s] || safe(s) || 'N/A';
}

// ─────────────────────────────────────────────────────────────────────────────
// Markdown → blocs PDF
// ─────────────────────────────────────────────────────────────────────────────
function parseMd(md) {
  if (!md) return [];
  const blocks = [];
  const lines = md.split('\n');
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (l.startsWith('```')) {
      const lang = l.slice(3).trim() || 'code';
      const code = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) { code.push(lines[i]); i++; }
      blocks.push({ t: 'code', lang, content: code.join('\n') });
      i++; continue;
    }
    if (l.startsWith('## '))  { blocks.push({ t: 'h2', content: l.slice(3).trim() }); i++; continue; }
    if (l.startsWith('### ')) { blocks.push({ t: 'h3', content: l.slice(4).trim() }); i++; continue; }
    if (l.trim() === '---')   { blocks.push({ t: 'hr' }); i++; continue; }
    if (l.match(/^[-*] /))   { blocks.push({ t: 'li', content: l.slice(2).trim() }); i++; continue; }
    if (l.trim() === '')      { blocks.push({ t: 'br' }); i++; continue; }
    const text = l.replace(/\*\*([^*]+)\*\*/g, '$1').replace(/\*([^*]+)\*/g, '$1')
                   .replace(/`([^`]+)`/g, '$1').trim();
    if (text) blocks.push({ t: 'p', content: text });
    i++;
  }
  return blocks;
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation logo base64 → Buffer PNG/JPEG (null si SVG/WebP/invalide)
// ─────────────────────────────────────────────────────────────────────────────
async function prepareLogoBuffer(logoB64) {
  if (!logoB64 || !logoB64.startsWith('data:image/')) return null;
  const mimeMatch = logoB64.match(/^data:image\/([^;]+);base64,/);
  if (!mimeMatch) return null;
  const mime = mimeMatch[1].toLowerCase();
  if (mime === 'svg+xml' || mime === 'svg' || mime === 'webp') return null;
  const raw = Buffer.from(logoB64.split(',')[1], 'base64');
  if (raw.length < 50) return null;
  const isPNG  = raw[0] === 0x89 && raw[1] === 0x50;
  const isJPEG = raw[0] === 0xFF && raw[1] === 0xD8;
  if (!isPNG && !isJPEG) return null;
  return raw;
}

// ─────────────────────────────────────────────────────────────────────────────
// generatePDF — retourne Promise<Buffer>
// ─────────────────────────────────────────────────────────────────────────────
async function generatePDF(investigation, findings, iocs, analyst, settings, lang = 'fr') {
  const logoBuffer = await prepareLogoBuffer((settings && settings.company_logo) || null);

  return new Promise((resolve, reject) => {
    const accent     = (settings && settings.report_header_color) || '#e63946';
    const company    = (settings && settings.company_name)        || 'KQLab';
    const companySub = (settings && settings.company_subtitle)    || 'Security Operations Center';
    const accentRgb  = hex2rgb(accent);

    const doc = new PDFDocument({
      size: 'A4', autoFirstPage: false,
      margins: { top: 54, bottom: 40, left: 36, right: 36 },
      info: {
        Title:   safe(investigation.title),
        Author:  safe((analyst && analyst.display_name) || company),
        Creator: 'KQLab — Security Investigation Platform',
        Subject: 'Security Investigation Report',
      },
    });

    const bufs = [];
    doc.on('data', b => bufs.push(b));
    doc.on('end',  () => resolve(Buffer.concat(bufs)));
    doc.on('error', reject);

    // ── Page 1 : Couverture (avant d'enregistrer pageAdded) ──────────────────
    doc.addPage({ margin: 0 });
    renderCover(doc, investigation, analyst, accent, accentRgb, company, companySub, logoBuffer, lang);

    // ── Pages 2+ : en-tête + pied de page automatiques ───────────────────────
    let pageNum = 1;

    doc.on('pageAdded', () => {
      pageNum++;
      const PW = doc.page.width;
      const PH = doc.page.height;
      const ML = doc.page.margins.left;
      const MR = doc.page.margins.right;
      const savedY = doc.y;
      const origBottom = doc.page.margins.bottom;
      doc.page.margins.bottom = 0;

      // Barre accent haut (3 px)
      doc.rect(0, 0, PW, 3).fill(accent);

      // Fond blanc de l'en-tête
      doc.rect(0, 3, PW, 38).fill('#ffffff');

      // Logo miniature en en-tête
      let hdrTextX = ML;
      if (logoBuffer) {
        try {
          doc.image(logoBuffer, 10, 9, { height: 22, fit: [68, 22] });
          hdrTextX = ML + 24;
        } catch(e) {}
      }

      // Nom société (accent) + titre rapport (gris)
      const cmpLabel = safe(company).toUpperCase();
      doc.font('Helvetica-Bold').fontSize(7.5).fillColor(accent, 1)
         .text(cmpLabel, hdrTextX, 16, { lineBreak: false, characterSpacing: 0.4 });
      const cmpW = doc.widthOfString(cmpLabel, { fontSize: 7.5 });
      doc.font('Helvetica').fontSize(7.5).fillColor(C.muted, 1)
         .text(`  —  ${safe(investigation.title)}`,
               hdrTextX + cmpW, 16, { width: PW - hdrTextX - cmpW - 80, lineBreak: false });

      // Numéro de page (droite)
      doc.font('Helvetica').fontSize(7.5).fillColor(C.muted, 1)
         .text(`p. ${pageNum}`, 0, 16, { width: PW - 12, align: 'right', lineBreak: false });

      // Séparateur sous en-tête
      doc.rect(ML, 39, PW - ML - MR, 0.5).fill(C.border);

      // Pied de page
      const FY = PH - 32;
      doc.rect(ML, FY, PW - ML - MR, 0.5).fill(C.border);
      doc.font('Helvetica').fontSize(6.5).fillColor(C.muted, 1)
         .text(rs('confidential', lang), ML, FY + 8, { lineBreak: false });
      doc.font('Helvetica').fontSize(6.5).fillColor(C.muted, 1)
         .text(`INV-${safe(investigation.id).slice(-8).toUpperCase()}`,
               0, FY + 8, { width: PW - MR, align: 'right', lineBreak: false });

      doc.page.margins.bottom = origBottom;
      doc.y = Math.max(savedY, 52);
    });

    // ── Page 2 : Table des matières ──────────────────────────────────────────
    doc.addPage();
    renderTOC(doc, investigation, findings, iocs, analyst, accent, lang);

    // ── Page 3+ : Corps ──────────────────────────────────────────────────────
    doc.addPage();

    sectionTitle(doc, '01', rs('sec_01', lang), accent);
    const summary = investigation.executive_summary || investigation.description || '';
    renderMd(doc, summary || rs('no_summary', lang), accent);

    if (iocs && iocs.length) {
      needsPage(doc, 100);
      sectionTitle(doc, '02', `${rs('sec_02', lang)} — ${iocs.length}`, accent);
      renderIoCs(doc, iocs, accent, lang);
    }

    if (findings && findings.length) {
      needsPage(doc, 100);
      sectionTitle(doc, '03', `${rs('sec_03', lang)} — ${findings.length}`, accent);
      findings.forEach(f => { needsPage(doc, 90); renderFinding(doc, f, accent, lang); });
    }

    needsPage(doc, 90);
    sectionTitle(doc, '04', rs('sec_04', lang), accent);
    renderMd(doc, safe(investigation.conclusion) || rs('no_conclusion', lang), accent);

    // Bloc signature
    const _sigML = doc.page.margins.left;
    doc.moveDown(2.5);
    if (doc.y < doc.page.height - 110) {
      const sigY = doc.y;
      doc.rect(_sigML, sigY, 180, 0.5).fill(C.border);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(C.text, 1)
         .text(safe((analyst && analyst.display_name) || rs('analyst_label', lang)), _sigML, sigY + 10);
      doc.font('Helvetica').fontSize(8.5).fillColor(C.muted, 1)
         .text(safe((analyst && analyst.role) || rs('analyst_role', lang)), _sigML, sigY + 24, { lineBreak: false });
      doc.font('Helvetica').fontSize(8).fillColor(C.muted, 1)
         .text(fmtDate(Date.now(), lang), _sigML, sigY + 38, { lineBreak: false });
    }

    doc.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Page de couverture — inspiré SysReptor/HTB-CDSA
// A4: W≈595.28  H≈841.89
// Structure: dark navy full-page, logo+company en haut, titre centré sur la page,
//            zone méta en bas, CONFIDENTIEL au pied.
// ─────────────────────────────────────────────────────────────────────────────
function renderCover(doc, investigation, analyst, accent, accentRgb, company, sub, logoBuffer, lang) {
  const W = doc.page.width;   // 595.28
  const H = doc.page.height;  // 841.89
  const PAD = 42;             // marge gauche/droite

  // ── 1. Fond intégral dark navy ────────────────────────────────────────────
  doc.rect(0, 0, W, H).fill('#161d2a');

  // ── 2. Zone logo + company (haut) ────────────────────────────────────────
  //   Logo centré verticalement sur 90 pt depuis le haut.
  //   Si image : affichée à gauche, texte company à droite.
  //   Si pas d'image : monogramme stylisé + company name.
  const LOGO_Y = 38;
  const LOGO_H = 62;
  let contentX = PAD; // x de départ pour le texte company

  if (logoBuffer) {
    try {
      doc.image(logoBuffer, PAD, LOGO_Y, { fit: [LOGO_H, LOGO_H], align: 'left', valign: 'center' });
      contentX = PAD + LOGO_H + 16;
    } catch(e) { /* fallback text */ }
  }

  if (!logoBuffer || contentX === PAD) {
    // Monogramme : carré arrondi accent + initiale(s) blanche(s)
    const mono = safe(company).trim().split(/\s+/).map(w => w[0]).join('').slice(0,2).toUpperCase() || 'KV';
    doc.roundedRect(PAD, LOGO_Y, LOGO_H, LOGO_H, 8).fill(accent);
    doc.font('Helvetica-Bold').fontSize(26).fillColor('#ffffff', 1)
       .text(mono, PAD, LOGO_Y + (LOGO_H - 30) / 2, { width: LOGO_H, align: 'center', lineBreak: false });
    contentX = PAD + LOGO_H + 16;
  }

  // Company name (bold, blanc) + sous-titre (gris clair)
  const nameY = LOGO_Y + 10;
  doc.font('Helvetica-Bold').fontSize(18).fillColor('#f1f5f9', 1)
     .text(safe(company).toUpperCase(), contentX, nameY,
           { lineBreak: false, characterSpacing: 0.8 });
  if (sub) {
    doc.font('Helvetica').fontSize(9).fillColor('#64748b', 1)
       .text(safe(sub), contentX, nameY + 26, { lineBreak: false });
  }

  // ── 3. Ligne de séparation sous le header ────────────────────────────────
  const SEP1_Y = LOGO_Y + LOGO_H + 22;
  doc.rect(PAD, SEP1_Y, W - PAD * 2, 0.5).fill('#1e293b');

  // ── 4. Label catégorie (accent, uppercase tracké) ─────────────────────────
  //   Positionné à ~29% de la hauteur de la page (≈244 pt), comme HTB-CDSA.
  const CAT_Y = Math.round(H * 0.29);
  doc.font('Helvetica-Bold').fontSize(9).fillColor(accent, 1)
     .text(rs('cover_type', lang), PAD, CAT_Y,
           { lineBreak: false, characterSpacing: 2.5 });
  // Trait accent sous le label
  doc.rect(PAD, CAT_Y + 14, 48, 2).fill(accent);

  // ── 5. Titre de l'investigation (blanc, grand) ────────────────────────────
  //   ~32% de la page (≈270 pt), jusqu'à 32% de hauteur max (≈270 pt allouée).
  const TITLE_Y  = CAT_Y + 26;
  const titleMax = Math.round(H * 0.22); // hauteur max pour le titre

  doc.font('Helvetica-Bold').fontSize(36).fillColor('#ffffff', 1)
     .text(safe(investigation.title), PAD, TITLE_Y,
           { width: W - PAD * 2, height: titleMax, lineGap: 6, ellipsis: true });

  const titleBottom = Math.min(doc.y, TITLE_Y + titleMax);

  // ── 6. Description / résumé (gris, 11pt) ─────────────────────────────────
  const rawDesc = safe(investigation.executive_summary || investigation.description || '');
  const DESC_Y  = titleBottom + 14;
  const DESC_MAX_Y = Math.round(H * 0.60); // ne pas dépasser 60% de la page

  if (rawDesc && DESC_Y < DESC_MAX_Y - 30) {
    const snippet = rawDesc
      .replace(/^#{1,6}\s+.+$/gm, '')
      .replace(/```[\s\S]*?```/g, '')
      .replace(/[*_`~]/g, '')
      .trim();
    doc.font('Helvetica').fontSize(11).fillColor('#475569', 1)
       .text(
         snippet.substring(0, 300) + (snippet.length > 300 ? '…' : ''),
         PAD, DESC_Y,
         { width: W - PAD * 2, height: DESC_MAX_Y - DESC_Y, lineGap: 3.5, ellipsis: true }
       );
  }

  // ── 7. Zone méta (bas de page, ~68% → ~80%) ──────────────────────────────
  //   Séparateur, puis grille 4 colonnes : analyste | date | sévérité | statut
  const META_TOP = Math.round(H * 0.70); // ≈589 pt
  doc.rect(PAD, META_TOP, W - PAD * 2, 0.5).fill('#1e293b');

  const META_Y  = META_TOP + 18;
  const sevRgb  = hex2rgb(sevColor(investigation.severity));
  const sevHex  = rgb2hex(sevRgb);
  const sevLabel = (safe(investigation.severity) || 'medium').toLowerCase();
  const sevText  = sevLabel.charAt(0).toUpperCase() + sevLabel.slice(1);
  const statusText = formatStatus(investigation.status, lang);

  const metaItems = [
    { label: rs('meta_analyst',  lang), value: safe((analyst && analyst.display_name) || 'N/A'), accent: false },
    { label: rs('meta_date',     lang), value: fmtDateShort(investigation.created_at, lang),     accent: false },
    { label: rs('meta_severity', lang), value: sevText,                                          accent: sevHex },
    { label: rs('meta_status',   lang), value: statusText,                                       accent: false },
  ];
  const colW = (W - PAD * 2) / metaItems.length;

  metaItems.forEach((m, i) => {
    const mx = PAD + i * colW;
    // Séparateur vertical entre colonnes
    if (i > 0) {
      doc.rect(mx, META_TOP + 6, 0.5, 56).fill('#1e293b');
    }
    // Label colonne
    doc.font('Helvetica').fontSize(7).fillColor('#334155', 1)
       .text(m.label, mx + 10, META_Y, { lineBreak: false, characterSpacing: 0.8 });
    // Valeur colonne
    const valColor = m.accent || '#e2e8f0';
    doc.font('Helvetica-Bold').fontSize(13).fillColor(valColor, 1)
       .text(m.value, mx + 10, META_Y + 14, { lineBreak: false, width: colW - 20 });
  });

  // ── 8. Pied de page ───────────────────────────────────────────────────────
  const FOOT_Y = H - 36;
  doc.rect(PAD, FOOT_Y, W - PAD * 2, 0.5).fill('#0f1923');

  doc.font('Helvetica').fontSize(7.5).fillColor('#374151', 1)
     .text(rs('confidential', lang), PAD, FOOT_Y + 10, { lineBreak: false });
  doc.font('Helvetica').fontSize(7.5).fillColor('#374151', 1)
     .text(`INV-${safe(investigation.id).slice(-8).toUpperCase()}`,
           0, FOOT_Y + 10, { width: W - PAD, align: 'right', lineBreak: false });

  doc.fillColor(C.text, 1);
}

// Monogramme/logo textuel fallback (utilisé en interne dans renderCover)
function _coverTextLogo(doc, company, sub, x, y) {
  doc.font('Helvetica-Bold').fontSize(18).fillColor('#f1f5f9', 1)
     .text(safe(company).toUpperCase() || 'KQLAB', x, y, { lineBreak: false });
  if (sub) {
    doc.font('Helvetica').fontSize(9).fillColor('#64748b', 1)
       .text(safe(sub), x, y + 25, { lineBreak: false });
    doc.fillColor('#f1f5f9', 1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Table des matières (page 2)
// ─────────────────────────────────────────────────────────────────────────────
function renderTOC(doc, investigation, findings, iocs, analyst, accent, lang) {
  const ML = doc.page.margins.left;
  const MR = doc.page.margins.right;
  const W  = doc.page.width - ML - MR;
  const NX = ML + 10;  // num x
  const TX = ML + 35;  // title x

  // Titre TDM
  doc.font('Helvetica-Bold').fontSize(22).fillColor(C.text, 1)
     .text(rs('toc_title', lang), ML, doc.y, { width: W });
  doc.moveDown(0.5);
  doc.rect(ML, doc.y, W, 2.5).fill(accent);
  doc.moveDown(1.4);

  const entries = [
    { num: '01', title: rs('sec_01', lang),
      sub: rs('toc_sub_01', lang),                                                   pg: 3 },
    { num: '02', title: rs('sec_02', lang),
      sub: `${(iocs && iocs.length) || 0} ${rs('toc_sub_02_n', lang)}`,             pg: 4 },
    { num: '03', title: rs('sec_03', lang),
      sub: `${(findings && findings.length) || 0} ${rs('toc_sub_03_n', lang)}`,     pg: 5 },
    { num: '04', title: rs('sec_04', lang),
      sub: rs('toc_sub_04', lang),                                                   pg: 6 },
  ];

  entries.forEach((e, i) => {
    needsPage(doc, 56);
    const y = doc.y;
    // Fond alterné
    if (i % 2 === 0) doc.rect(ML, y - 3, W, 40).fill(C.lightBg);
    // Bande accent gauche
    doc.rect(ML, y - 3, 3, 40).fill(accent);
    // Numéro
    doc.font('Helvetica-Bold').fontSize(16).fillColor(accent, 1)
       .text(e.num, NX, y + 5, { lineBreak: false });
    // Titre
    doc.font('Helvetica-Bold').fontSize(11).fillColor(C.text, 1)
       .text(e.title, TX, y + 3, { lineBreak: false });
    // Sous-titre
    doc.font('Helvetica').fontSize(8.5).fillColor(C.muted, 1)
       .text(e.sub, TX, y + 18, { lineBreak: false });
    // Pointillés
    const tw  = doc.widthOfString(e.title, { fontSize: 11 });
    const pgStr = String(e.pg);
    const pgW   = doc.widthOfString(pgStr, { fontSize: 11 });
    doc.moveTo(TX + tw + 8, y + 10)
       .lineTo(ML + W - pgW - 12, y + 10)
       .dash(1.5, { space: 3 }).strokeColor(C.border).stroke();
    doc.undash();
    // Numéro de page (droite)
    doc.font('Helvetica-Bold').fontSize(11).fillColor(C.muted, 1)
       .text(pgStr, ML, y + 6, { width: W, align: 'right', lineBreak: false });
    doc.moveDown(1.7);
  });

  // Encadré résumé investigation
  doc.moveDown(1.2);
  needsPage(doc, 100);
  const boxY = doc.y;
  const boxH = 92;
  const BX   = ML + 14;
  doc.roundedRect(ML, boxY, W, boxH, 5).fill(C.lightBg);
  doc.rect(ML, boxY, 4, boxH).fill(accent);

  doc.font('Helvetica-Bold').fontSize(8).fillColor(C.muted, 1)
     .text(rs('fiche_label', lang), BX, boxY + 12, { lineBreak: false, characterSpacing: 0.6 });
  doc.font('Helvetica-Bold').fontSize(11).fillColor(C.text, 1)
     .text(safe(investigation.title), BX, boxY + 26, { width: W - 24, lineBreak: false, ellipsis: true });

  const infoLine = [
    `${rs('analyst_label', lang)} : ${safe((analyst && analyst.display_name) || 'N/A')}`,
    `${rs('severity_label', lang)} : ${(safe(investigation.severity) || 'N/A').toUpperCase()}`,
    `${rs('status_label', lang)} : ${formatStatus(investigation.status, lang)}`,
  ].join('   ·   ');
  doc.font('Helvetica').fontSize(9).fillColor(C.muted, 1)
     .text(infoLine, BX, boxY + 46, { width: W - 24, lineBreak: false });
  doc.font('Helvetica').fontSize(9).fillColor(C.muted, 1)
     .text(`${rs('created_label', lang)} : ${fmtDate(investigation.created_at, lang)}   ·   ${rs('updated_label', lang)} : ${fmtDate(investigation.updated_at || investigation.created_at, lang)}`,
           BX, boxY + 62, { width: W - 24, lineBreak: false });
}

// ─────────────────────────────────────────────────────────────────────────────
// Titre de section numéroté
// ─────────────────────────────────────────────────────────────────────────────
function sectionTitle(doc, num, title, accent) {
  doc.moveDown(1.2);
  const y  = doc.y;
  const ML = doc.page.margins.left;
  const W  = doc.page.width - ML - doc.page.margins.right;

  doc.rect(ML, y, 4, 24).fill(accent);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(accent, 1)
     .text(num, ML + 10, y + 2, { lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(15).fillColor(C.text, 1)
     .text(safe(title), ML + 24, y, { width: W - 24 });

  doc.moveDown(0.25);
  doc.rect(ML, doc.y, W, 0.5).fill(C.border);
  doc.moveDown(0.75);
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu Markdown → PDF
// ─────────────────────────────────────────────────────────────────────────────
function renderMd(doc, markdown, accent) {
  const ML = doc.page.margins.left;
  const W  = doc.page.width - ML - doc.page.margins.right;
  parseMd(markdown).forEach(block => {
    needsPage(doc, 30);
    switch (block.t) {
      case 'p':
        doc.font('Helvetica').fontSize(10).fillColor(C.text, 1)
           .text(block.content, ML, doc.y, { width: W, lineGap: 2.5 });
        doc.moveDown(0.4);
        break;
      case 'h2':
        doc.moveDown(0.6);
        doc.font('Helvetica-Bold').fontSize(12.5).fillColor(C.text, 1)
           .text(block.content, ML, doc.y, { width: W });
        doc.moveDown(0.2);
        break;
      case 'h3':
        doc.font('Helvetica-Bold').fontSize(10.5).fillColor(C.muted, 1)
           .text(block.content, ML, doc.y, { width: W });
        doc.moveDown(0.2);
        break;
      case 'li':
        doc.font('Helvetica').fontSize(10).fillColor(C.text, 1)
           .text(`•  ${block.content}`, ML + 12, doc.y, { width: W - 12, lineGap: 1 });
        doc.moveDown(0.15);
        break;
      case 'code':
        needsPage(doc, Math.min(block.content.split('\n').length * 11.5 + 36, 200));
        renderCodeBlock(doc, block.lang, block.content);
        break;
      case 'hr':
        doc.rect(ML, doc.y + 4, W, 0.5).fill(C.border);
        doc.moveDown(0.6);
        break;
      case 'br':
        doc.moveDown(0.3);
        break;
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Bloc de code (fond sombre style VS Code)
// ─────────────────────────────────────────────────────────────────────────────
function renderCodeBlock(doc, lang, content) {
  const ML     = doc.page.margins.left;
  const W      = doc.page.width - ML - doc.page.margins.right;
  const lines  = safe(content).split('\n');
  const LH     = 11.5;
  const totalH = lines.length * LH + 34;
  const startY = doc.y;

  doc.roundedRect(ML, startY, W, totalH, 4).fill(C.codeBg);
  doc.rect(ML, startY, W, 18).fill('#161b22');
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#58a6ff', 1)
     .text((lang || 'code').toUpperCase(), ML + 8, startY + 5, { lineBreak: false });

  lines.forEach((line, i) => {
    doc.font('Courier').fontSize(8).fillColor('#e6edf3', 1)
       .text(line || ' ', ML + 8, startY + 22 + i * LH, { width: W - 16, lineBreak: false });
  });

  doc.y = startY + totalH + 8;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tableau IoCs
// ─────────────────────────────────────────────────────────────────────────────
function renderIoCs(doc, iocs, accent, lang) {
  const ML  = doc.page.margins.left;
  const MR  = doc.page.margins.right;
  const W   = doc.page.width - ML - MR;
  const ROW = 21;

  // Column positions derived from ML so they scale with any margin
  const PAD = 8;
  const x0  = ML + PAD;                  // TYPE start
  const x1  = x0 + 62  + 4;             // INDICATOR start
  const x2  = x1 + 185 + 4;             // SEVERITY start
  const x3  = x2 + 76  + 4;             // CONTEXT start
  const xR  = ML + W   - PAD;            // right edge
  const cols = [
    { label: rs('col_type',      lang), x: x0, w: 62         },
    { label: rs('col_indicator', lang), x: x1, w: 185        },
    { label: rs('col_severity',  lang), x: x2, w: 76         },
    { label: rs('col_context',   lang), x: x3, w: xR - x3    },
  ];

  // En-tête tableau
  const hY = doc.y;
  doc.rect(ML, hY, W, ROW + 2).fill('#1e293b');
  doc.font('Helvetica-Bold').fontSize(8).fillColor('#ffffff', 1);
  cols.forEach(c => doc.text(c.label, c.x, hY + 7, { width: c.w, lineBreak: false, characterSpacing: 0.3 }));
  doc.y = hY + ROW + 2;

  iocs.forEach((ioc, i) => {
    needsPage(doc, ROW + 2);
    const rY = doc.y;
    const bg = i % 2 === 0 ? '#ffffff' : '#f8fafc';
    doc.rect(ML, rY, W, ROW).fill(bg);

    const srHex = sevColor(ioc.severity);
    doc.rect(ML, rY, 3, ROW).fill(srHex);

    doc.font('Helvetica-Bold').fontSize(8.5).fillColor(C.text, 1)
       .text((safe(ioc.type) || 'OTHER').toUpperCase(), x0, rY + 6, { width: 62, lineBreak: false });
    doc.font('Courier').fontSize(8).fillColor(C.text, 1)
       .text(safe(ioc.value), x1, rY + 6, { width: 185, lineBreak: false, ellipsis: true });

    doc.roundedRect(x2, rY + 4, 72, 13, 2).fill(srHex);
    doc.font('Helvetica-Bold').fontSize(7).fillColor('#ffffff', 1)
       .text((safe(ioc.severity) || 'MEDIUM').toUpperCase(), x2, rY + 7, { width: 72, align: 'center', lineBreak: false });

    const ctx = safe(ioc.description || ioc.context || '—');
    doc.font('Helvetica').fontSize(8).fillColor(C.muted, 1)
       .text(ctx, x3, rY + 6, { width: cols[3].w, lineBreak: false, ellipsis: true });

    doc.rect(ML, rY + ROW, W, 0.3).fill(C.border);
    doc.y = rY + ROW;
  });

  doc.moveDown(0.8);
  const mal = iocs.filter(i => ['critical','high'].includes((i.severity||'').toLowerCase()) || i.malicious).length;
  doc.font('Helvetica').fontSize(8.5).fillColor(C.muted, 1)
     .text(`${rs('ioc_total', lang)} : ${iocs.length}  ·  ${rs('ioc_critical_high', lang)} : ${mal}  ·  ${rs('ioc_others', lang)} : ${iocs.length - mal}`, ML);
  doc.moveDown(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding individuel
// ─────────────────────────────────────────────────────────────────────────────
function renderFinding(doc, finding, accent, lang) {
  const ML = doc.page.margins.left;
  const W  = doc.page.width - ML - doc.page.margins.right;
  const sevRgb  = hex2rgb(sevColor(finding.severity));
  const sevHex  = rgb2hex(sevRgb);
  const bgLight = rgb2hex([
    Math.round(sevRgb[0] * 0.12 + 255 * 0.88),
    Math.round(sevRgb[1] * 0.12 + 255 * 0.88),
    Math.round(sevRgb[2] * 0.12 + 255 * 0.88),
  ]);

  const typeLabels = {
    finding:          rs('event_finding',          lang),
    initial_access:   rs('event_initial_access',   lang),
    lateral_movement: rs('event_lateral_movement', lang),
    ioc_detected:     rs('event_ioc_detected',     lang),
    exfiltration:     rs('event_exfiltration',     lang),
    custom:           rs('event_custom',           lang),
  };
  const typeLabel = typeLabels[finding.event_type] || rs('event_finding', lang);
  const dateFmt = finding.event_at
    ? new Date(finding.event_at).toLocaleString(rs('locale', lang), { dateStyle: 'medium', timeStyle: 'short' })
    : rs('date_unknown', lang);

  const cardY = doc.y;

  // En-tête de la carte finding
  doc.rect(ML, cardY, W, 24).fill(bgLight);
  doc.rect(ML, cardY, 4, 24).fill(sevHex);

  // Type + date (gauche)
  doc.font('Helvetica-Bold').fontSize(8).fillColor(sevHex, 1)
     .text(typeLabel.toUpperCase(), ML + 10, cardY + 5, { lineBreak: false, characterSpacing: 0.3 });
  doc.font('Helvetica').fontSize(8).fillColor(C.muted, 1)
     .text(`  ·  ${dateFmt}`, ML + 10 + doc.widthOfString(typeLabel.toUpperCase(), {fontSize:8}), cardY + 5,
           { lineBreak: false });

  // Badge sévérité (droite)
  const sLabel = (safe(finding.severity) || 'MEDIUM').toUpperCase();
  const sLW = doc.widthOfString(sLabel, { fontSize: 7.5 }) + 14;
  doc.roundedRect(ML + W - sLW - 4, cardY + 5, sLW, 14, 2).fill(sevHex);
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#ffffff', 1)
     .text(sLabel, ML + W - sLW - 4, cardY + 8, { width: sLW, align: 'center', lineBreak: false });

  doc.y = cardY + 28;

  // Titre finding
  doc.font('Helvetica-Bold').fontSize(11).fillColor(C.text, 1)
     .text(safe(finding.title) || rs('no_title', lang), ML, doc.y, { width: W });
  doc.moveDown(0.3);

  // Contenu / description
  const desc = safe(finding.description || finding.content || '');
  if (desc) {
    doc.font('Helvetica').fontSize(9.5).fillColor(C.text, 1)
       .text(desc, ML, doc.y, { width: W, lineGap: 2 });
    doc.moveDown(0.4);
  }

  // Blocs de code associés
  let cbs = [];
  try { cbs = JSON.parse(safe(finding.code_blocks) || '[]'); } catch(e) {}
  cbs.forEach(cb => {
    if (!cb.content) return;
    needsPage(doc, safe(cb.content).split('\n').length * 11.5 + 40);
    renderCodeBlock(doc, cb.lang || 'kql', cb.content);
  });

  doc.rect(ML, doc.y, W, 0.5).fill(C.border);
  doc.moveDown(1.1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Vérification d'espace restant — ajoute une page si besoin
// ─────────────────────────────────────────────────────────────────────────────
function needsPage(doc, height) {
  if (doc.page.height - doc.page.margins.bottom - doc.y < (height || 60)) {
    doc.addPage();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Markdown → blocs DOCX
// ─────────────────────────────────────────────────────────────────────────────
function parseMarkdownBlocks(md) {
  if (!md) return [];
  const blocks = [];
  const lines  = md.split('\n');
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith('```')) {
      const lang = line.slice(3).trim() || 'code';
      const code = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) { code.push(lines[i]); i++; }
      blocks.push({ type: 'code', lang, content: code.join('\n') });
      i++; continue;
    }
    if (line.startsWith('## '))  { blocks.push({ type: 'h2', content: line.slice(3).trim() }); i++; continue; }
    if (line.startsWith('### ')) { blocks.push({ type: 'h3', content: line.slice(4).trim() }); i++; continue; }
    if (line.trim() === '---')   { blocks.push({ type: 'hr' }); i++; continue; }
    if (line.match(/^[-*] /))   { blocks.push({ type: 'bullet', content: line.slice(2).trim() }); i++; continue; }
    if (line.trim() === '')      { blocks.push({ type: 'spacer' }); i++; continue; }
    const text = line.replace(/\*\*([^*]+)\*\*/g, '$1').replace(/\*([^*]+)\*/g, '$1')
                     .replace(/`([^`]+)`/g, '$1').trim();
    if (text) blocks.push({ type: 'paragraph', content: text });
    i++;
  }
  return blocks;
}

// ─────────────────────────────────────────────────────────────────────────────
// generateDOCX — retourne Promise<Buffer>
// ─────────────────────────────────────────────────────────────────────────────
async function generateDOCX(investigation, findings, iocs, analyst, settings, lang = 'fr') {
  const accentHex   = ((settings && settings.report_header_color) || '#e63946').replace('#', '');
  const companyName = (settings && settings.company_name)     || 'KQLab';
  const companySub  = (settings && settings.company_subtitle) || 'Security Operations Center';
  const logoData    = (settings && settings.company_logo)     || null;

  // ── Page de couverture ────────────────────────────────────────────────────
  const coverChildren = [];

  // Logo ou nom société
  if (logoData && logoData.startsWith('data:image/')) {
    try {
      const buf       = Buffer.from(logoData.split(',')[1], 'base64');
      const mimeMatch = logoData.match(/^data:image\/(\w+);/);
      coverChildren.push(new Paragraph({
        children: [new ImageRun({ data: buf, transformation: { width: 160, height: 64 }, type: (mimeMatch && mimeMatch[1]) || 'png' })],
        spacing: { after: 600 },
      }));
    } catch(e) {
      coverChildren.push(..._docxCoverCompany(companyName, companySub, accentHex));
    }
  } else {
    coverChildren.push(..._docxCoverCompany(companyName, companySub, accentHex));
  }

  // Libellé type rapport
  coverChildren.push(new Paragraph({
    children: [new TextRun({ text: rs('cover_type', lang), size: 16, color: 'AAAAAA', characterSpacing: 80 })],
    spacing: { before: 1600, after: 160 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: accentHex } },
  }));

  // Titre
  coverChildren.push(new Paragraph({
    children: [new TextRun({ text: safe(investigation.title), bold: true, size: 52, color: '111827' })],
    spacing: { before: 240, after: 600 },
  }));

  // Tableau méta couverture
  coverChildren.push(_docxCoverMetaTable(investigation, analyst, accentHex, lang));

  // ── Corps du rapport ──────────────────────────────────────────────────────
  const bodyChildren = [];

  // Section 01
  bodyChildren.push(_docxSectionHeading(`01 — ${rs('sec_01', lang)}`, accentHex));
  const summary = investigation.executive_summary || investigation.description || '';
  parseMarkdownBlocks(summary).forEach(b => bodyChildren.push(..._blockToDocx(b, accentHex)));
  if (!summary) bodyChildren.push(_docxItalic(rs('no_summary_plain', lang)));

  // Section 02 — IoCs
  if (iocs && iocs.length > 0) {
    bodyChildren.push(_docxSectionHeading(`02 — ${rs('sec_02', lang)} (${iocs.length})`, accentHex));
    bodyChildren.push(_docxIoCTable(iocs, lang));
    const mal = iocs.filter(i => i.severity === 'critical' || i.severity === 'high' || i.malicious).length;
    bodyChildren.push(new Paragraph({
      children: [new TextRun({
        text: `${rs('ioc_total', lang)} : ${iocs.length}  ·  ${rs('ioc_critical_high', lang)} : ${mal}  ·  ${rs('ioc_others', lang)} : ${iocs.length - mal}`,
        size: 18, color: '6B7280', italics: true,
      })],
      spacing: { before: 80, after: 120 },
    }));
  }

  // Section 03 — Timeline
  if (findings && findings.length > 0) {
    bodyChildren.push(_docxSectionHeading(`03 — ${rs('sec_03', lang)} (${findings.length})`, accentHex));
    findings.forEach(f => bodyChildren.push(..._docxFinding(f, accentHex, lang)));
  }

  // Section 04 — Conclusion
  bodyChildren.push(_docxSectionHeading(`04 — ${rs('sec_04', lang)}`, accentHex));
  const conclusion = safe(investigation.conclusion);
  parseMarkdownBlocks(conclusion).forEach(b => bodyChildren.push(..._blockToDocx(b, accentHex)));
  if (!conclusion) bodyChildren.push(_docxItalic(rs('no_conclusion_plain', lang)));

  // Signature
  bodyChildren.push(new Paragraph({ children: [], spacing: { before: 800 } }));
  bodyChildren.push(new Paragraph({
    children: [new TextRun({ text: safe((analyst && analyst.display_name) || rs('analyst_label', lang)), bold: true, size: 24 })],
    border: { top: { style: BorderStyle.SINGLE, size: 4, color: 'E5E7EB' } },
    spacing: { before: 200, after: 80 },
  }));
  bodyChildren.push(new Paragraph({
    children: [new TextRun({ text: safe((analyst && analyst.role) || rs('analyst_role', lang)), size: 20, color: '6B7280' })],
    spacing: { after: 60 },
  }));
  bodyChildren.push(new Paragraph({
    children: [new TextRun({ text: fmtDate(Date.now(), lang), size: 18, color: '9CA3AF' })],
  }));

  // ── Document final ────────────────────────────────────────────────────────
  // Twips: 1 inch = 1440, 1 mm ≈ 56.7
  const _MARGIN_SIDE = 720;  // ~12.7mm  (matches PDF 36pt = narrow)
  const _MARGIN_TOP  = 1080; // ~19mm
  const _MARGIN_BOT  = 720;  // ~12.7mm
  const _HDR_DIST    = 600;  // ~10.6mm header/footer distance

  const docx = new Document({
    styles: {
      default: { document: { run: { font: 'Calibri', size: 22, color: '111827' } } },
    },
    sections: [
      // Couverture (section sans en-tête/pied)
      {
        properties: { page: { margin: { top: _MARGIN_TOP, right: _MARGIN_SIDE, bottom: _MARGIN_BOT, left: _MARGIN_SIDE, header: _HDR_DIST, footer: _HDR_DIST } } },
        children: coverChildren,
      },
      // Corps avec en-tête et pied de page
      {
        properties: { page: { margin: { top: 1800, right: _MARGIN_SIDE, bottom: _MARGIN_BOT, left: _MARGIN_SIDE, header: _HDR_DIST, footer: _HDR_DIST } } },
        headers: { default: _docxHeader(companyName, safe(investigation.title), logoData, accentHex) },
        footers: { default: _docxFooter(investigation, accentHex, lang) },
        children: bodyChildren,
      },
    ],
  });

  return Packer.toBuffer(docx);
}

// ── Helpers DOCX privés ───────────────────────────────────────────────────────

function _docxCoverCompany(name, sub, accentHex) {
  return [
    new Paragraph({
      children: [new TextRun({ text: safe(name), bold: true, size: 44, color: accentHex })],
      spacing: { after: 100 },
    }),
    new Paragraph({
      children: [new TextRun({ text: safe(sub), size: 22, color: '6B7280' })],
      spacing: { after: 0 },
    }),
  ];
}

function _docxCoverMetaTable(investigation, analyst, accentHex, lang) {
  const cells = [
    [rs('meta_analyst',        lang), safe((analyst && analyst.display_name) || 'N/A')],
    [rs('meta_created',        lang), safe(investigation.created_at || '').slice(0, 10)],
    [rs('meta_status',         lang), formatStatus(investigation.status, lang)],
    [rs('meta_severity',       lang), (safe(investigation.severity) || 'medium').toUpperCase()],
    [rs('meta_classification', lang), rs('meta_classification_v', lang)],
  ];
  const nb  = { style: BorderStyle.NONE };
  const bb  = { style: BorderStyle.SINGLE, size: 4, color: 'E5E7EB' };
  const tb  = { style: BorderStyle.SINGLE, size: 8, color: accentHex };
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [new TableRow({
      children: cells.map(([label, value]) => new TableCell({
        children: [
          new Paragraph({ children: [new TextRun({ text: label, size: 14, color: '9CA3AF', characterSpacing: 60 })], spacing: { after: 40 } }),
          new Paragraph({ children: [new TextRun({ text: value, bold: true, size: 22 })],           spacing: { after: 40 } }),
        ],
        borders: { top: tb, left: nb, right: nb, bottom: bb },
        margins: { top: 180, bottom: 180, left: 160, right: 160 },
      })),
    })],
  });
}

function _docxSectionHeading(title, accentHex) {
  return new Paragraph({
    children: [new TextRun({ text: safe(title), bold: true, size: 30, color: accentHex })],
    border:  { bottom: { style: BorderStyle.SINGLE, size: 6, color: 'E5E7EB' } },
    spacing: { before: 560, after: 240 },
  });
}

function _docxItalic(text) {
  return new Paragraph({
    children: [new TextRun({ text: safe(text), italics: true, color: '9CA3AF', size: 22 })],
    spacing: { after: 80 },
  });
}

function _docxIoCTable(iocs, lang) {
  const hdrCells = [
    rs('col_type',      lang),
    rs('col_indicator', lang),
    rs('col_severity',  lang),
    rs('col_context',   lang),
  ].map(h =>
    new TableCell({
      children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 18, color: 'FFFFFF' })], spacing: { before: 80, after: 80 } })],
      shading:  { type: ShadingType.SOLID, color: '1E293B', fill: '1E293B' },
      margins:  { top: 80, bottom: 80, left: 120, right: 120 },
    })
  );
  const dataRows = iocs.map((ioc, i) => {
    const shade = i % 2 === 0 ? 'FFFFFF' : 'F8FAFC';
    const cell  = (text, opts) => new TableCell({
      children: [new Paragraph({ children: [new TextRun(Object.assign({ text: safe(text), size: 18 }, opts || {}))], spacing: { before: 60, after: 60 } })],
      shading: { type: ShadingType.SOLID, color: shade, fill: shade },
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
    });
    return new TableRow({ children: [
      cell((safe(ioc.type) || 'OTHER').toUpperCase(), { bold: true }),
      cell(safe(ioc.value), { font: 'Courier New' }),
      cell((safe(ioc.severity) || 'MEDIUM').toUpperCase(), { bold: true }),
      cell(safe(ioc.description || ioc.context || '—'), { color: '6B7280' }),
    ]});
  });
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows:  [new TableRow({ children: hdrCells }), ...dataRows],
  });
}

function _blockToDocx(block, accentHex) {
  switch (block.type) {
    case 'paragraph':
      return [new Paragraph({ children: [new TextRun({ text: block.content, size: 22 })], spacing: { after: 120 } })];
    case 'h2':
      return [new Paragraph({ children: [new TextRun({ text: block.content, bold: true, size: 28, color: accentHex })], spacing: { before: 240, after: 100 } })];
    case 'h3':
      return [new Paragraph({ children: [new TextRun({ text: block.content, bold: true, size: 24 })], spacing: { before: 180, after: 80 } })];
    case 'bullet':
      return [new Paragraph({ children: [new TextRun({ text: `•  ${block.content}`, size: 22 })], indent: { left: 360 }, spacing: { after: 60 } })];
    case 'code': {
      const codeLines = safe(block.content).split('\n');
      return [
        new Paragraph({ children: [new TextRun({ text: (block.lang || 'code').toUpperCase(), bold: true, size: 16, color: '58A6FF', font: 'Courier New' })], shading: { type: ShadingType.SOLID, color: '161B22', fill: '161B22' }, spacing: { before: 100 } }),
        ...codeLines.map((line, idx) => new Paragraph({
          children: [new TextRun({ text: line || ' ', font: 'Courier New', size: 18, color: 'E6EDF3' })],
          shading:  { type: ShadingType.SOLID, color: '0D1117', fill: '0D1117' },
          spacing:  idx === codeLines.length - 1 ? { after: 140 } : { after: 0 },
          indent:   { left: 200 },
        })),
      ];
    }
    case 'hr':
      return [new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'E5E7EB' } }, spacing: { before: 120, after: 120 } })];
    default:
      return [new Paragraph({ children: [], spacing: { after: 60 } })];
  }
}

function _docxFinding(finding, accentHex, lang) {
  const blocks = [];
  const sevLabel = (safe(finding.severity) || 'MEDIUM').toUpperCase();
  const typeLabels = {
    finding:          rs('event_finding',          lang),
    initial_access:   rs('event_initial_access',   lang),
    lateral_movement: rs('event_lateral_movement', lang),
    ioc_detected:     rs('event_ioc_detected',     lang),
    exfiltration:     rs('event_exfiltration',     lang),
    custom:           rs('event_custom_short',     lang),
  };
  const typeLabel = typeLabels[finding.event_type] || rs('event_finding', lang);

  blocks.push(new Paragraph({
    children: [
      new TextRun({ text: `[${sevLabel}] `, bold: true, size: 22, color: accentHex }),
      new TextRun({ text: safe(finding.title) || rs('no_title', lang), bold: true, size: 22 }),
    ],
    border:  { left: { style: BorderStyle.SINGLE, size: 16, color: accentHex } },
    indent:  { left: 240 },
    spacing: { before: 320, after: 80 },
  }));

  if (finding.event_at) {
    blocks.push(new Paragraph({
      children: [new TextRun({
        text: `${typeLabel}  ·  ${new Date(finding.event_at).toLocaleString(rs('locale', lang), { dateStyle: 'long', timeStyle: 'short' })}`,
        size: 18, color: '6B7280', italics: true,
      })],
      indent:  { left: 240 },
      spacing: { after: 100 },
    }));
  }

  const desc = safe(finding.description || finding.content);
  if (desc) {
    blocks.push(new Paragraph({ children: [new TextRun({ text: desc, size: 22 })], spacing: { after: 120 } }));
  }

  let cbs = [];
  try { cbs = JSON.parse(safe(finding.code_blocks) || '[]'); } catch(e) {}
  cbs.forEach(cb => {
    if (!cb.content) return;
    blocks.push(new Paragraph({ children: [new TextRun({ text: (cb.lang || 'kql').toUpperCase(), bold: true, size: 16, color: '58A6FF', font: 'Courier New' })], shading: { type: ShadingType.SOLID, color: '161B22', fill: '161B22' }, spacing: { before: 80 } }));
    safe(cb.content).split('\n').forEach((line, idx, arr) => {
      blocks.push(new Paragraph({
        children: [new TextRun({ text: line || ' ', font: 'Courier New', size: 18, color: 'E6EDF3' })],
        shading:  { type: ShadingType.SOLID, color: '0D1117', fill: '0D1117' },
        spacing:  idx === arr.length - 1 ? { after: 140 } : { after: 0 },
        indent:   { left: 200 },
      }));
    });
  });

  blocks.push(new Paragraph({ border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: 'E5E7EB' } }, spacing: { before: 80, after: 80 } }));
  return blocks;
}

function _docxHeader(companyName, reportTitle, logoData, accentHex) {
  let children;
  if (logoData && logoData.startsWith('data:image/')) {
    try {
      const buf       = Buffer.from(logoData.split(',')[1], 'base64');
      const mimeMatch = logoData.match(/^data:image\/(\w+);/);
      children = [new Paragraph({
        children: [
          new ImageRun({ data: buf, transformation: { width: 80, height: 30 }, type: (mimeMatch && mimeMatch[1]) || 'png' }),
          new TextRun({ text: `  ${safe(companyName).toUpperCase()}`, bold: true, size: 16, color: accentHex, characterSpacing: 40 }),
          new TextRun({ text: `  —  ${safe(reportTitle)}`, size: 16, color: '9CA3AF' }),
        ],
        border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: accentHex } },
        spacing: { before: 60, after: 80 },
      })];
    } catch(e) {
      children = [_docxSimpleHeader(companyName, reportTitle, accentHex)];
    }
  } else {
    children = [_docxSimpleHeader(companyName, reportTitle, accentHex)];
  }
  return new Header({ children });
}

function _docxSimpleHeader(companyName, reportTitle, accentHex) {
  return new Paragraph({
    children: [
      new TextRun({ text: safe(companyName).toUpperCase(), bold: true, size: 16, color: accentHex, characterSpacing: 40 }),
      new TextRun({ text: `  —  ${safe(reportTitle)}`, size: 16, color: '9CA3AF' }),
    ],
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: accentHex } },
    spacing: { before: 60, after: 80 },
  });
}

function _docxFooter(investigation, accentHex, lang) {
  return new Footer({
    children: [new Paragraph({
      children: [
        new TextRun({ text: rs('confidential_docx', lang), size: 16, color: '9CA3AF' }),
        new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '9CA3AF' }),
        new TextRun({ text: ' / ', size: 16, color: '9CA3AF' }),
        new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, color: '9CA3AF' }),
        new TextRun({ text: `  |  INV-${safe(investigation.id).slice(-8).toUpperCase()}`, size: 16, color: 'CCCCCC' }),
      ],
      border:    { top: { style: BorderStyle.SINGLE, size: 4, color: 'E5E7EB' } },
      alignment: AlignmentType.CENTER,
      spacing:   { before: 80 },
    })],
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// generateQueryPDF — single-query reference card — returns Promise<Buffer>
// ─────────────────────────────────────────────────────────────────────────────
async function generateQueryPDF(query, settings, lang) {
  lang = lang || 'fr';
  const logoBuffer = await prepareLogoBuffer((settings && settings.company_logo) || null);

  return new Promise((resolve, reject) => {
    const accent     = (settings && settings.report_header_color) || '#e63946';
    const company    = (settings && settings.company_name)        || 'KQLab';
    const accentRgb  = hex2rgb(accent);

    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 50, bottom: 50, left: 50, right: 50 },
      info: {
        Title:   safe(query.title),
        Author:  company,
        Creator: 'KQLab — Query Reference',
        Subject: 'KQL Query Reference Sheet',
      },
    });

    const bufs = [];
    doc.on('data', b => bufs.push(b));
    doc.on('end',  () => resolve(Buffer.concat(bufs)));
    doc.on('error', reject);

    const W = doc.page.width;
    const PL = 50, PR = 50, BODY_W = W - PL - PR;

    // ── Header bar ──────────────────────────────────────────────────────────
    doc.rect(0, 0, W, 52).fill(accent);

    let logoX = PL;
    if (logoBuffer) {
      try { doc.image(logoBuffer, PL, 10, { height: 32, fit: [64, 32] }); logoX = PL + 72; } catch(e) {}
    } else {
      const mono = safe(company).trim().split(/\s+/).map(w => w[0]).join('').slice(0,2).toUpperCase() || 'KV';
      doc.roundedRect(PL, 10, 32, 32, 4).fill(rgb2hex(darker(accentRgb, 30)));
      doc.font('Helvetica-Bold').fontSize(14).fillColor('#fff')
         .text(mono, PL, 18, { width: 32, align: 'center', lineBreak: false });
      logoX = PL + 40;
    }
    doc.font('Helvetica-Bold').fontSize(11).fillColor('#ffffff', 1)
       .text(safe(company).toUpperCase(), logoX, 16, { lineBreak: false, characterSpacing: 0.4 });
    doc.font('Helvetica').fontSize(9).fillColor('#ffffff', 0.75)
       .text('Query Reference Sheet', logoX, 30, { lineBreak: false });

    doc.y = 70;

    // ── Title + severity badge ───────────────────────────────────────────────
    const sevHex = sevColor(query.severity || 'medium');
    const sevText = (safe(query.severity) || 'medium').toUpperCase();
    const badgeW = doc.widthOfString(sevText, { fontSize: 9 }) + 16;
    doc.roundedRect(W - PR - badgeW, 70, badgeW, 18, 3).fill(sevHex);
    doc.font('Helvetica-Bold').fontSize(9).fillColor('#ffffff')
       .text(sevText, W - PR - badgeW, 75, { width: badgeW, align: 'center', lineBreak: false });

    doc.font('Helvetica-Bold').fontSize(17).fillColor(C.text)
       .text(safe(query.title), PL, 70, { width: BODY_W - badgeW - 10 });
    doc.moveDown(0.3);

    // ── Meta row ────────────────────────────────────────────────────────────
    const metaY = doc.y;
    const meta = [
      safe(query.language || 'KQL'),
      safe(query.environment || 'Defender'),
      safe(query.playbook || ''),
    ].filter(Boolean).join('  ·  ');
    doc.font('Helvetica').fontSize(9.5).fillColor(C.muted)
       .text(meta, PL, metaY, { lineBreak: false });
    doc.moveDown(0.6);
    doc.rect(PL, doc.y, BODY_W, 0.5).fill(C.border);
    doc.moveDown(0.7);

    // ── Description ─────────────────────────────────────────────────────────
    if (query.description && query.description.trim()) {
      doc.font('Helvetica').fontSize(10).fillColor(C.text)
         .text(safe(query.description), PL, doc.y, { width: BODY_W, lineGap: 2.5 });
      doc.moveDown(0.8);
    }

    // ── KQL code block ──────────────────────────────────────────────────────
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted, 1)
       .text((query.language || 'KQL').toUpperCase() + ' QUERY', PL, doc.y, { lineBreak: false, characterSpacing: 0.5 });
    doc.moveDown(0.4);
    renderCodeBlock(doc, query.language || 'kql', safe(query.kql || ''));
    doc.moveDown(0.6);

    // ── MITRE ATT&CK ────────────────────────────────────────────────────────
    let mitre = [];
    try { mitre = JSON.parse(query.mitre || '[]'); } catch(e) {}
    if (mitre.length) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted)
         .text('MITRE ATT&CK', PL, doc.y, { lineBreak: false, characterSpacing: 0.5 });
      doc.moveDown(0.4);
      const chipY = doc.y;
      let cx = PL;
      mitre.forEach(function(id) {
        const chipW = doc.widthOfString(id, { fontSize: 8 }) + 14;
        if (cx + chipW > W - PR) { doc.y += 16; cx = PL; }
        doc.roundedRect(cx, doc.y, chipW, 14, 3).fill(accent + '22');
        doc.font('Helvetica-Bold').fontSize(8).fillColor(accent)
           .text(id, cx + 7, doc.y + 3, { lineBreak: false });
        cx += chipW + 6;
      });
      doc.y += 18;
      doc.moveDown(0.4);
    }

    // ── Tags ────────────────────────────────────────────────────────────────
    let tags = [];
    try { tags = JSON.parse(query.tags || '[]'); } catch(e) {}
    if (tags.length) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted)
         .text('TAGS', PL, doc.y, { lineBreak: false, characterSpacing: 0.5 });
      doc.moveDown(0.4);
      let tx = PL;
      tags.forEach(function(tag) {
        const tw = doc.widthOfString(tag, { fontSize: 8 }) + 14;
        if (tx + tw > W - PR) { doc.y += 16; tx = PL; }
        doc.roundedRect(tx, doc.y, tw, 14, 3).fill(C.lightBg2);
        doc.rect(tx, doc.y, 3, 14).fill(C.border);
        doc.font('Helvetica').fontSize(8).fillColor(C.text)
           .text(safe(tag), tx + 8, doc.y + 3, { lineBreak: false });
        tx += tw + 5;
      });
      doc.y += 18;
      doc.moveDown(0.4);
    }

    // ── Footer ──────────────────────────────────────────────────────────────
    const FY = doc.page.height - 34;
    doc.rect(PL, FY, BODY_W, 0.5).fill(C.border);
    doc.font('Helvetica').fontSize(7.5).fillColor(C.muted)
       .text(safe(company) + '  ·  ' + company + ' KQL Reference  ·  ' + new Date().toLocaleDateString('fr-FR'), PL, FY + 8, { lineBreak: false });
    doc.font('Helvetica').fontSize(7.5).fillColor(C.muted)
       .text(safe(query.id || ''), 0, FY + 8, { width: W - PR, align: 'right', lineBreak: false });

    doc.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// generateHTML — self-contained HTML report for blog posts / tickets
// ─────────────────────────────────────────────────────────────────────────────
function generateHTML(investigation, findings, iocs, analyst, settings, lang) {
  lang = lang || 'fr';
  const accent     = (settings && settings.report_header_color) || '#e63946';
  const company    = (settings && settings.company_name)        || 'KQLab';
  const companySub = (settings && settings.company_subtitle)    || 'Security Operations Center';

  function esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Block-based MD→HTML using the shared parseMd() — avoids \n corruption inside <pre>
  function mdToHtml(md) {
    if (!md) return '';
    return parseMd(md).map(function(block) {
      switch (block.t) {
        case 'p':
          return `<p style="margin:0 0 14px;color:#374151;line-height:1.75">${esc(block.content)}</p>`;
        case 'h2':
          return `<h3 style="font-size:17px;font-weight:700;margin:24px 0 10px;color:#111827;padding-left:10px;border-left:3px solid ${accent}">${esc(block.content)}</h3>`;
        case 'h3':
          return `<h4 style="font-size:15px;font-weight:600;margin:18px 0 8px;color:#374151">${esc(block.content)}</h4>`;
        case 'li':
          return `<div style="margin:5px 0 5px 18px;color:#374151;line-height:1.6">• ${esc(block.content)}</div>`;
        case 'code':
          return `<div style="margin:14px 0"><div style="background:#161b22;color:#58a6ff;padding:5px 14px;border-radius:5px 5px 0 0;font-family:'Courier New',monospace;font-size:11px;font-weight:700;letter-spacing:.5px">${esc((block.lang || 'code').toUpperCase())}</div><pre style="background:#0d1117;color:#e6edf3;padding:14px 16px;margin:0;border-radius:0 0 5px 5px;overflow-x:auto;font-family:'Courier New',monospace;font-size:12.5px;line-height:1.6;white-space:pre"><code>${esc(block.content)}</code></pre></div>`;
        case 'hr':
          return '<hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0">';
        case 'br':
          return '<div style="height:6px"></div>';
        default:
          return '';
      }
    }).join('');
  }

  function sevBadgeHtml(sev) {
    const s = (sev || 'medium').toLowerCase();
    const c = C.sev[s] || C.sev.medium;
    return `<span style="display:inline-block;background:${c};color:#fff;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px">${s.toUpperCase()}</span>`;
  }

  function statusBadgeHtml(status) {
    const colors = { open: '#059669', 'in-progress': '#2563eb', in_progress: '#2563eb', closed: '#6b7280' };
    const c = colors[status] || '#6b7280';
    return `<span style="display:inline-block;background:${c}20;color:${c};padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;border:1px solid ${c}40">${esc(formatStatus(status, lang))}</span>`;
  }

  function sectionHead(num, title) {
    return `<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid #e5e7eb">
      <span style="flex-shrink:0;width:32px;height:32px;background:${accent};color:#fff;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:800;line-height:1">${esc(num)}</span>
      <h2 style="margin:0;font-size:20px;font-weight:800;color:#111827">${esc(title)}</h2>
    </div>`;
  }

  const summary    = safe(investigation.executive_summary || investigation.description || '');
  const conclusion = safe(investigation.conclusion || '');

  // ── IoC table ──────────────────────────────────────────────────────────────
  let iocHtml = '';
  if (iocs && iocs.length) {
    const rows = iocs.map(function(ioc, i) {
      const sev  = (ioc.severity || 'medium').toLowerCase();
      const sevC = C.sev[sev] || C.sev.medium;
      const bg   = i % 2 === 0 ? '#ffffff' : '#f8fafc';
      return `<tr style="background:${bg}">
        <td style="padding:9px 12px;border-left:3px solid ${sevC};font-weight:700;font-size:12px;white-space:nowrap;border-bottom:1px solid #f1f5f9">${esc((ioc.type || 'OTHER').toUpperCase())}</td>
        <td style="padding:9px 12px;font-family:'Courier New',monospace;font-size:12px;word-break:break-all;border-bottom:1px solid #f1f5f9">${esc(ioc.value || '')}</td>
        <td style="padding:9px 12px;white-space:nowrap;border-bottom:1px solid #f1f5f9"><span style="background:${sevC};color:#fff;padding:2px 9px;border-radius:3px;font-size:11px;font-weight:700">${sev.toUpperCase()}</span></td>
        <td style="padding:9px 12px;color:#6b7280;font-size:12.5px;border-bottom:1px solid #f1f5f9">${esc(ioc.description || ioc.context || '—')}</td>
      </tr>`;
    }).join('');
    const mal = iocs.filter(function(i) { return ['critical','high'].includes((i.severity||'').toLowerCase()) || i.malicious; }).length;
    // Wrap table in div for reliable border-radius (Firefox ignores overflow:hidden on <table>)
    iocHtml = `<div style="border-radius:6px;overflow:hidden;border:1px solid #e5e7eb;margin-bottom:10px">
      <table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="background:#1e293b;color:#fff">
          <th style="padding:10px 12px;text-align:left;font-size:11px;letter-spacing:.5px;font-weight:700">${rs('col_type', lang)}</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;letter-spacing:.5px;font-weight:700">${rs('col_indicator', lang)}</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;letter-spacing:.5px;font-weight:700">${rs('col_severity', lang)}</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;letter-spacing:.5px;font-weight:700">${rs('col_context', lang)}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p style="margin:0 0 0;font-size:12px;color:#9ca3af;font-style:italic">
      ${esc(rs('ioc_total', lang))} : ${iocs.length}  ·  ${esc(rs('ioc_critical_high', lang))} : ${mal}  ·  ${esc(rs('ioc_others', lang))} : ${iocs.length - mal}
    </p>`;
  }

  // ── Findings ───────────────────────────────────────────────────────────────
  let findingsHtml = '';
  if (findings && findings.length) {
    findingsHtml = findings.map(function(f) {
      const sev  = (f.severity || 'medium').toLowerCase();
      const sevC = C.sev[sev] || C.sev.medium;
      const sevRgbF = hex2rgb(sevC);
      const bgL  = rgb2hex([
        Math.round(sevRgbF[0] * 0.10 + 255 * 0.90),
        Math.round(sevRgbF[1] * 0.10 + 255 * 0.90),
        Math.round(sevRgbF[2] * 0.10 + 255 * 0.90),
      ]);
      const dateFmt = f.event_at
        ? new Date(f.event_at).toLocaleString(rs('locale', lang), { dateStyle: 'medium', timeStyle: 'short' })
        : rs('date_unknown', lang);
      let cbs = [];
      try { cbs = JSON.parse(safe(f.code_blocks) || '[]'); } catch(e) {}
      const codeHtml = cbs.filter(function(cb) { return cb.content; }).map(function(cb) {
        return `<div style="margin:12px 0">
          <div style="background:#161b22;color:#58a6ff;padding:5px 14px;border-radius:5px 5px 0 0;font-family:monospace;font-size:11px;font-weight:700;letter-spacing:.5px">${esc((cb.lang || 'kql').toUpperCase())}</div>
          <pre style="background:#0d1117;color:#e6edf3;padding:14px 16px;margin:0;border-radius:0 0 5px 5px;overflow-x:auto;font-family:'Courier New',monospace;font-size:12.5px;line-height:1.6;white-space:pre"><code>${esc(cb.content)}</code></pre>
        </div>`;
      }).join('');
      return `<div style="margin-bottom:14px;border:1px solid #e5e7eb;border-radius:7px;overflow:hidden">
        <div style="background:${bgL};padding:10px 14px 10px 18px;border-left:4px solid ${sevC}">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
            <span style="color:${sevC};font-weight:700;font-size:11.5px;text-transform:uppercase;letter-spacing:.6px">${esc((f.event_type || 'finding').toUpperCase())}  ·  ${esc(dateFmt)}</span>
            <span style="background:${sevC};color:#fff;padding:2px 9px;border-radius:3px;font-size:11px;font-weight:700;white-space:nowrap">${sev.toUpperCase()}</span>
          </div>
        </div>
        <div style="padding:16px 18px">
          <h4 style="margin:0 0 10px;font-size:15px;font-weight:700;color:#111827;line-height:1.4">${esc(f.title || rs('no_title', lang))}</h4>
          ${f.description ? `<p style="margin:0 0 12px;color:#374151;font-size:14px;line-height:1.7">${esc(f.description)}</p>` : ''}
          ${codeHtml}
        </div>
      </div>`;
    }).join('');
  }

  const metaCols = [
    [rs('analyst_label',  lang), esc(safe((analyst && analyst.display_name) || 'N/A'))],
    [rs('created_label',  lang), esc(fmtDate(investigation.created_at, lang))],
    [rs('status_label',   lang), statusBadgeHtml(investigation.status)],
    [rs('severity_label', lang), sevBadgeHtml(investigation.severity)],
  ];

  const snippetDesc = summary
    .replace(/```[\s\S]*?```/g, '')
    .replace(/[*_`#>\-]/g, '')
    .trim()
    .slice(0, 280);

  return Promise.resolve(`<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(investigation.title || rs('no_title', lang))} — ${esc(rs('cover_type', lang))}</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica Neue,Arial,sans-serif;font-size:14px;color:#111827;background:#fff;line-height:1.6}
h1,h2,h3,h4{margin:0;line-height:1.3}
p{margin:0 0 12px}
pre,code{font-family:'Courier New',Courier,monospace}
table{border-collapse:collapse}
@media(max-width:600px){
  .cover-inner{padding:32px 20px 28px !important}
  .body-wrap{padding:32px 20px !important}
  .meta-grid{gap:20px !important}
}
</style>
</head>
<body>

<!-- ══ Cover ══════════════════════════════════════════════════════ -->
<div style="background:#161d2a;color:#f1f5f9">
  <div class="cover-inner" style="max-width:900px;margin:0 auto;padding:52px 40px 48px">

    <!-- Brand -->
    <div style="margin-bottom:44px">
      <div style="font-size:20px;font-weight:900;letter-spacing:.8px;color:#f1f5f9">${esc(company.toUpperCase())}</div>
      <div style="font-size:12px;color:#64748b;margin-top:3px">${esc(companySub)}</div>
    </div>

    <!-- Report type label + accent bar -->
    <div style="font-size:10px;font-weight:700;letter-spacing:2.5px;color:${accent};text-transform:uppercase;margin-bottom:8px">${esc(rs('cover_type', lang))}</div>
    <div style="width:48px;height:2px;background:${accent};margin-bottom:24px"></div>

    <!-- Title -->
    <h1 style="font-size:32px;font-weight:900;color:#ffffff;line-height:1.2;margin:0 0 16px;max-width:700px">${esc(investigation.title || rs('no_title', lang))}</h1>

    <!-- Summary snippet -->
    ${snippetDesc ? `<p style="color:#94a3b8;font-size:13.5px;line-height:1.75;max-width:640px;margin:0">${esc(snippetDesc)}${summary.length > 280 ? '…' : ''}</p>` : ''}

    <!-- Meta grid -->
    <div class="meta-grid" style="border-top:1px solid #1e293b;margin-top:36px;padding-top:24px;display:flex;gap:32px;flex-wrap:wrap">
      ${metaCols.map(function([l,v]) {
        return `<div><div style="font-size:10px;letter-spacing:.8px;color:#475569;text-transform:uppercase;margin-bottom:7px">${l}</div><div style="font-size:15px;font-weight:700;color:#e2e8f0">${v}</div></div>`;
      }).join('')}
    </div>
  </div>
</div>

<!-- ══ Body ═══════════════════════════════════════════════════════ -->
<div class="body-wrap" style="max-width:900px;margin:0 auto;padding:52px 40px 64px">

  <!-- 01 — Executive Summary -->
  <div style="margin-bottom:56px">
    ${sectionHead('01', rs('sec_01', lang))}
    <div style="font-size:14px;line-height:1.8;color:#374151">
      ${summary ? mdToHtml(summary) : `<p style="color:#9ca3af;font-style:italic;margin:0">${esc(rs('no_summary_plain', lang))}</p>`}
    </div>
  </div>

  ${iocs && iocs.length ? `
  <!-- 02 — IoCs -->
  <div style="margin-bottom:56px">
    ${sectionHead('02', rs('sec_02', lang) + ' (' + iocs.length + ')')}
    ${iocHtml}
  </div>` : ''}

  ${findings && findings.length ? `
  <!-- 03 — Timeline -->
  <div style="margin-bottom:56px">
    ${sectionHead('03', rs('sec_03', lang) + ' (' + findings.length + ')')}
    ${findingsHtml}
  </div>` : ''}

  <!-- 04 — Conclusion -->
  <div style="margin-bottom:56px">
    ${sectionHead('04', rs('sec_04', lang))}
    <div style="font-size:14px;line-height:1.8;color:#374151">
      ${conclusion ? mdToHtml(conclusion) : `<p style="color:#9ca3af;font-style:italic;margin:0">${esc(rs('no_conclusion_plain', lang))}</p>`}
    </div>
  </div>

  <!-- Footer -->
  <div style="border-top:1px solid #e5e7eb;padding-top:20px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;color:#9ca3af;font-size:12px">
    <span>${esc(safe((analyst && analyst.display_name) || ''))} · ${esc(fmtDate(Date.now(), lang))}</span>
    <span>INV-${esc(safe(investigation.id).slice(-8).toUpperCase())} · ${esc(rs('confidential', lang))}</span>
  </div>

</div>
</body>
</html>`);
}

module.exports = { generatePDF, generateDOCX, generateHTML, generateQueryPDF, safeFilename };
