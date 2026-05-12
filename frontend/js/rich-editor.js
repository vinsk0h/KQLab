// ════════════════════════════════════════════════════════════════
// rich-editor.js — Éditeur Markdown avec toolbar pour investigations
// Aucune dépendance externe. Stockage : Markdown. Rendu : HTML.
// ════════════════════════════════════════════════════════════════

window.RichEditor = (function () {

  // ── Escape HTML (local, sans dépendance) ──────────────────────
  function escHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Alias langage → nom de grammaire Prism ───────────────────
  var LANG_MAP = {
    kql:        'kusto',
    kusto:      'kusto',
    powershell: 'powershell',
    ps1:        'powershell',
    bash:       'bash',
    sh:         'bash',
    cmd:        'batch',
    bat:        'batch',
    python:     'python',
    py:         'python',
    json:       'json',
    yaml:       'yaml',
    yml:        'yaml',
    sql:        'sql',
    xml:        'xml',
    text:       'plain',
    plain:      'plain',
  };

  // ── Convertir Markdown → HTML ─────────────────────────────────
  function mdToHtml(md) {
    if (!md) return '';

    // ÉTAPE 1 — Extraire les blocs de code vers des placeholders AVANT tout autre traitement.
    // Sans cela, les sauts de ligne internes au <pre> seraient fragmentés par le processeur de paragraphes.
    var codeBlocks = [];
    var html = md.replace(/```(\w+)?\n?([\s\S]*?)```/g, function(_, lang, code) {
      var l = (lang || 'text').toLowerCase();
      var prismLang = LANG_MAP[l] || l;
      var displayLang = l.toUpperCase();
      var highlighted = escHtml(code.trim());
      if (window.Prism && Prism.languages[prismLang]) {
        try {
          highlighted = Prism.highlight(code.trim(), Prism.languages[prismLang], prismLang);
        } catch(e) { /* fallback */ }
      }
      var block = '<div class="re-code-block">'
        + '<div class="re-code-header">'
        + '<span class="re-code-lang">' + escHtml(displayLang) + '</span>'
        + '<button class="re-copy-btn" type="button" onclick="RichEditor._copyCode(this)">'
        + '<svg width="11" height="11" viewBox="0 0 24 24" fill="none">'
        + '<rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="2"/>'
        + '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="2"/>'
        + '</svg> Copier</button></div>'
        + '<pre class="re-code-content language-' + escHtml(prismLang) + '" style="white-space:pre;overflow-x:auto">'
        + '<code class="language-' + escHtml(prismLang) + '">' + highlighted + '</code></pre>'
        + '</div>';
      var idx = codeBlocks.push(block) - 1;
      return '\x00CB' + idx + '\x00';
    });

    // ÉTAPE 2 — Appliquer les autres transformations Markdown sur le texte sans les blocs
    html = html
      .replace(/`([^`\n]+)`/g, '<code class="re-inline-code">$1</code>')
      .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*\n]+)\*/g, '<em>$1</em>')
      .replace(/^## (.+)$/gm, '<h3 class="re-h2">$1</h3>')
      .replace(/^### (.+)$/gm, '<h4 class="re-h3">$1</h4>')
      .replace(/^---$/gm, '<hr class="re-hr">')
      .replace(/^[ \t]*[\-\*] (.+)$/gm, '<li>$1</li>')
      .replace(/(<li>[\s\S]*?<\/li>)(\n<li>[\s\S]*?<\/li>)*/g, function(m) {
        return '<ul class="re-list">' + m + '</ul>';
      });

    // ÉTAPE 3 — Processeur de paragraphes (les placeholders sont traités comme éléments blocs)
    var lines = html.split('\n');
    var result = [];
    var inBlock = false;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var isPlaceholder = /^\x00CB\d+\x00$/.test(line.trim());
      var isHtml = isPlaceholder
        || /^<(div|ul|h[34]|hr)/.test(line.trim())
        || /^<\/(div|ul)>/.test(line.trim());
      if (isHtml) {
        if (inBlock) { result.push('</p>'); inBlock = false; }
        result.push(line);
      } else if (line.trim() === '') {
        if (inBlock) { result.push('</p>'); inBlock = false; }
      } else {
        if (!inBlock) { result.push('<p class="re-p">'); inBlock = true; }
        result.push(line);
      }
    }
    if (inBlock) result.push('</p>');

    html = result.join('\n');

    // ÉTAPE 4 — Réinjecter les blocs de code à la place de leurs placeholders
    codeBlocks.forEach(function(block, idx) {
      html = html.replace('\x00CB' + idx + '\x00', block);
    });

    return html;
  }

  // ── Insérer autour de la sélection ───────────────────────────
  function wrap(textarea, before, after, placeholder) {
    var start = textarea.selectionStart;
    var end   = textarea.selectionEnd;
    var sel   = textarea.value.substring(start, end) || placeholder || '';
    var replacement = before + sel + after;
    textarea.value = textarea.value.substring(0, start) + replacement + textarea.value.substring(end);
    var newStart = start + before.length;
    var newEnd   = newStart + sel.length;
    textarea.setSelectionRange(newStart, newEnd);
    textarea.focus();
    textarea.dispatchEvent(new Event('input'));
  }

  // ── Insérer un préfixe sur la ligne courante ─────────────────
  function insertLinePrefix(textarea, prefix) {
    var start     = textarea.selectionStart;
    var lineStart = textarea.value.lastIndexOf('\n', start - 1) + 1;
    var before    = textarea.value.substring(0, lineStart);
    var rest      = textarea.value.substring(lineStart);
    if (rest.startsWith(prefix)) {
      textarea.value = before + rest.substring(prefix.length);
    } else {
      textarea.value = before + prefix + rest;
    }
    textarea.focus();
    textarea.dispatchEvent(new Event('input'));
  }

  // ── Insérer un bloc de code ───────────────────────────────────
  function insertCodeBlock(textarea, lang) {
    var start = textarea.selectionStart;
    var end   = textarea.selectionEnd;
    var sel   = textarea.value.substring(start, end);
    var placeholder = sel || '// Votre code ici';
    var block = '\n```' + lang + '\n' + placeholder + '\n```\n';
    textarea.value = textarea.value.substring(0, start) + block + textarea.value.substring(end);
    var cursorPos = start + 4 + lang.length + 1;
    textarea.setSelectionRange(cursorPos, cursorPos + placeholder.length);
    textarea.focus();
    textarea.dispatchEvent(new Event('input'));
  }

  // ── Picker de langage ─────────────────────────────────────────
  function promptCodeBlock(textarea, triggerBtn) {
    var langs = ['kql', 'powershell', 'bash', 'cmd', 'python', 'json', 'yaml', 'sql', 'text'];
    var existing = document.getElementById('re-lang-picker');
    if (existing) { existing.remove(); return; }

    var picker = document.createElement('div');
    picker.id = 're-lang-picker';
    picker.className = 're-lang-picker';

    langs.forEach(function(l) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 're-lang-opt';
      btn.textContent = l.toUpperCase();
      btn.addEventListener('click', function() {
        picker.remove();
        insertCodeBlock(textarea, l);
      });
      picker.appendChild(btn);
    });

    if (triggerBtn) {
      var rect = triggerBtn.getBoundingClientRect();
      picker.style.cssText = 'position:fixed;top:' + (rect.bottom + 4) + 'px;left:' + rect.left + 'px;z-index:9999';
    }
    document.body.appendChild(picker);

    setTimeout(function() {
      document.addEventListener('click', function close(e) {
        if (!picker.contains(e.target)) {
          picker.remove();
          document.removeEventListener('click', close);
        }
      });
    }, 10);
  }

  // ── Définitions des actions toolbar ──────────────────────────
  function buildActions(textarea) {
    return [
      {
        icon: '<span class="re-toolbar-text" style="font-weight:900">B</span>',
        label: 'Gras', title: 'Gras (Ctrl+B)',
        fn: function() { wrap(textarea, '**', '**', 'texte en gras'); }
      },
      {
        icon: '<span class="re-toolbar-text" style="font-style:italic">I</span>',
        label: 'Italique', title: 'Italique (Ctrl+I)',
        fn: function() { wrap(textarea, '*', '*', 'texte en italique'); }
      },
      { divider: true },
      {
        icon: '<span class="re-toolbar-text">H2</span>',
        label: 'Titre 2', title: 'Titre de section',
        fn: function() { insertLinePrefix(textarea, '## '); }
      },
      {
        icon: '<span class="re-toolbar-text" style="font-size:9px">H3</span>',
        label: 'Titre 3', title: 'Sous-titre',
        fn: function() { insertLinePrefix(textarea, '### '); }
      },
      { divider: true },
      {
        icon: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><line x1="9" y1="6" x2="20" y2="6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="9" y1="12" x2="20" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="9" y1="18" x2="20" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="4" cy="6" r="1.5" fill="currentColor"/><circle cx="4" cy="12" r="1.5" fill="currentColor"/><circle cx="4" cy="18" r="1.5" fill="currentColor"/></svg>',
        label: 'Liste', title: 'Liste à puces',
        fn: function() { insertLinePrefix(textarea, '- '); }
      },
      { divider: true },
      {
        icon: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><polyline points="16 18 22 12 16 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="8 6 2 12 8 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        label: 'Code', title: 'Code inline (`code`) — Ctrl+K',
        fn: function() { wrap(textarea, '`', '`', 'code'); }
      },
      {
        icon: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><rect x="2" y="3" width="20" height="14" rx="2" stroke="currentColor" stroke-width="2"/><path d="M8 21h8M12 17v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        label: 'Bloc KQL', title: 'Insérer un bloc KQL',
        fn: function() { insertCodeBlock(textarea, 'kql'); }
      },
      {
        icon: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><polyline points="4 17 10 11 4 5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="19" x2="20" y2="19" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        label: 'Bloc…', title: 'Bloc de code (choisir le langage)',
        isLangPicker: true,
        fn: function(btn) { promptCodeBlock(textarea, btn); }
      },
      { divider: true },
      {
        icon: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><line x1="3" y1="12" x2="21" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        label: '—', title: 'Séparateur horizontal',
        fn: function() {
          var pos = textarea.selectionStart;
          var ins = '\n---\n';
          textarea.value = textarea.value.substring(0, pos) + ins + textarea.value.substring(pos);
          textarea.setSelectionRange(pos + ins.length, pos + ins.length);
          textarea.focus();
          textarea.dispatchEvent(new Event('input'));
        }
      },
    ];
  }

  // ── Créer l'éditeur ───────────────────────────────────────────
  function create(options) {
    // options: { containerId, textareaId, label, placeholder, rows, value, readonly }
    var container = document.getElementById(options.containerId);
    if (!container) return;

    var isReadonly = !!options.readonly;
    var value      = options.value || '';

    // Construire le HTML
    var html = '<div class="re-editor' + (isReadonly ? ' re-editor--readonly' : '') + '">';

    if (!isReadonly) {
      // Toolbar
      html += '<div class="re-toolbar">';

      var actions = buildActions(null); // placeholder, will bind after
      actions.forEach(function(a) {
        if (a.divider) {
          html += '<div class="re-toolbar-divider"></div>';
        } else {
          html += '<button type="button" class="re-toolbar-btn" title="' + escHtml(a.title || a.label) + '" aria-label="' + escHtml(a.label) + '">'
               + a.icon + '</button>';
        }
      });

      // Preview toggle + Fullscreen
      html += '<div style="flex:1"></div>';
      html += '<button type="button" class="re-toolbar-btn re-preview-toggle" title="Aperçu rendu" aria-label="Aperçu">'
           + '<svg width="12" height="12" viewBox="0 0 24 24" fill="none">'
           + '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2"/>'
           + '<circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg>'
           + '<span style="font-size:11px;margin-left:4px">Aperçu</span></button>';
      html += '<div class="re-toolbar-divider"></div>';
      html += '<button type="button" class="re-toolbar-btn re-fullscreen-btn" title="Plein écran (F11)" aria-label="Plein écran">'
           + '<svg class="re-fs-icon-expand" width="12" height="12" viewBox="0 0 24 24" fill="none">'
           + '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
           + '</svg>'
           + '<svg class="re-fs-icon-collapse" width="12" height="12" viewBox="0 0 24 24" fill="none" style="display:none">'
           + '<path d="M8 3v5H3M21 8h-5V3M3 16h5v5M16 21v-5h5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
           + '</svg>'
           + '<span class="re-fs-label" style="font-size:11px;margin-left:3px">Plein écran</span>'
           + '</button>';
      html += '</div>'; // end toolbar
    }

    // Body
    html += '<div class="re-body">';

    if (!isReadonly) {
      html += '<textarea id="' + escHtml(options.textareaId) + '" class="re-textarea"'
           + ' rows="' + (options.rows || 8) + '"'
           + ' placeholder="' + escHtml(options.placeholder || (typeof i18n!=='undefined'?i18n.t('re_placeholder'):'Write here…')) + '"'
           + '>' + escHtml(value) + '</textarea>';
    }

    var previewHtml = mdToHtml(value) || (isReadonly ? '<p class="re-empty-hint">Aucun contenu.</p>' : '');
    html += '<div class="re-preview' + (isReadonly ? ' re-preview--always' : '') + '" id="' + escHtml(options.textareaId) + '-preview"'
         + (isReadonly ? '' : ' style="display:none"') + '>'
         + previewHtml + '</div>';

    html += '</div>'; // end body

    if (!isReadonly) {
      html += '<div class="re-footer">'
           + '<span class="re-hint">**gras** · *italique* · `code` · ```kql ... ```</span>'
           + '<span class="re-char-count" id="' + escHtml(options.textareaId) + '-count">' + value.length.toLocaleString() + ' car.</span>'
           + '</div>';
    }

    if (options.label) {
      html = '<div class="re-label">' + escHtml(options.label) + '</div>' + html;
    }

    html += '</div>'; // end re-editor wrapper (label outside)

    container.innerHTML = '<div class="re-editor-wrap">' + (options.label ? '<div class="re-label">' + escHtml(options.label) + '</div>' : '') + html.replace('<div class="re-label">' + escHtml(options.label || '') + '</div>', '') + '</div>';
    // Simpler approach: set directly
    container.innerHTML = html;

    if (isReadonly) return;

    var textarea = document.getElementById(options.textareaId);
    var preview  = document.getElementById(options.textareaId + '-preview');
    var counter  = document.getElementById(options.textareaId + '-count');
    if (!textarea) return;

    // Compteur
    function updateCount() {
      if (counter) counter.textContent = textarea.value.length.toLocaleString() + ' car.';
    }

    // Auto-resize avec respect du max-height CSS
    function autoResize() {
      textarea.style.height = 'auto';
      var maxH = parseInt(getComputedStyle(textarea).maxHeight) || 380;
      var targetH = Math.max(100, Math.min(textarea.scrollHeight, maxH));
      textarea.style.height = targetH + 'px';
      textarea.style.overflowY = textarea.scrollHeight > maxH ? 'auto' : 'hidden';
    }
    autoResize();
    textarea.addEventListener('input', function() { autoResize(); updateCount(); });

    // Raccourcis clavier
    textarea.addEventListener('keydown', function(e) {
      if (e.ctrlKey || e.metaKey) {
        if (e.key === 'b') { e.preventDefault(); wrap(textarea, '**', '**', 'texte en gras'); }
        if (e.key === 'i') { e.preventDefault(); wrap(textarea, '*', '*', 'texte en italique'); }
        if (e.key === 'k') { e.preventDefault(); wrap(textarea, '`', '`', 'code'); }
      }
      if (e.key === 'Tab') {
        e.preventDefault();
        var s = textarea.selectionStart;
        textarea.value = textarea.value.substring(0, s) + '    ' + textarea.value.substring(s);
        textarea.setSelectionRange(s + 4, s + 4);
        textarea.dispatchEvent(new Event('input'));
      }
    });

    // Binder les boutons toolbar (même ordre que buildActions)
    var actions = buildActions(textarea);
    var buttons = [].slice.call(container.querySelectorAll('.re-toolbar-btn:not(.re-preview-toggle):not(.re-fullscreen-btn)'));
    var btnIdx  = 0;
    actions.forEach(function(a) {
      if (a.divider) return;
      var btn = buttons[btnIdx++];
      if (!btn) return;
      btn.addEventListener('click', function() { a.fn(btn); });
    });

    // Toggle aperçu
    var previewToggle = container.querySelector('.re-preview-toggle');
    var previewMode   = false;
    if (previewToggle) {
      previewToggle.addEventListener('click', function() {
        previewMode = !previewMode;
        textarea.style.display = previewMode ? 'none' : 'block';
        preview.style.display  = previewMode ? 'block' : 'none';
        previewToggle.classList.toggle('active', previewMode);
        if (previewMode) {
          preview.innerHTML = mdToHtml(textarea.value) || '<p class="re-empty-hint">Rien à afficher.</p>';
          if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(preview); });
        } else {
          autoResize();
        }
      });
    }

    // Mise à jour aperçu si visible
    textarea.addEventListener('input', function() {
      if (preview && preview.style.display !== 'none') {
        preview.innerHTML = mdToHtml(textarea.value);
        if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(preview); });
      }
    });

    // ── Mode plein écran ──────────────────────────────────────
    var fsBtn      = container.querySelector('.re-fullscreen-btn');
    var fsOverlay  = null;
    var isFullscreen = false;

    // Génère le HTML de la toolbar (même icônes que la toolbar principale)
    function buildFsToolbarHtml() {
      var tbActions = buildActions(null);
      var h = '';
      tbActions.forEach(function(a) {
        if (a.divider) {
          h += '<div class="re-toolbar-divider"></div>';
        } else {
          h += '<button type="button" class="re-toolbar-btn re-fs-tb-btn" title="' + escHtml(a.title || a.label) + '" aria-label="' + escHtml(a.label) + '">'
             + a.icon + '</button>';
        }
      });
      return h;
    }

    function enterFullscreen() {
      if (isFullscreen) return;
      isFullscreen = true;

      var labelTxt = escHtml(options.label || 'Éditeur');
      var plhTxt   = escHtml(options.placeholder || (typeof i18n!=='undefined'?i18n.t('re_placeholder'):'Write here…'));

      fsOverlay = document.createElement('div');
      fsOverlay.className = 're-fs-overlay';
      fsOverlay.innerHTML =
        '<div class="re-fs-modal">'
        // Header
        + '<div class="re-fs-header">'
        +   '<span class="re-fs-title">' + labelTxt + '</span>'
        +   '<div class="re-fs-header-actions">'
        +     '<button type="button" class="re-toolbar-btn re-fs-preview-btn" title="Aperçu">'
        +       '<svg width="12" height="12" viewBox="0 0 24 24" fill="none">'
        +       '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2"/>'
        +       '<circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg>'
        +       '<span style="font-size:11px;margin-left:3px">Aperçu</span>'
        +     '</button>'
        +     '<button type="button" class="re-toolbar-btn re-fs-close-btn" title="Quitter le plein écran (Echap)">'
        +       '<svg width="12" height="12" viewBox="0 0 24 24" fill="none">'
        +       '<path d="M8 3v5H3M21 8h-5V3M3 16h5v5M16 21v-5h5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
        +       '</svg>'
        +       '<span style="font-size:11px;margin-left:3px">Quitter</span>'
        +     '</button>'
        +   '</div>'
        + '</div>'
        // Toolbar
        + '<div class="re-toolbar re-fs-toolbar">' + buildFsToolbarHtml() + '</div>'
        // Corps
        + '<div class="re-fs-body">'
        +   '<textarea class="re-textarea re-fs-textarea" id="re-fs-ta-' + escHtml(options.textareaId) + '"'
        +   ' placeholder="' + plhTxt + '"></textarea>'
        +   '<div class="re-preview re-fs-preview" id="re-fs-pv-' + escHtml(options.textareaId) + '" style="display:none"></div>'
        + '</div>'
        // Footer
        + '<div class="re-fs-footer">'
        +   '<span class="re-hint">Echap pour fermer · Ctrl+B · Ctrl+I · Ctrl+K · Tab = 4 espaces</span>'
        +   '<span class="re-char-count" id="re-fs-cnt-' + escHtml(options.textareaId) + '">0 car.</span>'
        + '</div>'
        + '</div>'; // end re-fs-modal

      document.body.appendChild(fsOverlay);
      document.body.style.overflow = 'hidden';

      var fsTa   = document.getElementById('re-fs-ta-'  + options.textareaId);
      var fsPv   = document.getElementById('re-fs-pv-'  + options.textareaId);
      var fsCnt  = document.getElementById('re-fs-cnt-' + options.textareaId);
      var fsPvBtn  = fsOverlay.querySelector('.re-fs-preview-btn');
      var fsClBtn  = fsOverlay.querySelector('.re-fs-close-btn');

      // Copier le contenu de la textarea principale
      fsTa.value = textarea.value;
      if (fsCnt) fsCnt.textContent = fsTa.value.length.toLocaleString() + ' car.';

      // Animation d'ouverture
      requestAnimationFrame(function() { fsOverlay.classList.add('open'); });

      setTimeout(function() { fsTa.focus(); }, 60);

      // Binder toolbar plein écran (même ordre que buildActions)
      var fsActions  = buildActions(fsTa);
      var fsTbBtns   = [].slice.call(fsOverlay.querySelectorAll('.re-fs-tb-btn'));
      var fsBtnIdx   = 0;
      fsActions.forEach(function(a) {
        if (a.divider) return;
        var btn = fsTbBtns[fsBtnIdx++];
        if (!btn) return;
        btn.addEventListener('click', function() { a.fn(btn); });
      });

      // Compteur + sync vers textarea principale
      fsTa.addEventListener('input', function() {
        if (fsCnt) fsCnt.textContent = fsTa.value.length.toLocaleString() + ' car.';
        // Sync en temps réel vers textarea principale
        textarea.value = fsTa.value;
        textarea.dispatchEvent(new Event('input'));
        // Mise à jour aperçu si visible
        if (fsPv && fsPv.style.display !== 'none') {
          fsPv.innerHTML = mdToHtml(fsTa.value);
          if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(fsPv); });
        }
      });

      // Raccourcis clavier dans le plein écran
      fsTa.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') { e.preventDefault(); exitFullscreen(); return; }
        if (e.ctrlKey || e.metaKey) {
          if (e.key === 'b') { e.preventDefault(); wrap(fsTa, '**', '**', 'texte en gras'); }
          if (e.key === 'i') { e.preventDefault(); wrap(fsTa, '*', '*', 'texte en italique'); }
          if (e.key === 'k') { e.preventDefault(); wrap(fsTa, '`', '`', 'code'); }
        }
        if (e.key === 'Tab') {
          e.preventDefault();
          var s = fsTa.selectionStart;
          fsTa.value = fsTa.value.substring(0, s) + '    ' + fsTa.value.substring(s);
          fsTa.setSelectionRange(s + 4, s + 4);
          fsTa.dispatchEvent(new Event('input'));
        }
      });

      // Toggle aperçu plein écran
      var fsPvMode = false;
      fsPvBtn.addEventListener('click', function() {
        fsPvMode = !fsPvMode;
        fsTa.style.display = fsPvMode ? 'none' : '';
        fsPv.style.display = fsPvMode ? 'block' : 'none';
        fsPvBtn.classList.toggle('active', fsPvMode);
        if (fsPvMode) {
          fsPv.innerHTML = mdToHtml(fsTa.value) || '<p class="re-empty-hint">Rien à afficher.</p>';
          if (window.Prism) requestAnimationFrame(function() { Prism.highlightAllUnder(fsPv); });
        }
      });

      // Bouton fermer + clic fond
      fsClBtn.addEventListener('click', exitFullscreen);
      fsOverlay.addEventListener('click', function(e) { if (e.target === fsOverlay) exitFullscreen(); });

      // Mettre à jour icônes du bouton principal
      updateFsBtnIcon(true);
    }

    function exitFullscreen() {
      if (!isFullscreen || !fsOverlay) return;
      isFullscreen = false;

      // Sync contenu final vers textarea principale
      var fsTa = document.getElementById('re-fs-ta-' + options.textareaId);
      if (fsTa) {
        textarea.value = fsTa.value;
        textarea.dispatchEvent(new Event('input'));
      }

      fsOverlay.classList.remove('open');
      var ov = fsOverlay;
      fsOverlay = null;
      setTimeout(function() { if (ov.parentNode) ov.remove(); }, 220);
      document.body.style.overflow = '';

      updateFsBtnIcon(false);
      textarea.focus();
    }

    function updateFsBtnIcon(entering) {
      if (!fsBtn) return;
      var expandIcon   = fsBtn.querySelector('.re-fs-icon-expand');
      var collapseIcon = fsBtn.querySelector('.re-fs-icon-collapse');
      var lbl          = fsBtn.querySelector('.re-fs-label');
      if (expandIcon)   expandIcon.style.display   = entering ? 'none' : '';
      if (collapseIcon) collapseIcon.style.display = entering ? '' : 'none';
      if (lbl)          lbl.textContent             = entering ? (typeof i18n!=='undefined'?i18n.t('re_reduce'):'Minimize') : (typeof i18n!=='undefined'?i18n.t('re_fullscreen'):'Fullscreen');
      fsBtn.classList.toggle('active', entering);
    }

    if (fsBtn) {
      fsBtn.addEventListener('click', function() {
        if (isFullscreen) exitFullscreen(); else enterFullscreen();
      });
    }

    // F11 dans la textarea principale ouvre le plein écran
    textarea.addEventListener('keydown', function(e) {
      if (e.key === 'F11' && !isFullscreen) { e.preventDefault(); enterFullscreen(); }
    });
  }

  // ── Copier un bloc de code depuis l'aperçu ───────────────────
  function copyCode(btn) {
    var block = btn.closest('.re-code-block');
    if (!block) return;
    var code = block.querySelector('code');
    if (!code) return;
    navigator.clipboard.writeText(code.textContent).then(function() {
      var orig = btn.innerHTML;
      btn.textContent = '✓ Copié';
      setTimeout(function() { btn.innerHTML = orig; }, 2000);
    });
  }

  // ── API publique ──────────────────────────────────────────────
  return {
    create:    create,
    mdToHtml:  mdToHtml,

    getValue: function(textareaId) {
      var el = document.getElementById(textareaId);
      return el ? el.value : '';
    },
    setValue: function(textareaId, value) {
      var el = document.getElementById(textareaId);
      if (el) { el.value = value; el.dispatchEvent(new Event('input')); }
    },

    // Exposé pour l'onclick du bouton copier dans le rendu HTML
    _copyCode: copyCode
  };

})();
