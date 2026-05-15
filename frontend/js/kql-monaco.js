// frontend/js/kql-monaco.js
// Monaco Editor module for KQLab

window.KQLMonaco = (function () {
  'use strict';

  var _ready          = false;
  var _loading        = false;
  var _langRegistered = false;
  var _themeWatching  = false;
  var _formEditor     = null;
  var _detailEditor   = null;

  // ── 1. Langage KQL ──────────────────────────────────────────────────────

  function _registerLanguage() {
    if (_langRegistered) return;
    _langRegistered = true;

    monaco.languages.register({ id: 'kql' });

    monaco.languages.setMonarchTokensProvider('kql', {
      ignoreCase: true,
      keywords: [
        'where','summarize','extend','project','project-away','project-rename',
        'join','union','let','parse','parse-where','evaluate','render',
        'order','by','sort','top','top-nested','limit','take','count',
        'bin','ago','between','contains','has','has_all','has_any',
        'startswith','endswith','matches','regex','mv-expand','mv-apply',
        'datatable','print','range','search','find','distinct','make-series',
        'invoke','externaldata','consume','fork','facet','sample','reduce',
        'and','or','not','in','on','kind','inner','leftouter','rightouter',
        'fullouter','leftanti','rightanti','leftsemi'
      ],
      functions: [
        'tostring','toint','tolong','todouble','tobool','todatetime','totimespan',
        'format_datetime','format_timespan','datetime_diff','datetime_add',
        'iif','iff','case','coalesce','isempty','isnotempty','isnull','isnotnull',
        'array_length','array_concat','bag_keys','bag_merge','dynamic',
        'split','strcat','strcat_delim','replace','replace_string','extract',
        'extract_all','indexof','substring','strlen','trim','toupper','tolower',
        'countif','sumif','avgif','minif','maxif','dcount','dcountif',
        'percentile','percentiles','stdev','variance',
        'prev','next','row_number','row_cumsum',
        'now','startofday','startofweek','startofmonth',
        'endofday','endofweek','endofmonth',
        'dayofweek','hourofday','getmonth','getyear',
        'parsejson','parse_json','todynamic','zip','pack','pack_array',
        'url_decode','url_encode','base64_encode_tostring','base64_decode_tostring'
      ],
      tables: [
        'DeviceEvents','DeviceProcessEvents','DeviceNetworkEvents','DeviceFileEvents',
        'DeviceRegistryEvents','DeviceLogonEvents','DeviceImageLoadEvents','DeviceAlertEvents',
        'SecurityEvent','SecurityAlert','SigninLogs','AADSignInEventsBeta',
        'AuditLogs','AzureActivity','CommonSecurityLog','Syslog','OfficeActivity',
        'CloudAppEvents','AlertInfo','AlertEvidence','IdentityLogonEvents',
        'IdentityQueryEvents','IdentityDirectoryEvents','EmailEvents',
        'EmailAttachmentInfo','EmailUrlInfo','UrlClickEvents',
        'BehaviorAnalytics','ThreatIntelligenceIndicator','Watchlist',
        'DeviceTvmSecureConfigurationAssessment','DeviceTvmSoftwareVulnerabilities',
        'DeviceTvmSoftwareInventory','DeviceInfo','DeviceNetworkInfo'
      ],
      tokenizer: {
        root: [
          [/\/\/.*$/,           'comment'],
          [/\/\*/,              'comment', '@blockComment'],
          [/"([^"\\]|\\.)*$/,  'string.invalid'],
          [/"/,                 'string',  '@stringDouble'],
          [/'([^'\\]|\\.)*$/,  'string.invalid'],
          [/'/,                 'string',  '@stringSingle'],
          [/\b\d+[smhd]\b/,    'number.duration'],
          [/\b\d+(\.\d+)?\b/,  'number'],
          [/==|!=|<=|>=|=~|!~/, 'operator'],
          [/\|/,                'operator.pipe'],
          [/[a-zA-Z_][\w-]*/, {
            cases: {
              '@keywords':  'keyword',
              '@functions': 'type.identifier',
              '@tables':    'variable',
              '@default':   'identifier'
            }
          }],
          [/[{}()\[\]]/, 'delimiter'],
          [/[,;.]/,      'delimiter']
        ],
        blockComment: [
          [/[^/*]+/, 'comment'],
          [/\*\//,   'comment', '@pop'],
          [/[/*]/,   'comment']
        ],
        stringDouble: [
          [/[^"\\]+/, 'string'],
          [/\\./,     'string.escape'],
          [/"/,       'string', '@pop']
        ],
        stringSingle: [
          [/[^'\\]+/, 'string'],
          [/\\./,     'string.escape'],
          [/'/,       'string', '@pop']
        ]
      }
    });

    console.info('[KQLMonaco] Langage kql enregistré');
  }

  // ── 2. Thèmes ────────────────────────────────────────────────────────────

  function _registerThemes() {
    monaco.editor.defineTheme('kql-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword',         foreground: '569cd6', fontStyle: 'bold'   },
        { token: 'type.identifier', foreground: 'dcdcaa'                      },
        { token: 'variable',        foreground: '4ec9b0'                      },
        { token: 'comment',         foreground: '6a9955', fontStyle: 'italic' },
        { token: 'string',          foreground: 'ce9178'                      },
        { token: 'string.escape',   foreground: 'd7ba7d'                      },
        { token: 'string.invalid',  foreground: 'ff0000'                      },
        { token: 'number',          foreground: 'b5cea8'                      },
        { token: 'number.duration', foreground: 'b5cea8', fontStyle: 'bold'   },
        { token: 'operator',        foreground: 'd4d4d4'                      },
        { token: 'operator.pipe',   foreground: 'c586c0', fontStyle: 'bold'   },
        { token: 'delimiter',       foreground: 'd4d4d4'                      },
        { token: 'identifier',      foreground: '9cdcfe'                      }
      ],
      colors: {
        'editor.background':              '#0d1117',
        'editor.foreground':              '#e6edf3',
        'editor.lineHighlightBackground': '#161b2280',
        'editorLineNumber.foreground':    '#484f58',
        'editorCursor.foreground':        '#58a6ff',
        'editor.selectionBackground':     '#264f7880',
        'editorGutter.background':        '#0d1117'
      }
    });

    monaco.editor.defineTheme('kql-light', {
      base: 'vs',
      inherit: true,
      rules: [
        { token: 'keyword',         foreground: '0000ff', fontStyle: 'bold'   },
        { token: 'type.identifier', foreground: '795e26'                      },
        { token: 'variable',        foreground: '267f99'                      },
        { token: 'comment',         foreground: '008000', fontStyle: 'italic' },
        { token: 'string',          foreground: 'a31515'                      },
        { token: 'string.escape',   foreground: 'ee0000'                      },
        { token: 'number',          foreground: '098658'                      },
        { token: 'number.duration', foreground: '098658', fontStyle: 'bold'   },
        { token: 'operator.pipe',   foreground: 'af00db', fontStyle: 'bold'   },
        { token: 'identifier',      foreground: '001080'                      }
      ],
      colors: {}
    });

    console.info('[KQLMonaco] Thèmes kql-dark / kql-light définis');
  }

  // ── 3. Autocomplétion ────────────────────────────────────────────────────

  function _registerCompletion() {
    monaco.languages.registerCompletionItemProvider('kql', {
      provideCompletionItems: function (model, position) {
        var word  = model.getWordUntilPosition(position);
        var range = {
          startLineNumber: position.lineNumber, endLineNumber: position.lineNumber,
          startColumn: word.startColumn,        endColumn: word.endColumn
        };
        var K   = monaco.languages.CompletionItemKind;
        var ITR = monaco.languages.CompletionItemInsertTextRule;
        var s   = [];

        ['where','summarize','extend','project','join','union','let','parse',
         'evaluate','render','order by','sort by','top','limit','take','count',
         'bin','distinct','make-series','mv-expand','find','search','datatable',
         'between','contains','has','startswith','endswith','and','or','not'
        ].forEach(function (k) {
          s.push({ label: k, kind: K.Keyword, insertText: k, range: range });
        });

        s.push(
          { label: 'join kind=inner', kind: K.Snippet, range: range,
            insertText: 'join kind=inner (\n\t${1:table}\n\t| where ${2:condition}\n) on ${3:field}',
            insertTextRules: ITR.InsertAsSnippet, detail: 'Inner join' },
          { label: 'where TimeGenerated >', kind: K.Snippet, range: range,
            insertText: 'where TimeGenerated > ago(${1:7d})',
            insertTextRules: ITR.InsertAsSnippet },
          { label: 'summarize count() by', kind: K.Snippet, range: range,
            insertText: 'summarize Count=count() by ${1:field}',
            insertTextRules: ITR.InsertAsSnippet },
          { label: 'extend iif', kind: K.Snippet, range: range,
            insertText: 'extend ${1:Field} = iif(${2:condition}, ${3:true}, ${4:false})',
            insertTextRules: ITR.InsertAsSnippet },
          { label: 'let var =', kind: K.Snippet, range: range,
            insertText: 'let ${1:varName} = ${2:value};',
            insertTextRules: ITR.InsertAsSnippet }
        );

        ['tostring','toint','todouble','tobool','todatetime','format_datetime','iif',
         'case','coalesce','isempty','isnotempty','isnull','isnotnull','parsejson',
         'split','strcat','extract','substring','trim','toupper','tolower',
         'dcount','countif','sumif','percentile','now','startofday','startofweek',
         'startofmonth','endofday','ago','bin','dynamic','todynamic','pack','zip',
         'array_length','base64_encode_tostring','base64_decode_tostring'
        ].forEach(function (f) {
          s.push({ label: f, kind: K.Function,
            insertText: f + '(${1})', insertTextRules: ITR.InsertAsSnippet, range: range });
        });

        ['DeviceEvents','DeviceProcessEvents','DeviceNetworkEvents','DeviceFileEvents',
         'DeviceRegistryEvents','DeviceLogonEvents','SecurityEvent','SigninLogs',
         'AuditLogs','AzureActivity','CommonSecurityLog','Syslog','OfficeActivity',
         'CloudAppEvents','AlertInfo','AlertEvidence','IdentityLogonEvents',
         'BehaviorAnalytics','DeviceInfo','ThreatIntelligenceIndicator','Watchlist'
        ].forEach(function (t) {
          s.push({ label: t, kind: K.Class, insertText: t, range: range, detail: 'KQL table' });
        });

        return { suggestions: s };
      }
    });
  }

  // ── 4. Sync thème dark/light ─────────────────────────────────────────────

  function _watchTheme() {
    if (_themeWatching) return;
    _themeWatching = true;
    new MutationObserver(function () {
      monaco.editor.setTheme(
        document.body.classList.contains('light') ? 'kql-light' : 'kql-dark'
      );
    }).observe(document.body, { attributes: true, attributeFilter: ['class'] });
  }

  function _currentTheme() {
    return document.body.classList.contains('light') ? 'kql-light' : 'kql-dark';
  }

  // ── 5. Init AMD (idempotent) ─────────────────────────────────────────────

  function init(callback) {
    if (typeof require === 'undefined') {
      console.warn('[KQLMonaco] AMD loader absent — Monaco désactivé');
      if (callback) callback(false);
      return;
    }
    if (_ready) {
      if (callback) callback(true);
      return;
    }
    if (_loading) {
      var poll = setInterval(function () {
        if (_ready) { clearInterval(poll); if (callback) callback(true); }
      }, 50);
      return;
    }
    _loading = true;
    require(['vs/editor/editor.main'], function () {
      _registerLanguage();    // 1. langage + tokenizer
      _registerThemes();      // 2. thèmes (après tokenizer, avant create())
      _registerCompletion();  // 3. autocomplétion
      _watchTheme();          // 4. observer dark/light (une seule fois)
      _ready   = true;
      _loading = false;
      console.info('[KQLMonaco] Monaco Editor prêt');
      if (callback) callback(true);
    });
  }

  // ── 6. Éditeur formulaire (lecture/écriture) ─────────────────────────────
  // container doit être display:none dans le HTML.
  // mountForm : affiche le container AVANT monaco.editor.create() (critique pour la coloration).

  function mountForm(containerId, textareaId, initialValue) {
    var container = document.getElementById(containerId);
    var textarea  = document.getElementById(textareaId);
    if (!container || !textarea) {
      console.warn('[KQLMonaco] mountForm: éléments introuvables', containerId, textareaId);
      return null;
    }

    if (_formEditor) { try { _formEditor.dispose(); } catch (e) {} _formEditor = null; }

    // ── Afficher le container AVANT create() ──
    // Monaco doit mesurer des dimensions > 0 au moment de la création.
    textarea.style.display  = 'none';
    container.style.display = 'block';
    if (!container.style.height || container.offsetHeight < 50) {
      container.style.height = '300px';
    }

    try {
      _formEditor = monaco.editor.create(container, {
        value:                initialValue != null ? initialValue : (textarea.value || ''),
        language:             'kql',
        theme:                _currentTheme(),
        fontSize:             13,
        fontFamily:           '"JetBrains Mono", "Fira Code", monospace',
        minimap:              { enabled: false },
        lineNumbers:          'on',
        wordWrap:             'on',
        automaticLayout:      true,
        scrollBeyondLastLine: false,
        tabSize:              4,
        insertSpaces:         true,
        suggestOnTriggerCharacters: true,
        quickSuggestions:     { other: true, comments: false, strings: false },
        folding:              true,
        renderLineHighlight:  'gutter',
        padding:              { top: 12, bottom: 12 },
        scrollbar:            { verticalScrollbarSize: 6, horizontalScrollbarSize: 6 }
      });

      // Sync Monaco → textarea en temps réel
      _formEditor.onDidChangeModelContent(function () {
        var ta = document.getElementById(textareaId);
        if (ta) ta.value = _formEditor.getValue();
      });
    } catch (e) {
      console.error('[KQLMonaco] mountForm: erreur create()', e);
      container.style.display = 'none';
      textarea.style.display  = '';
      _formEditor = null;
    }

    return _formEditor;
  }

  function unmountForm(containerId, textareaId) {
    if (_formEditor) { try { _formEditor.dispose(); } catch (e) {} _formEditor = null; }
    var container = document.getElementById(containerId);
    var textarea  = document.getElementById(textareaId);
    if (container) container.style.display = 'none';
    if (textarea)  textarea.style.display  = '';
  }

  // ── 7. Éditeur détail (lecture seule) ────────────────────────────────────
  // Le container est rendu visible par app.js AVANT d'appeler mountDetail().

  function mountDetail(containerId, value) {
    var container = document.getElementById(containerId);
    if (!container) {
      console.warn('[KQLMonaco] mountDetail: container introuvable', containerId);
      return null;
    }

    if (_detailEditor) { try { _detailEditor.dispose(); } catch (e) {} _detailEditor = null; }

    // Hauteur calculée sur le contenu (container doit déjà être visible)
    var lines  = (value || '').split('\n').length;
    var height = Math.min(Math.max(lines * 19 + 32, 80), 520);
    container.style.height = height + 'px';

    try {
      _detailEditor = monaco.editor.create(container, {
        value:                value || '',
        language:             'kql',
        theme:                _currentTheme(),
        readOnly:             true,
        fontSize:             13,
        fontFamily:           '"JetBrains Mono", "Fira Code", monospace',
        minimap:              { enabled: false },
        lineNumbers:          'on',
        wordWrap:             'on',
        automaticLayout:      true,
        scrollBeyondLastLine: false,
        renderLineHighlight:  'none',
        folding:              false,
        padding:              { top: 12, bottom: 12 },
        scrollbar:            { verticalScrollbarSize: 4 }
      });
    } catch (e) {
      console.error('[KQLMonaco] mountDetail: erreur create()', e);
      _detailEditor = null;
    }

    return _detailEditor;
  }

  function unmountDetail() {
    if (_detailEditor) { try { _detailEditor.dispose(); } catch (e) {} _detailEditor = null; }
  }

  // Met à jour la valeur du détail (pour updateResolved avec variables)
  function setDetailValue(v) {
    if (_detailEditor) try { _detailEditor.setValue(v); } catch (e) {}
  }

  return {
    init:           init,
    mountForm:      mountForm,
    unmountForm:    unmountForm,
    mountDetail:    mountDetail,
    unmountDetail:  unmountDetail,
    setDetailValue: setDetailValue
  };

})();
