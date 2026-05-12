// KQL Vault — Automatic platform detection from KQL content
//
// Primary source: table_requirements + environment_profiles loaded from the DB
// via buildExtrasFromDb(db) at call time.
// Hardcoded baseline acts as fallback when the DB is not available.

// ── Hardcoded baseline (mirrors table_requirements seed) ─────────────────────
var BASELINE = {
  Defender: new Set([
    "AlertEvidence","AlertInfo","CloudAppEvents",
    "DeviceEvents","DeviceFileEvents","DeviceImageLoadEvents","DeviceInfo",
    "DeviceLogonEvents","DeviceNetworkEvents","DeviceProcessEvents","DeviceRegistryEvents",
    "DeviceNetworkInfo","DeviceFileCertificateInfo",
    "DeviceTvmInfoGathering","DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSoftwareInventory","DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB","DeviceTvmSecureConfigurationAssessmentKB",
    "EmailAttachmentInfo","EmailEvents","EmailPostDeliveryEvents","EmailUrlInfo",
    "IdentityDirectoryEvents","IdentityLogonEvents","IdentityQueryEvents",
    "UrlClickEvents","ExposureGraphEdges","ExposureGraphNodes",
  ]),
  Sentinel: new Set([
    "AADManagedIdentitySignInLogs","AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs","AADSpnSignInEventsBeta",
    "AuditLogs","AzureActivity","AzureDiagnostics","AzureMetrics",
    "BehaviorAnalytics","CommonSecurityLog",
    "Event","Heartbeat","MicrosoftGraphActivityLogs",
    "OfficeActivity","Perf","SecurityAlert","SecurityEvent",
    "SecurityIncident","SentinelHealth","SigninLogs","Syslog",
    "ThreatIntelligenceIndicator","UserPeerAnalytics","VMConnection",
    "Watchlist","WindowsEvent","WindowsFirewall",
    "StorageBlobLogs","StorageFileLogs","StorageQueueLogs","StorageTableLogs",
    "W3CIISLog","AppServiceHTTPLogs","DnsEvents","GitHubAudit",
    "AWSCloudTrail","AWSGuardDuty","AWSVPCFlow","AIAgentsInfo",
  ]),
};

// ── Build extras from live DB data ────────────────────────────────────────────
// Merges table_requirements rows and custom_tables from all environment_profiles.
// Call once per request/sync cycle and pass the result to detectEnvironment().
function buildExtrasFromDb(db) {
  var defender = [], sentinel = [];

  try {
    db.prepare("SELECT table_name, platform FROM table_requirements").all()
      .forEach(function(r) {
        if (r.platform === "Defender") defender.push(r.table_name);
        else if (r.platform === "Sentinel") sentinel.push(r.table_name);
      });
  } catch(e) {}

  try {
    db.prepare("SELECT platform, custom_tables FROM environment_profiles").all()
      .forEach(function(p) {
        var tables;
        try { tables = JSON.parse(p.custom_tables || "[]"); } catch(e) { tables = []; }
        tables.forEach(function(t) {
          if (typeof t !== "string" || !t.trim()) return;
          if (p.platform === "Defender") defender.push(t.trim());
          else if (p.platform === "Sentinel") sentinel.push(t.trim());
        });
      });
  } catch(e) {}

  return { defender: defender, sentinel: sentinel };
}

// ── Core detection ────────────────────────────────────────────────────────────
// extras = { defender: string[], sentinel: string[] }  (from buildExtrasFromDb)
// Returns 'Defender', 'Sentinel', 'Both', or null (no known tables found).
function detectEnvironment(kql, extras) {
  if (!kql || typeof kql !== "string") return null;

  var tokens = kql.match(/\b[A-Z][A-Za-z0-9]{3,}\b/g);
  if (!tokens) return null;

  // Merge baseline with runtime extras (runtime takes precedence — same Set logic)
  var defSet, senSet;
  if (extras && (extras.defender.length || extras.sentinel.length)) {
    defSet = new Set(BASELINE.Defender);
    extras.defender.forEach(function(t) { defSet.add(t); });
    senSet = new Set(BASELINE.Sentinel);
    extras.sentinel.forEach(function(t) { senSet.add(t); });
  } else {
    defSet = BASELINE.Defender;
    senSet = BASELINE.Sentinel;
  }

  var hasD = false, hasS = false;
  for (var i = 0; i < tokens.length; i++) {
    if (defSet.has(tokens[i])) hasD = true;
    if (senSet.has(tokens[i])) hasS = true;
    if (hasD && hasS) break;
  }

  if (hasD && hasS) return "Both";
  if (hasD) return "Defender";
  if (hasS) return "Sentinel";
  return null;
}

module.exports = { detectEnvironment, buildExtrasFromDb };
