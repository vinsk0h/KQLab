/**
 * Microsoft Security Table Knowledge Base
 * Maps every known table to its platform, license requirement, and connector requirement.
 *
 * Sources:
 * - https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
 * - https://learn.microsoft.com/en-us/azure/sentinel/data-source-schema-reference
 */

var TABLE_KB = {
  // ═══════════════════════════════════════
  // DEFENDER XDR - Tables Advanced Hunting
  // ═══════════════════════════════════════

  // MDE (Microsoft Defender for Endpoint)
  "DeviceProcessEvents":       { platform: "defender_xdr", requires: "mde",    desc: "Process creation and related events" },
  "DeviceNetworkEvents":       { platform: "defender_xdr", requires: "mde",    desc: "Network connections and related events" },
  "DeviceFileEvents":          { platform: "defender_xdr", requires: "mde",    desc: "File creation, modification, and other events" },
  "DeviceRegistryEvents":      { platform: "defender_xdr", requires: "mde",    desc: "Registry key creation and modification" },
  "DeviceLogonEvents":         { platform: "defender_xdr", requires: "mde",    desc: "Sign-ins and other authentication events" },
  "DeviceImageLoadEvents":     { platform: "defender_xdr", requires: "mde",    desc: "DLL loading events" },
  "DeviceEvents":              { platform: "defender_xdr", requires: "mde",    desc: "Multiple event types including security controls" },
  "DeviceInfo":                { platform: "defender_xdr", requires: "mde",    desc: "Machine information including OS" },
  "DeviceNetworkInfo":         { platform: "defender_xdr", requires: "mde",    desc: "Network properties of machines" },
  "DeviceFileCertificateInfo": { platform: "defender_xdr", requires: "mde",    desc: "Certificate info of signed files" },

  // MDE P2 (Threat & Vulnerability Management)
  "DeviceTvmSoftwareVulnerabilities":         { platform: "defender_xdr", requires: "mde_p2", desc: "Software vulnerabilities on devices" },
  "DeviceTvmSoftwareInventory":               { platform: "defender_xdr", requires: "mde_p2", desc: "Software installed on devices" },
  "DeviceTvmInfoGathering":                   { platform: "defender_xdr", requires: "mde_p2", desc: "TVM assessment events" },
  "DeviceTvmSecureConfigurationAssessment":   { platform: "defender_xdr", requires: "mde_p2", desc: "Security configuration assessments" },
  "DeviceTvmSecureConfigurationAssessmentKB": { platform: "defender_xdr", requires: "mde_p2", desc: "Knowledge base of security configs" },
  "DeviceTvmSoftwareVulnerabilitiesKB":       { platform: "defender_xdr", requires: "mde_p2", desc: "Knowledge base of vulnerabilities" },
  "DeviceTvmBrowserExtensions":               { platform: "defender_xdr", requires: "mde_p2", desc: "Browser extensions installed" },
  "DeviceTvmCertificateInfo":                 { platform: "defender_xdr", requires: "mde_p2", desc: "Certificate information" },
  "DeviceBaselineComplianceAssessment":        { platform: "defender_xdr", requires: "mde_p2", desc: "Baseline compliance checks" },
  "DeviceBaselineComplianceProfiles":          { platform: "defender_xdr", requires: "mde_p2", desc: "Baseline compliance profiles" },

  // MDI (Microsoft Defender for Identity)
  "IdentityLogonEvents":     { platform: "defender_xdr", requires: "mdi", desc: "AD and Entra ID authentication events" },
  "IdentityQueryEvents":     { platform: "defender_xdr", requires: "mdi", desc: "AD query activities (LDAP, DNS)" },
  "IdentityDirectoryEvents": { platform: "defender_xdr", requires: "mdi", desc: "AD domain controller events" },
  "IdentityInfo":            { platform: "defender_xdr", requires: "mdi", desc: "User account information from AD/Entra" },

  // MDO (Microsoft Defender for Office 365)
  "EmailEvents":             { platform: "defender_xdr", requires: "mdo", desc: "Email delivery and filtering events" },
  "EmailAttachmentInfo":     { platform: "defender_xdr", requires: "mdo", desc: "Information about email attachments" },
  "EmailUrlInfo":            { platform: "defender_xdr", requires: "mdo", desc: "URLs in emails" },
  "EmailPostDeliveryEvents": { platform: "defender_xdr", requires: "mdo", desc: "Post-delivery actions on emails" },
  "UrlClickEvents":          { platform: "defender_xdr", requires: "mdo", desc: "Safe Links click events" },

  // MDA (Microsoft Defender for Cloud Apps)
  "CloudAppEvents": { platform: "defender_xdr", requires: "mda", desc: "Cloud app activities" },

  // Alerts & Incidents (M365 Defender)
  "AlertInfo":       { platform: "defender_xdr", requires: "m365_defender", desc: "Alert metadata" },
  "AlertEvidence":   { platform: "defender_xdr", requires: "m365_defender", desc: "Evidence linked to alerts" },
  "BehaviorInfo":    { platform: "defender_xdr", requires: "m365_defender", desc: "Behavior-based detections" },
  "BehaviorEntities":{ platform: "defender_xdr", requires: "m365_defender", desc: "Entities in behaviors" },

  // ═══════════════════════════════════════
  // SENTINEL - Tables Log Analytics
  // ═══════════════════════════════════════

  // Entra ID / Azure AD (connecteur: AzureActiveDirectory)
  "SigninLogs":                      { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Interactive sign-in logs" },
  "AADNonInteractiveUserSignInLogs": { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Non-interactive sign-ins" },
  "AADServicePrincipalSignInLogs":   { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Service principal sign-ins" },
  "AADManagedIdentitySignInLogs":    { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Managed identity sign-ins" },
  "AADProvisioningLogs":             { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Provisioning logs" },
  "AADRiskyUsers":                   { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Risky users from Identity Protection" },
  "AADUserRiskEvents":               { platform: "sentinel", requires: "AzureActiveDirectory", desc: "User risk events" },
  "AuditLogs":                       { platform: "sentinel", requires: "AzureActiveDirectory", desc: "Entra ID audit trail" },

  // Office 365 (connecteur: Office365)
  "OfficeActivity": { platform: "sentinel", requires: "Office365", desc: "Office 365 audit logs" },

  // Security Events (connecteur: SecurityEvents)
  "SecurityEvent": { platform: "sentinel", requires: "SecurityEvents", desc: "Windows Security Events (legacy)" },
  "Event":         { platform: "sentinel", requires: "SecurityEvents", desc: "Windows Events (legacy)" },
  "WindowsEvent":  { platform: "sentinel", requires: "SecurityEvents", desc: "Windows Events (new AMA)" },

  // Syslog (connecteur: Syslog)
  "Syslog":            { platform: "sentinel", requires: "Syslog", desc: "Linux syslog" },
  "CommonSecurityLog": { platform: "sentinel", requires: "Syslog", desc: "CEF formatted logs" },

  // Azure Activity (connecteur: AzureActivity)
  "AzureActivity":   { platform: "sentinel", requires: "AzureActivity", desc: "Azure subscription activity" },
  "AzureDiagnostics":{ platform: "sentinel", requires: "AzureActivity", desc: "Azure resource diagnostics" },

  // Sentinel natives (pas de connecteur requis)
  "SecurityAlert":                { platform: "sentinel", requires: null, desc: "Alerts from all providers" },
  "SecurityIncident":             { platform: "sentinel", requires: null, desc: "Sentinel incidents" },
  "ThreatIntelligenceIndicator":  { platform: "sentinel", requires: null, desc: "Threat intelligence IOCs" },
  "Watchlist":                    { platform: "sentinel", requires: null, desc: "Sentinel watchlists" },
  "SentinelHealth":               { platform: "sentinel", requires: null, desc: "Sentinel health diagnostics" },
  "_GetWatchlist":                { platform: "sentinel", requires: null, desc: "Watchlist function" },
  "SentinelAudit":                { platform: "sentinel", requires: null, desc: "Sentinel audit events" },

  // Azure Monitor (connecteur: AzureMonitor)
  "Heartbeat":    { platform: "sentinel", requires: "AzureMonitor", desc: "Agent heartbeat" },
  "Perf":         { platform: "sentinel", requires: "AzureMonitor", desc: "Performance counters" },
  "VMConnection": { platform: "sentinel", requires: "AzureMonitor", desc: "VM connection data" },
  "Update":       { platform: "sentinel", requires: "AzureMonitor", desc: "Update assessment" },

  // DNS (connecteur: DNS)
  "DnsEvents":    { platform: "sentinel", requires: "DNS", desc: "DNS query logs" },
  "DnsInventory": { platform: "sentinel", requires: "DNS", desc: "DNS server inventory" },
};

// Tables Defender disponibles dans Sentinel via le connecteur MicrosoftThreatProtection
var DEFENDER_TABLES_IN_SENTINEL = [
  "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents",
  "DeviceLogonEvents", "DeviceImageLoadEvents", "DeviceEvents", "DeviceInfo", "DeviceNetworkInfo",
  "DeviceFileCertificateInfo", "DeviceTvmSoftwareVulnerabilities", "DeviceTvmSoftwareInventory",
  "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents", "UrlClickEvents",
  "CloudAppEvents", "IdentityLogonEvents", "IdentityQueryEvents", "IdentityDirectoryEvents", "IdentityInfo",
  "AlertInfo", "AlertEvidence", "BehaviorInfo", "BehaviorEntities"
];

module.exports = { TABLE_KB, DEFENDER_TABLES_IN_SENTINEL };
