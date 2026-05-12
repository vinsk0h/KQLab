/**
 * sanitize.js — Input sanitization and validation helpers.
 * Used across all route handlers to strip dangerous characters and enforce length limits.
 */

const VALID_ENVIRONMENTS = ["Defender", "Sentinel", "Both"];
const VALID_SEVERITIES   = ["critical", "high", "medium", "low", "info"];
const VALID_LANGUAGES    = ["KQL", "ELK", "SPL"];

/**
 * Strip characters that could enable XSS or injection, then truncate.
 * @param {string} str
 * @param {number} maxLen — default 200
 * @returns {string}
 */
function sanitize(str, maxLen = 200) {
  if (typeof str !== "string") return "";
  return str.replace(/[<>]/g, "").trim().slice(0, maxLen);
}

/**
 * Return value if it is in the allowed list, otherwise return fallback.
 * @param {*} value
 * @param {Array} allowed
 * @param {*} fallback
 * @returns {*}
 */
function validateEnum(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

/**
 * Validate a CSS hex color: #rgb or #rrggbb.
 * @param {*} value
 * @returns {boolean}
 */
function isValidHexColor(value) {
  return typeof value === "string" && /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(value);
}

/**
 * Normalize and validate a URL for safe storage.
 * Uses new URL() to parse, then returns .href (never reconstructed manually).
 * Does NOT strip slashes — sanitize() must not be used on URLs.
 * @param {string} raw
 * @returns {string|null} normalized href, or null if invalid
 */
function sanitizeUrl(raw) {
  if (typeof raw !== "string") return null;
  var trimmed = raw.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return null;
  try {
    return new URL(trimmed).href;
  } catch(e) {
    return null;
  }
}

/**
 * Validate a base64 image data URI (JPEG/PNG/WebP/GIF).
 * @param {string|undefined} raw — raw value from request body
 * @param {number} maxBytes — max length of the data URI string (default 204800 ≈ 150 KB)
 * @returns {{ ok: boolean, value: string|null, error?: string }}
 */
function validateAvatarDataUri(raw, maxBytes) {
  if (maxBytes === undefined) maxBytes = 204800;
  if (!raw || raw === "") return { ok: true, value: null };
  if (!/^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/]+=*$/.test(raw))
    return { ok: false, error: "Format invalide. JPEG, PNG, WebP ou GIF uniquement." };
  if (raw.length > maxBytes)
    return { ok: false, error: "Image trop grande (max " + Math.round(maxBytes / 1024) + " Ko)." };
  return { ok: true, value: raw };
}

module.exports = {
  sanitize,
  sanitizeUrl,
  validateEnum,
  isValidHexColor,
  validateAvatarDataUri,
  VALID_ENVIRONMENTS,
  VALID_SEVERITIES,
  VALID_LANGUAGES,
};
