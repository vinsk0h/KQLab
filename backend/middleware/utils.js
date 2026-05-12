/**
 * utils.js — Re-exports from lib/sanitize.js and middleware/roles.js.
 * All route files continue to require("../middleware/utils") unchanged.
 */

const { sanitize, sanitizeUrl, validateEnum, isValidHexColor, validateAvatarDataUri, VALID_ENVIRONMENTS, VALID_SEVERITIES, VALID_LANGUAGES } = require("../lib/sanitize");
const { requireWriter, requireAdmin } = require("./roles");

module.exports = {
  sanitize,
  sanitizeUrl,
  validateEnum,
  isValidHexColor,
  validateAvatarDataUri,
  requireWriter,
  requireAdmin,
  VALID_ENVIRONMENTS,
  VALID_SEVERITIES,
  VALID_LANGUAGES,
};
