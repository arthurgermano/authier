const {
  UNSUPPORTED_GRANT_TYPE,
  SERVER_ERROR,
  throwError,
} = require("../errors/index.js");

// ------------------------------------------------------------------------------------------------
/**
 * @summary. Checks if the client's grant types provided has the requested grant type
 * @param {String} requested_grant_type - The requested grant type.
 * @param {Array} expected_grant_types - The client grant types.
 * @throws ServerError | UnsupportedGrantType
 * @returns {Boolean} - True if the client's grant types has the requested grant type.
 */
function validateGrant(requested_grant_type, expected_grant_types = []) {
  if (typeof requested_grant_type !== "string") {
    throwError(
      SERVER_ERROR,
      "validateGrant(): requested_grant_type must be a valid string"
    );
  }
  if (!Array.isArray(expected_grant_types)) {
    throwError(
      SERVER_ERROR,
      "validateGrant(): expected_grant_types must be a valid array"
    );
  }
  if (expected_grant_types.length === 0) {
    throwError(
      SERVER_ERROR,
      "validateGrant(): expected_grant_types must be a valid array"
    );
  }
  if (!expected_grant_types.includes(requested_grant_type)) {
    throwError(
      UNSUPPORTED_GRANT_TYPE,
      `validateGrant(): Not supported the grant type: ${requested_grant_type}`
    );
  }
  return true;
}

// ------------------------------------------------------------------------------------------------

module.exports = {
  validateGrant,
};
