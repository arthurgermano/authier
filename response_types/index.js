const {
  UNSUPPORTED_RESPONSE_TYPE,
  SERVER_ERROR,
  throwError,
} = require("../errors/index.js");

// ------------------------------------------------------------------------------------------------

/**
 * @summary. Validates if the provided response type is equal to the current response type
 * @param {String} response_type - Response type to be validated.
 * @param {String} expected_response_type - Expected Response type to be validated.
 * @throws ServerError | UnsupportedResponseType
 * @returns {Boolean} - True if the response type is equal to the expected response type.
 */
function validateResponse(response_type, expected_response_type) {
  if (typeof response_type !== "string") {
    throwError(
      SERVER_ERROR,
      "validateResponse(): response_type must be a valid string"
    );
  }

  if (typeof expected_response_type !== "string") {
    throwError(
      SERVER_ERROR,
      "validateResponse(): expected_response_type must be a valid string"
    );
  }

  if (expected_response_type !== response_type) {
    throwError(
      SERVER_ERROR,
      `validateResponse(): Expected: (${expected_response_type}) - Received: (${response_type})`
    );
  }
  return true;
}

// ------------------------------------------------------------------------------------------------

module.exports = {
  validateResponse,
};
