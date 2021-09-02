const {
  SERVER_ERROR,
  UNSUPPORTED_RESPONSE_TYPE,
} = require("../errors/Errors.js");

/** Class implementing Response Types */
class ResponseTypes {
  /**
   * Response Type identification string.
   * @type {String}
   */
  response_type;

  /**
   * Supported Response Types Array provided.
   * @static
   * @type {Array}
   */
  static supported_response_types;

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Creates a Response Type
   *
   * @param {String} response_type - The response type - required and not null.
   *
   * @constructor
   *
   * @throws ServerError
   */
  constructor(response_type) {
    if (!response_type || response_type === "") {
      throw SERVER_ERROR;
    }
    this.response_type = response_type;
    if (!ResponseTypes.supported_response_types) {
      ResponseTypes.supported_response_types = [];
    }
    ResponseTypes.supported_response_types.push(this.response_type);
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Returns the response types registered
   * @static
   */
  static getSupportedResponseTypes() {
    return ResponseTypes.supported_response_types;
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the provided response type is equal to the current response type
   *
   * @param {String} response_type - Response type to be validated.
   *
   * @throws UnsupportedResponseType
   */
  validateResponse(response_type) {
    if (this.response_type !== response_type) {
      throw UNSUPPORTED_RESPONSE_TYPE;
    }
  }
  // ------------------------------------------------------------------------------------
}

module.exports = ResponseTypes;
