const {
  INVALID_REQUEST,
  SERVER_ERROR,
  INVALID_SCOPE,
  TODO_ERROR,
  throwError,
} = require("../errors/index.js");

const { returnDefaultValue } = require("../common");

// ------------------------------------------------------------------------------------------------

class AuthFlow {
  /**
   * Client option to issue or not a refresh client token - default is true
   * @type {Boolean}
   * @default true
   */
  issues_refresh_token;

  /**
   * Client's option whether the redirect_uri is required
   * @type {Boolean}
   * @default true
   */
  redirect_uri_required;

  /**
   * Client's option whether the scope is required
   * @type {Boolean}
   * @default false
   */
  scope_required;

  /**
   * Client's option whether the state is required
   * @type {Boolean}
   * @default true
   */
  state_required;

  /**
   * Refresh Token TTL - default is 7200 seconds
   * @type {Number}
   * @default 7200
   */
  refresh_token_expires_in;

  /**
   * Token TTL - default is 3600 seconds
   * @type {Number}
   * @default 3600
   */
  token_expires_in;

  /**
   * Match all scope option
   * @param {Boolean}
   * @default true
   */
  match_all_scopes;

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Creates a Auth Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    this.issues_refresh_token = returnDefaultValue(
      options.issues_refresh_token,
      true
    );
    this.redirect_uri_required = returnDefaultValue(
      options.redirect_uri_required,
      true
    );
    this.scope_required = returnDefaultValue(options.scope_required, false);
    this.state_required = returnDefaultValue(options.state_required, true);
    this.refresh_token_expires_in = returnDefaultValue(
      options.refresh_token_expires_in,
      7200
    );
    this.token_expires_in = returnDefaultValue(options.token_expires_in, 3600);
    this.match_all_scopes = returnDefaultValue(options.match_all_scopes, true);
  }

  // ----------------------------------------------------------------------------------------------
  /**
   * @summary. Checks provided redirect_uri against Client redirect_uris
   * @param {String} redirect_uri - The redirect_uri provided in the request
   * @param {Array} redirect_uris - The client allowed redirect_uris
   * @throws ServerError | InvalidRequest
   * @returns {Boolean} - True if the redirect_uri is valid
   */
  validateRedirectUri(redirect_uri, redirect_uris, uri_encoded = false) {
    if (typeof redirect_uri !== "string") {
      throwError(
        SERVER_ERROR,
        "validateRedirectUri(): redirect_uri must be a valid string containing a valid URI"
      );
    }
    if (!Array.isArray(redirect_uris) || redirect_uris.length == 0) {
      throwError(
        SERVER_ERROR,
        "validateRedirectUri(): redirect_uris must be an array of strings containing valid URIs"
      );
    }

    for (let uri of redirect_uris) {
      if (uri_encoded) {
        uri = encodeURIComponent(uri);
      }
      if (uri === redirect_uri) {
        return true;
      }
    }
    throwError(
      INVALID_REQUEST,
      "validateRedirectUri(): redirect_uri is not valid for the client"
    );
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Checks if the state is required and is correct
   * @param {String} state - The state provided in the request
   * @param {String} expected_state - The state expected in the request
   * @throws ServerError | InvalidRequest
   * @returns {Boolean} - True if the state is valid
   */
  validateState(state, expected_state) {
    if (typeof state !== "string") {
      throwError(SERVER_ERROR, "validateState(): state must be a valid string");
    }
    if (typeof expected_state !== "string") {
      throwError(
        SERVER_ERROR,
        "validateState(): expected_state must be a valid string"
      );
    }
    if (state !== expected_state) {
      throwError(
        INVALID_REQUEST,
        "validateState(): state is different from the expected state"
      );
    }
    return true;
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates if the scopes provided are correct only if required or provided
   * @param {Array} scopes - Array os scopes provided in the request.
   * @param {Array} expected_scopes - The scopes array provided in the request.
   * @throws InvalidScope | ServerError
   * @returns {Boolean} - True if the scopes are valid
   */
  validateScopes(scopes, expected_scopes, match_all = true, required = false) {
    if (!Array.isArray(expected_scopes) || expected_scopes.length == 0) {
      return "";
    }
    if (!Array.isArray(scopes) || scopes.length == 0) {
      if (required) {
        throwError(
          INVALID_SCOPE,
          "validateScopes(): The scopes requested are not valid for this client"
        );
      }
    }

    let valid_scopes = [];
    if (match_all) {
      // must match all scopes listed
      // if any scope is not granted, throw error
      // otherwise return true
      for (let expected_scope of expected_scopes) {
        const hasScope = scopes.find((s) => s === expected_scope);
        if (!hasScope) {
          throwError(
            INVALID_SCOPE,
            "validateScopes(): The scope " + scope + " is not valid"
          );
        }
      }
      return scopes;
    }

    // if any scope is valid and is listed then return true
    // otherwise throw an error
    for (let expected_scope of expected_scopes) {
      const hasScope = scopes.find((s) => s === scope);
      if (hasScope) {
        valid_scopes.push(expected_scope);
      }
    }
    if (valid_scopes.length > 0) {
      return valid_scopes;
    }
    throwError(
      INVALID_SCOPE,
      `validateScopes(): No scope requested are able to be granted by this client`
    );
  }

  // ----------------------------------------------------------------------------------------------
  /**
   * @summary. Generates a new access token
   * @param {Object} scopes_granted - The scopes granted to the client
   * @param {Object} token_info - The info to be passed to the token
   * @throws ServerError
   * @returns {Object} - The token generated
   */
  async generateToken(scopes_granted, token_info) {
    throwError(TODO_ERROR, "generateToken(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates the token against the server
   * @param {Object} token_info - The token to be validated
   * @throws ServerError
   * @returns {Boolean} - True if the token is valid
   */
  async validateToken(token_info) {
    throwError(TODO_ERROR, "validateToken(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Gets the token info from the server
   * @param {Object} params - List of params to be passed to create a token - it differs depending on the grant type
   * @throws ServerError
   * @returns {Boolean} - True if the token is valid
   */
  async getToken({ params }) {
    throwError(TODO_ERROR, "getToken(): not implemented yet!");
  }
}
// ------------------------------------------------------------------------------------------------

module.exports = AuthFlow;
