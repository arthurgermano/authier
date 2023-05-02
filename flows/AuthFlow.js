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
  scopes_required;

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

  /**
   * The grant types of this client
   * @param {Array}
   * @default []
   */
  grant_types;

  /**
   * The scopes of this client
   * @param {Array}
   * @default []
   */
  scopes;

  /**
   * The redirects_uri of this client
   * @param {Array}
   * @default []
   */
  redirect_uris;

    /**
   * is_uri_encoded - Whether the redirect_uri is encoded or not
   * @param {Boolean}
   * @default false
   */
    is_uri_encoded;

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
    this.scopes_required = returnDefaultValue(options.scopes_required, false);
    this.state_required = returnDefaultValue(options.state_required, true);
    this.refresh_token_expires_in = returnDefaultValue(
      options.refresh_token_expires_in,
      7200
    );
    this.token_expires_in = returnDefaultValue(options.token_expires_in, 3600);
    this.match_all_scopes = returnDefaultValue(options.match_all_scopes, true);
    this.scopes = returnDefaultValue(options.scopes, []);
    this.redirect_uris = returnDefaultValue(options.redirect_uris, []);
    this.grant_types = returnDefaultValue(options.grant_types, []);
    this.is_uri_encoded = returnDefaultValue(options.is_uri_encoded, false);
  }

  // ----------------------------------------------------------------------------------------------
  /**
   * @summary. Checks provided redirect_uri against Client redirect_uris
   * @param {String} redirect_uri - The redirect_uri provided in the request
   * @param {Array} redirect_uris - The client allowed redirect_uris
   * @throws ServerError | InvalidRequest
   * @returns {Boolean} - True if the redirect_uri is valid
   */
  validateRedirectUri(redirect_uri) {
    if (typeof redirect_uri !== "string") {
      throwError(
        INVALID_REQUEST,
        "validateRedirectUri(): redirect_uri must be a valid string containing a valid URI"
      );
    }
    if (!Array.isArray(this.redirect_uris) || this.redirect_uris.length == 0) {
      throwError(
        INVALID_REQUEST,
        "validateRedirectUri(): redirect_uris must be an array of strings containing valid URIs, but the client has no redirect_uris registered"
      );
    }

    for (let uri of this.redirect_uris) {
      if (this.is_uri_encoded) {
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
   * @summary. Validates if the scopes provided are correct only if required or provided
   * @param {Array} scopes - Array os scopes provided in the request.
   * @param {Array} expected_scopes - The scopes array provided in the request.
   * @throws InvalidScope | ServerError
   * @returns {Boolean} - True if the scopes are valid
   */
  validateScopes(expected_scopes) {
    if (!Array.isArray(expected_scopes) || expected_scopes.length == 0) {
      if (this.scopes_required) {
        throwError(
          INVALID_SCOPE,
          "validateScopes(): No scopes informed but this client requires scopes to be informed"
        );
      }
      return this.scopes;
    }
    if (!Array.isArray(this.scopes) || this.scopes.length == 0) {
      throwError(
        INVALID_SCOPE,
        "validateScopes(): The scopes requested are not valid for this client - this client has no scopes"
      );
    }
    if (this.match_all_scopes) {
      // must match all scopes listed
      // if any scope is not granted, throw error
      // otherwise return true
      for (let expected_scope of expected_scopes) {
        const hasScope = this.scopes.find((s) => s === expected_scope);
        if (!hasScope) {
          throwError(
            INVALID_SCOPE,
            "validateScopes(): The scope " + expected_scope + " is not valid"
          );
        }
      }
      return expected_scopes;
    }

    // if any scope is valid and is listed then return true
    // otherwise throw an error
    let valid_scopes = [];
    for (let expected_scope of expected_scopes) {
      const hasScope = this.scopes.find((s) => s === expected_scope);
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
