const { validateGrant } = require("../grant_types/index.js");
const { validateResponse } = require("../response_types/index.js");
const { TODO_ERROR } = require("../errors/index.js");
const AuthFlow = require("./AuthFlow.js");

// ------------------------------------------------------------------------------------------------

class AuthorizationCodeFlow extends AuthFlow {
  /**
   * Authorization Code flow code string.
   * @type {String}
   */
  code;

  /**
   * Authorization Code TTL - Default is 5 minutes.
   * @type {Number}
   */
  code_expires_in;

  /**
   * is_uri_encoded - Whether the redirect_uri is encoded or not
   * @param {String}
   */
  is_uri_encoded;

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Creates a Authorization Code Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    super(options);
    this.code = options.code;
    this.code_expires_in = options.code_expires_in || 300;
    this.is_uri_encoded = options.is_uri_encoded || false;
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Returns the a new code
   * @param {String} response_type - The response type.
   * @param {Array} client_redirect_uris - The client redirect uris.
   * @param {String} redirect_uri - The redirect uri string to redirect the request after resource approval.
   * @param {Array} requested_scopes - The scopes requested.
   * @param {Array} client_scopes - The client scopes.
   * @param {String} state - The state string to be added to the redirect uri.
   * @param {Object} code_info - The code information to be added to the code.
   * @return {Object} code - the code information object
   */
  async getCode({
    response_type,
    client_redirect_uris = [],
    redirect_uri,
    requested_scopes = [],
    client_scopes = [],
    state,
    code_info,
  }) {
    try {
      validateResponse(response_type, "code");
      const scopes_granted = this.validateScopes(
        requested_scopes,
        client_scopes,
        this.match_all_scopes,
        this.scope_required
      );
      if (this.redirect_uri_required) {
        this.validateRedirectUri(
          redirect_uri,
          client_redirect_uris,
          this.is_uri_encoded
        );
      }
      if (this.state_required) {
        this.validateState(state, state);
      }

      return await this.generateCode({
        scopes_granted,
        code_info,
        state,
        redirect_uri,
      });
    } catch (error) {
      throw error;
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * @summary. Gets a new token from the server
   * @param {String} code - The authorization code.
   * @param {Object} client_grant_types - The client grant types.
   * @param {Object} client_scopes - The client scopes.
   * @param {Object} scopes_requested - The scopes requested.
   * @param {Object} client_redirect_uris - The client redirect uris.
   * @param {String} redirect_uri - The redirect uri string to redirect the request after resource approval.
   * @param {Object} token_info - The token information to be added to the token.
   * @throws ServerError
   * @returns {Object} - An object with the token generated and the token information provided
   */
  async getToken({
    code,
    client_grant_types = [],
    client_scopes,
    scopes_requested,
    client_redirect_uris = [],
    redirect_uri,
    token_info,
  }) {
    try {
      validateGrant("authorization_code", client_grant_types);
      const code_validation = await this.validateCode(code, scopes_requested);
      const scopes_granted = this.validateScopes(
        scopes_requested,
        client_scopes,
        this.match_all_scopes,
        this.scope_required
      );
      this.validateRedirectUri(
        redirect_uri,
        client_redirect_uris,
        this.is_uri_encoded
      );
      return await this.generateToken({
        scopes_granted,
        token_info,
        redirect_uri,
        code_validation,
      });
    } catch (error) {
      throw error;
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Basically generates a string code and returns it
   * - Can be implemented to do more things as save generated codes in the database etc...
   * @param {Object} scopes_requested - The client grant types.
   * @param {Object} code_info - The code information to be added to the code.
   * @throws ServerError
   * @return {String} code - the code giving access to resources
   */
  async generateCode({ scopes_requested, state, code_info }) {
    // Must generate a code
    // Must return the code as string as a promise
    throw TODO_ERROR;
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates a provided code
   * - Can be implemented to do more things as save codes in the database etc...
   * @param {String} code - The code string to be validated.
   * @param {Object} scopes_requested - The scopes requested.
   * @throws Errors - Depending of the flow
   * @return {Object} validation of the code information - the code giving access to request a token
   */
  async validateCode({ code, scopes_requested }) {
    // Must validate the code
    // check its scopes, signature, etc
    // Must return the validation info or throw an exception
    throw TODO_ERROR;
  }

  // ----------------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------------------

module.exports = AuthorizationCodeFlow;
