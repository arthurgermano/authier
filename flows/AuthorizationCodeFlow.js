const { validateGrant } = require("../grant_types/index.js");
const { validateResponse } = require("../response_types/index.js");
const { TODO_ERROR, SERVER_ERROR, throwError } = require("../errors/index.js");
const { returnDefaultValue } = require("../common");
const { createHash } = require("crypto");
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
   * @default 300
   */
  code_expires_in;

  /**
   * is_uri_encoded - Whether the redirect_uri is encoded or not
   * @param {Boolean}
   * @default false
   */
  is_uri_encoded;

  /**
   * pcke_required - Whether the pcke is required or not
   * @param {Boolean}
   * @default true
   */
  pcke_required;

  /**
   * code_challenge_method - The code challenge method
   * @param {String}
   * @default S256
   */
  code_challenge_method;

  /**
   * mapping_challenge_methods - The mapper for code challenge methods
   * @param {Object}
   * @default { plain: "plain", "S256": "sha256" }
   */
  mapping_challenge_methods;

  /**
   * allow_plain_pkce_method - Whether the pcke plain method is allowed
   * @param {Boolean}
   * @default false
   */
  allow_plain_pkce_method;

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Creates a Authorization Code Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    super(options);
    this.code = options.code;
    this.code_expires_in = returnDefaultValue(options.code_expires_in, 300);
    this.is_uri_encoded = returnDefaultValue(options.is_uri_encoded, false);
    this.pcke_required = returnDefaultValue(options.pcke_required, true);
    this.code_challenge_method = returnDefaultValue(
      options.code_challenge_method,
      "S256"
    );
    this.mapping_challenge_methods = returnDefaultValue(
      options.mapping_challenge_methods,
      { plain: "plain", S256: "sha256" }
    );
    this.allow_plain_pkce_method = returnDefaultValue(
      options.allow_plain_pkce_method,
      false
    );

    this.validateCodeChallengeMethod(this.code_challenge_method);
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
    code_challenge,
    code_challenge_method,
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
      if (this.pcke_required) {
        this.validateCodeChallengeMethod(code_challenge_method);
        this.validateCodeChallenge(code_challenge);
      }

      return await this.generateCode({
        scopes_granted,
        code_info,
        state,
        redirect_uri,
        code_challenge,
        code_challenge_method,
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
    code_verifier,
    code_challenge,
    code_challenge_method,
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
      if (this.pcke_required) {
        this.validateCodeVerifier(
          code_verifier,
          code_challenge,
          code_challenge_method
        );
      }
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
   * @summary. Validates the code challenge method provided is correct and if it is supported
   * @param {String} code_challenge_method - The code challenge method.
   * @throws ServerError
   */
  validateCodeChallengeMethod(code_challenge_method) {
    const is_code_challenge_supported = Object.keys(
      this.mapping_challenge_methods
    ).find((mcm) => mcm === code_challenge_method);
    if (!is_code_challenge_supported) {
      throwError(
        SERVER_ERROR,
        `The requested algorithm ${this.code_challenge_method} is not supported by this server!`
      );
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates the code challenge provided
   * @param {String} code_challenge - The code challenge.
   * @throws ServerError
   */
  validateCodeChallenge(code_challenge) {
    if (
      !code_challenge ||
      code_challenge.length == 0 ||
      typeof code_challenge != "string"
    ) {
      throwError(
        SERVER_ERROR,
        `The code challenge "${this.code_challenge}" is not correct or is missing!`
      );
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates the code verifier provided
   * @param {String} code_verifier - The code verifier.
   * @throws ServerError
   */
  validateCodeVerifier(code_verifier, code_challenge, code_challenge_method) {
    this.validateCodeChallenge(code_challenge);
    if (
      !code_verifier ||
      code_verifier.length == 0 ||
      typeof code_verifier != "string"
    ) {
      throwError(
        SERVER_ERROR,
        `The code verifier "${this.code_verifier}" is not correct or is missing!`
      );
    }
    const decoded_verifier = this.decodeVerifier(
      code_verifier,
      code_challenge_method
    );
    if (decoded_verifier !== code_challenge) {
      throwError(
        SERVER_ERROR,
        `The code verifier is not matching the code challenge!`
      );
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Gets the challenge code from the verifier code
   * @param {String} code_verifier - The code verifier.
   * @returns {String} code_challenge
   * @throws ServerError
   */
  decodeVerifier(code_verifier, code_challenge_method) {
    if (code_challenge_method == "plain") {
      if (!this.allow_plain_pkce_method) {
        throwError(
          SERVER_ERROR,
          "This client doesn't not allow plain as code challege method"
        );
      }
      return code_verifier;
    }

    const algorithmKey = Object.keys(this.mapping_challenge_methods).find(
      (mcm) => mcm === code_challenge_method
    );
    if (!algorithmKey) {
      throwError(
        SERVER_ERROR,
        `The algorithm "${code_challenge_method}" is not supported by this client or server`
      );
    }
    return createHash(this.mapping_challenge_methods[algorithmKey])
      .update(code_verifier)
      .digest()
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
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
    throwError(TODO_ERROR, "generateCode(): not implemented yet!");
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
    throwError(TODO_ERROR, "validateCode(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------------------

module.exports = AuthorizationCodeFlow;
