const { validateGrant } = require("../grant_types/index.js");
const { validateResponse } = require("../response_types/index.js");
const {
  TODO_ERROR,
  SERVER_ERROR,
  throwError,
  INVALID_REQUEST,
} = require("../errors/index.js");
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
   * pkce_required - Whether the pkce is required or not
   * @param {Boolean}
   * @default true
   */
  pkce_required;

  /**
   * mapping_challenge_methods - The mapper for code challenge methods
   * @param {Object}
   * @default { plain: "plain", "S256": "sha256" }
   */
  mapping_challenge_methods;

  /**
   * allow_plain_pkce_method - Whether the pkce plain method is allowed
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
    this.pkce_required = returnDefaultValue(options.pkce_required, true);

    // must be an object
    this.mapping_challenge_methods = returnDefaultValue(
      typeof options.mapping_challenge_methods == "object"
        ? options.mapping_challenge_methods
        : undefined,
      { S256: "sha256" }
    );

    this.allow_plain_pkce_method = returnDefaultValue(
      options.allow_plain_pkce_method,
      false
    );
    if (this.allow_plain_pkce_method) {
      this.mapping_challenge_methods.plain = "plain";
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Returns the a new code
   * @param {String} response_type - The response type.
   * @param {String} redirect_uri - The redirect uri string to redirect the request after resource approval.
   * @param {Array} requested_scopes - The scopes requested.
   * @param {Object} code_challenge - The code challenge using with pkce flow.
   * @param {Object} code_challenge_method - The code challenge method using with pkce flow.
   * @param {Object} code_info - The code information to be added to the code.
   * @return {Object} code - the code information object
   */
  async getCode({
    response_type,
    redirect_uri,
    requested_scopes = [],
    code_challenge,
    code_challenge_method = "S256",
    code_info,
  }) {
    try {
      validateResponse(response_type, "code");
      const scopes_granted = this.validateScopes(requested_scopes);
      if (this.redirect_uri_required) {
        this.validateRedirectUri(redirect_uri);
      }
      if (this.pkce_required) {
        this.validateCodeChallengeMethod(code_challenge_method);
        this.validateCodeChallenge(code_challenge);
      }

      return await this.generateCode({
        scopes_granted,
        code_info,
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
   * @param {String} redirect_uri - The redirect uri string to redirect the request after resource approval.
   * @param {Object} token_info - The token information to be added to the token.
   * @param {String} code_verifier - The authorization code verifier with PKCE flow.
   * @throws ServerError
   * @returns {Object} - An object with the token generated and the token information provided
   */
  async getToken({ code, redirect_uri, token_info, code_verifier }) {
    try {
      validateGrant("authorization_code", this.grant_types);
      this.validateRedirectUri(redirect_uri);
      const code_validation = await this.validateCode({
        code_verifier,
        code,
      });
      return await this.generateToken({
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
        INVALID_REQUEST,
        `The requested algorithm ${code_challenge_method} is not supported by this server!`
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
        INVALID_REQUEST,
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
        INVALID_REQUEST,
        `The code verifier "${this.code_verifier}" is not correct or is missing!`
      );
    }
    const decoded_verifier = this.decodeVerifier(
      code_verifier,
      code_challenge_method
    );

    if (decoded_verifier !== code_challenge) {
      throwError(
        INVALID_REQUEST,
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
   * - Can be implemented to do more things as save generated codes in the database etc..
   * @param {Object} args 
   * @throws ServerError
   * @return {String} code - the code giving access to resources
   */
  async generateCode({ ...args }) {
    // Must generate a code
    // Must return the code as string as a promise
    throwError(TODO_ERROR, "generateCode(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates a provided code
   * - Can be implemented to do more things as save codes in the database etc...
   * @param {String} code - The code string to be validated.
   * @param {String} code_verifier - The authorization code verifier with PKCE flow.
   * @throws Errors - Depending of the flow
   * @return {Object} validation of the code information - the code giving access to request a token
   */
  async validateCode({ code, code_verifier }) {
    // Must validate the code
    // check its scopes, signature, etc
    // Must return the validation info or throw an exception
    throwError(TODO_ERROR, "validateCode(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------------------

module.exports = AuthorizationCodeFlow;
