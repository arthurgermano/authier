const AuthFlow = require("../flows/AuthFlow.js");
const ERRORS = require("../errors/Errors.js");
const authorizationCodeGrant = require("../grants/AuthorizationCodeGrant.js");
const codeResponse = require("../responses/CodeResponse.js");

/**
 * Class implementing a Authorization Code flow OAuth2.
 * @extends AuthFlow
 */
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

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Creates a Authorization Code Flow
   * @param {String} provided_data.code - Authorization Code flow code string.
   *
   * @constructor
   */
  constructor(provided_data = {}) {
    super(provided_data);
    this.code = provided_data.code;
    this.code_expires_in = provided_data.code_expires_in || 300;
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates the flow to get a code -
   * - Validates the client_id
   * - Validates the response type
   * - Validates if the redirect uri is correct with the client redirect uri
   * - Validates the scopes provided if they match the client scopes
   * - Validates if the state is valid and if it is required or not
   * - Generates a code to request a token
   *
   * @param {Object} provided_data - An object with the Authorization Code Flow info required to generate a Code.
   * @param {String} provided_data.client_id - The client_id string identification.
   * @param {String} provided_data.response_type - The response_type must be "code".
   * @param {String} provided_data.redirect_uri - The redirect uri string to redirect the request after resource approval.
   * @param {String} provided_data.scopes - The scopes being requested
   * @param {String} provided_data.state - The state if required by the client
   *
   * @param {Object} options - An object with all the options needed to generate code function.
   *
   * @throws InvalidRequest
   * @throws InvalidClient
   * @throws MismatchClient
   * @throws ServerError
   * @throws UnsupportedResponseType
   * @throws InvalidScope
   *
   * @return {String} code - the code of Authorize Code Flow
   */
  async getCodeResponse(provided_data, options = {}) {
    if (!provided_data) {
      throw ERRORS.INVALID_REQUEST;
    }
    try {
      this.validateClientId(provided_data.client_id);
      codeResponse.validateResponse(provided_data.response_type);
      this.validateUri(provided_data.redirect_uri, options.encoded_uri);
      this.validateScopes(provided_data.scopes);
      this.isStateValid(provided_data.state);
      this.code = await this.generateCode(provided_data, options);
      return this.code;
    } catch (error) {
      throw error;
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Returns Authorization Code Flow Properties
   *
   * @return {Object} Authorization Code flow - properties
   */
  getProperties() {
    return {
      ...super.getProperties(),
      code: this.code,
      code_expires_in: this.code_expires_in,
    };
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates the flow to get a token -
   * - Validates the client_id
   * - Validates if the client has the grant type
   * - Validates if the redirect uri is correct with the client redirect uri
   * - Validates if the requested uri is the same of the redirect uri
   * - Validates if the code provided matches the one stored
   * - Updates option object param with code_validation property returned by the validateCode function
   * - Generates a token to provide access
   *
   * @param {Object} provided_data - An object with the Authorization Code Flow info required to generate a Code.
   * @param {String} provided_data.client_id - The client_id string identification.
   * @param {String} provided_data.grant_type - The grant_type must be "authorization_code".
   * @param {String} provided_data.redirect_uri - The redirect uri string to redirect the request after resource approval.
   * @param {String} provided_data.code_requested_uri - The redirect uri requested in the code request
   * @param {String} provided_data.code - The code to be validated received in the first request
   *
   * @param {Object} options - An object with all the options needed to generate token function.
   *
   * @throws InvalidRequest
   * @throws InvalidClient
   * @throws MismatchClient
   * @throws InvalidGrant
   * @throws ServerError
   *
   * @return {String} token - the token giving access to resources
   */
  async getToken(provided_data, options = {}) {
    if (!provided_data) {
      throw ERRORS.INVALID_REQUEST;
    }
    try {
      this.validateClientId(provided_data.client_id);
      this.validateGrantType(authorizationCodeGrant, provided_data.grant_type);
      this.validateUri(provided_data.redirect_uri);
      this.validateRequestedUri(
        provided_data.code_requested_uri,
        provided_data.redirect_uri
      );

      options.code_validation = await this.validateCode(provided_data.code);

      return await this.generateToken(provided_data, options);
    } catch (error) {
      throw error;
    }
  }

  // ------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Basically generates a string code and returns it
 * - Can be implemented to do more things as save generated codes in the database etc...
 *
 * @param {Object} code_data - The code information that must be included in the code.
 *
 * @param {Object} options - The options that must be considered when generating the code should have the information to be added into the code
 *
 * @throws ServerError
 *
 * @return {String} code - the code giving access to resources
 */
async function generateCode(code_data, options) {
  // Must generate a code
  // Must return the code as string as a promise
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Validates a provided code
 * - Can be implemented to do more things as save codes in the database etc...
 *
 * @param {String} code - The code string to be validated.
 *
 * @throws Errors - Depending of the flow
 *
 * @return {String} code - the code giving access to request a token
 */
async function validateCode(code) {
  // Must validate the code
  // check its scopes, signature, etc
  // Must return the validation info or throw an exception
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

AuthorizationCodeFlow.prototype.generateCode = generateCode;
AuthorizationCodeFlow.prototype.validateCode = validateCode;

module.exports = AuthorizationCodeFlow;
