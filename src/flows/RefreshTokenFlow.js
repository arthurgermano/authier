const AuthFlow = require("../flows/AuthFlow.js");
const ERRORS = require("../errors/Errors.js");
const refreshTokenGrant = require("../grants/RefreshTokenGrant.js");

/**
 * Class implementing a Refresh Token flow OAuth2.
 * @extends AuthFlow
 */
class RefreshTokenFlow extends AuthFlow {
  /**
   * Summary. Creates a Refresh Token Flow
   *
   * @constructor
   */
  constructor(provided_data = {}) {
    super(provided_data);
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates the flow to get a token -
   * - Validates the client_id
   * - Validates the if the client has the grant type and the grant type is refresh_token
   * - Validates the scopes required
   *
   * @param {Object} provided_data - An object with the Authorization Code Flow info required to generate a Code.
   * @param {String} provided_data.client_id - The client_id string identification.
   * @param {String} provided_data.grant_type - The grant_type must be "password".
   * @param {String} provided_data.scopes - The scopes being requested
   *
   * @param {Object} options - An object with all the options needed to generate token function.
   *
   * @throws InvalidClient
   * @throws InvalidGrant
   * @throws InvalidRequest
   * @throws InvalidScope
   * @throws MismatchClient
   * @throws ServerError
   *
   * @return {String} token - the token giving access to resources
   */
  async getToken(provided_data, options) {
    if (!provided_data) {
      throw ERRORS.INVALID_REQUEST;
    }
    try {
      this.validateClientId(provided_data.client_id);
      this.validateGrantType(refreshTokenGrant, provided_data.grant_type);
      this.validateScopes(provided_data.scopes);

      return await this.generateRefreshToken(provided_data, options);
    } catch (error) {
      throw error;
    }
  }

  // ------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Basically generates a string refresh token and returns it
 * - Can be implemented to do more things as save generated refresh tokens in the database etc...
 *
 * @param {Object} refresh_token_data - The refresh token information that must be included in the token.
 *
 * @param {Object} options - The options that must be considered when generating the token should have the information to be added into the token
 *
 * @throws ServerError
 *
 * @return {String} refresh_token - the refresh_token giving access to generate a new token
 */
async function generateRefreshToken(refresh_token_data, options) {
  // Must generate a refresh_token
  // Must return the refresh_token as string as a promise
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Validates the refresh token provided
 *
 * @param {String} refresh_token - The refresh_token string to be validated.
 *
 * @throws AccessDenied
 * @throws InvalidRequest
 * 
 * @return {Object} refresh_token_validation - the properties set inside the token must be returned
 */
async function validateRefreshToken(refresh_token) {
  // Must validate the refresh_token
  // check it's signature, etc
  // Must return the validation info or throw an exception
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

RefreshTokenFlow.prototype.generateRefreshToken = generateRefreshToken;
RefreshTokenFlow.prototype.validateRefreshToken = validateRefreshToken;

module.exports = RefreshTokenFlow;
