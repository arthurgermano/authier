const { validateGrant } = require("../grant_types/index.js");
const { TODO_ERROR, throwError } = require("../errors/index.js");
const AuthFlow = require("./AuthFlow.js");
const { returnDefaultValue } = require("../common");

// ------------------------------------------------------------------------------------------------

class RefreshTokenFlow extends AuthFlow {
  /**
   * @summary. Creates a Refresh Token Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    super(options);
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Gets the refresh token info from the server
   * @param {Array} client_grant_types - The client grant types.
   * @param {Array} client_scopes - The client scopes.
   * @param {Array} scopes_requested - The scopes requested.
   * @param {Object} token_info - The token information to be added to the token.
   * @throws ServerError
   * @returns {Object} - An object with the refresh token generated and the token information provided
   */
  async getToken({
    client_grant_types = [],
    client_scopes,
    scopes_requested,
    token_info,
  }) {
    try {
      validateGrant("refresh_token", client_grant_types);
      const scopes_granted = this.validateScopes(
        client_scopes,
        scopes_requested,
        this.match_all_scopes,
        this.scope_required
      );
      return await this.generateRefreshToken({ scopes_granted, token_info });
    } catch (error) {
      throw error;
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Basically generates a string refresh token and returns it
   * - Can be implemented to do more things as save generated refresh tokens in the database etc...
   * @param {Object} scopes_granted - The scopes granted to the refresh token
   * @param {Object} token_info - The token information to be passed to the token
   * @throws ServerError
   * @return {String} refresh_token - the refresh_token giving access to generate a new token
   */
  async generateRefreshToken({ scopes_granted, token_info }) {
    // Must generate a refresh_token
    // Must return the refresh_token as string as a promise
    throwError(TODO_ERROR, "generateRefreshToken(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates the refresh token provided
   * @param {String} refresh_token - The refresh_token string to be validated.
   * @throws AccessDenied | InvalidRequest
   * @return {Object} refresh_token_validation - the properties set inside the token must be returned
   */
  async validateRefreshToken({ refresh_token }) {
    // Must validate the refresh_token
    // check it's signature, etc
    // Must return the validation info or throw an exception
    throwError(TODO_ERROR, "validateRefreshToken(): not implemented yet!");
  }
}

// ------------------------------------------------------------------------------------------------

module.exports = RefreshTokenFlow;
