const { validateGrant } = require("../grant_types/index.js");
const AuthFlow = require("./AuthFlow.js");

// ------------------------------------------------------------------------------------------------

class ClientCredentialsFlow extends AuthFlow {
  /**
   * @summary. Creates a Client Credentials Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    super(options);
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Gets a new token from the server
   * @param {Array} scopes_requested - The scopes requested.
   * @param {Object} token_info - The token information to be added to the token.
   * @throws ServerError
   * @returns {Object} - An object with the token generated and the token information provided
   */
  async getToken({
    scopes_requested,
    token_info,
  }) {
    try {
      validateGrant("client_credentials", this.grant_types);
      const scopes_granted = this.validateScopes(scopes_requested);
      return await this.generateToken({ scopes_granted, token_info });
    } catch (error) {
      throw error;
    }
  }
}

// ------------------------------------------------------------------------------------------------

module.exports = ClientCredentialsFlow;
