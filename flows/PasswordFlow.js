const { validateGrant } = require("../grant_types/index.js");
const AuthFlow = require("./AuthFlow.js");

// ------------------------------------------------------------------------------------------------

class PasswordFlow extends AuthFlow {
  /**
   * @summary. Creates a Password Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    super(options);
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Gets a new token from the server
   * @param {Array} client_grant_types - The client grant types.
   * @param {Array} client_scopes - The client scopes.
   * @param {Array} scopes_requested - The scopes requested.
   * @param {Object} token_info - The token information to be added to the token.
   * @throws ServerError
   * @returns {Object} - An object with the token generated and the token information provided
   */
  async getToken({
    client_grant_types = [],
    client_scopes,
    scopes_requested,
    token_info,
  }) {
    try {
      validateGrant("password", client_grant_types);
      const scopes_granted = this.validateScopes(
        scopes_requested,
        client_scopes,
        this.match_all_scopes,
        this.scope_required
      );
      return await this.generateToken({ scopes_granted, token_info });
    } catch (error) {
      throw error;
    }
  }

  // ----------------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------------------

module.exports = PasswordFlow;
