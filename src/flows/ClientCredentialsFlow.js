const AuthFlow = require("../flows/AuthFlow.js");
const ERRORS = require("../errors/Errors.js");
const clientCredentialsGrant = require("../grants/ClientCredentialsGrant.js");

/**
 * Class implementing a Client Credentials flow OAuth2.
 * @extends AuthFlow
 */
class ClientCredentialsFlow extends AuthFlow {

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Creates a Client Credentials Flow
   *
   * @param {Object} provided_data - An object with the class properties to be set.
   * @param {String} provided_data.client_id - The client_id string identification.
   * @param {String} provided_data.client_secret - The client_secret string.
   * @param {String} provided_data.grant_types - The grant types granted for this client.
   * @param {String} provided_data.redirect_uris - The client redirect uris string separated by spaces.
   * @param {String} provided_data.scopes - The client scopes string separated by spaces.
   * @param {Boolean} provided_data.scope_required - Option boolean declaring if the scope is required.
   * @param {Boolean} provided_data.state_required - Option boolean declaring if the state is required.
   * @param {Boolean} provided_data.redirect_uri_required - Option boolean declaring if the redirect uri is required.
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
   * - Validates the client_secret
   * - Validates the if the client has the grant type and the grant type is client_credentials
   * - Validates the scopes required
   * 
   * @param {Object} provided_data - An object with the Authorization Code Flow info required to generate a Code.
   * @param {String} provided_data.client_id - The client_id string identification.
   * @param {String} provided_data.client_secret - The client_secret string identification.
   * @param {String} provided_data.grant_type - The grant_type must be "authorization_code".
   * @param {String} provided_data.scopes - The scopes being requested
   * 
   * @param {Object} options - An object with all the options needed to generate token function.
   *
   * @throws InvalidRequest
   * @throws InvalidClient
   * @throws MismatchClient
   * @throws InvalidGrant
   * @throws ServerError
   * @throws InvalidScope
   * 
   * @return {String} token - the token giving access to resources
   */
  async getToken(provided_data, options) {
    if (!provided_data) {
      throw ERRORS.INVALID_REQUEST;
    }
    try {
      this.validateClientId(provided_data.client_id);
      this.validateGrantType(clientCredentialsGrant, provided_data.grant_type);
      if (provided_data.client_secret !== this.client_secret) {
        throw ERRORS.INVALID_CLIENT;
      }
      this.validateScopes(provided_data.scopes);
      return await this.generateToken(provided_data, options);
    } catch (error) {
      throw error;
    }
  }

  // ------------------------------------------------------------------------------------
  
}

module.exports = ClientCredentialsFlow;
