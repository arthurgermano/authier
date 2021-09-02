const AuthFlow = require("../flows/AuthFlow.js");
const ERRORS = require("../errors/Errors.js");
const passwordGrant = require("../grants/PasswordGrant.js");

/**
 * Class implementing a Password flow OAuth2.
 * @extends AuthFlow
 */
class PasswordFlow extends AuthFlow {
  /**
   * Password flow user_name string.
   * @type {String}
   */
  user_name;

  /**
   * Password flow password string.
   * @type {String}
   */
  password;

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Creates a Password Flow
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
   * @param {String} provided_data.user_name - Resource's user_name
   * @param {String} provided_data.password - Resource's password
   *
   * @constructor
   */
  constructor(provided_data = {}) {
    super(provided_data);
    this.user_name = provided_data.user_name;
    this.password = provided_data.password;
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Returns Password Flow Properties
   *
   * @return {Object} Password flow - properties
   */
  getProperties() {
    return {
      ...super.getProperties(),
      user_name: this.user_name,
      password: this.password,
    };
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates the flow to get a token -
   * - Validates the user_name
   * - Validates the password
   * - Validates the if the client has the grant type and the grant type is password
   * - Validates the scopes required
   *
   * @param {Object} provided_data - An object with the Authorization Code Flow info required to generate a Code.
   * @param {String} provided_data.user_name - The user_name string identification.
   * @param {String} provided_data.password - The password string identification.
   * @param {String} provided_data.grant_type - The grant_type must be "password".
   * @param {String} provided_data.scopes - The scopes being requested
   *
   * @param {Object} options - An object with all the options needed to generate token function.
   *
   * @throws AccessDenied
   * @throws InvalidRequest
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
      passwordGrant.validateGrantType(provided_data.grant_type);
      this.validateScopes(provided_data.scopes);
      this.validateResource(provided_data);
      return await this.generateToken(provided_data, options);
    } catch (error) {
      throw error;
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Sets all the class properties
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
   * @param {Boolean} provided_data.user_name - The resource user_name identification.
   * @param {Boolean} provided_data.password - The resource password identification.
   */
  setProperties(provided_data) {
    super.setProperties(provided_data);
    this.user_name = provided_data.user_name;
    this.password = provided_data.password;
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates the resource credentials provided
   *
   * @param {Object} provided_data - An object with the Password Flow Resource Info.
   * @param {Object} provided_data.user_name - The user_name string to be validated.
   * @param {Object} provided_data.password - The password string to be validated.
   *
   * @throws AccessDenied
   * @throws InvalidRequest
   */
  validateResource(provided_data) {
    if (!this.user_name) {
      throw ERRORS.INVALID_REQUEST;
    } else if (this.user_name !== provided_data.user_name) {
      throw ERRORS.ACCESS_DENIED;
    } else if (this.password !== provided_data.password) {
      throw ERRORS.ACCESS_DENIED;
    }
  }

  // ------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------

/**
 * Summary.
 * - Finds a matching Resource in the database
 * - Fills the Class Properties
 * - Returns the resource found or throws INVALID_REQUEST
 *
 * @param {String} user_name - The user_name string provided in the request.
 *
 * @throws InvalidRequest
 * @throws ServerError
 *
 * @return {Object} properties - Class properties
 */
PasswordFlow.prototype.findResource = async function findResource(user_name) {
  // Must populate the fields
  throw ERRORS.TODO_ERROR;
};

// ------------------------------------------------------------------------------------

module.exports = PasswordFlow;
