const ERRORS = require("../errors/Errors.js");

/** Class implementing a authentication flow OAuth2 */
class AuthFlow {
  /**
   * Client's identification string.
   * @type {String}
   */
  client_id;

  /**
   * Client's secret string.
   * @type {String}
   */
  client_secret;

  /**
   * Grant types granted for this client
   * @type {String}
   */
  grant_types;

  /**
   * Token issuer identification.
   * @type {String}
   */
  issuer;

  /**
   * Client option to issue or not a refresh client token - default is true
   * @type {String}
   */
  issues_refresh_token;

  /**
   * Client's option whether the redirect_uri is required
   * @type {Boolean}
   */
  redirect_uri_required;

  /**
   * Client's redirect uris string separated by spaces
   * @type {String}
   */
  redirect_uris;

  /**
   * Refresh Token TTL - default is 7200 seconds
   * @type {Number}
   */
  refresh_token_expires_in;

  /**
   * Client's custom scopes string separated by spaces
   * @type {String}
   */
  scopes;

  /**
   * Client's option whether the scope is required
   * @type {Boolean}
   */
  scope_required;

  /**
   * Client's option whether the state is required
   * @type {Boolean}
   */
  state_required;

  /**
   * Token TTL - default is 3600 seconds
   * @type {Number}
   */
  token_expires_in;

  /**
   * Summary. Creates a AuthFlow
   *
   * @param {Object} provided_data - An object with the class properties to be set.
   * @param {String} provided_data.client_id - The client_id string identification.
   * @param {String} provided_data.client_secret - The client_secret string.
   * @param {String} provided_data.issuer - The issuer string.
   * @param {String} provided_data.issues_refresh_token - Client option wether refreshes token or not.
   * @param {String} provided_data.grant_types - The grant types granted for this client.
   * @param {Boolean} provided_data.redirect_uri_required - Option boolean declaring if the redirect uri is required.
   * @param {String} provided_data.redirect_uris - The client redirect uris string separated by spaces.
   * @param {Boolean} provided_data.refresh_token_expires_in - Refresh Token TTL - default is 7200 seconds
   * @param {String} provided_data.scopes - The client scopes string separated by spaces.
   * @param {Boolean} provided_data.scope_required - Option boolean declaring if the scope is required.
   * @param {Boolean} provided_data.state_required - Option boolean declaring if the state is required.
   * @param {Boolean} provided_data.token_expires_in - Token TTL - default is 3600 seconds
   *
   * @constructor
   */
  constructor(provided_data = {}) {
    this.setProperties(provided_data);
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Returns all the class properties
   *
   * @return {Object} properties - Class properties
   */
  getProperties() {
    return {
      client_id: this.client_id,
      client_secret: this.client_secret,
      issuer: this.issuer,
      issues_refresh_token: this.issues_refresh_token,
      grant_types: this.grant_types,
      redirect_uris: this.redirect_uris,
      redirect_uri_required: this.redirect_uri_required,
      refresh_token_expires_in: this.refresh_token_expires_in,
      scope_required: this.scope_required,
      scopes: this.scopes,
      state_required: this.state_required,
      token_expires_in: this.token_expires_in,
    };
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Checks provided redirect_uri against Client redirect_uris
   *
   * @param {String} redirect_uri - The redirect_uri provided in the request
   *
   * @throws TypeError
   * @throws InvalidRequest
   */
  hasClientUri(redirect_uri, encoded = false) {
    const splitUrls = this.redirect_uris.split(" ");
    const uri = !encoded ? redirect_uri : encodeURIComponent(redirect_uri);
    const hasUrl = splitUrls.find(
      (urlItem) => (!encoded ? urlItem : encodeURIComponent(urlItem)) === uri
    );
    if (!hasUrl) {
      throw {
        ...ERRORS.INVALID_REQUEST,
        error_description: "The redirect_uri is invalid",
      };
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Checks if the state is required and is correct
   *
   * @param {String} state - The state provided in the request
   *
   * @throws TypeError
   * @throws InvalidRequest
   */
  isStateValid(state) {
    if (this.state_required && (!state || state === "")) {
      throw {
        ...ERRORS.INVALID_REQUEST,
        error_description: "The state is invalid",
      };
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
   * @param {String} provided_data.issuer - The issuer string.
   * @param {String} provided_data.issues_refresh_token - Client option wether refreshes token or not.
   * @param {String} provided_data.scopes - The client scopes string separated by spaces.
   * @param {Boolean} provided_data.scope_required - Option boolean declaring if the scope is required.
   * @param {Boolean} provided_data.state_required - Option boolean declaring if the state is required.
   * @param {Boolean} provided_data.redirect_uri_required - Option boolean declaring if the redirect uri is required.
   * @param {String} provided_data.redirect_uris - The client redirect uris string separated by spaces.
   * @param {Boolean} provided_data.refresh_token_expires_in - Refresh Token TTL - default is 7200 seconds
   * @param {Boolean} provided_data.token_expires_in - Token TTL - default is 3600 seconds
   *
   */
  setProperties(provided_data = {}) {
    this.client_id = provided_data.client_id;
    this.client_secret = provided_data.client_secret;
    this.issuer = provided_data.issuer;
    this.issues_refresh_token = provided_data.issues_refresh_token || true;
    this.grant_types = provided_data.grant_types;
    this.redirect_uri_required = provided_data.redirect_uri_required;
    this.redirect_uris = provided_data.redirect_uris;
    this.refresh_token_expires_in =
      provided_data.refresh_token_expires_in || 7200;
    this.scope_required = provided_data.scope_required;
    this.scopes = provided_data.scopes;
    this.state_required = provided_data.state_required;
    this.token_expires_in = provided_data.token_expires_in || 3600;
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the Client id matches the loaded into class properties client_id
   *
   * @param {String} client_id - The client_id string identification provided in the request.
   *
   * @throws InvalidClient
   * @throws MismatchClient
   */
  validateClientId(client_id) {
    if (!this.client_id) {
      throw ERRORS.INVALID_CLIENT;
    } else if (this.client_id !== client_id) {
      throw ERRORS.MISMATCH_CLIENT;
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates the grant type informed and if the Client has it
   *
   * @param {Object} grant_class - The grant_class to validate grant type provided.
   * @param {String} provided_grant_type - The grant_type provided in the request.
   *
   * @throws InvalidGrant
   * @throws ServerError
   * @throws UnsupportedGrantType
   */
  validateGrantType(grant_class, provided_grant_type) {
    grant_class.validateGrantType(provided_grant_type);
    grant_class.hasClientGrantType(this.grant_types);
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the requested redirect uri informed matches the second redirect uri informed
   * Mostly used when the flow has two parts like authorization code
   *
   * @param {String} requested_redirect_uri - The first requested redirect uri - informed in the first request.
   * @param {String} redirect_uri - The second requested redirect uri - informed in the subsequent request.
   *
   * @throws InvalidRequest
   */
  validateRequestedUri(requested_redirect_uri, redirect_uri) {
    if (requested_redirect_uri !== redirect_uri) {
      throw {
        ...ERRORS.INVALID_REQUEST,
        error_description:
          "The requested uri is different from the last provided",
      };
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the scopes provided are correct only if required or provided
   *
   * @param {String} scopes - The scopes string provided in the request.
   *
   * @throws InvalidScope
   */
  validateScopes(scopes) {
    if (!this.scope_required && !scopes) {
      return;
    }

    if (!scopes || !this.scopes) {
      throw ERRORS.INVALID_SCOPE;
    }

    const client_scopes = this.scopes.split(" ");
    const client_requested_scopes = scopes.split(" ");
    for (let scopeItem of client_requested_scopes) {
      if (!client_scopes.includes(scopeItem)) {
        throw ERRORS.INVALID_SCOPE;
      }
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the state provided are correct
   *
   * @param {String} state - The state string provided in the request.
   *
   * @throws InvalidRequest
   */
  validateState(state) {
    if (this.state !== state) {
      throw {
        ...ERRORS.INVALID_REQUEST,
        error_description: "The state is different from the last provided",
      };
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the redirect_uri provided are correct only if required or provided
   *
   * @param {String} redirect_uri - The redirect_uri string provided in the request.
   * @param {String} encoded - IF the redirect_uri should be URIEncoded before check.
   *
   * @throws InvalidClient
   * @throws InvalidRequest
   * @throws TypeError
   */
  validateUri(redirect_uri, encoded = false) {
    if (!this.redirect_uri_required && !redirect_uri) {
      return true;
    } else if (!this.redirect_uris) {
      throw ERRORS.INVALID_CLIENT;
    }
    this.hasClientUri(redirect_uri, encoded);
  }

  // ------------------------------------------------------------------------------------
}

// ------------------------------------------------------------------------------------

/**
 * Summary.
 * - Finds a matching client_id Client in the database
 * - Fills the Class Properties
 * - Returns the client found or throws INVALID_CLIENT
 *
 * @param {String} client_id - The client_id string provided in the request.
 *
 * @throws InvalidClient
 * @throws InvalidRequest
 * @throws ServerError
 *
 * @return {Object} properties - Class properties
 */
async function findClient(client_id) {
  // Must populate the fields
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Basically generates a string token and returns it
 * - Can be implemented to do more things as save generated tokens in the database etc...
 *
 * @param {Object} token_data - The token information that must be included in the token.
 *
 * @param {Object} options - The options that must be considered when generating the token should have the information to be added into the token
 *
 * @throws ServerError
 *
 * @return {String} token - the token giving access to resources
 */
async function generateToken(token_data, options) {
  // Must generate a token
  // Must return the token as string as a promise
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Validates the flow to get a token - each child flow has its own logic
 * - Can be implemented to do more things as save tokens in the database etc...
 *
 * @param {Object} token_generate_data - The token information that must be included in the token to validate the get token request
 *
 * @param {Object} options - The options that must be considered when generating the token should have the information to be added into the token
 *
 * @throws Errors - Depending of the flow
 *
 * @return {String} token - the token giving access to resources
 */
async function getToken(token_generate_data, options) {
  // Must return a valid token information as promise
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

/**
 * Summary. Validates a provided token
 * - Can be implemented to do more things as save tokens in the database etc...
 *
 * @param {String} token - The token string to be validated.
 *
 * @throws Errors - Depending of the flow
 *
 * @return {String} token - the token giving access to resources
 */
async function validateToken(token) {
  // Must return if the token is valid or not
  throw ERRORS.TODO_ERROR;
}

// ------------------------------------------------------------------------------------

/*
 * Modifying class with the methods that should be implemented
 * Not all methods are here - for example generateCode or validateCode are inside the
 * authorization flow and must be implemented
 */
AuthFlow.prototype.findClient = findClient;
AuthFlow.prototype.generateToken = generateToken;
AuthFlow.prototype.getToken = getToken;
AuthFlow.prototype.validateToken = validateToken;

module.exports = AuthFlow;
