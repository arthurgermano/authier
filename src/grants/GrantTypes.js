const {
  INVALID_GRANT,
  SERVER_ERROR,
  UNSUPPORTED_GRANT_TYPE,
} = require("../errors/Errors.js");

/** Class implementing Grant Types */
class GrantTypes {
  /**
   * Grant Type identification string.
   * @type {String}
   */
  grant_type;

  /**
   * Supported Grant Types Array provided.
   * @static
   * @type {Array}
   */
  static supported_grant_types;

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Creates a Grant Type
   *
   * @param {String} grant_type - The grant type - required and not null.
   *
   * @constructor
   *
   * @throws ServerError
   */
  constructor(grant_type) {
    if (!grant_type || grant_type === "") {
      throw SERVER_ERROR;
    }
    this.grant_type = grant_type;
    if (!GrantTypes.supported_grant_types) {
      GrantTypes.supported_grant_types = [];
    }
    GrantTypes.supported_grant_types.push(this.grant_type);
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Checks if the client's grant types provided has the requested grant type
   *
   * @param {String} client_grant_types - The client grant types - separated by spaces.
   *
   * @throws ServerError
   * @throws UnsupportedGrantType
   */
  hasClientGrantType(client_grant_types) {
    if (!client_grant_types || !this.grant_type) {
      throw SERVER_ERROR;
    }

    const client_grant_types_list = client_grant_types.split(" ");
    if (!client_grant_types_list.includes(this.grant_type)) {
      throw UNSUPPORTED_GRANT_TYPE;
    }
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Returns the grant types registered
   * @static
   */
  static getSupportedGrantTypes() {
    return GrantTypes.supported_grant_types;
  }

  // ------------------------------------------------------------------------------------

  /**
   * Summary. Validates if the provided grant type is equal to the current grant type
   *
   * @param {String} grant_type - Grant type to be validated.
   *
   * @throws InvalidGrant
   */
  validateGrantType(grant_type) {
    if (this.grant_type !== grant_type) {
      throw INVALID_GRANT;
    }
  }

  // ------------------------------------------------------------------------------------
}

module.exports = GrantTypes;
