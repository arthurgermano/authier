const { validateGrant } = require("../grant_types/index.js");
const { TODO_ERROR, throwError } = require("../errors/index.js");
const AuthFlow = require("./AuthFlow.js");

// ------------------------------------------------------------------------------------------------

class DeviceCodeFlow extends AuthFlow {
  static slow_down = { error: "slow_down" };
  static authorization_pending = { error: "authorization_pending" };
  static access_denied = { error: "access_denied" };
  static expired_token = { error: "expired_token" };

  /**
   * @summary. Creates a Device Flow
   *
   * @constructor
   */
  constructor(options = {}) {
    super(options);
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Returns the a new device_code and user_code
   * @param {Array} requested_scopes - The scopes requested.
   * @param {Array} client_scopes - The client scopes.
   * @param {String} verification_uri - The verification uri the user must enter and register the user code.
   * @param {Integer} interval - The ideal interval the device should keep asking for the token.
   * @param {Integer} expires_in - The time that the code expires.
   * @param {String} add_chars - Add chars to the user_code.
   * @param {Boolean} only_numbers - Whether the user_code must be composed only by numbers and added chars.
   * @param {Integer} user_code_size - The size of the user code.
   * @return {Object} device_code - the device_code and user_code information object
   */
  async requestDeviceCode({
    requested_scopes = [],
    client_scopes = [],
    verification_uri = "",
    interval = 5,
    expires_in = 1800,
    add_chars = "",
    only_numbers = false,
    user_code_size = 10,
    device_code_info = {},
  }) {
    try {
      const scopes_granted = this.validateScopes(
        requested_scopes,
        client_scopes,
        this.match_all_scopes,
        this.scope_required
      );
      const user_code = this.generateUserCode({
        only_numbers,
        add_chars,
        size: user_code_size,
      });
      return {
        device_code: await this.generateDeviceCode({
          scopes_granted,
          user_code,
          verification_uri,
          interval,
          expires_in,
          device_code_info,
        }),
        user_code,
      };
    } catch (error) {
      throw error;
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Returns the generated device code
   * @param {Array} scopes_requested - The scopes requested.
   * @param {Object} device_code_info - The information to be added to the device_code_info.
   * @return {String} device_code - the device_code
   */
  async generateDeviceCode({ scopes_requested, device_code_info }) {
    // Must generate the device code
    throwError(TODO_ERROR, "generateDeviceCode(): not implemented yet!");
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Returns the generated user code
   * @param {Integer} size - The size of the code.
   * @param {Boolean} only_numbers - Whether the user_code must be composed only by numbers and added chars.
   * @param {String} add_chars - Add chars to the user_code.
   * @return {String} user_code - the device_code
   */
  generateUserCode({ size = 10, only_numbers = false, add_chars = "" }) {
    const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    if (size <= 4) {
      size = 5;
    }
    let chars = numbers + add_chars;
    if (!only_numbers) {
      chars += letters;
    }
    chars = chars.split("");
    let user_code = "";
    while (size-- > 0) {
      user_code += chars[Math.floor(Math.random() * (chars.length - 1) + 1)];
    }
    return user_code;
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Gets a new token from the server
   * @param {String} device_code - The device code.
   * @param {Object} client_grant_types - The client grant types.
   * @param {Object} client_scopes - The client scopes.
   * @param {Object} scopes_requested - The scopes requested.
   * @param {Object} token_info - The token information to be added to the token.
   * @throws ServerError
   * @returns {Object} - An object with the token generated and the token information provided
   */
  async getToken({
    device_code,
    client_grant_types = [],
    client_scopes,
    scopes_requested,
    token_info,
  }) {
    try {
      validateGrant("device_code", client_grant_types);
      const device_code_validation = await this.validateDeviceCode({
        device_code,
        scopes_requested,
      });
      const scopes_granted = this.validateScopes(
        scopes_requested,
        client_scopes,
        this.match_all_scopes,
        this.scope_required
      );
      return await this.generateToken({
        scopes_granted,
        token_info,
        device_code_validation,
      });
    } catch (error) {
      throw error;
    }
  }

  // ----------------------------------------------------------------------------------------------

  /**
   * @summary. Validates a provided device code
   * - Can be implemented to do more things as save codes in the database etc...
   * @param {String} device_code - The code string to be validated.
   * @param {Object} scopes_requested - The scopes requested.
   * @throws Errors - Depending of the flow
   * @return {Object} validation of the code information - the code giving access to request a token
   */
  async validateDeviceCode({ device_code, scopes_requested }) {
    // Must validate the code
    // check its scopes, signature, etc
    // Must return the validation info or throw an exception
    throwError(TODO_ERROR, "validateDeviceCode(): not implemented yet!");
  }
}

// ------------------------------------------------------------------------------------------------

module.exports = DeviceCodeFlow;
