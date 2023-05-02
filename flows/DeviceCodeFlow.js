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
   * @param {Integer} interval - The ideal interval the device should keep asking for the token.
   * @param {Integer} expires_in - The time that the code expires.
   * @param {String} add_chars - Add chars to the user_code.
   * @param {Boolean} only_numbers - Whether the user_code must be composed only by numbers and added chars.
   * @param {Integer} user_code_size - The size of the user code.
   * @param {Object} device_code_info - The info that shoulb be passed down to the generateToken
   * @return {Object} device_code - the device_code and user_code information object
   */
  async requestDeviceCode({
    requested_scopes = [],
    interval = 5,
    expires_in = 1800,
    add_chars = "",
    only_numbers = false,
    user_code_size = 10,
    device_code_info = {},
  }) {
    try {
      validateGrant("device_code", this.grant_types);
      const scopes_granted = this.validateScopes(requested_scopes);
      const user_code = this.generateUserCode({
        only_numbers,
        add_chars,
        size: user_code_size,
      });
      return {
        device_code: await this.generateDeviceCode({
          scopes_granted,
          user_code,
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
   * @param {Object} token_info - The token information to be added to the token.
   * @throws ServerError
   * @returns {Object} - An object with the token generated and the token information provided
   */
  async getToken({ device_code, token_info }) {
    try {
      validateGrant("device_code", this.grant_types);
      const device_code_validation = await this.validateDeviceCode({
        device_code,
      });
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
   * @throws Errors - Depending of the flow
   * @return {Object} validation of the code information - the code giving access to request a token
   */
  async validateDeviceCode({ device_code }) {
    // Must validate the code
    // check its scopes, signature, etc
    // Must return the validation info or throw an exception
    throwError(TODO_ERROR, "validateDeviceCode(): not implemented yet!");
  }
}

// ------------------------------------------------------------------------------------------------

module.exports = DeviceCodeFlow;
