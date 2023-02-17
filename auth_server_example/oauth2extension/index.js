const OAuth2Lib = require("../../index");
const AuthFlow = OAuth2Lib.AuthFlow;
const AuthorizationCodeFlow = OAuth2Lib.AuthorizationCodeFlow;
const RefreshTokenFlow = OAuth2Lib.RefreshTokenFlow;
const DeviceCodeFlow = OAuth2Lib.DeviceCodeFlow;
const { checkToken, signToken } = require("./utils.js");

// --------------------------  PROTOTYPE FUNCTIONS  -----------------------------------------------
// ------------------------------------------------------------------------------------------------

AuthFlow.prototype.generateToken = async function generateToken(args) {
  return await signToken({
    exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
    sub: args.token_info.sub,
    iss: args.token_info.iss,
    scopes: args.scopes_granted || "",
    redirect_uri: args.redirect_uri, // present only in authorization code flow
  });
};

// ------------------------------------------------------------------------------------------------

AuthFlow.prototype.validateToken = async function validateToken(token) {
  try {
    return await checkToken(token);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------------------

// --------------------------  AUTHORIZATION CODE FUNCTIONS  --------------------------------------

AuthorizationCodeFlow.prototype.generateCode = async function generateCode(
  args
) {
  return await signToken({
    exp: Math.floor(Date.now() / 1000) + 55 * this.code_expires_in,
    sub: args.code_info.sub,
    iss: args.code_info.iss,
    scopes: args.scopes_granted || "",
    redirect_uri: args.redirect_uri,
  });
};

// ------------------------------------------------------------------------------------------------

AuthorizationCodeFlow.prototype.validateCode = async function validateCode(
  args
) {
  try {
    return await checkToken(args.code);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------------------

// --------------------------  REFRESH TOKEN FUNCTIONS  -------------------------------------------

RefreshTokenFlow.prototype.generateRefreshToken =
  async function generateRefreshToken(args) {
    return await signToken({
      exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
      sub: args.token_info.sub,
      iss: args.token_info.iss,
      scopes: args.scopes_granted || "",
    });
  };

// ------------------------------------------------------------------------------------------------

RefreshTokenFlow.prototype.validateRefreshToken =
  async function validateRefreshToken(refresh_token) {
    try {
      return await checkToken(refresh_token);
    } catch (error) {
      throw error;
    }
  };

// ------------------------------------------------------------------------------------------------
// --------------------------  DEVICE CODE FUNCTIONS  ---------------------------------------------

DeviceCodeFlow.prototype.generateDeviceCode = async function generateDeviceCode(
  args
) {
  return await signToken({
    ...device_code_info,
    exp: Math.floor(Date.now() / 1000) + args.expires_in,
    scopes: args.scopes_granted || "",
    verification_uri: args.verification_uri,
    user_code: args.user_code,
    interval: args.interval,
  });
};

DeviceCodeFlow.prototype.validateDeviceCode = async function validateDeviceCode(
  args
) {
  try {
    return await checkToken(args.device_code);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------------------

module.exports = OAuth2Lib;
