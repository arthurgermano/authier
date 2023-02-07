const OAuth2Lib = require("../../index");
const AuthFlow = OAuth2Lib.AuthFlow;
const AuthorizationCodeFlow = OAuth2Lib.AuthorizationCodeFlow;
const RefreshTokenFlow = OAuth2Lib.RefreshTokenFlow;
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

AuthorizationCodeFlow.prototype.generateCode = async function generateToken(
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
  code
) {
  try {
    return await checkToken(code);
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

module.exports = OAuth2Lib;
