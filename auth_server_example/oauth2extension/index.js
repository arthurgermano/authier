const OAuth2Lib = require("authier");
const AuthFlow = OAuth2Lib.AuthFlow;
const AuthorizationCodeFlow = OAuth2Lib.AuthorizationCodeFlow;
const PasswordFlow = OAuth2Lib.PasswordFlow;
const RefreshTokenFlow = OAuth2Lib.RefreshTokenFlow;
const {
  checkToken,
  getClients,
  signToken,
  getResources,
} = require("./utils.js");

// --------------------------  PROTOTYPE FUNCTIONS  -----------------------------------

// --------------------------  AUTH FLOW FUNCTIONS  -----------------------------------

AuthFlow.prototype.findClient = async function findClient(client_id) {
  const clients = await getClients();
  const client = clients.find((cItem) => cItem.client_id === client_id);
  if (!client) {
    throw OAuth2Lib.Errors.INVALID_CLIENT;
  }
  this.setProperties(client);
  return client;
};

// ------------------------------------------------------------------------------------

AuthFlow.prototype.generateToken = async function generateToken(
  token_data,
  options = {}
) {
  return await signToken({
    exp: Math.floor(Date.now() / 1000) + this.client.token_expires_in,
    sub: options.sub,
    iss: this.issuer || options.iss,
    scopes: token_data.scopes || "",
    redirect_uri: token_data.redirect_uri,
  });
};

// ------------------------------------------------------------------------------------

AuthFlow.prototype.validateToken = async function validateToken(token) {
  try {
    return await checkToken(token);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------

// --------------------------  AUTHORIZATION CODE FUNCTIONS  --------------------------

AuthorizationCodeFlow.prototype.generateCode = async function generateToken(
  code_data,
  options = {}
) {
  return await signToken({
    exp: options.exp || Math.floor(Date.now() / 1000) + 55 * 5,
    sub: options.sub,
    iss: this.issuer || options.iss,
    scopes: code_data.scopes || "",
    redirect_uri: code_data.redirect_uri,
  });
};

// ------------------------------------------------------------------------------------

AuthorizationCodeFlow.prototype.validateCode = async function validateCode(
  code
) {
  try {
    return await checkToken(code);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------

// --------------------------  REFRESH TOKEN FUNCTIONS  -------------------------------

RefreshTokenFlow.prototype.generateRefreshToken =
  async function generateRefreshToken(refresh_token_data, options = {}) {
    return await signToken({
      exp: Math.floor(Date.now() / 1000) + this.client.refresh_token_expires_in,
      sub: options.sub,
      iss: this.issuer || options.iss,
      scopes: refresh_token_data.scopes || "",
      redirect_uri: refresh_token_data.redirect_uri,
    });
  };

// ------------------------------------------------------------------------------------

RefreshTokenFlow.prototype.validateRefreshToken =
  async function validateRefreshToken(refresh_token) {
    try {
      return await checkToken(refresh_token);
    } catch (error) {
      throw error;
    }
  };

// ------------------------------------------------------------------------------------

// --------------------------  PASSWORD FUNCTIONS  ------------------------------------

PasswordFlow.prototype.findResource = async function findResource(user_name) {
  const resources = await getResources();
  const resource = resources.find((rItem) => rItem.user_name === user_name);
  if (!resource) {
    throw OAuth2Lib.Errors.ACCESS_DENIED;
  }
  this.setProperties({ ...resource, grant_types: "password" });
  return resource;
};

// ------------------------------------------------------------------------------------

module.exports = OAuth2Lib;
