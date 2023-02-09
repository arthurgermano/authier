const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { createHash, randomBytes } = require("crypto");

const privateKey = fs.readFileSync(
  path.resolve(__dirname, "./keys/jwtRS512.key")
);
const publicKey = fs.readFileSync(
  path.resolve(__dirname, "./keys/jwtRS512.key.pub")
);

const clientData = {
  client_id: "abcxyz",
  client_secret: "abcxyz2",
  grant_types: "client_credentials authorization_code refresh_token",
  redirect_uris:
    "http://localhost:3000/cb http://localhost:3000/cb2 http://localhost:3000/cb3",
  scopes: "scopeA scopeB",
  scope_required: true,
  state_required: true,
  redirect_uri_required: true,
  issuer: "my company issuer1",
};

const passwordData = {
  username: "test",
  password: "testpass",
};

// ------------------------------------------------------------------------------------
// --------------------------  COMMON FUNCTIONS  --------------------------------------

function checkToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, publicKey, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      resolve(decoded);
    });
  });
}

// ------------------------------------------------------------------------------------

function signToken(jwtContent = {}) {
  return new Promise((resolve, reject) => {
    jwtContent.iat = Math.floor(Date.now() / 1000);
    jwt.sign(jwtContent, privateKey, { algorithm: "RS512" }, (err, token) => {
      if (err) {
        return resolve(err);
      }
      resolve(token);
    });
  });
}

// ------------------------------------------------------------------------------------

function decodeToken(token) {
  return new Promise((resolve, reject) => {
    try {
      resolve(jwt.decode(token));
    } catch (err) {
      reject(err);
    }
  });
}

// ------------------------------------------------------------------------------------

function generateRandomBytes(size = 32) {
  return randomBytes(size);
}

// ------------------------------------------------------------------------------------

function base64URLEncode(str) {
  return str
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// ------------------------------------------------------------------------------------

function generateVerifier() {
  return base64URLEncode(generateRandomBytes());
}

// ------------------------------------------------------------------------------------

function sha(buffer, algorithm = "sha256") {
  return createHash(algorithm).update(buffer).digest();
}

// ------------------------------------------------------------------------------------

function generateChallenge(verifier, algorithm) {
  return base64URLEncode(sha(verifier, algorithm));
}

// ------------------------------------------------------------------------------------

module.exports = {
  checkToken,
  signToken,
  decodeToken,
  clientData,
  generateChallenge,
  sha,
  generateVerifier,
  base64URLEncode,
  generateRandomBytes,
};
