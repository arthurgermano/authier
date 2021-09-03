const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const privateKey = fs.readFileSync(
  path.resolve(__dirname, "./../keys/jwtRS512.key")
);
const publicKey = fs.readFileSync(
  path.resolve(__dirname, "./../keys/jwtRS512.key.pub")
);

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

async function getClients() {
  return new Promise((resolve, reject) => {
    fs.readFile("./db/client_data.json", (err, data) => {
      if (err) return reject(err);
      resolve(JSON.parse(data.toString()));
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

async function getResources() {
  return new Promise((resolve, reject) => {
    fs.readFile("./db/resource_data.json", (err, data) => {
      if (err) return reject(err);
      resolve(JSON.parse(data.toString()));
    });
  });
}

// ------------------------------------------------------------------------------------

module.exports = {
  checkToken,
  getClients,
  signToken,
  getResources,
};
