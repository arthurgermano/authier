// Require the framework and instantiate it
const fastify = require("fastify")({
  logger: true,
});
const fs = require("fs");
const OAuth2Lib = require("./oauth2extension");
const { clientData } = require("./oauth2extension/utils.js");

// Declare a route
fastify.get("/", function (request, reply) {
  reply.send({ hello: getClients() });
});

// Run the server!
fastify.listen(3000, async function (err, address) {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }

  await TestAuthCode();
  await TestAuthCodePKCE();
  await TestClientCredentials();
  await TestRefreshToken();
  await TestDeviceCode();

  fastify.log.info(`server listened on ${address}`);
  process.exit(0);
});

function getClients() {
  let clients = fs.readFileSync("./db/data.json");
  return JSON.parse(clients);
}

async function TestAuthCode() {
  try {
    console.log("------------------------------");
    console.log("AUTHORIZATION CODE FLOW START");
    console.log("------------------------------");
    const authCode = new OAuth2Lib.AuthorizationCodeFlow({
      pkce_required: false,
    });

    console.log("------------------------------");
    const code = await authCode.getCode({
      response_type: "code",
      client_redirect_uris: clientData.redirect_uris.split(" "),
      redirect_uri: "http://localhost:3000/cb",
      requested_scopes: ["scopeA"],
      client_scopes: clientData.scopes.split(" "),
      state: "stateABCZYX",
      code_info: { sub: "12345" },
    });
    console.log("------------------------------");
    console.log("CODE");
    console.log(code);
    console.log("------------------------------");

    const codeValidated = await authCode.validateCode(code);
    console.log("------------------------------");
    console.log("VALIDATING CODE");
    console.log(codeValidated);
    console.log("------------------------------");

    const token = await authCode.getToken({
      code: code,
      client_grant_types: clientData.grant_types.split(" "),
      client_scopes: clientData.scopes.split(" "),
      scopes_requested: ["scopeA"],
      client_redirect_uris: clientData.redirect_uris.split(" "),
      redirect_uri: "http://localhost:3000/cb",
      token_info: { sub: "12345" },
    });

    console.log("------------------------------");
    console.log("TOKEN");
    console.log(token);
    console.log("------------------------------");
  } catch (err) {
    console.log(err);
  } finally {
    console.log("------------------------------");
    console.log("AUTHORIZATION CODE FLOW END");
    console.log("------------------------------\n\n");
  }
}

async function TestAuthCodePKCE() {
  try {
    console.log("------------------------------");
    console.log("AUTHORIZATION CODE FLOW WITH PKCE START");
    console.log("------------------------------");
    const authCode = new OAuth2Lib.AuthorizationCodeFlow();

    console.log("------------------------------");
    const code = await authCode.getCode({
      response_type: "code",
      client_redirect_uris: clientData.redirect_uris.split(" "),
      redirect_uri: "http://localhost:3000/cb",
      requested_scopes: ["scopeA"],
      client_scopes: clientData.scopes.split(" "),
      state: "stateABCZYX",
      code_info: { sub: "12345" },
      code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
      code_challenge_method: "S256",
    });
    console.log("------------------------------");
    console.log("CODE");
    console.log(code);
    console.log("------------------------------");

    const codeValidated = await authCode.validateCode(code);
    console.log("------------------------------");
    console.log("VALIDATING CODE");
    console.log(codeValidated);
    console.log("------------------------------");

    const token = await authCode.getToken({
      code: code,
      client_grant_types: clientData.grant_types.split(" "),
      client_scopes: clientData.scopes.split(" "),
      scopes_requested: ["scopeA"],
      client_redirect_uris: clientData.redirect_uris.split(" "),
      redirect_uri: "http://localhost:3000/cb",
      token_info: { sub: "12345" },
      code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
      code_challenge_method: "S256",
      code_verifier:
        "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
    });

    console.log("------------------------------");
    console.log("TOKEN");
    console.log(token);
    console.log("------------------------------");
  } catch (err) {
    console.log(err);
  } finally {
    console.log("------------------------------");
    console.log("AUTHORIZATION CODE FLOW WITH PKCE END");
    console.log("------------------------------\n\n");
  }
}

async function TestClientCredentials() {
  try {
    console.log("------------------------------");
    console.log("CLIENT CREDENTIALS FLOW START");
    console.log("------------------------------");
    const clientCredentials = new OAuth2Lib.ClientCredentialsFlow();
    console.log("------------------------------");
    const token = await clientCredentials.getToken({
      client_grant_types: clientData.grant_types.split(" "),
      client_scopes: clientData.scopes.split(" "),
      scopes_requested: ["scopeA"],
      token_info: { sub: "12345" },
    });
    console.log("------------------------------");
    console.log("TOKEN");
    console.log(token);
    console.log("------------------------------");
  } catch (err) {
    console.log(err);
  } finally {
    console.log("------------------------------");
    console.log("CLIENT CREDENTIALS FLOW END");
    console.log("------------------------------\n\n");
  }
}

async function TestRefreshToken() {
  try {
    console.log("------------------------------");
    console.log("REFRESH TOKEN FLOW START");
    console.log("------------------------------");
    
    const refreshTokenFlow = new OAuth2Lib.RefreshTokenFlow();
    const token = await refreshTokenFlow.getToken({
      client_grant_types: clientData.grant_types.split(" "),
      client_scopes: clientData.scopes.split(" "),
      scopes_requested: ["scopeA"],
      token_info: { sub: "12345" },
    });
    console.log("------------------------------");
    console.log("TOKEN");
    console.log(token);
    console.log("------------------------------");
  } catch (err) {
    console.log(err);
  } finally {
    console.log("------------------------------");
    console.log("REFRESH TOKEN FLOW END");
    console.log("------------------------------\n\n");
  }
}

async function TestDeviceCode() {
  try {
    console.log("------------------------------");
    console.log("DEVICE CODE START");
    console.log("------------------------------");
    const deviceFlow = new OAuth2Lib.DeviceFlow();
    deviceFlow.generateUserCode({ size: 7});
    console.log("------------------------------");

  } catch (err) {
    console.log(err);
  } finally {
    console.log("------------------------------");
    console.log("DEVICE CODE END");
    console.log("------------------------------\n\n");
  }
}

