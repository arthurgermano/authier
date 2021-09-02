// Require the framework and instantiate it
const fastify = require("fastify")({
  logger: true,
});
const fs = require("fs");
const OAuth2Lib = require("./oauth2extension");

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
  await TestClientCredentials();
  await TestPassword();
  await TestRefreshToken();

  fastify.log.info(`server listening on ${address}`);
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
    const authCode = new OAuth2Lib.AuthorizationCodeFlow();
    await authCode.findClient("abcxyz");

    console.log("------------------------------");
    console.log("CLIENT PROPERTIES");
    console.log(authCode.getProperties());
    console.log("------------------------------");
    const code = await authCode.getCodeResponse({
      client_id: "abcxyz",
      response_type: "code",
      redirect_uri: "http://localhost:3000/cb",
      state: "abc123",
      scopes: "scopeA",
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
      client_id: "abcxyz",
      code,
      grant_type: "authorization_code",
      redirect_uri: "http://localhost:3000/cb",
      code_requested_uri: codeValidated.redirect_uri,
      scopes: codeValidated.scopes,
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

async function TestClientCredentials() {
  try {
    console.log("------------------------------");
    console.log("CLIENT CREDENTIALS FLOW START");
    console.log("------------------------------");
    const clientCredentials = new OAuth2Lib.ClientCredentialsFlow();
    await clientCredentials.findClient("abcxyz");
    console.log("------------------------------");
    console.log("CLIENT PROPERTIES");
    console.log(clientCredentials.getProperties());
    console.log("------------------------------");
    const token = await clientCredentials.getToken({
      client_id: "abcxyz",
      client_secret: "abcxyz2",
      grant_type: "client_credentials",
      scopes: "scopeA scopeB",
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
  console.log(OAuth2Lib.GrantTypes.getSupportedGrantTypes());
}

async function TestPassword() {
  try {
    console.log("------------------------------");
    console.log("PASSWORD FLOW START");
    console.log("------------------------------");
    const passwordFlow = new OAuth2Lib.PasswordFlow();
    await passwordFlow.findResource("abcxyz2");
    console.log("RESOURCE PROPERTIES");
    console.log(passwordFlow.getProperties());
    console.log("------------------------------");
    const token = await passwordFlow.getToken({
      user_name: "abcxyz2",
      password: "abcxyz2",
      grant_type: "password",
    });
    console.log("------------------------------");
    console.log("TOKEN");
    console.log(token);
    console.log("------------------------------");
  } catch (err) {
    console.log(err);
  } finally {
    console.log("------------------------------");
    console.log("PASSWORD FLOW END");
    console.log("------------------------------\n\n");
  }
}

async function TestRefreshToken() {
  try {
    console.log("------------------------------");
    console.log("REFRESH TOKEN FLOW START");
    console.log("------------------------------");
    const refreshTokenFlow = new OAuth2Lib.RefreshTokenFlow();
    await refreshTokenFlow.findClient("abcxyz");
    console.log("RESOURCE PROPERTIES");
    console.log(refreshTokenFlow.getProperties());
    console.log("------------------------------");
    const token = await refreshTokenFlow.getToken({
      client_id: "abcxyz",
      client_secret: "abcxyz",
      grant_type: "refresh_token",
      scopes: "scopeA scopeB",
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
