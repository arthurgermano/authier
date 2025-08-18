// Require o framework e nossas classes da biblioteca já implementadas
const fastify = require("fastify")({
  logger: true,
});
const OAuth2Lib = require("./authier_extension");
const { findClientById } = require("./authier_extension/utils.js");

const TOKEN_LENGTH = 20;

// ==================================================================================================================================================

// --- Funções de Teste ---

async function TestAuthCode() {
  console.log("------------------------------------------");
  console.log("INÍCIO: Authorization Code Flow (sem PKCE)");
  console.log("------------------------------------------");
  try {
    const clientOptions = findClientById("abcxyz");
    if (!clientOptions) throw new Error("Cliente 'abcxyz' não encontrado.");

    console.log("=> Inicializando fluxo de autorização...");
    // Instancia o fluxo desabilitando o PKCE para este teste específico
    const authCodeFlow = new OAuth2Lib.AuthorizationCode({
      ...clientOptions,
      pkce_required: false,
    });

    console.log("=> Gerando código de autorização...");
    const code = await authCodeFlow.getCode({
      response_type: "code",
      redirect_uri: "http://localhost:3000/cb",
      scope: "scopeA",
      state: "state12345",
      code_info: { sub: "user-test-no-pkce" },
    });
    console.log("Código gerado:", code.substring(0, TOKEN_LENGTH) + "\n");

    console.log("=> Trocando código por token...");
    const tokenPayload = await authCodeFlow.getToken({
      code: code,
      redirect_uri: "http://localhost:3000/cb",
      token_info: { sub: "user-test-no-pkce", iss: clientOptions.issuer },
    });
    console.log(
      "Token de acesso gerado:",
      tokenPayload.substring(0, TOKEN_LENGTH) + "\n"
    );
  } catch (err) {
    console.error("ERRO NO FLUXO:", err.message || err);
  } finally {
    console.log("--- FIM: Authorization Code Flow (sem PKCE) ---\n\n");
  }
}

// ==================================================================================================================================================

async function TestAuthCodePKCE() {
  console.log("------------------------------------------");
  console.log("INÍCIO: Authorization Code Flow (com PKCE)");
  console.log("------------------------------------------");
  try {
    const clientOptions = findClientById("abcxyz");
    if (!clientOptions) throw new Error("Cliente 'abcxyz' não encontrado.");

    const authCodeFlow = new OAuth2Lib.AuthorizationCode(clientOptions);

    console.log("=> Gerando código de autorização...");
    const code = await authCodeFlow.getCode({
      response_type: "code",
      redirect_uri: "http://localhost:3000/cb",
      scope: "scopeA scopeB",
      state: "stateABCZYX",
      code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
      code_challenge_method: "S256",
      code_info: { sub: "user-123", iss: clientOptions.issuer },
    });
    console.log("Código gerado:", code.substring(0, TOKEN_LENGTH) + "\n");

    console.log("=> Trocando código por token...");
    const tokenPayload = await authCodeFlow.getToken({
      code: code,
      redirect_uri: "http://localhost:3000/cb",
      code_verifier:
        "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      token_info: { sub: "user-123", iss: clientOptions.issuer },
    });
    console.log(
      "Token de acesso gerado:",
      tokenPayload.substring(0, TOKEN_LENGTH) + "\n"
    );
  } catch (err) {
    console.error("ERRO NO FLUXO:", err.message || err);
  } finally {
    console.log("--- FIM: Authorization Code Flow (com PKCE) ---\n\n");
  }
}

// ==================================================================================================================================================

async function TestClientCredentials() {
  console.log("------------------------------------------");
  console.log("INÍCIO: Client Credentials Flow");
  console.log("------------------------------------------");
  try {
    const clientOptions = findClientById("abcxyz");
    if (!clientOptions) throw new Error("Cliente 'abcxyz' não encontrado.");

    const clientCredentialsFlow = new OAuth2Lib.ClientCredentials(
      clientOptions
    );

    console.log("=> Gerando token de acesso...");
    const token = await clientCredentialsFlow.getToken({
      scope: "scopeA",
      token_info: { sub: clientOptions.client_id, iss: clientOptions.issuer },
    });
    console.log("Token de acesso gerado:", token.substring(0, TOKEN_LENGTH) + "\n");
  } catch (err) {
    console.error("ERRO NO FLUXO:", err.message || err);
  } finally {
    console.log("--- FIM: Client Credentials Flow ---\n\n");
  }
}

// ==================================================================================================================================================

async function TestRefreshToken() {
  console.log("------------------------------------------");
  console.log("INÍCIO: Refresh Token Flow");
  console.log("------------------------------------------");
  try {
    const clientOptions = findClientById("abcxyz");
    if (!clientOptions) throw new Error("Cliente 'abcxyz' não encontrado.");

    const refreshTokenFlow = new OAuth2Lib.RefreshToken(clientOptions);

    // Etapa de pré-requisito: Gerar um refresh token para podermos testar o fluxo.
    console.log("=> Gerando um refresh token de pré-requisito...");
    const originalTokenData = {
      sub: "user-refresh-test",
      scopes: ["scopeA", "scopeB"],
    };
    const refreshToken = await refreshTokenFlow.issueNewRefreshToken(
      originalTokenData
    );
    console.log(
      "Refresh token gerado:",
      refreshToken.substring(0, TOKEN_LENGTH) + "\n"
    );


    console.log("Validando o token gerado...")
    const isTokenValid = await refreshTokenFlow.validateRefreshToken(
      refreshToken
    );
    if (!isTokenValid) {
      console.log("REFRESH TOKEN inválido...");
      return;
    }
    console.log("Refresh token válido!")

    // Agora, usamos o refresh token para obter um novo access token
    console.log("=> Usando refresh token para obter um novo access token...");
    const newAccessToken = await refreshTokenFlow.getToken({
      refresh_token: refreshToken,
      scope: "scopeA", // Solicitando um subconjunto dos escopos originais (válido)
    });
    console.log(
      "Novo access refresh_token gerado:",
      newAccessToken.substring(0, TOKEN_LENGTH) + "\n"
    );
  } catch (err) {
    console.error("ERRO NO FLUXO:", err.message || err);
  } finally {
    console.log("--- FIM: Refresh Token Flow ---\n\n");
  }
}

// ==================================================================================================================================================

async function TestDeviceCodeNotApproved() {
  console.log("------------------------------------------");
  console.log("INÍCIO: Device Code Flow - NOT APPROVED");
  console.log("------------------------------------------");
  try {
    const clientOptions = findClientById("abcxyz");
    if (!clientOptions) throw new Error("Cliente 'abcxyz' não encontrado.");

    const deviceCodeFlow = new OAuth2Lib.DeviceCode(clientOptions);

    // Etapa 1: Requisição dos códigos
    console.log("=> Requisitando códigos de dispositivo e de usuário...");
    const codes = await deviceCodeFlow.requestDeviceCode({
      scope: "scopeA",
    });
    console.log("Códigos recebidos:", codes, "\n");

    // Etapa 2: Simulação do polling
    console.log("=> Tentando obter token (polling)...");
    // Esta chamada vai falhar com 'authorization_pending', que é o comportamento esperado.
    await deviceCodeFlow.getToken({ device_code: codes.device_code });


  } catch (err) {
    // Verificamos se o erro é o esperado para o fluxo de polling
    if (err.error === "authorization_pending") {
      console.log(
        "SUCESSO: Recebido o erro esperado 'authorization_pending'. O dispositivo continuaria o polling.\n"
      );
    } else {
      console.error("ERRO INESPERADO NO FLUXO:", err.message || err);
    }
  } finally {
    console.log("--- FIM: Device Code Flow ---\n\n");
  }
}

// ==================================================================================================================================================

async function TestDeviceCodeApproved() {
  console.log("------------------------------------------");
  console.log("INÍCIO: Device Code Flow - APPROVED");
  console.log("------------------------------------------");
  try {
    const clientOptions = findClientById("abcxyz");
    if (!clientOptions) throw new Error("Cliente 'abcxyz' não encontrado.");

    const deviceCodeFlow = new OAuth2Lib.DeviceCode(clientOptions);

    // Etapa 1: Requisição dos códigos
    console.log("=> Requisitando códigos de dispositivo e de usuário...");
    const codes = await deviceCodeFlow.requestDeviceCode({
      scope: "scopeA",
      device_code_info: { simulatingStatus: "approved" },
    });
    console.log("Códigos recebidos:", codes, "\n");

    // Etapa 2: Simulação do polling
    console.log("=> Tentando obter token (polling)...");
    // Agora a chamada vai funcionar foi aprovado - simulating status
    const token = await deviceCodeFlow.getToken({ device_code: codes.device_code });

    console.log(
      "Novo device token gerado:",
      token.substring(0, TOKEN_LENGTH) + "\n"
    );
    
  } catch (err) {
    // Verificamos se o erro é o esperado para o fluxo de polling
    if (err.error === "authorization_pending") {
      console.log(
        "SUCESSO: Recebido o erro esperado 'authorization_pending'. O dispositivo continuaria o polling.\n"
      );
    } else {
      console.error("ERRO INESPERADO NO FLUXO:", err.message || err);
    }
  } finally {
    console.log("--- FIM: Device Code Flow ---\n\n");
  }
}

// ==================================================================================================================================================

// --- Servidor de Teste ---
async function start() {
  try {
    // Não precisamos realmente ouvir requisições, apenas executar os testes.
    console.log("Iniciando suíte de testes da biblioteca OAuth2\n");

    await TestAuthCode();
    await TestAuthCodePKCE();
    await TestClientCredentials();
    await TestRefreshToken();
    await TestDeviceCodeNotApproved();
    await TestDeviceCodeApproved();

    console.log("Todos os testes foram concluídos.");
    process.exit(0);
  } catch (err) {
    console.error("Ocorreu um erro fatal na suíte de testes:", err);
    process.exit(1);
  }
}

// ==================================================================================================================================================

start();

// ==================================================================================================================================================
