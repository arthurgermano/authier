import { describe, it, beforeEach, expect } from "vitest";
import { OAuthError, ERROR_SPECS } from "../src/errors/index.js";
import { checkToken, decodeToken, signToken, clientData } from "./utils.js";
import DeviceCodeFlow from "../src/flows/DeviceCodeFlow.js";

// ==============================================================================================================================================----

/**
 * @class MockDeviceCodeFlow
 * @description Implementação mock do DeviceCodeFlow para fins de teste.
 * Simula o comportamento de interações com o banco de dados codificando/decodificando JWTs.
 */
class MockDeviceCodeFlow extends DeviceCodeFlow {
  /**
   * Simula a geração de um token de acesso final.
   */
  async generateToken({validation_data, token_info = {}}) {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
      ...validation_data,
      scope: validation_data.scopes.join(" "), // Garante que o escopo seja uma string para o token final
      ...token_info,
    };
    // Limpa propriedades que são específicas do fluxo de device_code
    // e não devem estar no token de acesso final.
    delete payload.status;
    delete payload.user_code;
    delete payload.interval;
    delete payload.iat; // Remove o iat original para obter um novo do signToken
    delete payload.simulatedStatus;
    return await signToken(payload);
  }

  /**
   * Simula a geração e "persistência" de um device_code.
   * Os dados são armazenados em um JWT para serem decodificados posteriormente por `validateDeviceCode`.
   */
  async generateDeviceCode({
    scopes_granted,
    user_code,
    interval,
    device_code_info,
  }) {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + this.device_code_expires_in,
      ...device_code_info,
      client_id: this.client_id,
      scopes: scopes_granted,
      user_code,
      interval,
      // O status é embutido no token para fins de simulação.
      status: device_code_info?.simulatedStatus || "pending",
    };
    return await signToken(payload);
  }

  /**
   * Simula a validação de um device_code.
   * Decodifica o JWT e verifica o status embutido para simular respostas de polling.
   */
  async validateDeviceCode(deviceCode) {
    try {
      const decoded = await checkToken(deviceCode);

      // Simula diferentes respostas de polling com base no status no token
      switch (decoded.status) {
        case "approved":
          return {
            scopes: decoded.scopes,
            user_id: decoded.sub, // 'sub' é o identificador do usuário
            ...decoded, // Passa outros dados para a geração do token
          };
        case "pending":
          OAuthError.throw("AUTHORIZATION_PENDING");
          break;
        case "denied":
          OAuthError.throw("ACCESS_DENIED");
          break;
        case "slow_down":
          OAuthError.throw("SLOW_DOWN");
          break;
        default:
          // Se o status for desconhecido, trata como uma concessão inválida
          OAuthError.throw("INVALID_GRANT", {
            detail: "Código de dispositivo com status inválido.",
          });
      }
    } catch (error) {
      // Lida com erros de JWT (expirado, assinatura inválida, etc.) e os mapeia para erros OAuth2.
      if (error.name === "TokenExpiredError") {
        OAuthError.throw("EXPIRED_TOKEN");
      }
      if (error instanceof OAuthError) {
        throw error; // Relança OAuthErrors do bloco switch
      }
      // Para qualquer outro erro de JWT ou inesperado, trata como uma concessão inválida.
      OAuthError.throw("INVALID_GRANT", {
        detail: "O código do dispositivo é inválido ou malformado.",
      });
    }
  }
}

// ==============================================================================================================================================----

describe("DeviceCodeFlow", () => {
  let dcFlow;

  beforeEach(() => {
    dcFlow = new MockDeviceCodeFlow({ ...clientData });
  });

  // ==============================================================================================================================================----

  describe("Constructor", () => {
    it("deve instanciar com sucesso com opções válidas", () => {
      expect(dcFlow).toBeInstanceOf(DeviceCodeFlow);
      expect(dcFlow.device_code_expires_in).toBe(1800);
      expect(dcFlow.interval).toBe(5);
    });

    it("deve lançar 'INVALID_REQUEST' se 'verification_uri' não for fornecido", () => {
      expect.assertions(2);
      const options = { ...clientData };
      delete options.verification_uri;
      try {
        new MockDeviceCodeFlow(options);
      } catch (e) {
        expect(e).toBeInstanceOf(OAuthError);
        expect(e.error).toBe("invalid_request");
      }
    });

    it("deve lançar 'INVALID_REQUEST' se 'verification_uri_complete' não for fornecido", () => {
      expect.assertions(2);
      const options = { ...clientData };
      delete options.verification_uri_complete;
      try {
        new MockDeviceCodeFlow(options);
      } catch (e) {
        expect(e).toBeInstanceOf(OAuthError);
        expect(e.error).toBe("invalid_request");
      }
    });

    it("deve atribuir opções customizadas corretamente", () => {
      const customFlow = new MockDeviceCodeFlow({
        ...clientData,
        device_code_expires_in: 300,
        interval: 10,
        user_code_size: 6,
      });
      expect(customFlow.device_code_expires_in).toBe(300);
      expect(customFlow.interval).toBe(10);
      expect(customFlow.user_code_size).toBe(6);
    });

    it("deve usar valores padrão para user_code_size e device_grant_name se não fornecidos", () => {
      const flow = new MockDeviceCodeFlow({ ...clientData });
      expect(flow.user_code_size).toBe(8);
      expect(flow.device_grant_name).toBe("device_code");
    });
  });

  // ==============================================================================================================================================----

  describe("Private Methods", () => {
    describe("_generateUserCode()", () => {
      it("deve gerar um código com o tamanho padrão (8)", () => {
        const code = dcFlow._generateUserCode({});
        expect(code).toBeTypeOf("string");
        expect(code.length).toBe(8);
      });

      it("deve gerar um código com tamanho customizado", () => {
        const code = dcFlow._generateUserCode({ size: 10 });
        expect(code.length).toBe(10);
      });

      it("deve gerar um código contendo apenas caracteres não ambíguos", () => {
        const code = dcFlow._generateUserCode({ size: 100 });
        expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXYZ0-9]+$/);
      });

      it("deve incluir caracteres adicionais quando fornecidos", () => {
        const code = dcFlow._generateUserCode({ size: 100, add_chars: "-" });
        expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXYZ0-9-]+$/);
        // A asserção `toContain` foi removida pois o teste se torna instável ("flaky"),
        // uma vez que a inclusão do caractere do `add_chars` é aleatória e não garantida pela implementação.
      });
    });
  });

  // ==============================================================================================================================================--

  describe("requestDeviceCode()", () => {
    it("deve retornar a estrutura correta de dados com um escopo válido", async () => {
      // 1. EXECUÇÃO: Chama o método com um escopo que é permitido no 'clientData'
      const response = await dcFlow.requestDeviceCode({ scope: "scopeA" });

      // 2. ASSERTIVAS: Verifica se o objeto retornado contém todos os campos esperados e com os valores corretos
      expect(response).toHaveProperty("device_code");
      expect(response).toHaveProperty("user_code");
      expect(response.user_code).toBeTypeOf("string");
      expect(response.expires_in).toBe(clientData.device_code_expires_in);
      expect(response.interval).toBe(5);
      expect(response.verification_uri).toBe(clientData.verification_uri);
      expect(response.verification_uri_complete).toContain(response.user_code);

      // 3. VERIFICAÇÃO INTERNA: Decodifica o 'device_code' para garantir que foi gerado com os dados certos
      const decoded = await decodeToken(response.device_code);
      expect(decoded.scopes).toEqual(["scopeA"]);
      expect(decoded.client_id).toBe(clientData.client_id);
      expect(decoded.status).toBe("pending");
    });

    it("deve retornar um array de escopos vazio se nenhum for fornecido e não for obrigatório", async () => {
      // EXECUÇÃO: Chama o método sem o parâmetro 'scope'
      dcFlow = new MockDeviceCodeFlow({ ...clientData, scopes_required: false });
      const response = await dcFlow.requestDeviceCode({});

      // ASSERTIVA: O fluxo deve continuar normalmente, mas o código gerado não deve ter escopos
      expect(response.device_code).toBeTypeOf("string");
      const decoded = await decodeToken(response.device_code);
      expect(decoded.scopes).toEqual([]);
    });

    it("deve lançar um erro 'invalid_scope' para um escopo não permitido pelo cliente", async () => {
      // Garante que as 4 assertivas dentro do bloco 'catch' serão executadas
      expect.assertions(4);

      try {
        // EXECUÇÃO: Tenta solicitar um escopo que não existe na configuração 'clientData'
        await dcFlow.requestDeviceCode({ scope: "escopo_que_nao_existe" });
      } catch (error) {
        // ASSERTIVAS: Verifica se o erro lançado é o de escopo inválido, conforme as especificações
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    it("deve lançar 'invalid_scope' se um dos escopos na lista for inválido e match_all_scopes for true", async () => {
      expect.assertions(4);
      try {
        // EXECUÇÃO: Envia um escopo válido e um inválido. Como a configuração padrão exige que todos sejam válidos, deve falhar.
        await dcFlow.requestDeviceCode({ scope: "scopeA escopo_invalido" });
      } catch (error) {
        // ASSERTIVAS: O erro deve ser de escopo inválido
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    it("deve conceder apenas escopos válidos se match_all_scopes for false", async () => {
      dcFlow = new MockDeviceCodeFlow({ ...clientData, match_all_scopes: false });
      const response = await dcFlow.requestDeviceCode({
        scope: "scopeA escopo_invalido scopeB",
      });
      const decoded = await decodeToken(response.device_code);
      expect(decoded.scopes).toEqual(["scopeA", "scopeB"]);
    });

    it("deve passar device_code_info para generateDeviceCode", async () => {
      const response = await dcFlow.requestDeviceCode({
        scope: "scopeA", device_code_info: { custom_data: "teste" }
      });
      const decoded = await decodeToken(response.device_code);
      expect(decoded.custom_data).toBe("teste");
    });

    it("deve lançar 'invalid_scope' se o cliente não tiver escopos configurados mas eles forem solicitados", async () => {
      expect.assertions(2);
      const flowWithoutScopes = new MockDeviceCodeFlow({
        ...clientData,
        scopes: "", // Cliente sem escopos
      });
      try {
        await flowWithoutScopes.requestDeviceCode({ scope: "scopeA" });
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe("invalid_scope");
      }
    });

    it("deve tratar escopos duplicados e espaços extras na string de escopo", async () => {
      const response = await dcFlow.requestDeviceCode({
        scope: "  scopeA scopeB  scopeA  ",
      });
      const decoded = await decodeToken(response.device_code);
      // O método _parseScopeString remove duplicatas e espaços
      expect(decoded.scopes).toEqual(["scopeA", "scopeB"]);
    });
  });

  // ==============================================================================================================================================--

  describe("getToken()", () => {
    it("deve retornar um access_token quando o device_code for aprovado", async () => {
      // 1. SETUP: Gera um device_code, simulando que o usuário já o aprovou.
      // Para isso, passamos um status especial e o ID do usuário.
      const { device_code } = await dcFlow.requestDeviceCode({
        scope: "scopeA scopeB",
        device_code_info: {
          simulatedStatus: "approved",
          sub: "user-id-123", // 'sub' (subject) é o ID do usuário
        },
      });

      // 2. EXECUÇÃO: Troca o device_code aprovado por um token de acesso.
      const token = await dcFlow.getToken({ device_code });

      // 3. ASSERTIVAS: Verifica se o token de acesso foi gerado corretamente.
      expect(token).toBeTypeOf("string");
      const decodedToken = await checkToken(token);
      expect(decodedToken.sub).toBe("user-id-123");
      expect(decodedToken.scope).toBe("scopeA scopeB");
    });

    it("deve lançar 'AUTHORIZATION_PENDING' para um código com status 'pending'", async () => {
      expect.assertions(4);

      // 1. SETUP: Gera um device_code padrão, que começa com o status 'pending'.
      const { device_code } = await dcFlow.requestDeviceCode({
        scope: "scopeA",
      });

      try {
        // 2. EXECUÇÃO: Tenta obter o token. A chamada deve falhar.
        await dcFlow.getToken({ device_code });
      } catch (error) {
        // 3. ASSERTIVAS: Verifica se o erro é de autorização pendente.
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.AUTHORIZATION_PENDING.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.AUTHORIZATION_PENDING.description
        );
        expect(error.status).toBe(ERROR_SPECS.AUTHORIZATION_PENDING.status);
      }
    });

    it("deve lançar 'ACCESS_DENIED' para um código com status 'denied'", async () => {
      expect.assertions(2);
      const { device_code } = await dcFlow.requestDeviceCode({
        // Adiciona um escopo para passar na validação inicial, já que o cliente o exige.
        // O foco do teste é o comportamento do getToken.
        scope: "scopeA",
        device_code_info: { simulatedStatus: "denied" },
      });
      try {
        await dcFlow.getToken({ device_code });
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect(error.error).toBe("access_denied");
      }
    });

    it("deve lançar 'SLOW_DOWN' para um código com status 'slow_down'", async () => {
      expect.assertions(2);
      const { device_code } = await dcFlow.requestDeviceCode({
        scope: "scopeA",
        device_code_info: { simulatedStatus: "slow_down" },
      });
      try {
        await dcFlow.getToken({ device_code });
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect(error.error).toBe("slow_down");
      }
    });

    it("deve lançar 'EXPIRED_TOKEN' para um device_code expirado", async () => {
      expect.assertions(2);
      const expired_code = await signToken({ exp: Math.floor(Date.now() / 1000) - 1 });
      try {
        await dcFlow.getToken({ device_code: expired_code });
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect(error.error).toBe("expired_token");
      }
    });

    it("deve lançar 'INVALID_GRANT' para um device_code malformado", async () => {
      expect.assertions(2);
      try {
        await dcFlow.getToken({ device_code: "codigo-invalido" });
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect(error.error).toBe("invalid_grant");
      }
    });

    it("deve lançar 'INVALID_REQUEST' se device_code não for fornecido", async () => {
      expect.assertions(2);
      try {
        await dcFlow.getToken({});
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect(error.error).toBe("invalid_request");
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' se o cliente não suportar 'device_code'", async () => {
      expect.assertions(2);
      const flowWithoutGrant = new MockDeviceCodeFlow({
        ...clientData,
        grant_types: "authorization_code", // Remove 'device_code'
      });
      try {
        await flowWithoutGrant.getToken({ device_code: "any-code" });
      } catch (error) {
        // Usar `constructor.name` em vez de `toBeInstanceOf` para evitar problemas
        // de contexto de módulo que podem ocorrer em alguns test runners.
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe("unsupported_grant_type");
      }
    });

    it("deve lançar 'INVALID_GRANT' para um device_code com status desconhecido", async () => {
      expect.assertions(2);
      const { device_code } = await dcFlow.requestDeviceCode({
        scope: "scopeA",
        device_code_info: { simulatedStatus: "unknown_status" },
      });
      try {
        await dcFlow.getToken({ device_code });
      } catch (error) {
        expect(error).toBeInstanceOf(OAuthError);
        expect(error.error).toBe("invalid_grant");
      }
    });

    it("deve passar token_info para generateToken e incluí-lo no token final", async () => {
      const { device_code } = await dcFlow.requestDeviceCode({
        scope: "scopeA",
        device_code_info: {
          simulatedStatus: "approved",
          sub: "user-id-456",
        },
      });

      const token = await dcFlow.getToken({
        device_code,
        token_info: { aud: "my-audience", custom_claim: "value" },
      });

      const decodedToken = await checkToken(token);
      expect(decodedToken.aud).toBe("my-audience");
      expect(decodedToken.custom_claim).toBe("value");
      expect(decodedToken.sub).toBe("user-id-456");
    });

    it("deve funcionar com um 'device_grant_name' customizado", async () => {
      const customGrantName = "urn:ietf:params:oauth:grant-type:device_code";
      const customFlow = new MockDeviceCodeFlow({
        ...clientData,
        device_code_grant_name: customGrantName,
        grant_types: `${clientData.grant_types} ${customGrantName}`, // Adiciona o grant customizado
      });

      const { device_code } = await customFlow.requestDeviceCode({
        scope: "scopeA",
        device_code_info: {
          simulatedStatus: "approved",
          sub: "user-id-custom",
        },
      });

      // A chamada getToken deve ter sucesso com o grant type customizado
      const token = await customFlow.getToken({ device_code });
      const decoded = await checkToken(token);
      expect(decoded.sub).toBe("user-id-custom");
    });

    it("não deve incluir claims específicas do device_code no access_token final", async () => {
      const { device_code } = await dcFlow.requestDeviceCode({
        scope: "scopeA",
        device_code_info: {
          simulatedStatus: "approved",
          sub: "user-id-789",
        },
      });

      const token = await dcFlow.getToken({ device_code });
      const decodedToken = await checkToken(token);

      // Garante que as claims do fluxo intermediário não vazaram para o token final
      expect(decodedToken).not.toHaveProperty("status");
      expect(decodedToken).not.toHaveProperty("user_code");
      expect(decodedToken).not.toHaveProperty("interval");
      expect(decodedToken).not.toHaveProperty("simulatedStatus");
    });
  });

  // ==============================================================================================================================================----

  describe("Abstract Method Stubs", () => {
    it("generateDeviceCode() na classe base deve lançar 'TODO_ERROR'", async () => {
      expect.assertions(2);
      const baseFlow = new DeviceCodeFlow({ ...clientData });
      await expect(baseFlow.generateDeviceCode({})).rejects.toThrow(OAuthError);
      await expect(baseFlow.generateDeviceCode({})).rejects.toHaveProperty("error", "todo_error");
    });

    it("validateDeviceCode() na classe base deve lançar 'TODO_ERROR'", async () => {
      expect.assertions(2);
      const baseFlow = new DeviceCodeFlow({ ...clientData });
      await expect(baseFlow.validateDeviceCode("code")).rejects.toThrow(OAuthError);
      await expect(baseFlow.validateDeviceCode("code")).rejects.toHaveProperty("error", "todo_error");
    });
  });
});
