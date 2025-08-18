import { describe, it, beforeEach, expect } from "vitest";
import { OAuthError, ERROR_SPECS } from "../src/errors/index.js";
import { checkToken, signToken, clientData } from "./utils.js";
import ClientCredentialsFlow from "../src/flows/ClientCredentialsFlow.js";

/**
 * @class MockClientCredentialsFlow
 * @description Implementação mock do ClientCredentialsFlow para fins de teste.
 * Simula a geração de um token de acesso final.
 */
class MockClientCredentialsFlow extends ClientCredentialsFlow {
  async generateToken({scopes, token_info = {}}) {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
      client_id: this.client_id,
      scope: scopes.join(" "),
      ...token_info,
    };
    return await signToken(payload);
  }
}

describe("ClientCredentialsFlow", () => {
  let ccFlow;

  beforeEach(() => {
    ccFlow = new MockClientCredentialsFlow({ ...clientData });
  });

  describe("Constructor", () => {
    it("deve instanciar com sucesso com opções válidas", () => {
      expect(ccFlow).toBeInstanceOf(ClientCredentialsFlow);
      expect(ccFlow.client_id).toBe(clientData.client_id);
    });

    it("deve herdar propriedades de AuthFlow corretamente", () => {
      expect(ccFlow.token_expires_in).toBe(3600);
      expect(ccFlow.grant_types).toContain("client_credentials");
    });
  });

  describe("getToken()", () => {
    it("deve gerar um token com sucesso com um escopo válido", async () => {
      const token = await ccFlow.getToken({ scope: "scopeA" });
      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.scope).toBe("scopeA");
    });

    it("deve gerar um token com sucesso com múltiplos escopos válidos", async () => {
      const token = await ccFlow.getToken({ scope: "scopeA scopeB" });
      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.scope).toBe("scopeA scopeB");
    });

    it("deve gerar um token com escopos vazios se nenhum for fornecido e não forem obrigatórios", async () => {
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        scopes_required: false,
      });
      const token = await flow.getToken({});
      const decoded = await checkToken(token);
      expect(decoded.scope).toBe("");
    });

    it("deve tratar escopos duplicados e espaços extras", async () => {
      const token = await ccFlow.getToken({ scope: "  scopeB scopeA  scopeB  " });
      const decoded = await checkToken(token);
      // O _parseScopeString remove duplicatas e a ordem pode não ser garantida,
      // então verificamos a presença de cada um e o tamanho.
      const scopes = decoded.scope.split(" ");
      expect(scopes).toHaveLength(2);
      expect(scopes).toContain("scopeA");
      expect(scopes).toContain("scopeB");
    });

    it("deve passar token_info para generateToken e incluí-lo no token final", async () => {
      const token = await ccFlow.getToken({
        scope: "scopeA",
        token_info: { aud: "my-api", custom_claim: "test-value" },
      });
      const decoded = await checkToken(token);
      expect(decoded.aud).toBe("my-api");
      expect(decoded.custom_claim).toBe("test-value");
      expect(decoded.scope).toBe("scopeA");
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' se o cliente não suportar 'client_credentials'", async () => {
      expect.assertions(2);
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        grant_types: "authorization_code",
      });
      try {
        await flow.getToken({ scope: "scopeA" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("unsupported_grant_type");
      }
    });

    it("deve lançar 'INVALID_SCOPE' se um escopo inválido for solicitado e match_all_scopes for true", async () => {
      expect.assertions(3);
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        match_all_scopes: true,
      });
      try {
        await flow.getToken({ scope: "scopeA scope_invalido" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(e.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    it("deve conceder apenas escopos válidos se match_all_scopes for false", async () => {
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        match_all_scopes: false,
      });
      const token = await flow.getToken({
        scope: "scopeA scope_invalido scopeB",
      });
      const decoded = await checkToken(token);
      expect(decoded.scope).toBe("scopeA scopeB");
    });

    it("deve lançar 'INVALID_SCOPE' se escopos são obrigatórios mas nenhum é fornecido", async () => {
      expect.assertions(3);
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        scopes_required: true,
      });
      try {
        await flow.getToken({});
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_scope");
        expect(e.more_info.detail).toContain("obrigatório para este cliente");
      }
    });

    it("deve lançar 'INVALID_SCOPE' se nenhum dos escopos solicitados for válido", async () => {
      expect.assertions(2);
      try {
        await ccFlow.getToken({ scope: "invalid1 invalid2" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_scope");
      }
    });

    it("deve lançar 'INVALID_SCOPE' se o cliente não tiver escopos configurados mas eles forem solicitados", async () => {
      expect.assertions(2);
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        scopes: "", // Cliente sem escopos configurados
      });
      try {
        await flow.getToken({ scope: "scopeA" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_scope");
      }
    });
  });

  describe("Abstract Method Stubs", () => {
    it("generateToken() na classe base deve lançar 'TODO_ERROR'", async () => {
      expect.assertions(2);
      const baseFlow = new ClientCredentialsFlow({ ...clientData });
      try {
        await baseFlow.getToken({ scope: "scopeA" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("todo_error");
      }
    });
  });

  describe("Casos de Borda e Validações Adicionais", () => {
    it("deve lançar um erro no construtor se 'client_id' não for fornecido", () => {
      // Este teste valida o comportamento herdado de AuthFlow.
      expect(() => new MockClientCredentialsFlow({})).toThrow(
        "AuthFlowError: Não é possível instanciar um fluxo sem um 'client_id'."
      );
    });

    it("deve lançar 'INVALID_SCOPE' se o escopo for nulo e escopos forem obrigatórios", async () => {
      expect.assertions(2);
      const flow = new MockClientCredentialsFlow({
        ...clientData,
        scopes_required: true,
      });
      try {
        await flow.getToken({ scope: null });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_scope");
      }
    });

    it("deve incluir o client_id no token gerado", async () => {
      const token = await ccFlow.getToken({ scope: "scopeA" });
      const decoded = await checkToken(token);
      expect(decoded.client_id).toBe(clientData.client_id);
    });

    it("deve calcular a expiração do token corretamente", async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await ccFlow.getToken({ scope: "scopeA" });
      const decoded = await checkToken(token);
      // Permite uma pequena variação de tempo para a execução do teste.
      const expectedExp = now + ccFlow.token_expires_in;
      expect(decoded.exp).toBeGreaterThanOrEqual(expectedExp - 5);
      expect(decoded.exp).toBeLessThanOrEqual(expectedExp + 5);
    });

    it("deve permitir que token_info sobrescreva claims padrão", async () => {
      const customExp = Math.floor(Date.now() / 1000) + 100; // 100 segundos
      const token = await ccFlow.getToken({
        scope: "scopeA",
        token_info: {
          scope: "scope_sobrescrito",
          exp: customExp,
          client_id: "outro_client",
        },
      });
      const decoded = await checkToken(token);
      // Verifica se as claims de token_info tiveram precedência.
      expect(decoded.scope).toBe("scope_sobrescrito");
      expect(decoded.exp).toBe(customExp);
      expect(decoded.client_id).toBe("outro_client");
    });
  });
});