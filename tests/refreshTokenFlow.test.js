import { describe, it, beforeEach, expect } from "vitest";
import { OAuthError } from "../src/errors/index.js";
import { checkToken, signToken, clientData } from "./utils.js";
import RefreshTokenFlow from "../src/flows/RefreshTokenFlow.js";

/**
 * @class MockRefreshTokenFlow
 * @description Implementação mock do RefreshTokenFlow para fins de teste.
 * Simula a validação e geração de tokens usando JWTs.
 */
class MockRefreshTokenFlow extends RefreshTokenFlow {
  /**
   * Simula a geração de um novo token de acesso.
   */
  async generateToken({validation_data, scopes, token_info = {}}) {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
      // Mantém os dados originais do refresh token, como 'sub' (user_id)
      ...validation_data,
      // Garante que o escopo seja uma string para o token final
      scope: scopes.join(" "),
      ...token_info,
    };
    // O client_id já vem de validation_data
    return await signToken(payload);
  }

  /**
   * Simula a validação de um refresh token.
   * Decodifica o JWT e verifica suas claims.
   */
  async validateRefreshToken(refreshTokenString) {
    try {
      const decoded = await checkToken(refreshTokenString);

      // Valida se o token foi emitido para o cliente correto
      if (decoded.client_id !== this.client_id) {
        OAuthError.throw("INVALID_GRANT", {
          detail: "O refresh token foi emitido para outro cliente.",
        });
      }

      // Retorna os dados necessários para a próxima etapa
      return {
        sub: decoded.sub,
        client_id: decoded.client_id,
        // Converte a string de escopo do token de volta para um array
        scopes: decoded.scope ? decoded.scope.split(" ") : [],
        // Passa outras claims que possam ser úteis
        ...decoded,
      };
    } catch (error) {
      // Mapeia erros de JWT (expirado, inválido) para o erro OAuth2 correto.
      OAuthError.throw("INVALID_GRANT", {
        detail: "O refresh token é inválido, expirado ou revogado.",
      });
    }
  }

  /**
   * Simula a emissão de um novo refresh token (não usado nos testes de getToken, mas necessário para a classe).
   */
  async issueNewRefreshToken(originalTokenData) {
    // Para os testes de getToken, esta implementação não é crítica.
    return "new-mock-refresh-token";
  }
}

// Helper para criar um refresh token de teste
const createRefreshToken = (payload = {}) => {
  const defaultPayload = {
    sub: "user-123", // user_id
    client_id: clientData.client_id,
    scope: "scopeA scopeB",
    // Refresh tokens geralmente têm uma vida útil mais longa
    exp: Math.floor(Date.now() / 1000) + 7200, // 2 horas
  };
  return signToken({ ...defaultPayload, ...payload });
};

describe("RefreshTokenFlow", () => {
  let rtFlow;

  beforeEach(() => {
    rtFlow = new MockRefreshTokenFlow({ ...clientData });
  });

  describe("Constructor", () => {
    it("deve instanciar com sucesso com opções válidas", () => {
      expect(rtFlow).toBeInstanceOf(RefreshTokenFlow);
      expect(rtFlow.grant_types).toContain("refresh_token");
    });
  });

  describe("getToken()", () => {
    it("deve gerar um novo access_token com os escopos originais se nenhum novo for solicitado", async () => {
      const refreshToken = await createRefreshToken({ scope: "scopeA scopeB" });
      const accessToken = await rtFlow.getToken({ refresh_token: refreshToken });

      const decoded = await checkToken(accessToken);
      expect(decoded.sub).toBe("user-123");
      expect(decoded.scope).toBe("scopeA scopeB");
      expect(decoded.client_id).toBe(clientData.client_id);
    });

    it("deve gerar um novo access_token com um subconjunto dos escopos originais", async () => {
      const refreshToken = await createRefreshToken({ scope: "scopeA scopeB scopeC" });
      const accessToken = await rtFlow.getToken({
        refresh_token: refreshToken,
        scope: "scopeA scopeC",
      });

      const decoded = await checkToken(accessToken);
      expect(decoded.scope).toBe("scopeA scopeC");
    });

    it("deve lançar 'INVALID_SCOPE' se um escopo não concedido originalmente for solicitado", async () => {
      expect.assertions(2);
      const refreshToken = await createRefreshToken({ scope: "scopeA" });
      try {
        await rtFlow.getToken({
          refresh_token: refreshToken,
          scope: "scopeA scopeB", // scopeB não foi concedido originalmente
        });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_scope");
      }
    });

    it("deve lançar 'INVALID_REQUEST' se o refresh_token não for fornecido", async () => {
      expect.assertions(2);
      try {
        await rtFlow.getToken({}); // refresh_token ausente
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_request");
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' se o cliente não suportar 'refresh_token'", async () => {
      expect.assertions(2);
      const flow = new MockRefreshTokenFlow({
        ...clientData,
        grant_types: "authorization_code",
      });
      const refreshToken = await createRefreshToken();
      try {
        await flow.getToken({ refresh_token: refreshToken });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("unsupported_grant_type");
      }
    });

    it("deve lançar 'INVALID_GRANT' para um refresh_token expirado", async () => {
      expect.assertions(2);
      const refreshToken = await createRefreshToken({ exp: Math.floor(Date.now() / 1000) - 1 });
      try {
        await rtFlow.getToken({ refresh_token: refreshToken });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_grant");
      }
    });

    it("deve lançar 'INVALID_GRANT' para um refresh_token malformado", async () => {
      expect.assertions(2);
      try {
        await rtFlow.getToken({ refresh_token: "token-invalido" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_grant");
      }
    });

    it("deve lançar 'INVALID_GRANT' se o refresh_token foi emitido para outro cliente", async () => {
      expect.assertions(2);
      const refreshToken = await createRefreshToken({ client_id: "outro-cliente" });
      try {
        await rtFlow.getToken({ refresh_token: refreshToken });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_grant");
      }
    });

    it("deve herdar escopos vazios se o refresh_token original não tiver escopos", async () => {
      const refreshToken = await createRefreshToken({ scope: "" });
      const accessToken = await rtFlow.getToken({ refresh_token: refreshToken });
      const decoded = await checkToken(accessToken);
      expect(decoded.scope).toBe("");
    });

    it("deve lançar 'INVALID_SCOPE' se solicitar escopos quando o original não tem nenhum", async () => {
      expect.assertions(2);
      const refreshToken = await createRefreshToken({ scope: "" });
      try {
        await rtFlow.getToken({ refresh_token: refreshToken, scope: "scopeA" });
      } catch (e) {
        expect(e.constructor.name).toBe("OAuthError");
        expect(e.error).toBe("invalid_scope");
      }
    });

    it("deve passar token_info para generateToken e incluí-lo no token final", async () => {
      const refreshToken = await createRefreshToken();
      const accessToken = await rtFlow.getToken({
        refresh_token: refreshToken,
        token_info: { aud: "minha-api", custom: "valor" },
      });
      const decoded = await checkToken(accessToken);
      console.log(decoded)
      expect(decoded.aud).toBe("minha-api");
      expect(decoded.custom).toBe("valor");
    });
  });

  describe("Abstract Method Stubs", () => {
    it("validateRefreshToken() na classe base deve lançar 'TODO_ERROR'", async () => {
      const baseFlow = new RefreshTokenFlow({ ...clientData });
      await expect(
        baseFlow.getToken({ refresh_token: "some-token" })
      ).rejects.toHaveProperty("error", "todo_error");
    });

    it("issueNewRefreshToken() na classe base deve lançar 'TODO_ERROR'", async () => {
      const baseFlow = new RefreshTokenFlow({ ...clientData });
      await expect(
        baseFlow.issueNewRefreshToken({})
      ).rejects.toHaveProperty("error", "todo_error");
    });
  });
});
