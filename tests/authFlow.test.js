import { describe, it, beforeEach, expect } from "vitest";
import { OAuthError, ERROR_SPECS } from "../src/errors/index.js";
import { clientData } from "./utils.js";
import AuthFlow from "../src/flows/AuthFlow.js";

// ==================================================================================================================================================

describe("AuthFlow - Classe Base", () => {
  let authFlow;

  // beforeEach é executado antes de cada teste `it()`
  beforeEach(() => {
    authFlow = new AuthFlow({ ...clientData });
  });

  // ================================================================================================================================================

  describe("Constructor", () => {
    it("deve lançar um erro se 'client_id' não for fornecido", () => {
      // Um cliente DEVE ter um client_id, então a instanciação deve falhar.
      expect(() => new AuthFlow({})).toThrow(
        "AuthFlowError: Não é possível instanciar um fluxo sem um 'client_id'."
      );
    });

    it("deve atribuir valores padrão para opções não fornecidas", () => {
      const flow = new AuthFlow({ client_id: "test-client" });

      // Verifica se o client_id foi atribuído
      expect(flow.client_id).toBe("test-client");

      // Verifica os valores padrão para outras propriedades
      expect(flow.id).toBeNull();
      expect(flow.client_secret).toBeNull();
      expect(flow.issues_refresh_token).toBe(true);
      expect(flow.redirect_uri_required).toBe(true);
      expect(flow.scopes_required).toBe(false);
      expect(flow.state_required).toBe(true);
      expect(flow.match_all_scopes).toBe(true);
      expect(flow.refresh_token_expires_in).toBe(7200);
      expect(flow.token_expires_in).toBe(3600);

      // Verifica se as propriedades baseadas em string são arrays vazios por padrão
      expect(flow.grant_types).toEqual([]);
      expect(flow.scopes).toEqual([]);
      expect(flow.redirect_uris).toEqual([]);
    });

    it("deve atribuir corretamente os valores fornecidos nas opções", () => {
      const options = {
        id: 123,
        client_id: "provided-client-id",
        client_secret: "provided-secret",
        issues_refresh_token: false,
        redirect_uri_required: false,
        scopes_required: true,
        state_required: false,
        match_all_scopes: false,
        refresh_token_expires_in: 86400, // 1 dia
        token_expires_in: 1800, // 30 minutos
        grant_types: "authorization_code refresh_token",
        scopes: "scopeA scopeB",
        redirect_uris: "https://app.com/callback http://localhost/cb",
      };

      const flow = new AuthFlow(options);

      expect(flow.id).toBe(123);
      expect(flow.client_id).toBe("provided-client-id");
      expect(flow.client_secret).toBe("provided-secret");
      expect(flow.issues_refresh_token).toBe(false);
      expect(flow.redirect_uri_required).toBe(false);
      expect(flow.scopes_required).toBe(true);
      expect(flow.state_required).toBe(false);
      expect(flow.match_all_scopes).toBe(false);
      expect(flow.refresh_token_expires_in).toBe(86400);
      expect(flow.token_expires_in).toBe(1800);

      // Verifica se as strings foram corretamente divididas em arrays
      expect(flow.grant_types).toEqual(["authorization_code", "refresh_token"]);
      expect(flow.scopes).toEqual(["scopeA", "scopeB"]);
      expect(flow.redirect_uris).toEqual([
        "https://app.com/callback",
        "http://localhost/cb",
      ]);
    });

    it("deve processar corretamente strings com espaços extras", () => {
      const options = {
        client_id: "client-1",
        grant_types: " type1  type2 ", // Espaços no início, fim e extras no meio
        scopes: "scopeA   scopeB",
        redirect_uris: "uri1 ",
      };

      const flow = new AuthFlow(options);

      // A lógica de split deve ignorar os espaços extras
      expect(flow.grant_types).toEqual(["type1", "type2"]);
      expect(flow.scopes).toEqual(["scopeA", "scopeB"]);
      expect(flow.redirect_uris).toEqual(["uri1"]);
    });

    it("deve tratar 'grant_types', 'scopes' e 'redirect_uris' como arrays vazios se forem nulos, vazios ou não-strings", () => {
      // Teste com valores nulos, indefinidos e string vazia
      const flow1 = new AuthFlow({
        client_id: "client-1",
        grant_types: null,
        scopes: "",
        redirect_uris: undefined,
      });
      expect(flow1.grant_types).toEqual([]);
      expect(flow1.scopes).toEqual([]);
      expect(flow1.redirect_uris).toEqual([]);

      // Teste com tipos de dados incorretos
      const flow2 = new AuthFlow({
        client_id: "client-2",
        grant_types: [], // Não é string
        scopes: {}, // Não é string
        redirect_uris: 123, // Não é string
      });
      expect(flow2.grant_types).toEqual([]);
      expect(flow2.scopes).toEqual([]);
      expect(flow2.redirect_uris).toEqual([]);
    });
  });

  // ================================================================================================================================================

  describe("validateScopes()", () => {
    it("deve validar um escopo válido contido em uma string", () => {
      const granted = authFlow.validateScopes("scopeA");
      expect(granted).toEqual(["scopeA"]);
    });

    it("deve validar múltiplos escopos válidos", () => {
      const granted = authFlow.validateScopes("scopeA scopeB");
      expect(granted).toEqual(["scopeA", "scopeB"]);
    });

    it("deve lançar 'invalid_scope' para um escopo inválido", () => {
      expect.assertions(4);
      try {
        authFlow.validateScopes("scopeX");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    it("deve retornar apenas os escopos válidos quando match_all_scopes é false", () => {
      const customFlow = new AuthFlow({
        ...{ ...clientData },
        match_all_scopes: false,
      });
      const granted = customFlow.validateScopes("scopeC scopeB");
      expect(granted).toEqual(["scopeB"]);
    });

    it("deve lançar erro se match_all_scopes for true e um escopo for inválido", () => {
      expect.assertions(4);
      try {
        authFlow.validateScopes("scopeA scopeX");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    it("deve lançar erro se escopos são obrigatórios mas nenhum é fornecido", () => {
      const customFlow = new AuthFlow({
        ...{ ...clientData },
        scopes_required: true,
      });
      expect.assertions(4);
      try {
        customFlow.validateScopes("");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    it("não deve lançar erro se escopos não são obrigatórios e nenhum é fornecido", () => {
      const customFlow = new AuthFlow({
        ...{ ...clientData },
        scopes_required: false,
      });
      const granted = customFlow.validateScopes("");
      expect(granted).toEqual([]);
    });

    test("deve aceitar escopo válido com espaços extras", () => {
      expect(authFlow.validateScopes(" scopeA ")).toEqual(["scopeA"]);
    });

    test("deve lançar erro para escopo com case diferente (se case-sensitive)", () => {
      expect.assertions(4);
      try {
        authFlow.validateScopes("ScopeA");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });

    test("deve lançar erro para string de escopos separados por vírgula não suportada", () => {
      expect.assertions(4);
      try {
        authFlow.validateScopes("scopeA,scopeX");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_SCOPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_SCOPE.status);
      }
    });
  });

  // ================================================================================================================================================

  describe("Métodos Abstratos", () => {
    it("generateToken() deve lançar 'todo_error' por padrão", async () => {
      expect.assertions(4);
      try {
        await authFlow.generateToken();
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.TODO_ERROR.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.TODO_ERROR.description
        );
        expect(error.status).toBe(ERROR_SPECS.TODO_ERROR.status);
      }
    });

    it("validateToken() deve lançar 'todo_error' por padrão", async () => {
      expect.assertions(4);
      try {
        await authFlow.validateToken("some-token");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.TODO_ERROR.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.TODO_ERROR.description
        );
        expect(error.status).toBe(ERROR_SPECS.TODO_ERROR.status);
      }
    });

    it("getToken() deve lançar 'todo_error' por padrão", async () => {
      expect.assertions(4);
      try {
        await authFlow.getToken();
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.TODO_ERROR.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.TODO_ERROR.description
        );
        expect(error.status).toBe(ERROR_SPECS.TODO_ERROR.status);
      }
    });
  });

  // ================================================================================================================================================

  describe("validateGrantType()", () => {
    it("deve retornar true para um grant_type permitido", () => {
      expect(authFlow.validateGrantType("authorization_code")).toBe(true);
      expect(authFlow.validateGrantType("client_credentials")).toBe(true);
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' para um grant_type não permitido", () => {
      expect.assertions(4);
      try {
        authFlow.validateGrantType("password");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' quando grant_type é undefined", () => {
      expect.assertions(4);
      try {
        authFlow.validateGrantType(undefined);
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' quando grant_type é null", () => {
      expect.assertions(4);
      try {
        authFlow.validateGrantType(null);
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' quando grant_type é string vazia", () => {
      expect.assertions(4);
      try {
        authFlow.validateGrantType("");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' quando grant_types do cliente está vazio", () => {
      authFlow.grant_types = [];
      expect.assertions(4);
      try {
        authFlow.validateGrantType("authorization_code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' quando grant_types está com case sensitive diferente", () => {
      authFlow.grant_types = [];
      expect.assertions(4);
      try {
        authFlow.validateGrantType("Authorization_code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });

    it("deve lançar 'UNSUPPORTED_GRANT_TYPE' quando grant_types possui espaços ou mal formatado", () => {
      authFlow.grant_types = [];
      expect.assertions(4);
      try {
        authFlow.validateGrantType("authorization_code ");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_GRANT_TYPE.status);
      }
    });
  });

  // ================================================================================================================================================

  describe("validateResponseType()", () => {
    it("deve retornar true quando o response_type recebido é igual ao esperado", () => {
      expect(AuthFlow.validateResponseType("code", "code")).toBe(true);
    });

    it('deve lançar "INVALID_REQUEST" quando response_type é undefined', () => {
      expect.assertions(4);
      try {
        AuthFlow.validateResponseType(undefined, "code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_REQUEST.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_REQUEST.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_REQUEST.status);
      }
    });

    it('deve lançar "INVALID_REQUEST" quando response_type é null', () => {
      expect.assertions(4);
      try {
        AuthFlow.validateResponseType(null, "code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_REQUEST.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_REQUEST.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_REQUEST.status);
      }
    });

    it('deve lançar "INVALID_REQUEST" quando response_type é string vazia', () => {
      expect.assertions(4);
      try {
        AuthFlow.validateResponseType("", "code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.INVALID_REQUEST.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.INVALID_REQUEST.description
        );
        expect(error.status).toBe(ERROR_SPECS.INVALID_REQUEST.status);
      }
    });

    it('deve lançar "UNSUPPORTED_RESPONSE_TYPE" quando response_type é diferente do esperado', () => {
      expect.assertions(4);
      try {
        AuthFlow.validateResponseType("token", "code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.status);
      }
    });

    it('deve lançar "UNSUPPORTED_RESPONSE_TYPE" quando expectedResponseType está definido mas não bate', () => {
      expect.assertions(4);
      try {
        AuthFlow.validateResponseType("id_token", "code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.status);
      }
    });

    it('deve lançar "UNSUPPORTED_RESPONSE_TYPE" quando o response_type informado tem está mal formatado', () => {
      expect.assertions(4);
      try {
        AuthFlow.validateResponseType("code ", "code");
      } catch (error) {
        expect(error.constructor.name).toBe("OAuthError");
        expect(error.error).toBe(ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.code);
        expect(error.error_description).toBe(
          ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.description
        );
        expect(error.status).toBe(ERROR_SPECS.UNSUPPORTED_RESPONSE_TYPE.status);
      }
    });
  });
});
