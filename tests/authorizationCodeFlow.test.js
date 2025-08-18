import { describe, it, beforeEach, expect } from "vitest";
import AuthorizationCodeFlow from "../src/flows/AuthorizationCodeFlow.js";
import { OAuthError, ERROR_SPECS } from "../src/errors/index.js";
import {
  clientData,
  signToken,
  checkToken,
  generateVerifier,
  generateChallenge,
} from "./utils.js";
import { randomBytes, createHash } from "crypto";

// ==============================================================================================================================================----

/**
 * @class MockAuthorizationCodeFlow
 * @description Implementação mock do AuthorizationCodeFlow para fins de teste.
 * Simula a persistência de códigos de autorização em memória e a geração de tokens.
 */
class MockAuthorizationCodeFlow extends AuthorizationCodeFlow {
  // Simula um "banco de dados" em memória para os códigos de autorização.
  _db = new Map();
  _usedCodes = new Set();

  /**
   * Simula a geração e persistência de um código de autorização.
   */
  async generateCode({
    scopes_granted,
    code_info,
    redirect_uri,
    code_challenge,
    code_challenge_method,
  }) {
    const code = randomBytes(16).toString("hex");
    const expires_at = Date.now() + this.code_expires_in * 1000;

    this._db.set(code, {
      client_id: this.client_id,
      scopes_granted,
      code_info,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      expires_at,
    });

    return code;
  }

  /**
   * Simula a validação de um código de autorização.
   */
  async validateCode(code) {
    if (this._usedCodes.has(code)) {
      // O código já foi usado, é uma concessão inválida.
      OAuthError.throw("INVALID_GRANT", {
        detail: "Código de autorização já foi utilizado.",
      });
    }

    const data = this._db.get(code);

    if (!data) {
      OAuthError.throw("INVALID_GRANT", {
        detail: "Código de autorização inválido.",
      });
    }

    // Valida se o código foi emitido para o cliente que está tentando usá-lo.
    if (data.client_id !== this.client_id) {
      OAuthError.throw("INVALID_GRANT", {
        detail:
          "O código de autorização foi emitido para um cliente diferente.",
      });
    }

    if (Date.now() > data.expires_at) {
      this._db.delete(code); // Limpa o código expirado.
      OAuthError.throw("INVALID_GRANT", {
        detail: "Código de autorização expirado.",
      });
    }

    // Marca o código como usado para prevenir replay attacks.
    this._usedCodes.add(code);
    this._db.delete(code); // O código deve ser de uso único.

    return data;
  }

  /**
   * Simula a geração de um token de acesso final.
   */
  async generateToken({ validation_data, token_info = {} }) {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
      client_id: this.client_id,
      scope: validation_data.scopes_granted.join(" "),
      ...validation_data.code_info, // Inclui informações como user_id
      ...token_info,
    };
    return await signToken(payload);
  }

  // Helper para testes: limpa o estado do mock.
  _clearDb() {
    this._db.clear();
    this._usedCodes.clear();
  }
}

// ==============================================================================================================================================----

describe("AuthorizationCodeFlow", () => {
  let flow;
  const verifier = generateVerifier();
  const challenge = generateChallenge(verifier); // S256 por padrão

  beforeEach(() => {
    // Usamos o Mock para ter controle sobre os métodos de persistência.
    flow = new MockAuthorizationCodeFlow({ ...clientData });
  });

  // ==============================================================================================================================================----

  describe("Constructor", () => {
    it("deve instanciar com valores padrão", () => {
      const defaultFlow = new AuthorizationCodeFlow({ client_id: "test" });
      expect(defaultFlow.code_expires_in).toBe(300);
      expect(defaultFlow.pkce_required).toBe(true);
      expect(defaultFlow.supported_challenge_methods).toEqual(["S256"]);
    });

    it("deve instanciar com valores customizados", () => {
      const customFlow = new AuthorizationCodeFlow({
        client_id: "test",
        code_expires_in: 600,
        pkce_required: false,
      });
      expect(customFlow.code_expires_in).toBe(600);
      expect(customFlow.pkce_required).toBe(false);
    });

    it("deve permitir o método PKCE 'plain' se explicitamente configurado", () => {
      const plainAllowedFlow = new AuthorizationCodeFlow({
        client_id: "test",
        allow_plain_pkce_method: true,
      });
      expect(plainAllowedFlow.supported_challenge_methods).toEqual([
        "S256",
        "plain",
      ]);
    });
  });

  // ==============================================================================================================================================----

  describe("validateRedirectUri()", () => {
    it("deve retornar true se a validação de redirect_uri não for obrigatória", () => {
      const noRedirectFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        redirect_uri_required: false,
      });
      expect(noRedirectFlow.validateRedirectUri("qualquer-uri")).toBe(true);
    });

    it("deve lançar 'INVALID_REQUEST' se redirect_uri for nulo ou inválido", () => {
      expect(() => flow.validateRedirectUri(null)).toThrow(OAuthError);
      expect(() => flow.validateRedirectUri(undefined)).toThrow(OAuthError);
      expect(() => flow.validateRedirectUri(123)).toThrow(OAuthError);
      try {
        flow.validateRedirectUri("");
      } catch (e) {
        expect(e.error).toBe("invalid_request");
        expect(e.more_info.detail).toContain("obrigatório e inválido");
      }
    });

    it("deve lançar 'INVALID_REQUEST' se a redirect_uri não estiver na lista de permitidas", () => {
      expect(() =>
        flow.validateRedirectUri("http://nao-permitido.com")
      ).toThrow(OAuthError);
      try {
        flow.validateRedirectUri("http://nao-permitido.com");
      } catch (e) {
        expect(e.error).toBe("invalid_request");
        expect(e.more_info.detail).toContain(
          "não está na lista de URIs permitidas"
        );
      }
    });

    it("deve retornar true para uma redirect_uri válida e exata", () => {
      expect(flow.validateRedirectUri("http://localhost:3000/cb")).toBe(true);
    });

    it("NÃO deve permitir correspondência parcial de redirect_uri", () => {
      // OAuth 2.1 exige correspondência exata.
      expect(() =>
        flow.validateRedirectUri("http://localhost:3000/cb/extra")
      ).toThrow(OAuthError);
    });
  });

  // ==============================================================================================================================================----

  describe("getCode() - Etapa 1: Endpoint de Autorização", () => {
    const validParams = {
      response_type: "code",
      redirect_uri: "http://localhost:3000/cb",
      scope: "scopeA",
      code_challenge: challenge,
      code_challenge_method: "S256",
      code_info: { user_id: "user123" },
    };

    it("deve gerar um código de autorização com sucesso com parâmetros válidos", async () => {
      const code = await flow.getCode(validParams);
      expect(code).toBeTypeOf("string");
      expect(code.length).toBe(32); // 16 bytes em hex

      // Verifica se os dados foram "salvos" corretamente no mock
      const savedData = flow._db.get(code);
      expect(savedData.redirect_uri).toBe(validParams.redirect_uri);
      expect(savedData.scopes_granted).toEqual(["scopeA"]);
      expect(savedData.code_challenge).toBe(validParams.code_challenge);
      expect(savedData.code_challenge_method).toBe(
        validParams.code_challenge_method
      );
      expect(savedData.code_info).toEqual(validParams.code_info);
    });

    it("deve lançar 'UNSUPPORTED_RESPONSE_TYPE' para um response_type inválido", async () => {
      await expect(
        flow.getCode({ ...validParams, response_type: "token" })
      ).rejects.toHaveProperty("error", "unsupported_response_type");
    });

    it("deve lançar 'INVALID_REQUEST' se PKCE for obrigatório e code_challenge estiver faltando", async () => {
      await expect(
        flow.getCode({ ...validParams, code_challenge: undefined })
      ).rejects.toThrow(OAuthError);
      await expect(
        flow.getCode({ ...validParams, code_challenge: undefined })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve lançar 'INVALID_REQUEST' se o code_challenge_method não for suportado", async () => {
      await expect(
        flow.getCode({ ...validParams, code_challenge_method: "MD5" })
      ).rejects.toThrow(OAuthError);
      await expect(
        flow.getCode({ ...validParams, code_challenge_method: "MD5" })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve funcionar sem PKCE se pkce_required for false", async () => {
      const noPkceFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        pkce_required: false,
      });
      const code = await noPkceFlow.getCode({
        response_type: "code",
        redirect_uri: "http://localhost:3000/cb",
        scope: "scopeA",
      });
      expect(code).toBeTypeOf("string");
      const savedData = noPkceFlow._db.get(code);
      expect(savedData.code_challenge).toBeUndefined();
    });
  });

  // ==============================================================================================================================================----

  describe("getToken() - Etapa 2: Endpoint de Token", () => {
    let authCode;
    const redirect_uri = "http://localhost:3000/cb";

    // Antes de cada teste nesta suíte, gera um código de autorização válido.
    beforeEach(async () => {
      flow._clearDb(); // Garante que o DB mock esteja limpo
      authCode = await flow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA", "scopeB"],
        code_challenge: challenge,
        code_challenge_method: "S256",
        code_info: { user_id: "user123" },
      });
    });

    it("deve trocar um código válido por um token de acesso", async () => {
      const token = await flow.getToken({
        code: authCode,
        redirect_uri,
        code_verifier: verifier,
        token_info: { aud: "api1" },
      });

      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.client_id).toBe(clientData.client_id);
      expect(decoded.scope).toBe("scopeA scopeB");
      expect(decoded.user_id).toBe("user123");
      expect(decoded.aud).toBe("api1");
    });

    it("deve lançar 'INVALID_GRANT' se o código for inválido", async () => {
      await expect(
        flow.getToken({
          code: "codigo-invalido",
          redirect_uri,
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve lançar 'INVALID_GRANT' se o código já foi usado", async () => {
      // Usa o código uma vez
      await flow.getToken({
        code: authCode,
        redirect_uri,
        code_verifier: verifier,
      });

      // Tenta usar de novo
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve lançar 'INVALID_GRANT' se o código expirou", async () => {
      const expiredFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        code_expires_in: -1, // Expira imediatamente
      });
      const expiredCode = await expiredFlow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      await expect(
        expiredFlow.getToken({
          code: expiredCode,
          redirect_uri,
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve lançar 'INVALID_GRANT' se a redirect_uri não corresponder", async () => {
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: "http://diferente.com/cb",
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve lançar 'INVALID_REQUEST' se o code_verifier estiver faltando quando PKCE é obrigatório", async () => {
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: undefined,
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve lançar 'INVALID_GRANT' se o code_verifier for inválido", async () => {
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: "verifier-invalido",
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve funcionar com o método PKCE 'plain'", async () => {
      const plainFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        allow_plain_pkce_method: true,
      });
      const plainVerifier = "este-e-o-verifier";
      const plainCode = await plainFlow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA"],
        code_challenge: plainVerifier, // No método 'plain', challenge é igual ao verifier
        code_challenge_method: "plain",
      });

      const token = await plainFlow.getToken({
        code: plainCode,
        redirect_uri,
        code_verifier: plainVerifier,
      });

      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.scope).toBe("scopeA");
    });

    it("deve funcionar sem PKCE se pkce_required for false", async () => {
      const noPkceFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        pkce_required: false,
      });
      const code = await noPkceFlow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA"],
      });

      const token = await noPkceFlow.getToken({
        code,
        redirect_uri,
        // Nenhum code_verifier é passado
      });

      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.scope).toBe("scopeA");
    });
  });

  // ==============================================================================================================================================----

  describe("_transformVerifier()", () => {
    it("deve retornar o próprio verifier para o método 'plain'", () => {
      const verifier = "any-string";
      expect(flow._transformVerifier(verifier, "plain")).toBe(verifier);
    });

    it("deve retornar o hash SHA256 em base64url para o método 'S256'", () => {
      const verifier = "my-secret-verifier-string-12345";
      const expectedChallenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");
      expect(flow._transformVerifier(verifier, "S256")).toBe(expectedChallenge);
    });

    it("deve lançar 'SERVER_ERROR' para um método desconhecido", () => {
      expect(() => flow._transformVerifier("any", "UNKNOWN_METHOD")).toThrow(
        OAuthError
      );
      expect(() => flow._transformVerifier("any", "UNKNOWN_METHOD")).toThrow(
        expect.objectContaining({ error: "server_error" })
      );
    });
  });

  // ==============================================================================================================================================----

  describe("Abstract Method Stubs", () => {
    it("generateCode() na classe base deve lançar 'TODO_ERROR'", async () => {
      const baseFlow = new AuthorizationCodeFlow({ ...clientData });
      await expect(baseFlow.generateCode({})).rejects.toHaveProperty(
        "error",
        "todo_error"
      );
    });

    it("validateCode() na classe base deve lançar 'TODO_ERROR'", async () => {
      const baseFlow = new AuthorizationCodeFlow({ ...clientData });
      await expect(baseFlow.validateCode("any-code")).rejects.toHaveProperty(
        "error",
        "todo_error"
      );
    });
  });
});

// ==============================================================================================================================================----
// ==============================================================================================================================================----

describe("Casos de Borda e Validações Adicionais", () => {
  let flow;
  const verifier = generateVerifier();
  const challenge = generateChallenge(verifier);

  beforeEach(() => {
    flow = new MockAuthorizationCodeFlow({ ...clientData });
  });

  describe("getCode() - Validação de Escopo", () => {
    const baseParams = {
      response_type: "code",
      redirect_uri: "http://localhost:3000/cb",
      code_challenge: challenge,
      code_challenge_method: "S256",
    };

    it("deve conceder escopos parciais (válidos) quando match_all_scopes for false", async () => {
      const partialScopeFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        match_all_scopes: false,
      });
      const code = await partialScopeFlow.getCode({
        ...baseParams,
        scope: "scopeA scope_invalido",
      });
      const savedData = partialScopeFlow._db.get(code);
      expect(savedData.scopes_granted).toEqual(["scopeA"]);
    });

    it("deve lançar 'INVALID_SCOPE' se escopos forem obrigatórios mas não fornecidos", async () => {
      const requiredScopeFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        scopes_required: true,
      });
      await expect(
        requiredScopeFlow.getCode({ ...baseParams, scope: "" })
      ).rejects.toHaveProperty("error", "invalid_scope");
    });

    it("deve gerar um código sem escopos se não forem obrigatórios e não fornecidos", async () => {
      const optionalScopeFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        scopes_required: false,
      });
      const code = await optionalScopeFlow.getCode({ ...baseParams });
      const savedData = optionalScopeFlow._db.get(code);
      expect(savedData.scopes_granted).toEqual([]);
    });

    it("deve tratar espaços extras e duplicatas na string de escopo", async () => {
      const code = await flow.getCode({
        ...baseParams,
        scope: "  scopeB scopeA  scopeB ",
      });
      const savedData = flow._db.get(code);
      expect(new Set(savedData.scopes_granted)).toEqual(
        new Set(["scopeA", "scopeB"])
      );
    });
  });

  describe("getCode() - Validação de PKCE", () => {
    const baseParams = {
      response_type: "code",
      redirect_uri: "http://localhost:3000/cb",
      scope: "scopeA",
    };

    it("deve lançar 'INVALID_REQUEST' se o response_type for nulo ou undefined", async () => {
      await expect(
        flow.getCode({
          ...baseParams,
          response_type: null,
          code_challenge: challenge,
          code_challenge_method: "S256",
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve lançar 'INVALID_REQUEST' para um code_challenge malformado (não-string)", async () => {
      await expect(
        flow.getCode({
          ...baseParams,
          code_challenge: 12345,
          code_challenge_method: "S256",
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve lançar 'INVALID_REQUEST' se o challenge for uma string vazia e PKCE for obrigatório", async () => {
      await expect(
        flow.getCode({
          ...baseParams,
          code_challenge: "",
          code_challenge_method: "S256",
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve lançar 'INVALID_REQUEST' se o método 'plain' for usado mas não permitido", async () => {
      await expect(
        flow.getCode({
          ...baseParams,
          code_challenge: "desafio",
          code_challenge_method: "plain",
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("_validatePkceParameters deve tratar o método como 'plain' se for nulo ou undefined", () => {
      // O fluxo padrão não permite 'plain', então ele vai falhar, o que é o esperado.
      expect(() =>
        flow._validatePkceParameters("challenge", undefined)
      ).toThrow(expect.objectContaining({ error: "invalid_request" }));
    });
  });

  describe("getToken() - Validações de Segurança e Borda", () => {
    let authCode;
    const redirect_uri = "http://localhost:3000/cb";

    beforeEach(async () => {
      flow._clearDb();
      authCode = await flow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
    });

    it("deve lançar 'INVALID_GRANT' se o client_id do código não corresponder ao do fluxo", async () => {
      const anotherClientFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        client_id: "outro-cliente",
      });
      await expect(
        anotherClientFlow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve lançar 'INVALID_GRANT' se a redirect_uri for omitida no getToken quando foi usada no getCode", async () => {
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: undefined,
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve funcionar se a redirect_uri for omitida em ambas as etapas e não for obrigatória", async () => {
      const noRedirectFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        redirect_uri_required: false,
      });
      const code = await noRedirectFlow.generateCode({
        redirect_uri: undefined,
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      const token = await noRedirectFlow.getToken({
        code,
        redirect_uri: undefined,
        code_verifier: verifier,
      });
      expect(token).toBeTypeOf("string");
    });

    it("deve gerar um token com sucesso mesmo que token_info não seja fornecido", async () => {
      const token = await flow.getToken({
        code: authCode,
        redirect_uri,
        code_verifier: verifier,
      });
      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.aud).toBeUndefined();
    });

    it("deve lançar 'INVALID_REQUEST' se o verifier for uma string vazia e PKCE for obrigatório", async () => {
      await expect(
        flow.getToken({ code: authCode, redirect_uri, code_verifier: "" })
      ).rejects.toHaveProperty("error", "invalid_request");
    });
  });

  describe("getToken() - Comportamento do Token", () => {
    it("o token de acesso gerado deve conter as claims esperadas", async () => {
      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA", "scopeB"],
        code_challenge: challenge,
        code_challenge_method: "S256",
        code_info: { user_id: "user123", session_id: "sess456" },
      });
      const token = await flow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: verifier,
        token_info: { aud: "api-resource" },
      });
      const decoded = await checkToken(token);
      expect(decoded.client_id).toBe(clientData.client_id);
      expect(decoded.scope).toBe("scopeA scopeB");
      expect(decoded.user_id).toBe("user123");
      expect(decoded.session_id).toBe("sess456");
      expect(decoded.aud).toBe("api-resource");
      expect(decoded.iat).toBeTypeOf("number");
      expect(decoded.exp).toBeTypeOf("number");
    });

    it("o token de acesso gerado deve expirar de acordo com token_expires_in", async () => {
      const shortLivedFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        token_expires_in: 60,
      });
      const authCode = await shortLivedFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      const token = await shortLivedFlow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: verifier,
      });
      const decoded = await checkToken(token);
      const now = Math.floor(Date.now() / 1000);
      expect(decoded.exp).toBeGreaterThanOrEqual(now + 60 - 5);
      expect(decoded.exp).toBeLessThanOrEqual(now + 60 + 5);
    });
  });

  describe("Comportamento Interno do Mock", () => {
    it("validateCode deve remover o código do 'banco de dados' após o uso bem-sucedido", async () => {
      const code = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      expect(flow._db.has(code)).toBe(true);
      await flow.validateCode(code);
      expect(flow._db.has(code)).toBe(false);
    });

    it("validateCode deve adicionar o código à lista de códigos usados (prevenção de replay)", async () => {
      const code = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      expect(flow._usedCodes.has(code)).toBe(false);
      await flow.validateCode(code);
      expect(flow._usedCodes.has(code)).toBe(true);
    });

    it("validateCode deve remover um código expirado do 'banco de dados'", async () => {
      const expiredFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        code_expires_in: -1,
      });
      const code = await expiredFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
      });
      expect(expiredFlow._db.has(code)).toBe(true);
      await expect(expiredFlow.validateCode(code)).rejects.toThrow(OAuthError);
      expect(expiredFlow._db.has(code)).toBe(false);
    });
  });

  describe("PKCE quando não obrigatório (pkce_required: false)", () => {
    let noPkceRequiredFlow;
    beforeEach(() => {
      noPkceRequiredFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        pkce_required: false,
      });
    });

    it("deve validar PKCE se foi usado na etapa 1, mesmo que não seja obrigatório", async () => {
      const code = await noPkceRequiredFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      const token = await noPkceRequiredFlow.getToken({
        code,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: verifier,
      });
      expect(token).toBeTypeOf("string");
    });

    it("deve lançar 'INVALID_GRANT' se PKCE foi usado na etapa 1 mas o verifier está incorreto", async () => {
      const code = await noPkceRequiredFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      await expect(
        noPkceRequiredFlow.getToken({
          code,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: "verifier-incorreto",
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve lançar 'INVALID_REQUEST' se PKCE foi usado na etapa 1 mas o verifier está faltando", async () => {
      const code = await noPkceRequiredFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      await expect(
        noPkceRequiredFlow.getToken({
          code,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: undefined,
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });
  });
});
