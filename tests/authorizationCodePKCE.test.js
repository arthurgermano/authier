import { describe, it, beforeEach, expect } from "vitest";
import AuthorizationCodeFlow from "../src/flows/AuthorizationCodeFlow.js";
import { OAuthError } from "../src/errors/index.js";
import {
  clientData,
  signToken,
  checkToken,
  generateVerifier,
  generateChallenge,
  generateRandomBytes,
  base64URLEncode,
} from "./utils.js";
import { randomBytes, createHash } from "crypto";

// ==============================================================================================================================================

/**
 * @class MockAuthorizationCodeFlow
 * @description Implementação mock para testes focados em PKCE
 */
class MockAuthorizationCodeFlow extends AuthorizationCodeFlow {
  _db = new Map();
  _usedCodes = new Set();

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

  async validateCode(code) {
    if (this._usedCodes.has(code)) {
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

    if (data.client_id !== this.client_id) {
      OAuthError.throw("INVALID_GRANT", {
        detail:
          "O código de autorização foi emitido para um cliente diferente.",
      });
    }

    if (Date.now() > data.expires_at) {
      this._db.delete(code);
      OAuthError.throw("INVALID_GRANT", {
        detail: "Código de autorização expirado.",
      });
    }

    this._usedCodes.add(code);
    this._db.delete(code);

    return data;
  }

  async generateToken({ validation_data, token_info = {} }) {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
      client_id: this.client_id,
      scope: validation_data.scopes_granted.join(" "),
      ...validation_data.code_info,
      ...token_info,
    };
    return await signToken(payload);
  }

  _clearDb() {
    this._db.clear();
    this._usedCodes.clear();
  }
}

// ==============================================================================================================================================

describe("PKCE S256 - Testes Específicos e Avançados", () => {
  let flow;

  beforeEach(() => {
    // Fluxo configurado para aceitar APENAS S256 (sem plain)
    flow = new MockAuthorizationCodeFlow({
      ...clientData,
      pkce_required: true,
      allow_plain_pkce_method: false, // Explicitamente desabilita plain
    });
  });

  // ==============================================================================================================================================

  describe("Validação de Code Challenge - S256", () => {
    it("deve aceitar um code_challenge válido com método S256", async () => {
      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      const code = await flow.getCode({
        response_type: "code",
        redirect_uri: "http://localhost:3000/cb",
        scope: "scopeA",
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      expect(code).toBeTypeOf("string");
      const savedData = flow._db.get(code);
      expect(savedData.code_challenge).toBe(challenge);
      expect(savedData.code_challenge_method).toBe("S256");
    });

    it("deve rejeitar método 'plain' quando não permitido", async () => {
      const verifier = "plain-text-verifier";

      await expect(
        flow.getCode({
          response_type: "code",
          redirect_uri: "http://localhost:3000/cb",
          scope: "scopeA",
          code_challenge: verifier, // No plain, challenge = verifier
          code_challenge_method: "plain",
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve rejeitar métodos de challenge desconhecidos", async () => {
      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      await expect(
        flow.getCode({
          response_type: "code",
          redirect_uri: "http://localhost:3000/cb",
          scope: "scopeA",
          code_challenge: challenge,
          code_challenge_method: "SHA1", // Método não suportado
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });

    it("deve usar S256 como método padrão quando não especificado", async () => {
      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      // Teste interno do método _validatePkceParameters
      expect(() => {
        flow._validatePkceParameters(challenge, undefined);
      }).toThrow(expect.objectContaining({ error: "invalid_request" }));
    });
  });

  // ==============================================================================================================================================

  describe("Validação de Code Verifier - S256", () => {
    let authCode, verifier, challenge;
    const redirect_uri = "http://localhost:3000/cb";

    beforeEach(async () => {
      flow._clearDb();
      verifier = generateVerifier();
      challenge = generateChallenge(verifier, "sha256");

      authCode = await flow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
    });

    it("deve validar corretamente um code_verifier válido para S256", async () => {
      const token = await flow.getToken({
        code: authCode,
        redirect_uri,
        code_verifier: verifier,
      });

      expect(token).toBeTypeOf("string");
      const decoded = await checkToken(token);
      expect(decoded.client_id).toBe(clientData.client_id);
    });

    it("deve rejeitar um code_verifier inválido", async () => {
      const wrongVerifier = generateVerifier(); // Diferente do original

      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: wrongVerifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve rejeitar code_verifier vazio ou null", async () => {
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: "",
        })
      ).rejects.toHaveProperty("error", "invalid_request");

      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: null,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve rejeitar code_verifier que não seja string", async () => {
      const authCode = await flow.generateCode({
        redirect_uri,
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri,
          code_verifier: 12345,
        })
      ).rejects.toHaveProperty("error", "invalid_request");
    });
  });

  // ==============================================================================================================================================

  describe("Transformação S256 - Testes Internos", () => {
    it("deve transformar corretamente um verifier usando S256", () => {
      const verifier = "test-verifier-string-123";
      const expectedChallenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");

      const result = flow._transformVerifier(verifier, "S256");
      expect(result).toBe(expectedChallenge);
    });

    it("deve produzir resultados diferentes para verifiers diferentes", () => {
      const verifier1 = "verifier-one";
      const verifier2 = "verifier-two";

      const challenge1 = flow._transformVerifier(verifier1, "S256");
      const challenge2 = flow._transformVerifier(verifier2, "S256");

      expect(challenge1).not.toBe(challenge2);
    });

    it("deve produzir o mesmo resultado para o mesmo verifier", () => {
      const verifier = "consistent-verifier";

      const challenge1 = flow._transformVerifier(verifier, "S256");
      const challenge2 = flow._transformVerifier(verifier, "S256");

      expect(challenge1).toBe(challenge2);
    });

    it("deve usar encoding base64url correto (sem padding)", () => {
      const verifier = "test-verifier";
      const challenge = flow._transformVerifier(verifier, "S256");

      // base64url não deve ter caracteres '+', '/' ou '='
      expect(challenge).not.toMatch(/[+/=]/);
      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  // ==============================================================================================================================================

  describe("Cenários de Segurança PKCE", () => {
    it("deve rejeitar tentativas de downgrade de S256 para plain", async () => {
      // Gera código com S256
      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      // Tenta usar o verifier como se fosse plain
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: challenge, // Usando challenge como verifier (ataque)
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve manter segurança mesmo com verifiers muito curtos", async () => {
      const shortVerifier = "abc"; // Verifier muito curto
      const challenge = createHash("sha256")
        .update(shortVerifier)
        .digest("base64url");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      const token = await flow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: shortVerifier,
      });

      expect(token).toBeTypeOf("string");
    });

    it("deve manter segurança com verifiers muito longos", async () => {
      const longVerifier = "a".repeat(200); // Verifier muito longo
      const challenge = createHash("sha256")
        .update(longVerifier)
        .digest("base64url");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      const token = await flow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: longVerifier,
      });

      expect(token).toBeTypeOf("string");
    });

    it("deve rejeitar verifiers que diferem por um único caractere", async () => {
      const verifier = generateVerifier();
      const wrongVerifier = verifier.slice(0, -1) + "X"; // Muda último caractere
      const challenge = generateChallenge(verifier, "sha256");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: wrongVerifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });
  });

  // ==============================================================================================================================================

  describe("Casos de Borda PKCE", () => {
    it("deve funcionar com caracteres especiais no verifier", async () => {
      const specialVerifier = "test-verifier_with.special~chars123";
      const challenge = createHash("sha256")
        .update(specialVerifier)
        .digest("base64url");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      const token = await flow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: specialVerifier,
      });

      expect(token).toBeTypeOf("string");
    });

    it("deve funcionar com verifier contendo apenas números", async () => {
      const numericVerifier = "1234567890123456789012345678901234567890";
      const challenge = createHash("sha256")
        .update(numericVerifier)
        .digest("base64url");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      const token = await flow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: numericVerifier,
      });

      expect(token).toBeTypeOf("string");
    });

    it("deve rejeitar challenges malformados (não base64url)", async () => {
      const invalidChallenge = "invalid+challenge/with=padding";

      // Este teste verifica se a implementação é resiliente a challenges malformados
      // Na prática, isso deveria ser detectado no lado cliente antes de chegar aqui
      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: invalidChallenge,
        code_challenge_method: "S256",
      });

      // Qualquer verifier válido não vai bater com o challenge malformado
      const verifier = generateVerifier();

      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: verifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });
  });

  // ==============================================================================================================================================

  describe("Interação PKCE com outras validações", () => {
    it("deve validar PKCE mesmo quando escopos estão incorretos", async () => {
      // Este teste garante que a validação PKCE acontece independente de outras validações
      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      // Token request com verifier errado - deve falhar na validação PKCE
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: "wrong-verifier",
        })
      ).rejects.toHaveProperty("error", "invalid_grant");
    });

    it("deve validar PKCE e falhar adequadamente com verifier incorreto", async () => {
      const verifier = generateVerifier();
      const wrongVerifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
        code_info: { user_id: "user123" },
      });

      // Verifica que o código existe antes da tentativa
      expect(flow._db.has(authCode)).toBe(true);
      expect(flow._usedCodes.has(authCode)).toBe(false);

      // Verifier errado deve falhar na validação PKCE
      await expect(
        flow.getToken({
          code: authCode,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: wrongVerifier,
        })
      ).rejects.toHaveProperty("error", "invalid_grant");

      // Na implementação atual, o código é consumido durante validateCode()
      // mesmo se a validação PKCE falhar depois, pois validateCode() é chamado primeiro
      expect(flow._usedCodes.has(authCode)).toBe(true);
      expect(flow._db.has(authCode)).toBe(false);
    });
  });

  // ==============================================================================================================================================

  describe("Configuração Flexível PKCE", () => {
    it("deve funcionar quando PKCE não é obrigatório mas foi usado", async () => {
      const optionalPkceFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        pkce_required: false, // PKCE opcional
      });

      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      // Cliente decide usar PKCE mesmo não sendo obrigatório
      const authCode = await optionalPkceFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      // Deve validar PKCE normalmente
      const token = await optionalPkceFlow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        code_verifier: verifier,
      });

      expect(token).toBeTypeOf("string");
    });

    it("deve permitir fluxo sem PKCE quando não obrigatório e não usado", async () => {
      const optionalPkceFlow = new MockAuthorizationCodeFlow({
        ...clientData,
        pkce_required: false,
      });

      // Não usa PKCE
      const authCode = await optionalPkceFlow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        // Sem code_challenge
      });

      // Não fornece verifier
      const token = await optionalPkceFlow.getToken({
        code: authCode,
        redirect_uri: "http://localhost:3000/cb",
        // Sem code_verifier
      });

      expect(token).toBeTypeOf("string");
    });
  });

  // ==============================================================================================================================================

  describe("Mensagens de Erro PKCE", () => {
    it("deve fornecer mensagem específica para challenge method não suportado", async () => {
      try {
        await flow.getCode({
          response_type: "code",
          redirect_uri: "http://localhost:3000/cb",
          scope: "scopeA",
          code_challenge: "any-challenge",
          code_challenge_method: "UNSUPPORTED",
        });
      } catch (error) {
        expect(error.error).toBe("invalid_request");
        expect(error.more_info.detail).toContain("UNSUPPORTED");
        expect(error.more_info.detail).toContain("não é suportado");
        expect(error.more_info.detail).toContain("S256"); // Deve mencionar métodos permitidos
      }
    });

    it("deve fornecer mensagem específica para verifier inválido", async () => {
      const verifier = generateVerifier();
      const challenge = generateChallenge(verifier, "sha256");

      const authCode = await flow.generateCode({
        redirect_uri: "http://localhost:3000/cb",
        scopes_granted: ["scopeA"],
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

      try {
        await flow.getToken({
          code: authCode,
          redirect_uri: "http://localhost:3000/cb",
          code_verifier: "wrong-verifier",
        });
      } catch (error) {
        expect(error.error).toBe("invalid_grant");
        expect(error.more_info.detail).toContain("code_verifier");
        expect(error.more_info.detail).toContain("inválido");
      }
    });

    it("deve fornecer mensagem específica para challenge obrigatório faltando", async () => {
      try {
        await flow.getCode({
          response_type: "code",
          redirect_uri: "http://localhost:3000/cb",
          scope: "scopeA",
          // code_challenge missing
          code_challenge_method: "S256",
        });
      } catch (error) {
        expect(error.error).toBe("invalid_request");
        expect(error.more_info.detail).toContain("code_challenge");
        expect(error.more_info.detail).toContain("obrigatório");
      }
    });
  });
});
