import { OAuthError } from "../errors/index.js";
import { createHash } from "crypto";
import AuthFlow from "./AuthFlow.js";

// ==================================================================================================================================================

/**
 * @class AuthorizationCodeFlow
 * @extends AuthFlow
 * @description Implementa o fluxo "Authorization Code with PKCE" (RFC 6749, Seção 4.1 e RFC 7636).
 * Este é o fluxo mais seguro e recomendado para aplicações web e mobile.
 */
class AuthorizationCodeFlow extends AuthFlow {
  code_expires_in;
  pkce_required;
  supported_challenge_methods;

  /**
   * @constructor
   */
  constructor(options = {}) {
    super(options);
    this.code_expires_in = options.code_expires_in ?? 300; // 5 minutos
    this.pkce_required = options.pkce_required ?? true;

    // Configuração de PKCE simplificada e segura
    this.supported_challenge_methods = ["S256"];
    if (options.allow_plain_pkce_method === true) {
      // Permitir 'plain' apenas se explicitamente configurado. NÃO RECOMENDADO.
      this.supported_challenge_methods.push("plain");
    }
  }

  // ================================================================================================================================================

  /**
   * Valida a `redirect_uri` da requisição contra a lista de URIs permitidas para o cliente.
   * Aderente à prática de segurança de "correspondência exata" do OAuth 2.1.
   * @param {string} requestedRedirectUri - A `redirect_uri` fornecida na requisição.
   * @throws {OAuthError} Lança 'INVALID_REQUEST' se a URI não corresponder exatamente a nenhuma das URIs registradas.
   * @returns {true} Retorna `true` se a URI for válida.
   */
  validateRedirectUri(requestedRedirectUri) {
    if (this.redirect_uri_required === false) {
      return true;
    }

    if (!requestedRedirectUri || typeof requestedRedirectUri !== "string") {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "redirect_uri" é obrigatório e inválido.',
      });
    }

    // A especificação OAuth 2.1 exige uma correspondência exata de strings.
    if (!this.redirect_uris.includes(requestedRedirectUri)) {
      OAuthError.throw("INVALID_REQUEST", {
        detail:
          'A "redirect_uri" fornecida não está na lista de URIs permitidas para este cliente.',
      });
    }

    return true;
  }

  // ================================================================================================================================================

  // --- Etapa 1: Endpoint de Autorização ---

  /**
   * Orquestra a validação e geração de um código de autorização.
   * @param {object} params
   * @param {string} params.response_type - Deve ser "code".
   * @param {string} params.redirect_uri - URI para onde o usuário será redirecionado.
   * @param {string} [params.scope] - Escopos solicitados.
   * @param {string} [params.code_challenge] - Desafio PKCE.
   * @param {string} [params.code_challenge_method] - Método do desafio PKCE ('S256' ou 'plain').
   * @param {object} [params.code_info] - Informações adicionais para associar ao código (ex: user_id).
   * @returns {Promise<string>} O código de autorização gerado.
   */
  async getCode({
    response_type,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method,
    code_info,
  }) {
    AuthFlow.validateResponseType(response_type, "code");
    this.validateRedirectUri(redirect_uri); // Usa o método seguro da classe pai.
    const scopes_granted = this.validateScopes(scope); // Usa o método performático da classe pai.

    if (this.pkce_required) {
      this._validatePkceParameters(code_challenge, code_challenge_method);
    }

    return this.generateCode({
      scopes_granted,
      code_info,
      redirect_uri,
      code_challenge,
      code_challenge_method,
    });
  }

  // ================================================================================================================================================

  /**
   * Valida os parâmetros PKCE da requisição de autorização.
   * @private
   */
  _validatePkceParameters(challenge, method = "plain") {
    if (!this.supported_challenge_methods.includes(method)) {
      OAuthError.throw("INVALID_REQUEST", {
        detail: `O code_challenge_method "${method}" não é suportado. Métodos permitidos: [${this.supported_challenge_methods.join(
          ", "
        )}]`,
      });
    }
    if (!challenge || typeof challenge !== "string") {
      OAuthError.throw("INVALID_REQUEST", {
        detail:
          'O parâmetro "code_challenge" é obrigatório e deve ser uma string quando PKCE é exigido.',
      });
    }
  }

  // ================================================================================================================================================

  // --- Etapa 2: Endpoint de Token ---

  /**
   * Orquestra a troca de um código de autorização por um token de acesso.
   * @param {object} params
   * @param {string} params.code - O código de autorização recebido na Etapa 1.
   * @param {string} params.redirect_uri - A mesma URI de redirecionamento da Etapa 1.
   * @param {string} [params.code_verifier] - O verificador PKCE.
   * @param {object} [params.token_info] - Informações adicionais para o token.
   * @returns {Promise<object>} O resultado da geração do token.
   */
  async getToken({ code, redirect_uri, code_verifier, token_info }) {
    this.validateGrantType("authorization_code");

    // 1. Valida o código e recupera os dados salvos com ele.
    const validation_data = await this.validateCode(code);

    // 2. Valida se a redirect_uri da requisição de token é a mesma da requisição de código.
    if (validation_data.redirect_uri !== redirect_uri) {
      OAuthError.throw("INVALID_GRANT", {
        detail:
          'A "redirect_uri" não corresponde à usada na requisição de autorização.',
      });
    }

    // 3. **VALIDAÇÃO PKCE**
    // Se um `code_challenge` foi usado na requisição de autorização (ou seja, ele existe
    // nos dados validados), a validação do `code_verifier` é OBRIGATÓRIA, mesmo que
    // `pkce_required` seja `false` para o cliente. Isso previne ataques de downgrade.
    if (validation_data.code_challenge) {
      this._validateCodeVerifier(
        code_verifier,
        validation_data.code_challenge,
        validation_data.code_challenge_method
      );
    } else if (this.pkce_required) {
      // Se PKCE é obrigatório para o cliente, mas o código não tinha um challenge associado,
      // a concessão é inválida. Isso indica uma falha no processo de autorização.
      OAuthError.throw("INVALID_GRANT", {
        detail:
          'O "code_challenge" era obrigatório para este cliente, mas não foi fornecido na requisição de autorização.',
      });
    }

    // 4. Gera o token de acesso, passando os escopos e informações salvas com o código.
    return this.generateToken({ validation_data, token_info });
  }

  // ================================================================================================================================================

  /**
   * Valida o code_verifier contra o code_challenge armazenado.
   * @private
   */
  _validateCodeVerifier(verifier, challenge, method) {
    // Se esta função foi chamada, significa que um `challenge` existe (lógica em getToken).
    // Portanto, o `verifier` é sempre obrigatório.
    if (!verifier || typeof verifier !== "string") {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "code_verifier" é obrigatório.',
      });
    }

    const transformedVerifier = this._transformVerifier(verifier, method);

    if (transformedVerifier !== challenge) {
      OAuthError.throw("INVALID_GRANT", {
        detail: 'O "code_verifier" é inválido.',
      });
    }
  }

  // ================================================================================================================================================

  /**
   * Transforma o code_verifier usando o método especificado (S256 ou plain).
   * @private
   */
  _transformVerifier(verifier, method) {
    if (method === "plain") {
      return verifier;
    }
    if (method === "S256") {
      return createHash("sha256").update(verifier).digest("base64url"); // base64url é o formato correto para PKCE
    }
    // Este erro indica uma configuração de servidor inconsistente.
    OAuthError.throw("SERVER_ERROR", {
      detail: `Método de desafio desconhecido encontrado durante a validação do verificador: ${method}`,
    });
  }

  // ================================================================================================================================================

  // --- Stubs para Implementação ---

  /**
   * Gera e persiste um novo código de autorização.
   * @returns {Promise<string>} O código gerado.
   */
  async generateCode({
    scopes_granted,
    code_info,
    redirect_uri,
    code_challenge,
    code_challenge_method,
  }) {
    // TODO: Implementar a lógica de geração e persistência.
    // 1. Gerar uma string de código aleatória, única e segura.
    // 2. Salvar em um banco de dados (ex: Redis, com TTL) associando:
    //    - o código gerado
    //    - this.client_id
    //    - redirect_uri
    //    - scopes_granted (array de strings)
    //    - code_challenge
    //    - code_challenge_method
    //    - user_id (de `code_info`)
    //    - um timestamp de expiração (Date.now() + this.code_expires_in * 1000)
    // 3. Retornar a string do código.
    OAuthError.throw("TODO_ERROR", {
      detail: "generateCode(): não implementado.",
    });
  }

  // ================================================================================================================================================

  /**
   * Valida um código de autorização e o marca como usado.
   * @param {string} code - O código a ser validado.
   * @returns {Promise<object>} Os dados associados ao código.
   */
  async validateCode(code) {
    // TODO: Implementar a lógica de validação.
    // 1. Buscar o código no banco de dados.
    // 2. Se não encontrado ou já usado -> OAuthError.throw('INVALID_GRANT', { detail: 'Código inválido ou expirado.' })
    // 3. Verificar se não está expirado. -> OAuthError.throw('INVALID_GRANT', { detail: 'Código inválido ou expirado.' })
    // 4. **Importante:** Marcar o código como usado para prevenir "replay attacks".
    // 5. Retornar o objeto salvo no passo anterior: { client_id, redirect_uri, scopes, code_challenge, ... }
    OAuthError.throw("TODO_ERROR", {
      detail: "validateCode(): não implementado.",
    });
  }
}

// ==================================================================================================================================================

export default AuthorizationCodeFlow;

// ==================================================================================================================================================
