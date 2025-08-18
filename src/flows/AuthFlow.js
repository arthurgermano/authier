const { OAuthError } = require("../errors/index.js");

// ==================================================================================================================================================

/**
 * @class AuthFlow
 * @description Classe base que encapsula a lógica e as configurações comuns
 * a todos os fluxos de autorização OAuth 2.1. Ela representa um cliente
 * configurado e suas regras de negócio.
 */
class AuthFlow {
  // --- Propriedades de Configuração do Cliente (Nomes Originais Mantidos) ---

  id;
  client_id;
  client_secret;
  issues_refresh_token;
  redirect_uri_required;
  scopes_required;
  state_required;
  refresh_token_expires_in;
  token_expires_in;
  match_all_scopes;

  /**
   * Os grant types que este cliente tem permissão para usar.
   * @type {string[]}
   */
  grant_types;

  /**
   * Os escopos que este cliente tem permissão para conceder.
   * @type {string[]}
   */
  scopes;

  /**
   * As URIs de redirecionamento exatas e pré-registradas para este cliente.
   * @type {string[]}
   */
  redirect_uris;

  // ================================================================================================================================================

  /**
   * @constructor
   * @param {object} options - As opções de configuração do cliente, geralmente vindas do banco de dados.
   */
  constructor(options = {}) {
    // Validação essencial: um cliente DEVE ter um client_id.
    if (!options.client_id) {
      throw new Error(
        "AuthFlowError: Não é possível instanciar um fluxo sem um 'client_id'."
      );
    }

    // Usando o operador de coalescência nula (??) do JavaScript moderno.
    // É mais limpo e faz exatamente o que `returnDefaultValue` pretendia.
    this.id = options.id ?? null; // null é um default melhor que 0 para um ID.
    this.client_id = options.client_id;
    this.client_secret = options.client_secret ?? null;

    this.issues_refresh_token = options.issues_refresh_token ?? true;
    this.redirect_uri_required = options.redirect_uri_required ?? true;
    this.scopes_required = options.scopes_required ?? false; // Nome original mantido
    this.state_required = options.state_required ?? true;

    this.refresh_token_expires_in = options.refresh_token_expires_in ?? 7200; // 2 horas
    this.token_expires_in = options.token_expires_in ?? 3600; // 1 hora

    this.match_all_scopes = options.match_all_scopes ?? true;

    const splitString = (str) =>
      typeof str === "string" && str ? str.split(" ").filter((s) => s) : [];

    this.grant_types = options.grant_types
      ? splitString(options.grant_types)
      : [];
    this.scopes = options.scopes ? splitString(options.scopes) : [];
    this.redirect_uris = options.redirect_uris
      ? splitString(options.redirect_uris)
      : [];
  }

  // ================================================================================================================================================

  /**
   * Valida os escopos solicitados contra os escopos permitidos para o cliente.
   * @param {string} [requestedScopeString] - A string de escopos separada por espaços, vinda da requisição (ex: "read write email").
   * @returns {string[]} Retorna um array com os escopos validados e concedidos.
   * @throws {OAuthError} Lança 'INVALID_SCOPE' se a validação falhar.
   */
  validateScopes(requestedScopeString) {
    // A lógica de `validateScopes` espera um array, mas a requisição vem como string.
    // O ideal é normalizar a entrada. O parâmetro do método foi ajustado para refletir isso.
    const requestedScopes = this._parseScopeString(requestedScopeString);

    if (requestedScopes.length === 0) {
      // Usando a propriedade com o nome original: `scopes_required`
      if (this.scopes_required) {
        OAuthError.throw("INVALID_SCOPE", {
          detail:
            'O parâmetro "scope" é obrigatório para este cliente, mas não foi fornecido.',
        });
      }
      return []; // Se não for obrigatório e nada foi pedido, retorna um array vazio.
    }

    if (this.scopes.length === 0) {
      OAuthError.throw("INVALID_SCOPE", {
        detail:
          "O cliente solicitou escopos, mas não tem nenhum escopo registrado para conceder.",
      });
    }

    // Para performance, criamos um Set com os escopos permitidos para buscas rápidas (O(1)).
    const allowedScopesSet = new Set(this.scopes);
    const grantedScopes = [];

    for (const scope of requestedScopes) {
      if (allowedScopesSet.has(scope)) {
        grantedScopes.push(scope);
      } else if (this.match_all_scopes) {
        // Se a regra é "match_all" e um escopo não é permitido, a validação falha imediatamente.
        OAuthError.throw("INVALID_SCOPE", {
          detail: `O escopo "${scope}" não é permitido para este cliente.`,
        });
      }
    }

    // Se nenhum dos escopos solicitados pôde ser concedido, é um erro.
    if (grantedScopes.length === 0) {
      OAuthError.throw("INVALID_SCOPE", {
        detail: "Nenhum dos escopos solicitados é válido para este cliente.",
      });
    }

    return grantedScopes;
  }

  // ================================================================================================================================================

  /**
   * Função utilitária privada para converter a string de escopo em um array de strings.
   * @private
   * @param {string} scopeString - String de escopos (ex: "read write").
   * @returns {string[]} Array de escopos (ex: ['read', 'write']).
   */
  _parseScopeString(scopeString) {
    if (!scopeString || typeof scopeString !== "string") {
      return [];
    }
    // Remove duplicatas e espaços vazios.
    return [...new Set(scopeString.split(" ").filter((s) => s))];
  }

  // ================================================================================================================================================

  /**
   * Valida o 'grant_type' da requisição contra os tipos permitidos para este cliente.
   * @param {string} requestedGrantType - O `grant_type` recebido na requisição.
   * @throws {OAuthError} Lança 'UNSUPPORTED_GRANT_TYPE' se o tipo não for permitido.
   * @returns {true}
   */
  validateGrantType(requestedGrantType) {
    if (!this.grant_types.includes(requestedGrantType)) {
      OAuthError.throw('UNSUPPORTED_GRANT_TYPE', {
        detail: `O grant_type "${requestedGrantType}" não é suportado por este cliente.`,
      });
    }
    return true;
  }

  // ================================================================================================================================================

  /**
   * Valida o 'response_type' da requisição contra um valor esperado.
   * Este é um método estático porque não depende do estado de uma instância específica.
   * @static
   * @param {string} receivedResponseType - O `response_type` recebido.
   * @param {string} expectedResponseType - O `response_type` esperado para este fluxo.
   * @throws {OAuthError}
   * @returns {true}
   */
  static validateResponseType(receivedResponseType, expectedResponseType) {
    if (!receivedResponseType) {
        OAuthError.throw('INVALID_REQUEST', { detail: 'O parâmetro "response_type" é obrigatório.' });
    }
    if (receivedResponseType !== expectedResponseType) {
        OAuthError.throw('UNSUPPORTED_RESPONSE_TYPE', { detail: `O response_type "${receivedResponseType}" não é suportado para esta operação.` });
    }
    return true;
  }

  // ================================================================================================================================================

  // --- Funções de Interface (a serem implementadas pelas classes filhas) ---

  async generateToken(validation_data, token_info) {
    OAuthError.throw("TODO_ERROR", {
      detail: "generateToken(): não implementado na classe base.",
    });
  }

  async validateToken(token_info) {
    OAuthError.throw("TODO_ERROR", {
      detail: "validateToken(): não implementado na classe base.",
    });
  }

  async getToken(params) {
    OAuthError.throw("TODO_ERROR", {
      detail: "getToken(): não implementado na classe base.",
    });
  }
}

// ==================================================================================================================================================

export default AuthFlow;

// ==================================================================================================================================================
