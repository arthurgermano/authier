import { createHash, randomInt } from 'crypto';

/**
 * @file Módulo centralizado para gerenciamento de erros do OAuth 2.0.
 * @see {@link https://datatracker.ietf.org/doc/html/rfc6749#section-5.2} para erros padrão.
 * @see {@link https://datatracker.ietf.org/doc/html/rfc8628} para erros do Device Flow.
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7636} para erros PKCE.
 */

// ==================================================================================================================================================

// Define as especificações dos erros em um único local para fácil manutenção.
const ERROR_SPECS = {
  // --- Erros Padrão (RFC 6749) ---
  ACCESS_DENIED: {
    code: "access_denied",
    description:
      "O proprietário do recurso ou o servidor de autorização negou a solicitação.",
    status: 403, // A RFC não especifica, mas 403 (Forbidden) é semanticamente mais correto que 400.
  },
  INVALID_CLIENT: {
    code: "invalid_client",
    description:
      "A autenticação do cliente falhou (ex: cliente desconhecido, sem autenticação incluída ou método não suportado).",
    status: 401,
  },
  INVALID_GRANT: {
    code: "invalid_grant",
    description:
      "A concessão de autorização (ex: código de autorização, credenciais) ou o refresh token é inválido, expirado, revogado ou foi emitido para outro cliente.",
    status: 400,
  },
  INVALID_REQUEST: {
    code: "invalid_request",
    description:
      "A requisição está faltando um parâmetro obrigatório, inclui um valor de parâmetro não suportado, repete um parâmetro ou está malformada.",
    status: 400,
  },
  INVALID_SCOPE: {
    code: "invalid_scope",
    description:
      "O escopo solicitado é inválido, desconhecido, malformado ou excede o escopo concedido.",
    status: 400,
  },
  SERVER_ERROR: {
    code: "server_error",
    description:
      "O servidor de autorização encontrou uma condição inesperada que o impediu de atender à solicitação.",
    status: 500,
  },
  TEMPORARILY_UNAVAILABLE: {
    code: "temporarily_unavailable",
    description:
      "O servidor de autorização está temporariamente indisponível devido a sobrecarga ou manutenção.",
    status: 503,
  },
  UNSUPPORTED_GRANT_TYPE: {
    code: "unsupported_grant_type",
    description:
      "O tipo de concessão de autorização não é suportado pelo servidor.",
    status: 400,
  },
  UNSUPPORTED_RESPONSE_TYPE: {
    code: "unsupported_response_type",
    description:
      "O servidor de autorização não suporta a obtenção de um código de autorização usando este método.",
    status: 400,
  },

  // --- Erros Específicos (RFC 8628 - Device Flow) ---
  AUTHORIZATION_PENDING: {
    code: "authorization_pending",
    description:
      "A autorização do usuário está pendente. O cliente deve continuar o polling.",
    status: 400,
  },
  SLOW_DOWN: {
    code: "slow_down",
    description:
      "O cliente está fazendo o polling com muita frequência. A frequência deve ser reduzida.",
    status: 400,
  },
  EXPIRED_TOKEN: {
    // 'token' aqui se refere ao device_code
    code: "expired_token",
    description:
      "O device_code expirou e o fluxo de autorização deve ser reiniciado.",
    status: 400,
  },

  // --- Erros Adicionais Úteis ---
  INVALID_TOKEN: {
    code: "invalid_token",
    description:
      "O token de acesso fornecido é inválido, malformado, expirado ou foi revogado.",
    status: 401,
  },
  INSUFFICIENT_SCOPE: {
    code: "insufficient_scope",
    description:
      "O token de acesso não possui os escopos necessários para acessar o recurso solicitado.",
    status: 403,
  },
  UNAUTHORIZED_CLIENT: {
    code: "unauthorized_client",
    description:
      "O cliente não está autorizado a usar este método de concessão de autorização.",
    status: 400,
  },
  INVALID_REDIRECT_URI: {
    code: "invalid_redirect_uri",
    description:
      "A URI de redirecionamento fornecida não é válida ou não corresponde às URIs pré-registradas.",
    status: 400,
  },
  UNSUPPORTED_TOKEN_TYPE: {
    code: "unsupported_token_type",
    description:
      "O servidor de autorização não suporta a revogação do tipo de token apresentado.",
    status: 400,
  },

  // --- Erros Relacionados a Rate Limiting ---
  TOO_MANY_REQUESTS: {
    code: "too_many_requests",
    description:
      "O cliente excedeu o limite de taxa de requisições. Tente novamente mais tarde.",
    status: 429,
  },

  // --- Erros Relacionados a PKCE (RFC 7636) ---
  INVALID_CODE_CHALLENGE: {
    code: "invalid_request", // PKCE usa invalid_request para challenges inválidos
    description:
      "O code_challenge fornecido é inválido, malformado ou usa um método não suportado.",
    status: 400,
  },
  INVALID_CODE_VERIFIER: {
    code: "invalid_grant", // PKCE usa invalid_grant para verifiers inválidos
    description:
      "O code_verifier fornecido não corresponde ao code_challenge da requisição de autorização.",
    status: 400,
  },

  // --- Erros de Configuração e Estado ---
  CONFIGURATION_ERROR: {
    code: "server_error",
    description:
      "Erro na configuração do servidor de autorização. Contate o administrador.",
    status: 500,
  },
  SERVICE_UNAVAILABLE: {
    code: "temporarily_unavailable",
    description:
      "O serviço de autorização está temporariamente indisponível para manutenção.",
    status: 503,
  },

  // --- Erros Customizados (Específicos da sua aplicação) ---
  MISMATCH_CLIENT: {
    code: "mismatch_client",
    description: "A autenticação do cliente falhou - cliente não corresponde.",
    status: 400,
  },
  TODO_ERROR: {
    code: "todo_error",
    description: "A funcionalidade solicitada ainda não foi implementada.",
    status: 501, // 501 Not Implemented é semanticamente mais adequado.
  },

  // --- Erros de Validação de Dados ---
  MALFORMED_REQUEST: {
    code: "invalid_request",
    description:
      "A requisição contém dados malformados ou não pode ser processada.",
    status: 400,
  },
  MISSING_PARAMETER: {
    code: "invalid_request",
    description: "Um parâmetro obrigatório está ausente da requisição.",
    status: 400,
  },
  DUPLICATE_PARAMETER: {
    code: "invalid_request",
    description:
      "A requisição contém parâmetros duplicados que devem ser únicos.",
    status: 400,
  },

  // --- Erros de Segurança ---
  REPLAY_ATTACK: {
    code: "invalid_grant",
    description:
      "Tentativa de reutilização de uma concessão de uso único detectada.",
    status: 400,
  },
  SUSPICIOUS_ACTIVITY: {
    code: "access_denied",
    description:
      "Atividade suspeita detectada. A requisição foi negada por motivos de segurança.",
    status: 403,
  },
};

// ==================================================================================================================================================

/**
 * Classe customizada para representar um erro padrão do OAuth 2.0.
 * Estende a classe Error para obter stack traces e melhor integração.
 */
let OAuthError$1 = class OAuthError extends Error {
  constructor(spec, more_info) {
    // A `message` do erro será a descrição padrão.
    super(spec.description);

    // Propriedades do erro OAuth 2.0
    this.name = "OAuthError"; // Nome da classe para facilitar a depuração
    this.error = spec.code;
    this.error_description = spec.description;
    this.status = spec.status;

    // Informações adicionais para logging interno (não expostas ao cliente final).
    if (more_info) {
      this.more_info = more_info;
    }

    // Preserva o stack trace original
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, OAuthError);
    }
  }

  /**
   * Converte a instância do erro para um objeto JSON simples,
   * mantendo a compatibilidade com o formato de resposta esperado.
   * @param {boolean} [includeDebugInfo=false] - Se deve incluir informações de debug
   * @returns {{error: string, error_description: string, status?: number}}
   */
  toResponseObject(includeDebugInfo = false) {
    const response = {
      error: this.error,
      error_description: this.error_description,
      status: this.status,
    };

    // Inclui status apenas em modo debug ou para logs internos
    if (includeDebugInfo) {
      response.more_info = this.more_info;
    }

    return response;
  }

  /**
   * Converte para formato de resposta HTTP padrão OAuth 2.0
   * @returns {{body: object, status: number, headers: object}}
   */
  toHttpResponse() {
    return {
      status: this.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
      body: this.toResponseObject(),
    };
  }

  /**
   * Verifica se o erro é do tipo especificado
   * @param {keyof typeof ERROR_SPECS} errorType - Tipo do erro a verificar
   * @returns {boolean}
   */
  isType(errorType) {
    const spec = ERROR_SPECS[errorType];
    return spec && this.error === spec.code;
  }

  /**
   * Verifica se o erro é retryable (pode ser tentado novamente)
   * @returns {boolean}
   */
  isRetryable() {
    const retryableErrors = [
      "server_error",
      "temporarily_unavailable",
      "too_many_requests",
    ];
    return retryableErrors.includes(this.error);
  }

  /**
   * Factory method para criar e lançar uma instância de OAuthError.
   * @param {keyof typeof ERROR_SPECS} errorType - O tipo do erro (ex: 'INVALID_CLIENT').
   * @param {any} [more_info] - Informações adicionais para depuração.
   * @throws {OAuthError}
   */
  static throw(errorType, more_info) {
    const spec = ERROR_SPECS[errorType];
    if (!spec) {
      // Fallback para um erro de servidor caso um tipo de erro inválido seja passado.
      const serverErrorSpec = ERROR_SPECS.SERVER_ERROR;
      throw new OAuthError(serverErrorSpec, {
        originalErrorType: errorType,
        message: `Tipo de erro desconhecido: ${errorType}`,
        ...more_info,
      });
    }
    throw new OAuthError(spec, more_info);
  }

  /**
   * Cria uma instância sem lançar (útil para logging ou retornos condicionais)
   * @param {keyof typeof ERROR_SPECS} errorType - O tipo do erro
   * @param {any} [more_info] - Informações adicionais
   * @returns {OAuthError}
   */
  static create(errorType, more_info) {
    const spec = ERROR_SPECS[errorType];
    if (!spec) {
      const serverErrorSpec = ERROR_SPECS.SERVER_ERROR;
      return new OAuthError(serverErrorSpec, {
        originalErrorType: errorType,
        message: `Tipo de erro desconhecido: ${errorType}`,
        ...more_info,
      });
    }
    return new OAuthError(spec, more_info);
  }

  /**
   * Valida se um código de erro é válido
   * @param {string} errorCode - Código do erro a validar
   * @returns {boolean}
   */
  static isValidErrorCode(errorCode) {
    return Object.values(ERROR_SPECS).some((spec) => spec.code === errorCode);
  }

  /**
   * Obtém a especificação de um erro pelo código
   * @param {string} errorCode - Código do erro
   * @returns {object|null}
   */
  static getSpecByCode(errorCode) {
    return (
      Object.values(ERROR_SPECS).find((spec) => spec.code === errorCode) || null
    );
  }
};

// ==================================================================================================================================================

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

    this.grant_types = this._setArray(options.grant_types);
    this.scopes = this._setArray(options.scopes);
    this.redirect_uris = this._setArray(options.redirect_uris);
  }

  // ================================================================================================================================================

  _splitString(str) {
    if (typeof str === "string" && str) {
      return [...new Set(str.split(" ").filter((s) => s))];
    }
    return [];
  }

  // ================================================================================================================================================

  _setArray(obj) {
    if (!obj) {
      return [];
    }
    if (typeof obj === "string") {
      return this._splitString(obj);
    } else if (Array.isArray(obj)) {
      return obj;
    }
    return [];
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
    const requestedScopes = this._splitString(requestedScopeString);

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
   * Valida o 'grant_type' da requisição contra os tipos permitidos para este cliente.
   * @param {string} requestedGrantType - O `grant_type` recebido na requisição.
   * @throws {OAuthError} Lança 'UNSUPPORTED_GRANT_TYPE' se o tipo não for permitido.
   * @returns {true}
   */
  validateGrantType(requestedGrantType) {
    if (!this.grant_types.includes(requestedGrantType)) {
      OAuthError.throw("UNSUPPORTED_GRANT_TYPE", {
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
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "response_type" é obrigatório.',
      });
    }
    if (receivedResponseType !== expectedResponseType) {
      OAuthError.throw("UNSUPPORTED_RESPONSE_TYPE", {
        detail: `O response_type "${receivedResponseType}" não é suportado para esta operação.`,
      });
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
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "redirect_uri" é obrigatório e inválido.',
      });
    }

    // A especificação OAuth 2.1 exige uma correspondência exata de strings.
    if (!this.redirect_uris.includes(requestedRedirectUri)) {
      OAuthError$1.throw("INVALID_REQUEST", {
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
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: `O code_challenge_method "${method}" não é suportado. Métodos permitidos: [${this.supported_challenge_methods.join(
          ", "
        )}]`,
      });
    }
    if (!challenge || typeof challenge !== "string") {
      OAuthError$1.throw("INVALID_REQUEST", {
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
      OAuthError$1.throw("INVALID_GRANT", {
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
      OAuthError$1.throw("INVALID_GRANT", {
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
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "code_verifier" é obrigatório.',
      });
    }

    const transformedVerifier = this._transformVerifier(verifier, method);

    if (transformedVerifier !== challenge) {
      OAuthError$1.throw("INVALID_GRANT", {
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
    OAuthError$1.throw("SERVER_ERROR", {
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
    OAuthError$1.throw("TODO_ERROR", {
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
    OAuthError$1.throw("TODO_ERROR", {
      detail: "validateCode(): não implementado.",
    });
  }
}

// ==================================================================================================================================================

// ==================================================================================================================================================

/**
 * @class ClientCredentialsFlow
 * @extends AuthFlow
 * @description Implementa o fluxo de concessão "Client Credentials" (RFC 6749, Seção 4.4).
 * Este fluxo é usado para obter um token de acesso fora do contexto de um usuário individual,
 * permitindo que um cliente acesse recursos que ele mesmo controla.
 */
class ClientCredentialsFlow extends AuthFlow {
  // O construtor é herdado diretamente de AuthFlow, não sendo necessário reescrevê-lo.

  /**
   * Orquestra a validação e geração de um token de acesso para o fluxo Client Credentials.
   * @param {object} params - Os parâmetros da requisição.
   * @param {string} [params.scope] - A string de escopos solicitados, separados por espaço (ex: "read:data write:data").
   * @param {object} [params.token_info] - Informações adicionais para serem embutidas no token.
   * @returns {Promise<object>} Uma promessa que resolve com o resultado da geração do token.
   * @throws {OAuthError} Lança um erro apropriado se a validação falhar.
   */
  async getToken({ scope, token_info }) {
    // 1. Valida se o cliente tem permissão para usar este grant type.
    // Note que não há `try/catch` aqui, pois o erro deve se propagar naturalmente.
    this.validateGrantType("client_credentials");

    // 2. Valida os escopos solicitados (se houver) contra os permitidos para o cliente.
    // Nossa `validateScopes` refatorada espera a string de escopo e retorna os escopos concedidos.
    const scopes = this.validateScopes(scope);

    // 3. Delega a geração do token para o método da classe base (ou uma implementação concreta).
    // O `generateToken` receberá apenas os escopos que foram validados e permitidos.
    return this.generateToken({ scopes, token_info });
  }
}

// ==================================================================================================================================================

// ==================================================================================================================================================

/**
 * @class RefreshTokenFlow
 * @extends AuthFlow
 * @description Implementa o fluxo de concessão "Refresh Token" (RFC 6749, Seção 6).
 * Este fluxo é usado para obter um novo token de acesso usando um refresh token,
 * sem a necessidade de re-autenticação do usuário.
 */
class RefreshTokenFlow extends AuthFlow {
  /**
   * Orquestra a validação e geração de um novo token de acesso a partir de um refresh token.
   * @param {object} params - Os parâmetros da requisição.
   * @param {string} params.refresh_token - O refresh token fornecido pelo cliente.
   * @param {string} [params.scope] - A string de escopos (separados por espaço) solicitados para o novo token de acesso.
   * @returns {Promise<object>} Uma promessa que resolve com o novo refresh_token.
   */
  async getToken({ refresh_token, scope, token_info }) {
    // 1. Validações iniciais
    this.validateGrantType("refresh_token");
    if (!refresh_token) {
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "refresh_token" é obrigatório.',
      });
    }

    // 2. Valida o refresh token. Este método deve retornar os dados do token, incluindo os escopos originais.
    const validation_data = await this.validateRefreshToken(refresh_token);

    // 3. Lida com a lógica de escopo de forma segura
    const scopes = this._determineGrantedScopes(
      scope,
      validation_data.scopes
    );

    return await this.generateToken({ validation_data, scopes, token_info });
  }

  // ================================================================================================================================================

  /**
   * Determina os escopos a serem concedidos ao novo token de acesso.
   * @private
   * @param {string} requestedScopeString - A string de escopos solicitada.
   * @param {string[]} originalScopes - Os escopos originalmente associados ao refresh token.
   * @returns {string[]} O array de escopos a serem concedidos.
   */
  _determineGrantedScopes(requestedScopeString, originalScopes) {
    const requestedScopes = this._splitString(requestedScopeString);

    if (requestedScopes.length === 0) {
      // Nenhum escopo solicitado, o novo token herda os escopos originais.
      return originalScopes;
    }

    // Garante que todos os escopos solicitados são um subconjunto dos originais.
    const originalScopesSet = new Set(originalScopes);
    const isSubset = requestedScopes.every((scope) =>
      originalScopesSet.has(scope)
    );

    if (!isSubset) {
      OAuthError$1.throw("INVALID_SCOPE", {
        detail:
          "A requisição inclui escopos não concedidos originalmente ao refresh token.",
      });
    }

    // Se a validação passar, os escopos concedidos são os que foram solicitados.
    return requestedScopes;
  }

  // ================================================================================================================================================

  /**
   * Valida o refresh token fornecido (ex: verifica no DB, checa expiração, revogação).
   * @param {string} refreshTokenString - O refresh token recebido do cliente.
   * @returns {Promise<object>} Uma promessa que resolve com os dados do token (ex: { client_id, user_id, scopes: ['read'] }).
   * @throws {OAuthError} Lança 'INVALID_GRANT' se o token for inválido, expirado ou revogado.
   */
  async validateRefreshToken(refresh_token) {
    // TODO: Implementar a lógica de validação.
    // 1. Buscar o token no banco de dados.
    // 2. Se não encontrado, ou se já foi revogado -> OAuthError.throw('INVALID_GRANT')
    // 3. Verificar se não está expirado. -> OAuthError.throw('INVALID_GRANT')
    // 4. Verificar se o `client_id` associado ao token corresponde ao cliente autenticado. -> OAuthError.throw('INVALID_GRANT')
    // 5. Retornar o payload/dados do token, ex: { id: ..., user_id: ..., scopes: [...] }
    OAuthError$1.throw("TODO_ERROR", {
      detail: "validateRefreshToken(): não implementado.",
    });
  }

  // ================================================================================================================================================

  /**
   * Gera um novo refresh token e o persiste, opcionalmente invalidando o antigo.
   * @param {object} originalTokenData - Os dados do refresh token antigo para manter a linhagem.
   * @returns {Promise<string>} O novo refresh token como uma string.
   */
  async issueNewRefreshToken(validation_data) {
    // TODO: Implementar a lógica de geração e persistência.
    // 1. Gerar uma string aleatória e segura para o novo token.
    // 2. Salvar o novo token no banco de dados com os mesmos `user_id`, `client_id` e escopos do token original.
    // 3. Opcional e recomendado: Marcar o `originalTokenData.id` como revogado/usado no banco.
    // 4. Retornar a string do novo refresh token.
    OAuthError$1.throw("TODO_ERROR", {
      detail: "issueNewRefreshToken(): não implementado.",
    });
  }
}

// ==================================================================================================================================================

// ==================================================================================================================================================

/**
 * @class DeviceCodeFlow
 * @extends AuthFlow
 * @description Implementa o "Device Authorization Grant" (RFC 8628).
 */
class DeviceCodeFlow extends AuthFlow {
  device_code_expires_in;

  constructor(options = {}) {
    if (!options.verification_uri) {
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "verification_uri" é obrigatório.',
      });
    }
    if (!options.verification_uri_complete) {
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "verification_uri_complete" é obrigatório.',
      });
    }

    super(options);
    this.device_code_expires_in = options.device_code_expires_in ?? 1800; // 30 minutos
    this.interval = options.interval ?? 5; // 5 segundos
    this.verification_uri = options.verification_uri;

    // https://example.com/activate?user_code=
    this.verification_uri_complete = options.verification_uri_complete;

    this.user_code_size = options.user_code_size ?? 8; // 8 caracteres

    // Especificação original "urn:ietf:params:oauth:grant-type:device_code"
    this.device_grant_name = options.device_code_grant_name ?? "device_code";
  }

  // ================================================================================================================================================

  // --- Etapa 1: Requisição do Código de Dispositivo ---

  /**
   * Inicia o fluxo, gerando e retornando os códigos para o dispositivo e o usuário.
   * @param {object} params
   * @param {string} [params.scope] - Escopos solicitados.
   * @param {object} [params.device_code_info] - Informações para associar ao device_code (ex: nome do dispositivo).
   * @returns {Promise<object>} Objeto contendo `device_code`, `user_code`, `verification_uri`, `verification_uri_complete` `expires_in`, `interval`.
   */
  async requestDeviceCode({ scope, device_code_info }) {
    const scopes_granted = this.validateScopes(scope);
    const user_code = this._generateUserCode({
      size: this.user_code_size,
      add_chars: "-",
    });
    const interval = this.interval;

    const device_code = await this.generateDeviceCode({
      scopes_granted,
      user_code,
      interval,
      device_code_info,
    });

    return {
      device_code,
      user_code,
      verification_uri: this.verification_uri,
      verification_uri_complete: `${this.verification_uri_complete}${user_code}`,
      expires_in: this.device_code_expires_in,
      interval,
    };
  }

  // ================================================================================================================================================

  /**
   * Gera um código legível para o usuário de forma segura.
   * @private
   */
  _generateUserCode({ size = 8, add_chars = "" }) {
    const chars = "BCDFGHJKLMNPQRSTVWXYZ0123456789" + add_chars; // Caracteres não ambíguos
    let code = "";
    while (size-- > 0) {
      code += chars[randomInt(chars.length)]; // Usa um gerador criptograficamente seguro
    }
    return code;
  }

  // ================================================================================================================================================

  // --- Etapa 2: Polling do Token ---

  /**
   * Troca um device_code por um token de acesso, após aprovação do usuário.
   * @param {object} params
   * @param {string} params.device_code - O código de dispositivo.
   * @param {object} [params.token_info] - Informações adicionais para o token.
   * @returns {Promise<object>} O resultado da geração do token.
   */
  async getToken({ device_code, token_info }) {
    this.validateGrantType(this.device_grant_name);
    if (!device_code) {
      OAuthError$1.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "device_code" é obrigatório.',
      });
    }

    // `validateDeviceCode` agora pode lançar erros de polling, que devem ser tratados.
    const validation_data = await this.validateDeviceCode(device_code);

    // Se a validação for bem-sucedida, `validation_data` contém os dados necessários.
    return this.generateToken({ validation_data, token_info });
  }

  // ================================================================================================================================================

  // --- Stubs para Implementação ---

  /**
   * Gera e persiste um novo device_code.
   * @returns {Promise<string>} O device_code gerado.
   */
  async generateDeviceCode({
    scopes_granted,
    user_code,
    interval,
    device_code_info,
  }) {
    // TODO: Implementar a lógica de geração e persistência.
    // 1. Gerar uma string de `device_code` aleatória, única e segura.
    // 2. Salvar em um banco de dados (com TTL) associando:
    //    - device_code, user_code, this.client_id, scopes_granted, interval
    //    - um status inicial (ex: 'pending')
    //    - um timestamp de expiração
    // 3. Retornar a string do `device_code`.
    OAuthError$1.throw("TODO_ERROR", {
      detail: "generateDeviceCode(): não implementado.",
    });
    return "fake-device-code"; // Placeholder
  }

  // ================================================================================================================================================

  /**
   * Valida um device_code durante o polling.
   * @param {string} deviceCode - O código a ser validado.
   * @returns {Promise<object>} Os dados associados ao código se a autorização foi concedida.
   * @throws {OAuthError} Lança erros de polling (`AUTHORIZATION_PENDING`, `SLOW_DOWN`, `EXPIRED_TOKEN`) ou `INVALID_GRANT`.
   */
  async validateDeviceCode(deviceCode) {
    // TODO: Implementar a lógica de validação.
    // 1. Buscar o `deviceCode` no banco. Se não existir -> OAuthError.throw('INVALID_GRANT')
    // 2. Verificar se o `deviceCode` não expirou. Se sim -> OAuthError.throw('EXPIRED_TOKEN')
    // 3. Verificar o status:
    //    - Se o status for 'pending' -> OAuthError.throw('AUTHORIZATION_PENDING')
    //    - Se o status for 'denied' -> OAuthError.throw('ACCESS_DENIED')
    //    - Se o status for 'approved':
    //      a. Recuperar `user_id`, `scopes`, etc.
    //      b. Opcional: Marcar o código como usado/concluído.
    //      c. Retornar os dados: { user_id, scopes, ... }
    // 4. (Opcional) Implementar a lógica de `slow_down` se o dispositivo estiver fazendo polling muito rápido.
    OAuthError$1.throw("TODO_ERROR", {
      detail: "validateDeviceCode(): não implementado.",
    });
  }
}

// ==================================================================================================================================================

export { AuthFlow, AuthorizationCodeFlow, ClientCredentialsFlow, DeviceCodeFlow, ERROR_SPECS, OAuthError$1 as OAuthError, RefreshTokenFlow };
