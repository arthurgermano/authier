var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/errors/index.js
var errors_exports = {};
__export(errors_exports, {
  ERROR_SPECS: () => ERROR_SPECS,
  OAuthError: () => OAuthError,
  oauthErrorHandler: () => oauthErrorHandler
});
function oauthErrorHandler(err, req, res, next) {
  if (err instanceof OAuthError) {
    const response = err.toHttpResponse();
    return res.status(response.status).set(response.headers).json(response.body);
  }
  next(err);
}
var ERROR_SPECS, OAuthError;
var init_errors = __esm({
  "src/errors/index.js"() {
    ERROR_SPECS = {
      // --- Erros Padrão (RFC 6749) ---
      ACCESS_DENIED: {
        code: "access_denied",
        description: "O propriet\xE1rio do recurso ou o servidor de autoriza\xE7\xE3o negou a solicita\xE7\xE3o.",
        status: 403
        // A RFC não especifica, mas 403 (Forbidden) é semanticamente mais correto que 400.
      },
      INVALID_CLIENT: {
        code: "invalid_client",
        description: "A autentica\xE7\xE3o do cliente falhou (ex: cliente desconhecido, sem autentica\xE7\xE3o inclu\xEDda ou m\xE9todo n\xE3o suportado).",
        status: 401
      },
      INVALID_GRANT: {
        code: "invalid_grant",
        description: "A concess\xE3o de autoriza\xE7\xE3o (ex: c\xF3digo de autoriza\xE7\xE3o, credenciais) ou o refresh token \xE9 inv\xE1lido, expirado, revogado ou foi emitido para outro cliente.",
        status: 400
      },
      INVALID_REQUEST: {
        code: "invalid_request",
        description: "A requisi\xE7\xE3o est\xE1 faltando um par\xE2metro obrigat\xF3rio, inclui um valor de par\xE2metro n\xE3o suportado, repete um par\xE2metro ou est\xE1 malformada.",
        status: 400
      },
      INVALID_SCOPE: {
        code: "invalid_scope",
        description: "O escopo solicitado \xE9 inv\xE1lido, desconhecido, malformado ou excede o escopo concedido.",
        status: 400
      },
      SERVER_ERROR: {
        code: "server_error",
        description: "O servidor de autoriza\xE7\xE3o encontrou uma condi\xE7\xE3o inesperada que o impediu de atender \xE0 solicita\xE7\xE3o.",
        status: 500
      },
      TEMPORARILY_UNAVAILABLE: {
        code: "temporarily_unavailable",
        description: "O servidor de autoriza\xE7\xE3o est\xE1 temporariamente indispon\xEDvel devido a sobrecarga ou manuten\xE7\xE3o.",
        status: 503
      },
      UNSUPPORTED_GRANT_TYPE: {
        code: "unsupported_grant_type",
        description: "O tipo de concess\xE3o de autoriza\xE7\xE3o n\xE3o \xE9 suportado pelo servidor.",
        status: 400
      },
      UNSUPPORTED_RESPONSE_TYPE: {
        code: "unsupported_response_type",
        description: "O servidor de autoriza\xE7\xE3o n\xE3o suporta a obten\xE7\xE3o de um c\xF3digo de autoriza\xE7\xE3o usando este m\xE9todo.",
        status: 400
      },
      // --- Erros Específicos (RFC 8628 - Device Flow) ---
      AUTHORIZATION_PENDING: {
        code: "authorization_pending",
        description: "A autoriza\xE7\xE3o do usu\xE1rio est\xE1 pendente. O cliente deve continuar o polling.",
        status: 400
      },
      SLOW_DOWN: {
        code: "slow_down",
        description: "O cliente est\xE1 fazendo o polling com muita frequ\xEAncia. A frequ\xEAncia deve ser reduzida.",
        status: 400
      },
      EXPIRED_TOKEN: {
        // 'token' aqui se refere ao device_code
        code: "expired_token",
        description: "O device_code expirou e o fluxo de autoriza\xE7\xE3o deve ser reiniciado.",
        status: 400
      },
      // --- Erros Adicionais Úteis ---
      INVALID_TOKEN: {
        code: "invalid_token",
        description: "O token de acesso fornecido \xE9 inv\xE1lido, malformado, expirado ou foi revogado.",
        status: 401
      },
      INSUFFICIENT_SCOPE: {
        code: "insufficient_scope",
        description: "O token de acesso n\xE3o possui os escopos necess\xE1rios para acessar o recurso solicitado.",
        status: 403
      },
      UNAUTHORIZED_CLIENT: {
        code: "unauthorized_client",
        description: "O cliente n\xE3o est\xE1 autorizado a usar este m\xE9todo de concess\xE3o de autoriza\xE7\xE3o.",
        status: 400
      },
      INVALID_REDIRECT_URI: {
        code: "invalid_redirect_uri",
        description: "A URI de redirecionamento fornecida n\xE3o \xE9 v\xE1lida ou n\xE3o corresponde \xE0s URIs pr\xE9-registradas.",
        status: 400
      },
      UNSUPPORTED_TOKEN_TYPE: {
        code: "unsupported_token_type",
        description: "O servidor de autoriza\xE7\xE3o n\xE3o suporta a revoga\xE7\xE3o do tipo de token apresentado.",
        status: 400
      },
      // --- Erros Relacionados a Rate Limiting ---
      TOO_MANY_REQUESTS: {
        code: "too_many_requests",
        description: "O cliente excedeu o limite de taxa de requisi\xE7\xF5es. Tente novamente mais tarde.",
        status: 429
      },
      // --- Erros Relacionados a PKCE (RFC 7636) ---
      INVALID_CODE_CHALLENGE: {
        code: "invalid_request",
        // PKCE usa invalid_request para challenges inválidos
        description: "O code_challenge fornecido \xE9 inv\xE1lido, malformado ou usa um m\xE9todo n\xE3o suportado.",
        status: 400
      },
      INVALID_CODE_VERIFIER: {
        code: "invalid_grant",
        // PKCE usa invalid_grant para verifiers inválidos
        description: "O code_verifier fornecido n\xE3o corresponde ao code_challenge da requisi\xE7\xE3o de autoriza\xE7\xE3o.",
        status: 400
      },
      // --- Erros de Configuração e Estado ---
      CONFIGURATION_ERROR: {
        code: "server_error",
        description: "Erro na configura\xE7\xE3o do servidor de autoriza\xE7\xE3o. Contate o administrador.",
        status: 500
      },
      SERVICE_UNAVAILABLE: {
        code: "temporarily_unavailable",
        description: "O servi\xE7o de autoriza\xE7\xE3o est\xE1 temporariamente indispon\xEDvel para manuten\xE7\xE3o.",
        status: 503
      },
      // --- Erros Customizados (Específicos da sua aplicação) ---
      MISMATCH_CLIENT: {
        code: "mismatch_client",
        description: "A autentica\xE7\xE3o do cliente falhou - cliente n\xE3o corresponde.",
        status: 400
      },
      TODO_ERROR: {
        code: "todo_error",
        description: "A funcionalidade solicitada ainda n\xE3o foi implementada.",
        status: 501
        // 501 Not Implemented é semanticamente mais adequado.
      },
      // --- Erros de Validação de Dados ---
      MALFORMED_REQUEST: {
        code: "invalid_request",
        description: "A requisi\xE7\xE3o cont\xE9m dados malformados ou n\xE3o pode ser processada.",
        status: 400
      },
      MISSING_PARAMETER: {
        code: "invalid_request",
        description: "Um par\xE2metro obrigat\xF3rio est\xE1 ausente da requisi\xE7\xE3o.",
        status: 400
      },
      DUPLICATE_PARAMETER: {
        code: "invalid_request",
        description: "A requisi\xE7\xE3o cont\xE9m par\xE2metros duplicados que devem ser \xFAnicos.",
        status: 400
      },
      // --- Erros de Segurança ---
      REPLAY_ATTACK: {
        code: "invalid_grant",
        description: "Tentativa de reutiliza\xE7\xE3o de uma concess\xE3o de uso \xFAnico detectada.",
        status: 400
      },
      SUSPICIOUS_ACTIVITY: {
        code: "access_denied",
        description: "Atividade suspeita detectada. A requisi\xE7\xE3o foi negada por motivos de seguran\xE7a.",
        status: 403
      }
    };
    OAuthError = class _OAuthError extends Error {
      constructor(spec, more_info) {
        super(spec.description);
        this.name = "OAuthError";
        this.error = spec.code;
        this.error_description = spec.description;
        this.status = spec.status;
        if (more_info) {
          this.more_info = more_info;
        }
        if (Error.captureStackTrace) {
          Error.captureStackTrace(this, _OAuthError);
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
          status: this.status
        };
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
            Pragma: "no-cache"
          },
          body: this.toResponseObject()
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
          "too_many_requests"
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
          const serverErrorSpec = ERROR_SPECS.SERVER_ERROR;
          throw new _OAuthError(serverErrorSpec, {
            originalErrorType: errorType,
            message: `Tipo de erro desconhecido: ${errorType}`,
            ...more_info
          });
        }
        throw new _OAuthError(spec, more_info);
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
          return new _OAuthError(serverErrorSpec, {
            originalErrorType: errorType,
            message: `Tipo de erro desconhecido: ${errorType}`,
            ...more_info
          });
        }
        return new _OAuthError(spec, more_info);
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
        return Object.values(ERROR_SPECS).find((spec) => spec.code === errorCode) || null;
      }
    };
  }
});

// src/index.js
var index_exports = {};
__export(index_exports, {
  AuthFlow: () => AuthFlow_default,
  AuthorizationCodeFlow: () => AuthorizationCodeFlow_default,
  ClientCredentialsFlow: () => ClientCredentialsFlow_default,
  DeviceCodeFlow: () => DeviceCodeFlow_default,
  ERROR_SPECS: () => ERROR_SPECS,
  OAuthError: () => OAuthError,
  RefreshTokenFlow: () => RefreshTokenFlow_default
});
module.exports = __toCommonJS(index_exports);
init_errors();

// src/flows/AuthFlow.js
var { OAuthError: OAuthError2 } = (init_errors(), __toCommonJS(errors_exports));
var AuthFlow = class {
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
    if (!options.client_id) {
      throw new Error(
        "AuthFlowError: N\xE3o \xE9 poss\xEDvel instanciar um fluxo sem um 'client_id'."
      );
    }
    this.id = options.id ?? null;
    this.client_id = options.client_id;
    this.client_secret = options.client_secret ?? null;
    this.issues_refresh_token = options.issues_refresh_token ?? true;
    this.redirect_uri_required = options.redirect_uri_required ?? true;
    this.scopes_required = options.scopes_required ?? false;
    this.state_required = options.state_required ?? true;
    this.refresh_token_expires_in = options.refresh_token_expires_in ?? 7200;
    this.token_expires_in = options.token_expires_in ?? 3600;
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
    const requestedScopes = this._splitString(requestedScopeString);
    if (requestedScopes.length === 0) {
      if (this.scopes_required) {
        OAuthError2.throw("INVALID_SCOPE", {
          detail: 'O par\xE2metro "scope" \xE9 obrigat\xF3rio para este cliente, mas n\xE3o foi fornecido.'
        });
      }
      return [];
    }
    if (this.scopes.length === 0) {
      OAuthError2.throw("INVALID_SCOPE", {
        detail: "O cliente solicitou escopos, mas n\xE3o tem nenhum escopo registrado para conceder."
      });
    }
    const allowedScopesSet = new Set(this.scopes);
    const grantedScopes = [];
    for (const scope of requestedScopes) {
      if (allowedScopesSet.has(scope)) {
        grantedScopes.push(scope);
      } else if (this.match_all_scopes) {
        OAuthError2.throw("INVALID_SCOPE", {
          detail: `O escopo "${scope}" n\xE3o \xE9 permitido para este cliente.`
        });
      }
    }
    if (grantedScopes.length === 0) {
      OAuthError2.throw("INVALID_SCOPE", {
        detail: "Nenhum dos escopos solicitados \xE9 v\xE1lido para este cliente."
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
      OAuthError2.throw("UNSUPPORTED_GRANT_TYPE", {
        detail: `O grant_type "${requestedGrantType}" n\xE3o \xE9 suportado por este cliente.`
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
      OAuthError2.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "response_type" \xE9 obrigat\xF3rio.'
      });
    }
    if (receivedResponseType !== expectedResponseType) {
      OAuthError2.throw("UNSUPPORTED_RESPONSE_TYPE", {
        detail: `O response_type "${receivedResponseType}" n\xE3o \xE9 suportado para esta opera\xE7\xE3o.`
      });
    }
    return true;
  }
  // ================================================================================================================================================
  // --- Funções de Interface (a serem implementadas pelas classes filhas) ---
  async generateToken(validation_data, token_info) {
    OAuthError2.throw("TODO_ERROR", {
      detail: "generateToken(): n\xE3o implementado na classe base."
    });
  }
  async validateToken(token_info) {
    OAuthError2.throw("TODO_ERROR", {
      detail: "validateToken(): n\xE3o implementado na classe base."
    });
  }
  async getToken(params) {
    OAuthError2.throw("TODO_ERROR", {
      detail: "getToken(): n\xE3o implementado na classe base."
    });
  }
};
var AuthFlow_default = AuthFlow;

// src/flows/AuthorizationCodeFlow.js
init_errors();
var import_crypto = require("crypto");
var AuthorizationCodeFlow = class extends AuthFlow_default {
  code_expires_in;
  pkce_required;
  supported_challenge_methods;
  /**
   * @constructor
   */
  constructor(options = {}) {
    super(options);
    this.code_expires_in = options.code_expires_in ?? 300;
    this.pkce_required = options.pkce_required ?? true;
    this.supported_challenge_methods = ["S256"];
    if (options.allow_plain_pkce_method === true) {
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
        detail: 'O par\xE2metro "redirect_uri" \xE9 obrigat\xF3rio e inv\xE1lido.'
      });
    }
    if (!this.redirect_uris.includes(requestedRedirectUri)) {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'A "redirect_uri" fornecida n\xE3o est\xE1 na lista de URIs permitidas para este cliente.'
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
    code_info
  }) {
    AuthFlow_default.validateResponseType(response_type, "code");
    this.validateRedirectUri(redirect_uri);
    const scopes_granted = this.validateScopes(scope);
    if (this.pkce_required) {
      this._validatePkceParameters(code_challenge, code_challenge_method);
    }
    return this.generateCode({
      scopes_granted,
      code_info,
      redirect_uri,
      code_challenge,
      code_challenge_method
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
        detail: `O code_challenge_method "${method}" n\xE3o \xE9 suportado. M\xE9todos permitidos: [${this.supported_challenge_methods.join(
          ", "
        )}]`
      });
    }
    if (!challenge || typeof challenge !== "string") {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "code_challenge" \xE9 obrigat\xF3rio e deve ser uma string quando PKCE \xE9 exigido.'
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
    const validation_data = await this.validateCode(code);
    if (validation_data.redirect_uri !== redirect_uri) {
      OAuthError.throw("INVALID_GRANT", {
        detail: 'A "redirect_uri" n\xE3o corresponde \xE0 usada na requisi\xE7\xE3o de autoriza\xE7\xE3o.'
      });
    }
    if (validation_data.code_challenge) {
      this._validateCodeVerifier(
        code_verifier,
        validation_data.code_challenge,
        validation_data.code_challenge_method
      );
    } else if (this.pkce_required) {
      OAuthError.throw("INVALID_GRANT", {
        detail: 'O "code_challenge" era obrigat\xF3rio para este cliente, mas n\xE3o foi fornecido na requisi\xE7\xE3o de autoriza\xE7\xE3o.'
      });
    }
    return this.generateToken({ validation_data, token_info });
  }
  // ================================================================================================================================================
  /**
   * Valida o code_verifier contra o code_challenge armazenado.
   * @private
   */
  _validateCodeVerifier(verifier, challenge, method) {
    if (!verifier || typeof verifier !== "string") {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "code_verifier" \xE9 obrigat\xF3rio.'
      });
    }
    const transformedVerifier = this._transformVerifier(verifier, method);
    if (transformedVerifier !== challenge) {
      OAuthError.throw("INVALID_GRANT", {
        detail: 'O "code_verifier" \xE9 inv\xE1lido.'
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
      return (0, import_crypto.createHash)("sha256").update(verifier).digest("base64url");
    }
    OAuthError.throw("SERVER_ERROR", {
      detail: `M\xE9todo de desafio desconhecido encontrado durante a valida\xE7\xE3o do verificador: ${method}`
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
    code_challenge_method
  }) {
    OAuthError.throw("TODO_ERROR", {
      detail: "generateCode(): n\xE3o implementado."
    });
  }
  // ================================================================================================================================================
  /**
   * Valida um código de autorização e o marca como usado.
   * @param {string} code - O código a ser validado.
   * @returns {Promise<object>} Os dados associados ao código.
   */
  async validateCode(code) {
    OAuthError.throw("TODO_ERROR", {
      detail: "validateCode(): n\xE3o implementado."
    });
  }
};
var AuthorizationCodeFlow_default = AuthorizationCodeFlow;

// src/flows/ClientCredentialsFlow.js
init_errors();
var ClientCredentialsFlow = class extends AuthFlow_default {
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
    this.validateGrantType("client_credentials");
    const scopes = this.validateScopes(scope);
    return this.generateToken({ scopes, token_info });
  }
};
var ClientCredentialsFlow_default = ClientCredentialsFlow;

// src/flows/RefreshTokenFlow.js
init_errors();
var RefreshTokenFlow = class extends AuthFlow_default {
  /**
   * Orquestra a validação e geração de um novo token de acesso a partir de um refresh token.
   * @param {object} params - Os parâmetros da requisição.
   * @param {string} params.refresh_token - O refresh token fornecido pelo cliente.
   * @param {string} [params.scope] - A string de escopos (separados por espaço) solicitados para o novo token de acesso.
   * @returns {Promise<object>} Uma promessa que resolve com o novo refresh_token.
   */
  async getToken({ refresh_token, scope, token_info }) {
    this.validateGrantType("refresh_token");
    if (!refresh_token) {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "refresh_token" \xE9 obrigat\xF3rio.'
      });
    }
    const validation_data = await this.validateRefreshToken(refresh_token);
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
      return originalScopes;
    }
    const originalScopesSet = new Set(originalScopes);
    const isSubset = requestedScopes.every(
      (scope) => originalScopesSet.has(scope)
    );
    if (!isSubset) {
      OAuthError.throw("INVALID_SCOPE", {
        detail: "A requisi\xE7\xE3o inclui escopos n\xE3o concedidos originalmente ao refresh token."
      });
    }
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
    OAuthError.throw("TODO_ERROR", {
      detail: "validateRefreshToken(): n\xE3o implementado."
    });
  }
  // ================================================================================================================================================
  /**
   * Gera um novo refresh token e o persiste, opcionalmente invalidando o antigo.
   * @param {object} originalTokenData - Os dados do refresh token antigo para manter a linhagem.
   * @returns {Promise<string>} O novo refresh token como uma string.
   */
  async issueNewRefreshToken(validation_data) {
    OAuthError.throw("TODO_ERROR", {
      detail: "issueNewRefreshToken(): n\xE3o implementado."
    });
  }
};
var RefreshTokenFlow_default = RefreshTokenFlow;

// src/flows/DeviceCodeFlow.js
init_errors();
var import_crypto2 = require("crypto");
var DeviceCodeFlow = class extends AuthFlow_default {
  device_code_expires_in;
  constructor(options = {}) {
    if (!options.verification_uri) {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "verification_uri" \xE9 obrigat\xF3rio.'
      });
    }
    if (!options.verification_uri_complete) {
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "verification_uri_complete" \xE9 obrigat\xF3rio.'
      });
    }
    super(options);
    this.device_code_expires_in = options.device_code_expires_in ?? 1800;
    this.interval = options.interval ?? 5;
    this.verification_uri = options.verification_uri;
    this.verification_uri_complete = options.verification_uri_complete;
    this.user_code_size = options.user_code_size ?? 8;
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
      add_chars: "-"
    });
    const interval = this.interval;
    const device_code = await this.generateDeviceCode({
      scopes_granted,
      user_code,
      interval,
      device_code_info
    });
    return {
      device_code,
      user_code,
      verification_uri: this.verification_uri,
      verification_uri_complete: `${this.verification_uri_complete}${user_code}`,
      expires_in: this.device_code_expires_in,
      interval
    };
  }
  // ================================================================================================================================================
  /**
   * Gera um código legível para o usuário de forma segura.
   * @private
   */
  _generateUserCode({ size = 8, add_chars = "" }) {
    const chars = "BCDFGHJKLMNPQRSTVWXYZ0123456789" + add_chars;
    let code = "";
    while (size-- > 0) {
      code += chars[(0, import_crypto2.randomInt)(chars.length)];
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
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O par\xE2metro "device_code" \xE9 obrigat\xF3rio.'
      });
    }
    const validation_data = await this.validateDeviceCode(device_code);
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
    device_code_info
  }) {
    OAuthError.throw("TODO_ERROR", {
      detail: "generateDeviceCode(): n\xE3o implementado."
    });
    return "fake-device-code";
  }
  // ================================================================================================================================================
  /**
   * Valida um device_code durante o polling.
   * @param {string} deviceCode - O código a ser validado.
   * @returns {Promise<object>} Os dados associados ao código se a autorização foi concedida.
   * @throws {OAuthError} Lança erros de polling (`AUTHORIZATION_PENDING`, `SLOW_DOWN`, `EXPIRED_TOKEN`) ou `INVALID_GRANT`.
   */
  async validateDeviceCode(deviceCode) {
    OAuthError.throw("TODO_ERROR", {
      detail: "validateDeviceCode(): n\xE3o implementado."
    });
  }
};
var DeviceCodeFlow_default = DeviceCodeFlow;
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthFlow,
  AuthorizationCodeFlow,
  ClientCredentialsFlow,
  DeviceCodeFlow,
  ERROR_SPECS,
  OAuthError,
  RefreshTokenFlow
});
/**
 * @file Ponto de entrada principal da biblioteca Authier.
 * @author Arthur José Germano
 * @license MIT
 * @description Este arquivo exporta todas as classes e utilitários públicos
 * que compõem a interface da biblioteca, permitindo aos usuários
 * construir implementações de servidor OAuth 2.1.
 * * @module authier
 */
