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
class OAuthError extends Error {
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
}

// ==================================================================================================================================================

/**
 * Middleware helper para tratamento de erros OAuth em Express.js
 * @param {Error} err - Erro capturado
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @param {function} next - Next middleware function
 */
function oauthErrorHandler(err, req, res, next) {
  if (err instanceof OAuthError) {
    const response = err.toHttpResponse();
    return res
      .status(response.status)
      .set(response.headers)
      .json(response.body);
  }

  // Se não for OAuthError, passa para o próximo handler
  next(err);
}

// ==================================================================================================================================================

// Exporta a classe, especificações e helpers
export { OAuthError, ERROR_SPECS, oauthErrorHandler };

// ==================================================================================================================================================
