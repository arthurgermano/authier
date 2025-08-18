/**
 * @file Módulo centralizado para gerenciamento de erros do OAuth 2.0.
 * @see {@link https://datatracker.ietf.org/doc/html/rfc6749#section-5.2} para erros padrão.
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
  }

  /**
   * Converte a instância do erro para um objeto JSON simples,
   * mantendo a compatibilidade com o formato de resposta esperado.
   * @returns {{error: string, error_description: string, status: number}}
   */
  toResponseObject() {
    return {
      error: this.error,
      error_description: this.error_description,
      status: this.status,
    };
  }

  /**
   * Factory method para criar e lançar uma instância de OAuthError.
   * @param {keyof typeof ERROR_SPECS} errorType - O tipo do erro (ex: 'INVALID_CLIENT').
   * @param {any} [more_info] - Informações adicionais para depuração.
   */
  static throw(errorType, more_info) {
    const spec = ERROR_SPECS[errorType];
    if (!spec) {
      // Fallback para um erro de servidor caso um tipo de erro inválido seja passado.
      const serverErrorSpec = ERROR_SPECS.SERVER_ERROR;
      throw new OAuthError(
        serverErrorSpec,
        `Tipo de erro desconhecido: ${errorType}`
      );
    }
    throw new OAuthError(spec, more_info);
  }
}

// ==================================================================================================================================================

// Exporta a classe e o objeto de especificações para uso no seu projeto.
export {
  OAuthError,
  ERROR_SPECS,
};

// ==================================================================================================================================================
