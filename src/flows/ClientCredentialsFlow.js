import { OAuthError } from "../errors/index.js";
import AuthFlow from "./AuthFlow.js";

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

export default ClientCredentialsFlow;

// ==================================================================================================================================================
