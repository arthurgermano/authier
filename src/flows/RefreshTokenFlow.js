import { OAuthError } from "../errors/index.js";
import AuthFlow from "./AuthFlow.js";

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
      OAuthError.throw("INVALID_REQUEST", {
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
      OAuthError.throw("INVALID_SCOPE", {
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
    OAuthError.throw("TODO_ERROR", {
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
    OAuthError.throw("TODO_ERROR", {
      detail: "issueNewRefreshToken(): não implementado.",
    });
  }
}

// ==================================================================================================================================================

export default RefreshTokenFlow;

// ==================================================================================================================================================
