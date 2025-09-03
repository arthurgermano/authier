import { OAuthError } from "../errors/index.js";
import { randomInt } from "crypto";
import AuthFlow from "./AuthFlow.js";

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
      OAuthError.throw("INVALID_REQUEST", {
        detail: 'O parâmetro "verification_uri" é obrigatório.',
      });
    }
    if (!options.verification_uri_complete) {
      OAuthError.throw("INVALID_REQUEST", {
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
      OAuthError.throw("INVALID_REQUEST", {
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
    OAuthError.throw("TODO_ERROR", {
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
    OAuthError.throw("TODO_ERROR", {
      detail: "validateDeviceCode(): não implementado.",
    });
  }
}

// ==================================================================================================================================================

export default DeviceCodeFlow;

// ==================================================================================================================================================
