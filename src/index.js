/**
 * @file Ponto de entrada principal da biblioteca Authier.
 * @author Arthur José Germano
 * @license MIT
 * @description Este arquivo exporta todas as classes e utilitários públicos
 * que compõem a interface da biblioteca, permitindo aos usuários
 * construir implementações de servidor OAuth 2.1.
 * * @module authier
 */

// --- Manuseio de Erros ---

/**
 * Classe de erro customizada para todas as falhas relacionadas ao OAuth 2.0/2.1,
 * permitindo um tratamento de erro robusto e padronizado.
 * @public
 */
export { OAuthError } from './errors/index.js';


// --- Classes de Fluxo Base ---

/**
 * A classe pai abstrata que contém a configuração e a lógica comum
 * a todos os fluxos de autorização. Deve ser estendida, não instanciada diretamente.
 * @public
 */
export { default as AuthFlow } from './flows/AuthFlow.js';

/**
 * Implementa a lógica abstrata do fluxo "Authorization Code with PKCE" (RFC 6749, RFC 7636).
 * É o fluxo mais seguro e recomendado para aplicações com interação do usuário.
 * @public
 */
export { default as AuthorizationCodeFlow } from './flows/AuthorizationCodeFlow.js';

/**
 * Implementa a lógica abstrata do fluxo "Client Credentials" (RFC 6749, Seção 4.4).
 * Ideal para comunicação máquina-a-máquina (M2M).
 * @public
 */
export { default as ClientCredentialsFlow } from './flows/ClientCredentialsFlow.js';

/**
 * Implementa a lógica abstrata do fluxo "Refresh Token" (RFC 6749, Seção 6).
 * Permite que os clientes obtenham novos tokens de acesso sem re-autenticação do usuário.
 * @public
 */
export { default as RefreshTokenFlow } from './flows/RefreshTokenFlow.js';

/**
 * Implementa a lógica abstrata do "Device Authorization Grant" (RFC 8628).
 * Projetado para dispositivos com capacidade de entrada limitada, como Smart TVs.
 * @public
 */
export { default as DeviceCodeFlow } from './flows/DeviceCodeFlow.js';