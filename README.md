# Authier

[![NPM Version](https://img.shields.io/npm/v/authier.svg)](https://www.npmjs.com/package/authier)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Authier** é uma biblioteca leve, segura e moderna para construir servidores de autorização **OAuth 2.1** em Node.js. Ela foi projetada para ser extensível e não opinativa sobre sua camada de persistência, permitindo que você se concentre na lógica de negócios enquanto a biblioteca cuida da conformidade e segurança do fluxo OAuth.

## Índice

- [Authier](#authier)
  - [Índice](#índice)
  - [Filosofia e Recursos](#filosofia-e-recursos)
  - [Instalação](#instalação)
  - [Começando: Um Exemplo Rápido](#começando-um-exemplo-rápido)
  - [A Classe Base `AuthFlow`](#a-classe-base-authflow)
    - [Opções de Configuração Comuns](#opções-de-configuração-comuns)
    - [Métodos Utilitários](#métodos-utilitários)
  - [Implementando os Fluxos OAuth 2.1](#implementando-os-fluxos-oauth-21)
    - [1. Authorization Code Flow](#1-authorization-code-flow)
    - [2. Client Credentials Flow](#2-client-credentials-flow)
    - [3. Refresh Token Flow](#3-refresh-token-flow)
    - [4. Device Code Flow](#4-device-code-flow)
  - [Tratamento de Erros](#tratamento-de-erros)
  - [Testando](#testando)
  - [Licença](#licença)

---

## Filosofia e Recursos

A `authier` foi construída com os seguintes princípios em mente:

-   ✅ **Segurança em Primeiro Lugar**: Implementa as melhores práticas de segurança do OAuth 2.1, como **PKCE (Proof Key for Code Exchange)** obrigatório por padrão, correspondência exata de `redirect_uri` e prevenção de ataques de repetição.
-   🚀 **Foco no OAuth 2.1**: Abandona fluxos legados e inseguros (como o *Resource Owner Password Credentials*) em favor dos fluxos recomendados pela especificação mais recente.
-   🧩 **Arquitetura Extensível**: Você estende as classes de fluxo e implementa a lógica de persistência (com seu banco de dados, Redis, etc.). Isso desacopla a lógica do OAuth do seu armazenamento de dados.
-   🕊️ **Leve e Sem Dependências**: Nenhuma dependência de produção. Você traz sua própria biblioteca de JWT ou o que preferir para gerar tokens.

---

## Instalação

```bash
npm install authier
```

Você também precisará de uma biblioteca para gerar e validar JWTs, como `jsonwebtoken`.

```bash
npm install jsonwebtoken
```

---

## Começando: Um Exemplo Rápido

A melhor maneira de entender a `authier` é ver como ela funciona. O padrão principal é: **estender a classe do fluxo e implementar os métodos de persistência**.

Aqui está um exemplo completo usando o `AuthorizationCodeFlow` com um "banco de dados" em memória.

```javascript
// myAuthServer.js
import { AuthorizationCodeFlow, OAuthError } from 'authier';
import { randomBytes } from 'crypto';
import jwt from 'jsonwebtoken'; // Exemplo usando jsonwebtoken

// 1. Defina os dados do seu cliente (isso viria do seu banco de dados)
const clientData = {
  client_id: 'my-app-client-id',
  grant_types: 'authorization_code refresh_token',
  redirect_uris: 'https://meuapp.com/callback',
  scopes: 'read:profile write:data',
  pkce_required: true, // Padrão já é true
};

// Simulação de um banco de dados em memória para códigos
const codeDatabase = new Map();
const usedCodes = new Set();

// 2. Estenda a classe do fluxo desejado
class MyAuthorizationCodeFlow extends AuthorizationCodeFlow {

  // 3. Implemente os métodos de persistência obrigatórios

  async generateCode({ scopes_granted, code_info, redirect_uri, code_challenge, code_challenge_method }) {
    const code = randomBytes(32).toString('hex');
    const expires_at = Date.now() + (this.code_expires_in * 1000);

    console.log(`Gerando código ${code} para o cliente ${this.client_id}`);
    codeDatabase.set(code, {
      client_id: this.client_id,
      scopes_granted,
      user_id: code_info.user_id, // Ex: ID do usuário logado
      redirect_uri,
      code_challenge,
      code_challenge_method,
      expires_at,
    });

    return code;
  }

  async validateCode(code) {
    if (usedCodes.has(code)) {
      OAuthError.throw('INVALID_GRANT', { detail: 'Código já utilizado.' });
    }

    const stored = codeDatabase.get(code);
    if (!stored) {
      OAuthError.throw('INVALID_GRANT', { detail: 'Código inválido.' });
    }
    if (Date.now() > stored.expires_at) {
      codeDatabase.delete(code);
      OAuthError.throw('INVALID_GRANT', { detail: 'Código expirado.' });
    }

    // O código deve ser de uso único
    usedCodes.add(code);
    codeDatabase.delete(code);

    return stored;
  }

  async generateToken({ validation_data, token_info = {} }) {
    const payload = {
      iss: 'https://meu-auth-server.com',
      sub: validation_data.user_id,
      client_id: this.client_id,
      scope: validation_data.scopes_granted.join(' '),
      ...token_info,
    };
    // Use sua chave privada para assinar o token
    return jwt.sign(payload, 'SEU_SEGREDO_PRIVADO', {
      algorithm: 'HS256',
      expiresIn: this.token_expires_in,
    });
  }
}

// 4. Use sua classe nos seus endpoints (ex: com Express.js)

const flow = new MyAuthorizationCodeFlow(clientData);

// Em uma rota de autorização:
// const code = await flow.getCode({
//   response_type: 'code',
//   redirect_uri: 'https://meuapp.com/callback',
//   scope: 'read:profile',
//   code_challenge: '...',
//   code_challenge_method: 'S256',
//   code_info: { user_id: 'user-123' }
// });

// Em uma rota de token:
// const token = await flow.getToken({
//   code: '...',
//   redirect_uri: 'https://meuapp.com/callback',
//   code_verifier: '...'
// });
```

---

## A Classe Base `AuthFlow`

`AuthFlow` é a classe base da qual todos os outros fluxos herdam. Ela contém a lógica e as configurações comuns a todos os clientes.

### Opções de Configuração Comuns

Estas opções são passadas no construtor de qualquer classe de fluxo:

| Opção                      | Tipo      | Padrão                               | Descrição                                                                                             |
| -------------------------- | --------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `client_id`                | `string`  | **Obrigatório**                      | O identificador único do cliente.                                                                     |
| `client_secret`            | `string`  | `null`                               | O segredo do cliente, usado para autenticação de clientes confidenciais.                              |
| `grant_types`              | `string`  | `[]`                                 | String com os `grant_types` permitidos para o cliente, separados por espaço (ex: "authorization_code"). |
| `scopes`                   | `string`  | `[]`                                 | String com os escopos que o cliente pode solicitar, separados por espaço (ex: "read write").          |
| `redirect_uris`            | `string`  | `[]`                                 | String com as URIs de redirecionamento exatas e permitidas, separadas por espaço.                     |
| `token_expires_in`         | `number`  | `3600` (1 hora)                      | Tempo de vida do token de acesso, em segundos.                                                        |
| `refresh_token_expires_in` | `number`  | `7200` (2 horas)                     | Tempo de vida do refresh token, em segundos.                                                          |
| `issues_refresh_token`     | `boolean` | `true`                               | Se o cliente pode ou não receber refresh tokens.                                                      |
| `redirect_uri_required`    | `boolean` | `true`                               | Se a `redirect_uri` é obrigatória nas requisições.                                                    |
| `scopes_required`          | `boolean` | `false`                              | Se o parâmetro `scope` é obrigatório nas requisições.                                                 |
| `match_all_scopes`         | `boolean` | `true`                               | Se `true`, todos os escopos solicitados devem ser válidos. Se `false`, concede apenas os válidos.     |

### Métodos Utilitários

-   `validateScopes(scopeString)`: Valida uma string de escopos contra os escopos permitidos para o cliente.
-   `validateGrantType(grantType)`: Valida se o `grant_type` solicitado é permitido para o cliente.
-   `AuthFlow.validateResponseType(received, expected)`: Método estático para validar o `response_type`.

---

## Implementando os Fluxos OAuth 2.1

### 1. Authorization Code Flow

O fluxo mais comum e seguro, ideal para aplicações web e mobile onde o usuário se autentica através de um redirecionamento.

-   **Classe:** `AuthorizationCodeFlow`
-   **Configurações Adicionais:**
    -   `code_expires_in` (number, padrão: `300`): Tempo de vida do código de autorização, em segundos.
    -   `pkce_required` (boolean, padrão: `true`): Se o PKCE é obrigatório. **Recomendado manter `true`**.
    -   `allow_plain_pkce_method` (boolean, padrão: `false`): Se permite o método `plain` para PKCE. **NÃO RECOMENDADO**.
-   **Métodos de Uso:**
    -   `getCode(params)`: Inicia o fluxo, valida os parâmetros e gera um código.
    -   `getToken(params)`: Troca o código por um token de acesso.
-   **Métodos a Implementar:**
    -   `async generateCode({ scopes_granted, code_info, ... })`: Deve gerar e persistir um código de autorização único e seguro, associando-o ao `client_id`, escopos, `redirect_uri`, `code_challenge` e `user_id`.
    -   `async validateCode(code)`: Deve validar o código, garantir que não expirou e não foi usado, e então marcá-lo como usado (uso único).
    -   `async generateToken({ validation_data, token_info })`: Deve gerar o token de acesso final.

### 2. Client Credentials Flow

Usado para comunicação máquina-a-máquina, onde a aplicação se autentica em seu próprio nome, sem um usuário final.

-   **Classe:** `ClientCredentialsFlow`
-   **Configurações Adicionais:** Nenhuma. Herda de `AuthFlow`.
-   **Métodos de Uso:**
    -   `getToken(params)`: Gera um token de acesso para o cliente.
-   **Métodos a Implementar:**
    -   `async generateToken({ scopes, token_info })`: Deve gerar o token de acesso final.

### 3. Refresh Token Flow

Permite que um cliente obtenha um novo token de acesso usando um *refresh token*, sem precisar que o usuário se autentique novamente.

-   **Classe:** `RefreshTokenFlow`
-   **Configurações Adicionais:** Nenhuma. Herda de `AuthFlow`.
-   **Prática Recomendada:** Implemente a **rotação de refresh tokens**: a cada uso, invalide o refresh token antigo e emita um novo.
-   **Métodos de Uso:**
    -   `getToken(params)`: Troca um refresh token por um novo par de tokens.
-   **Métodos a Implementar:**
    -   `async validateRefreshToken(refreshToken)`: Deve validar o refresh token (se existe, não expirou, não foi revogado) e retornar seus dados associados (`client_id`, `user_id`, escopos).
    -   `async issueNewRefreshToken(validation_data)`: **(Opcional, mas recomendado)** Deve gerar um novo refresh token e invalidar o antigo (`validation_data.original_token`).
    -   `async generateToken({ validation_data, scopes, token_info })`: Deve gerar o novo token de acesso.

### 4. Device Code Flow

Projetado para dispositivos com capacidade de entrada limitada, como Smart TVs, consoles de jogos e dispositivos IoT.

-   **Classe:** `DeviceCodeFlow`
-   **Configurações Adicionais:**
    -   `verification_uri` (string, **obrigatório**): A URL que o usuário deve visitar em outro dispositivo (ex: `https://example.com/activate`).
    -   `verification_uri_complete` (string, **obrigatório**): A URL que pode ser exibida com o `user_code` já preenchido.
    -   `device_code_expires_in` (number, padrão: `1800`): Tempo de vida do `device_code`, em segundos.
    -   `interval` (number, padrão: `5`): O intervalo mínimo em segundos que o cliente deve aguardar entre as chamadas de polling.
    -   `user_code_size` (number, padrão: `8`): O tamanho do `user_code` gerado.
    -   `device_grant_name` (string, padrão: `"device_code"`): O nome do grant type. Pode ser alterado para o valor padrão da RFC (`"urn:ietf:params:oauth:grant-type:device_code"`).
-   **Métodos de Uso:**
    -   `requestDeviceCode(params)`: Inicia o fluxo, gerando o `device_code` e o `user_code`.
    -   `getToken(params)`: O cliente faz polling neste método para tentar trocar o `device_code` por um token.
-   **Métodos a Implementar:**
    -   `async generateDeviceCode({ ... })`: Deve gerar e persistir um `device_code` e um `user_code`, associando-os a um status inicial (ex: `'pending'`).
    -   `async validateDeviceCode(deviceCode)`: Deve verificar o status do `deviceCode`. Se pendente, lança `AUTHORIZATION_PENDING`. Se negado, lança `ACCESS_DENIED`. Se aprovado, retorna os dados para a geração do token.
    -   `async generateToken({ validation_data, token_info })`: Deve gerar o token de acesso final.

---

## Tratamento de Erros

A `authier` utiliza uma classe de erro customizada, `OAuthError`, para garantir que as respostas de erro sigam o padrão da RFC 6749.

Para lançar um erro padrão, use o método estático `throw`:

```javascript
import { OAuthError } from 'authier';

function myValidation(code) {
  if (!code) {
    // Lança um erro 'invalid_grant' com uma mensagem de detalhe para logging.
    OAuthError.throw('INVALID_GRANT', { detail: 'O código fornecido é nulo.' });
  }
}
```

A biblioteca já lida com a maioria dos erros de validação de parâmetros. Você precisará lançar `OAuthError` principalmente na sua lógica de persistência (ex: código não encontrado, token revogado).

**Erros Comuns:**

-   `INVALID_REQUEST`: Parâmetro faltando ou malformado.
-   `INVALID_CLIENT`: Falha na autenticação do cliente.
-   `INVALID_GRANT`: Credencial inválida (código, refresh token, etc.).
-   `INVALID_SCOPE`: Escopo inválido ou não permitido.
-   `UNSUPPORTED_GRANT_TYPE`: O cliente não tem permissão para usar o fluxo.
-   `ACCESS_DENIED`: O usuário ou o servidor negou a requisição.
-   `SERVER_ERROR`: Erro inesperado no servidor.

**Erros do Device Flow:**

-   `AUTHORIZATION_PENDING`: O usuário ainda não aprovou a requisição.
-   `SLOW_DOWN`: O cliente está fazendo polling muito rápido.
-   `EXPIRED_TOKEN`: O `device_code` expirou.

---

## Testando

A biblioteca vem com uma suíte de testes completa para cada fluxo. Para rodar os testes:

```bash
npm test
```

Você também pode rodar testes para um fluxo específico:

```bash
# Exemplo para o AuthorizationCodeFlow
npm run testAuthorizationCodeFlow
```

Analisar os arquivos em `/tests` é uma ótima maneira de ver exemplos de implementação de cada fluxo.

---

## Licença

MIT