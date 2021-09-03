# Authier

## Simple Authenticator Library

Authier is a simple library helper to make it easier to implement and serve authentication methods using OAuth2.0.

## Index

- [Authier](#authier)
  - [Simple Authenticator Library](#simple-authenticator-library)
  - [Index](#index)
  - [Features](#features)
  - [Install](#install)
  - [Test It](#test-it)
    - [Example](#example)
    - [Auth Flow](#auth-flow)
      - [Fields of Client](#fields-of-client)
      - [Example of Functions of Auth Flow Implemented](#example-of-functions-of-auth-flow-implemented)
    - [Code Flow](#code-flow)
      - [Fields of Code](#fields-of-code)
      - [Example of Functions of Code Flow Implemented](#example-of-functions-of-code-flow-implemented)
    - [Password Flow](#password-flow)
      - [Fields of Password](#fields-of-password)
      - [Example of Functions of Password Flow Implemented](#example-of-functions-of-password-flow-implemented)
    - [Refresh Token Flow](#refresh-token-flow)
      - [Example of Functions of Refresh Token Flow Implemented](#example-of-functions-of-refresh-token-flow-implemented)
    - [Example of All Methods to be Implemented](#example-of-all-methods-to-be-implemented)

## Features

- No Dependencies
- Simple to Use

## Install

To install Authier is simple:

with npm

```bash
npm i authier
```

## Test It
Testing it locally:
- Clone this project into your local machine.
- Inside the project folder auth_server_example, run npm install
- Then just run node index.js or nodemon index.js 
- It will simple use a local file to example a Database and runs some tests
- Edit at your will to help you understand how the lib works, but it is very simple.

### Example

Create an extension to override or implement the required functions as showed in the example here:
<br />
<a href="https://github.com/arthurgermano/authier/blob/master/auth_server_example/oauth2extension/index.js" target="_blank">
Example of Authier Extension
</a>
<br />

### Auth Flow

#### Fields of Client

```js
/**
 * Client's identification string.
 * @type {String}
 */
client_id;

/**
 * Client's secret string.
 * @type {String}
 */
client_secret;

/**
 * Token issuer identification.
 * @type {String}
 */
issuer;

/**
 * Grant types granted for this client
 * @type {String}
 */
grant_types;

/**
 * Client's redirect uris string separated by spaces
 * @type {String}
 */
redirect_uris;

/**
 * Client's custom scopes string separated by spaces
 * @type {String}
 */
scopes;

/**
 * Client's option whether the scope is required
 * @type {Boolean}
 */
scope_required;

/**
 * Client's option whether the state is required
 * @type {Boolean}
 */
state_required;

/**
 * Client's option whether the redirect_uri is required
 * @type {Boolean}
 */
redirect_uri_required;
```

#### Example of Functions of Auth Flow Implemented

```js
// --------------------------  AUTH FLOW FUNCTIONS  -----------------------------------

AuthFlow.prototype.findClient = async function findClient(client_id) {
  const clients = await getClients();
  const client = clients.find((cItem) => cItem.client_id === client_id);
  if (!client) {
    throw OAuth2Lib.Errors.INVALID_CLIENT;
  }
  this.setProperties(client);
  return client;
};

// ------------------------------------------------------------------------------------

AuthFlow.prototype.generateToken = async function generateToken(
  token_data,
  options = {}
) {
  return await signToken({
    exp: options.exp || Math.floor(Date.now() / 1000) + 55 * 60,
    sub: options.sub,
    iss: options.iss,
    scopes: token_data.scopes || "",
    redirect_uri: token_data.redirect_uri,
  });
};

// ------------------------------------------------------------------------------------

AuthFlow.prototype.validateToken = async function validateToken(token) {
  try {
    return await checkToken(token);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------
```

<hr />

### Code Flow
#### Fields of Code
It inherits from Auth Flow fields and adds the following:

```js
/**
 * Authorization Code flow code string.
 * @type {String}
 */
code;
```

#### Example of Functions of Code Flow Implemented

It inherits from Auth Flow functions and adds the following:

```js
// --------------------------  AUTHORIZATION CODE FUNCTIONS  --------------------------

AuthorizationCodeFlow.prototype.generateCode = async function generateToken(
  code_data,
  options = {}
) {
  return await signToken({
    exp: options.exp || Math.floor(Date.now() / 1000) + 55 * 5,
    sub: options.sub,
    iss: options.iss,
    scopes: code_data.scopes || "",
    redirect_uri: code_data.redirect_uri,
  });
};

// ------------------------------------------------------------------------------------

AuthorizationCodeFlow.prototype.validateCode = async function validateCode(
  code
) {
  try {
    return await checkToken(code);
  } catch (error) {
    throw error;
  }
};

// ------------------------------------------------------------------------------------
```

<hr />

### Password Flow
#### Fields of Password
It inherits from Auth Flow fields and adds the following:

```js
/**
 * Password flow user_name string.
 * @type {String}
 */
user_name;

/**
 * Password flow password string.
 * @type {String}
 */
password;
```

#### Example of Functions of Password Flow Implemented

It inherits from Auth Flow functions and adds the following:

```js
// --------------------------  PASSWORD FUNCTIONS  ------------------------------------

PasswordFlow.prototype.findResource = async function findResource(user_name) {
  const resources = await getResources();
  const resource = resources.find((rItem) => rItem.user_name === user_name);
  if (!resource) {
    throw OAuth2Lib.Errors.ACCESS_DENIED;
  }
  this.setProperties({ ...resource, grant_types: "password" });
  return resource;
};

// ------------------------------------------------------------------------------------
```

### Refresh Token Flow

#### Example of Functions of Refresh Token Flow Implemented

It inherits from Auth Flow functions and adds the following:

```js
// --------------------------  REFRESH TOKEN FUNCTIONS  -------------------------------

RefreshTokenFlow.prototype.generateRefreshToken =
  async function generateRefreshToken(refresh_token_data, options = {}) {
    return await signToken({
      exp: options.exp || Math.floor(Date.now() / 1000) + 55 * 60 * 24,
      sub: options.sub,
      iss: options.iss,
      scopes: refresh_token_data.scopes || "",
      redirect_uri: refresh_token_data.redirect_uri,
    });
  };

// ------------------------------------------------------------------------------------

RefreshTokenFlow.prototype.validateRefreshToken =
  async function validateRefreshToken(refresh_token) {
    try {
      return await checkToken(refresh_token);
    } catch (error) {
      throw error;
    }
  };

// ------------------------------------------------------------------------------------
```

### Example of All Methods to be Implemented

The example of all methods that should be implemented:
<br />
<a href="https://github.com/arthurgermano/authier/blob/master/auth_server_example/oauth2extension/index.js" target="_blank">
Example of Authier Extension
</a>
<br />
