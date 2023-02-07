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
    - [Fields](#fields)
    - [Example of Functions of Auth Flow Implemented](#example-of-functions-of-auth-flow-implemented)
  - [Client Credentials Flow](#client-credentials-flow)
    - [Fields](#fields-1)
    - [Example of Functions of Code Flow Implemented](#example-of-functions-of-code-flow-implemented)
  - [Code Flow](#code-flow)
    - [Fields](#fields-2)
    - [Example of Functions of Code Flow Implemented](#example-of-functions-of-code-flow-implemented-1)
  - [Password Flow](#password-flow)
    - [Fields](#fields-3)
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

## Example

Create an extension to override or implement the required functions as showed in the example here:
<br />
<a href="https://github.com/arthurgermano/authier/blob/master/auth_server_example/oauth2extension/index.js" target="_blank">
Example of Authier Extension
</a>
<br />

## Auth Flow

### Fields

```js
  /**
   * Client option to issue or not a refresh client token - default is true
   * @type {Boolean}
   */
  issues_refresh_token;

  /**
   * Client's option whether the redirect_uri is required
   * @type {Boolean}
   */
  redirect_uri_required;

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
   * Refresh Token TTL - default is 7200 seconds
   * @type {Number}
   */
  refresh_token_expires_in;

  /**
   * Token TTL - default is 3600 seconds
   * @type {Number}
   */
  token_expires_in;

  /**
   * Match all scope option
   * @param {Object}
   */
  match_all_scopes;
```

### Example of Functions of Auth Flow Implemented

```js

// ------------------------------------------------------------------------------------

AuthFlow.prototype.generateToken = async function generateToken(args) {
  return await signToken({
    exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
    sub: args.token_info.sub,
    iss: args.token_info.iss,
    scopes: args.scopes_granted || "",
    redirect_uri: args.redirect_uri, // present only in authorization code flow
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

## Client Credentials Flow
### Fields
It inherits from Auth Flow fields

### Example of Functions of Code Flow Implemented
There is no need to implement functions as long as you implemented Auth Flow Functions

<hr />

## Code Flow
### Fields
It inherits from Auth Flow fields and adds the following:

```js
  /**
   * Authorization Code flow code string.
   * @type {String}
   */
  code;

  /**
   * Authorization Code TTL - Default is 5 minutes.
   * @type {Number}
   */
  code_expires_in;

  /**
   * is_uri_encoded - Whether the redirect_uri is encoded or not
   * @param {String}
   */
  is_uri_encoded;
```

### Example of Functions of Code Flow Implemented

It inherits from Auth Flow functions and adds the following:

```js
// --------------------------  AUTHORIZATION CODE FUNCTIONS  --------------------------

AuthorizationCodeFlow.prototype.generateCode = async function generateToken(
  args
) {
  return await signToken({
    exp: Math.floor(Date.now() / 1000) + 55 * this.code_expires_in,
    sub: args.code_info.sub,
    iss: args.code_info.iss,
    scopes: args.scopes_granted || "",
    redirect_uri: args.redirect_uri,
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

## Password Flow
### Fields
It inherits from Auth Flow fields.

### Example of Functions of Password Flow Implemented

It inherits from Auth Flow functions.

## Refresh Token Flow

### Example of Functions of Refresh Token Flow Implemented

It inherits from Auth Flow functions and adds the following:

```js
// --------------------------  REFRESH TOKEN FUNCTIONS  -------------------------------

RefreshTokenFlow.prototype.generateRefreshToken =
  async function generateRefreshToken(args) {
    return await signToken({
      exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
      sub: args.token_info.sub,
      iss: args.token_info.iss,
      scopes: args.scopes_granted || "",
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

## Example of All Methods to be Implemented

The example of all methods that should be implemented:
<br />
<a href="https://github.com/arthurgermano/authier/blob/master/auth_server_example/oauth2extension/index.js" target="_blank">
Example of Authier Extension
</a>
<br />
