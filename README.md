# Authier

## Simple Authenticator Library

Authier is a simple library helper to make it easier to implement and serve authentication methods using OAuth2.0.

## Index

- [Authier](#authier)
  - [Features](#features)
  - [Install](#install)
  - [Example](#example)
  - [Auth Flow](#auth-flow)
    - [Fields of Client](#fields-of-client)
  - [Methods to be Implemented](#methods-to-be-implemented)
  

## Features

- No Dependencies
- Simple to Use

## Install

To install Authier is simple:

with npm

```bash
npm i authier
```

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
### Methods to be Implemented
The methods that should be implemented:
<br />
<a href="https://github.com/arthurgermano/authier/blob/master/auth_server_example/oauth2extension/index.js" target="_blank">
Example of Authier Extension
</a>
<br />
