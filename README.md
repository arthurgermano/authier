# Authier

## Simple Authenticator Library

Authier is a simple library helper to make it easier to implement and serve authentication methods using OAuth2.0.

## Index

- [Authier](#authier)
  - [Features](#features)
  - [Install](#install)
  - [Example](#example)
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

### Methods to be Implemented

#### Auth Flow

##### Find Client
```js
/**
 * Summary.
 * - Finds a matching client_id Client in the database
 * - Fills the Class Properties
 * - Returns the client found or throws INVALID_CLIENT
 *
 * @param {String} client_id - The client_id string provided in the request.
 *
 * @throws InvalidClient
 * @throws InvalidRequest
 * @throws ServerError
 *
 * @return {Object} properties - Class properties
 */
async function findClient(client_id) {
  // Must populate the fields
  throw ERRORS.TODO_ERROR;
}
```
