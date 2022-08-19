const ACCESS_DENIED = {
  error: "access_denied",
  error_description: `The resource owner or authorization server denied the request.`,
  status: 400,
};

const INVALID_CLIENT = {
  error: "invalid_client",
  error_description: `Client authentication failed (e.g., unknown client, no
                      client authentication included, or unsupported
                      authentication method).`,
  status: 401,
};

const INVALID_GRANT = {
  error: "invalid_grant",
  error_description: `The provided authorization grant (e.g., authorization
                      code, resource owner credentials) or refresh token is
                      invalid, expired, revoked, does not match the redirection
                      URI used in the authorization request, or was issued to
                      another client.`,
  status: 400,
};

const INVALID_REQUEST = {
  error: "invalid_request",
  error_description: `The request is missing a required parameter, includes an
                      unsupported parameter value (other than grant type),
                      repeats a parameter, includes multiple credentials,
                      utilizes more than one mechanism for authenticating the
                      client, or is otherwise malformed.`,
  status: 400,
};

const INVALID_SCOPE = {
  error: "invalid_scope",
  error_description: `The requested scope is invalid, unknown, malformed, or
                      exceeds the scope granted by the resource owner.`,
  status: 400,
};

const MISMATCH_CLIENT = {
  error: "mismatch_client",
  error_description: `Client authentication failed - client mismatch`,
  status: 400,
};

const SERVER_ERROR = {
  error: "server_error",
  error_description: `The authorization server encountered an unexpected
                      condition that prevented it from fulfilling the request.
                      (This error code is needed because a 500 Internal Server
                      Error HTTP status code cannot be returned to the client
                      via an HTTP redirect.)`,
  status: 500,
};

const TEMPORARILY_UNAVAILABLE = {
  error: "temporarily_unavailable",
  error_description: `The authorization server is currently unable to handle
                      the request due to a temporary overloading or maintenance
                      of the server.`,
  status: 503,
};

const TODO_ERROR = {
  error: "todo_error",
  error_description: `The code requested is not implemented yet.`,
  status: 500,
};

const UNSUPPORTED_GRANT_TYPE = {
  error: "unsupported_grant_type",
  error_description: `The authorization grant type is not supported by the
                      authorization server.`,
  status: 400,
};

const UNSUPPORTED_RESPONSE_TYPE = {
  error: "unsupported_response_type",
  error_description: `The authorization server does not support obtaining an
                      authorization code using this method.`,
  status: 400,
};

function throwError(error, more_info) {
  if (typeof error !== "object") {
    throw {
      ...SERVER_ERROR,
      exception: "throwError(): error must be a valid object",
    };
  }
  throw { ...error, more_info };
}

module.exports = {
  ACCESS_DENIED,
  INVALID_CLIENT,
  INVALID_GRANT,
  INVALID_REQUEST,
  INVALID_SCOPE,
  MISMATCH_CLIENT,
  SERVER_ERROR,
  TEMPORARILY_UNAVAILABLE,
  TODO_ERROR,
  UNSUPPORTED_GRANT_TYPE,
  UNSUPPORTED_RESPONSE_TYPE,
  throwError,
};
