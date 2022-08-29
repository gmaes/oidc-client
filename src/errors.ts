function InternalOAuthError(message, err) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = "InternalOAuthError";
  this.message = message;
  this.oauthError = err;
}

/**
 * Inherit from `Error`.
 */
InternalOAuthError.prototype.__proto__ = Error.prototype;

/**
 * Returns a string representing the error.
 *
 * @return {String}
 * @api public
 */
InternalOAuthError.prototype.toString = function () {
  var m = this.message;
  if (this.oauthError) {
    if (this.oauthError instanceof Error) {
      m += " (" + this.oauthError + ")";
    } else if (this.oauthError.statusCode && this.oauthError.data) {
      m +=
        " (status: " +
        this.oauthError.statusCode +
        " data: " +
        this.oauthError.data +
        ")";
    }
  }
  return m;
};

function AuthorizationError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case "access_denied":
        status = 403;
        break;
      case "server_error":
        status = 502;
        break;
      case "temporarily_unavailable":
        status = 503;
        break;
    }
  }

  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.code = code || "server_error";
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
AuthorizationError.prototype.__proto__ = Error.prototype;

/**
 * `TokenError` error.
 *
 * TokenError represents an error received from a token endpoint.  For details,
 * refer to RFC 6749, section 5.2.
 *
 * References:
 *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
 *
 * @constructor
 * @param {String} [message]
 * @param {String} [code]
 * @param {String} [uri]
 * @param {Number} [status]
 * @api public
 */
function TokenError(message, code, uri, status) {
  Error.call(this);
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.code = code || "invalid_request";
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
TokenError.prototype.__proto__ = Error.prototype;

/**
 * Expose `TokenError`.
 */

export { TokenError, AuthorizationError, InternalOAuthError };
