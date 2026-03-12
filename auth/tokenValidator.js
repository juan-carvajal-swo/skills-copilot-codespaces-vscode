'use strict';

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const authConfig = require('./config');

/**
 * TokenValidator verifies Azure External ID (CIAM) ID / access tokens.
 *
 * Tokens are validated against the JWKS endpoint published by the tenant,
 * ensuring they have a valid signature, have not expired, and were issued
 * for this application's client ID.
 */
class TokenValidator {
  constructor() {
    if (authConfig.jwksUri) {
      this._jwksClient = jwksClient({
        jwksUri: authConfig.jwksUri,
        cache: true,
        cacheMaxEntries: 5,
        cacheMaxAge: 10 * 60 * 1000, // 10 minutes
      });
    }
  }

  /**
   * Fetches the public signing key from the JWKS endpoint for the given
   * key ID (`kid` header in the JWT).
   *
   * @param {object} header - Decoded JWT header
   * @param {Function} callback
   */
  _getSigningKey(header, callback) {
    if (!this._jwksClient) {
      return callback(new Error('JWKS client is not configured'));
    }
    this._jwksClient.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    });
  }

  /**
   * Validates a JWT issued by Azure External ID.
   *
   * @param {string} token - Raw JWT string
   * @returns {Promise<object>} Decoded and verified token claims
   */
  validateToken(token) {
    return new Promise((resolve, reject) => {
      const verifyOptions = {
        algorithms: ['RS256'],
        audience: authConfig.clientId,
        issuer: [
          `https://${authConfig.tenantId}/v2.0`,
          `${authConfig.msal.auth.authority}/v2.0`,
        ],
      };
      jwt.verify(
        token,
        this._getSigningKey.bind(this),
        verifyOptions,
        (err, decoded) => {
          if (err) return reject(err);
          resolve(decoded);
        }
      );
    });
  }

  /**
   * Decodes a JWT without signature verification.
   * Useful for extracting claims for informational purposes only.
   *
   * @param {string} token
   * @returns {object|null} Decoded payload or null on failure
   */
  decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch {
      return null;
    }
  }
}

module.exports = new TokenValidator();
