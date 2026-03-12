'use strict';

/**
 * SessionManager handles CIAM session lifecycle operations.
 *
 * Session data stored per request (express-session):
 *   req.session.isAuthenticated  {boolean}
 *   req.session.homeAccountId    {string}  - MSAL account identifier
 *   req.session.idTokenClaims    {object}  - Decoded claims from the ID token
 *   req.session.accessToken      {string}  - Current access token
 *   req.session.csrfState        {string}  - One-time CSRF state for OAuth flow
 */
class SessionManager {
  /**
   * Persists the authentication result returned by MSAL into the session.
   *
   * @param {import('express').Request} req
   * @param {import('@azure/msal-node').AuthenticationResult} authResult
   */
  setAuthSession(req, authResult) {
    req.session.isAuthenticated = true;
    req.session.homeAccountId = authResult.account.homeAccountId;
    req.session.idTokenClaims = authResult.idTokenClaims;
    req.session.accessToken = authResult.accessToken;
  }

  /**
   * Returns the current session authentication state.
   *
   * @param {import('express').Request} req
   * @returns {{ isAuthenticated: boolean, claims: object|null }}
   */
  getSessionState(req) {
    return {
      isAuthenticated: req.session.isAuthenticated === true,
      claims: req.session.idTokenClaims || null,
    };
  }

  /**
   * Stores a one-time CSRF state value in the session before initiating
   * the OAuth authorization code flow.
   *
   * @param {import('express').Request} req
   * @param {string} state
   */
  setCsrfState(req, state) {
    req.session.csrfState = state;
  }

  /**
   * Validates and clears the CSRF state stored in the session.
   * Returns true when the provided state matches the stored value.
   *
   * @param {import('express').Request} req
   * @param {string} state - State value received in the OAuth callback
   * @returns {boolean}
   */
  validateAndClearCsrfState(req, state) {
    const stored = req.session.csrfState;
    delete req.session.csrfState;
    return typeof stored === 'string' && stored === state;
  }

  /**
   * Clears all authentication data from the session.
   * Does NOT destroy the express-session cookie (caller must do that if needed).
   *
   * @param {import('express').Request} req
   */
  clearAuthSession(req) {
    req.session.isAuthenticated = false;
    delete req.session.homeAccountId;
    delete req.session.idTokenClaims;
    delete req.session.accessToken;
  }

  /**
   * Fully destroys the express session and resolves the callback.
   *
   * @param {import('express').Request} req
   * @returns {Promise<void>}
   */
  destroySession(req) {
    return new Promise((resolve, reject) => {
      req.session.destroy((err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  }
}

module.exports = new SessionManager();
