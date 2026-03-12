'use strict';

const sessionManager = require('../auth/sessionManager');
const authService = require('../auth/authService');

/**
 * Express middleware that enforces authentication on protected routes.
 *
 * Behavior:
 *  1. If the session already has a valid `isAuthenticated` flag, passes through.
 *  2. Attempts a silent MSAL token refresh when a homeAccountId is present
 *     but the session has expired.
 *  3. Redirects to /auth/login when no valid session can be established.
 */
async function ensureAuthenticated(req, res, next) {
  const { isAuthenticated } = sessionManager.getSessionState(req);

  if (isAuthenticated) {
    return next();
  }

  // Attempt silent token acquisition to renew an expired session
  if (req.session.homeAccountId) {
    try {
      const account = await authService.getAccountByHomeId(req.session.homeAccountId);
      const tokenResult = await authService.acquireTokenSilent(account);

      if (tokenResult) {
        sessionManager.setAuthSession(req, tokenResult);
        return next();
      }
    } catch (error) {
      console.error('[authMiddleware] Silent token refresh failed:', error.message);
    }
  }

  // Store the originally requested URL so we can redirect back after login
  req.session.returnTo = req.originalUrl;
  res.redirect('/auth/login');
}

/**
 * Middleware that attaches the current session state to res.locals so that
 * view templates can access authentication information.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 */
function attachSessionState(req, res, next) {
  const { isAuthenticated, claims } = sessionManager.getSessionState(req);
  res.locals.isAuthenticated = isAuthenticated;
  res.locals.user = claims;
  next();
}

module.exports = { ensureAuthenticated, attachSessionState };
