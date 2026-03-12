'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const authService = require('../auth/authService');
const sessionManager = require('../auth/sessionManager');

const router = express.Router();

/**
 * GET /auth/login
 *
 * Initiates the Azure External ID OAuth 2.0 authorization code flow.
 * Generates a CSRF-state nonce, stores it in the session, and redirects
 * the browser to the Azure External ID hosted login page.
 */
router.get('/login', async (req, res, next) => {
  try {
    const state = uuidv4();
    sessionManager.setCsrfState(req, state);

    const authCodeUrl = await authService.getAuthCodeUrl(state);
    res.redirect(authCodeUrl);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /auth/callback
 *
 * Handles the redirect back from Azure External ID after the user
 * has authenticated. Validates the CSRF state, exchanges the code
 * for tokens, and persists the auth result in the session.
 */
router.get('/callback', async (req, res, next) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(401).json({ error, error_description });
    }

    if (!sessionManager.validateAndClearCsrfState(req, state)) {
      return res.status(400).json({ error: 'invalid_state', message: 'CSRF state mismatch' });
    }

    const tokenResult = await authService.acquireTokenByCode(code, state);
    sessionManager.setAuthSession(req, tokenResult);

    const returnTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(returnTo);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /auth/logout
 *
 * Clears the local session and redirects the browser to the Azure
 * External ID logout endpoint so that the federated SSO session is
 * also terminated.
 */
router.get('/logout', async (req, res, next) => {
  try {
    const { homeAccountId } = req.session;
    const logoutUrl = await authService.getLogoutUrl(homeAccountId);

    await sessionManager.destroySession(req);
    res.redirect(logoutUrl);
  } catch (error) {
    next(error);
  }
});

/**
 * GET /auth/session
 *
 * Returns the current session state as JSON.
 * Useful for Single Page Applications to check authentication status.
 */
router.get('/session', (req, res) => {
  const { isAuthenticated, claims } = sessionManager.getSessionState(req);
  if (!isAuthenticated) {
    return res.status(401).json({ isAuthenticated: false });
  }
  res.json({
    isAuthenticated: true,
    user: {
      name: claims?.name,
      email: claims?.email || claims?.preferred_username,
      sub: claims?.sub,
      oid: claims?.oid,
    },
  });
});

module.exports = router;
