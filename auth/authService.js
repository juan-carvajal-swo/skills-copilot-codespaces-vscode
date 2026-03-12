'use strict';

const msal = require('@azure/msal-node');
const authConfig = require('./config');

/**
 * AuthService handles interactions with Azure External ID (CIAM)
 * using the Microsoft Authentication Library (MSAL) for Node.js.
 *
 * Supports:
 *  - Authorization Code Flow (with PKCE for public clients)
 *  - Silent token acquisition using refresh tokens stored in session
 *  - Sign-out / session cleanup
 */
class AuthService {
  constructor() {
    this._msalClient = new msal.ConfidentialClientApplication(authConfig.msal);
  }

  /**
   * Builds the authorization URL to redirect the user to Azure External ID
   * login page.
   *
   * @param {string} state - CSRF-protection state value (stored in session)
   * @returns {Promise<string>} Authorization URL
   */
  async getAuthCodeUrl(state) {
    const authCodeUrlParams = {
      scopes: authConfig.scopes,
      redirectUri: authConfig.redirectUri,
      state,
    };
    return this._msalClient.getAuthCodeUrl(authCodeUrlParams);
  }

  /**
   * Exchanges the authorization code received from Azure External ID for
   * access + ID tokens.
   *
   * @param {string} code  - Authorization code from the query string
   * @param {string} state - State value to verify CSRF protection
   * @returns {Promise<msal.AuthenticationResult>}
   */
  async acquireTokenByCode(code, state) {
    const tokenRequest = {
      code,
      scopes: authConfig.scopes,
      redirectUri: authConfig.redirectUri,
      state,
    };
    return this._msalClient.acquireTokenByCode(tokenRequest);
  }

  /**
   * Attempts a silent token refresh using the cached account.
   * Falls back gracefully when the refresh token has expired.
   *
   * @param {msal.AccountInfo} account - Account retrieved from the MSAL cache
   * @returns {Promise<msal.AuthenticationResult|null>}
   */
  async acquireTokenSilent(account) {
    if (!account) return null;
    try {
      const silentRequest = {
        account,
        scopes: authConfig.scopes,
        forceRefresh: false,
      };
      return await this._msalClient.acquireTokenSilent(silentRequest);
    } catch (error) {
      if (error instanceof msal.InteractionRequiredAuthError) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Returns the MSAL account object by its homeAccountId.
   *
   * @param {string} homeAccountId
   * @returns {Promise<msal.AccountInfo|null>}
   */
  async getAccountByHomeId(homeAccountId) {
    const tokenCache = this._msalClient.getTokenCache();
    return tokenCache.getAccountByHomeId(homeAccountId);
  }

  /**
   * Builds the Azure External ID logout URL and removes the account from
   * the MSAL token cache.
   *
   * @param {string} homeAccountId - Account to log out
   * @returns {Promise<string>} Logout URL
   */
  async getLogoutUrl(homeAccountId) {
    const account = await this.getAccountByHomeId(homeAccountId);
    if (account) {
      await this._msalClient.getTokenCache().removeAccount(account);
    }
    const logoutUrl = new URL(
      `${authConfig.msal.auth.authority}/oauth2/v2.0/logout`
    );
    logoutUrl.searchParams.set(
      'post_logout_redirect_uri',
      authConfig.postLogoutRedirectUri
    );
    return logoutUrl.toString();
  }
}

module.exports = new AuthService();
