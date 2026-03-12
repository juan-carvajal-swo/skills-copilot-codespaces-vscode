'use strict';

require('dotenv').config();

/**
 * Azure External ID (CIAM) configuration.
 *
 * This configuration supports the OAuth 2.0 authorization code flow
 * with PKCE for Single Page Applications or the confidential client
 * flow for server-side web applications using Azure External ID.
 *
 * Reference:
 * https://learn.microsoft.com/en-us/azure/active-directory/external-identities/customers/
 */

const msalConfig = {
  auth: {
    clientId: process.env.AZURE_CLIENT_ID,
    authority: process.env.AZURE_AUTHORITY,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
  },
  system: {
    loggerOptions: {
      loggerCallback(loglevel, message) {
        if (process.env.NODE_ENV !== 'test') {
          console.log(`[MSAL] ${message}`);
        }
      },
      piiLoggingEnabled: false,
      logLevel: 3, // Warning
    },
  },
};

const authConfig = {
  msal: msalConfig,
  redirectUri: process.env.REDIRECT_URI || 'http://localhost:3000/auth/callback',
  postLogoutRedirectUri: process.env.POST_LOGOUT_REDIRECT_URI || 'http://localhost:3000',
  scopes: (process.env.API_SCOPES || 'openid profile email offline_access').split(' '),
  jwksUri: process.env.JWKS_URI,
  tenantId: process.env.AZURE_TENANT_ID,
  clientId: process.env.AZURE_CLIENT_ID,
};

module.exports = authConfig;
