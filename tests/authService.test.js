'use strict';

process.env.AZURE_CLIENT_ID = 'test-client-id';
process.env.AZURE_TENANT_ID = 'test-tenant-id';
process.env.AZURE_CLIENT_SECRET = 'test-client-secret';
process.env.AZURE_AUTHORITY = 'https://test-tenant.ciamlogin.com/test-tenant-id';
process.env.REDIRECT_URI = 'http://localhost:3000/auth/callback';
process.env.POST_LOGOUT_REDIRECT_URI = 'http://localhost:3000';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.NODE_ENV = 'test';

// Mock MSAL before requiring authService
jest.mock('@azure/msal-node', () => {
  const InteractionRequiredAuthError = class extends Error {
    constructor(msg) {
      super(msg);
      this.name = 'InteractionRequiredAuthError';
    }
  };

  return {
    ConfidentialClientApplication: jest.fn().mockImplementation(() => ({
      getAuthCodeUrl: jest.fn().mockResolvedValue('https://login.example.com/auth'),
      acquireTokenByCode: jest.fn().mockResolvedValue({
        account: { homeAccountId: 'home-id-123' },
        idTokenClaims: { name: 'Test User' },
        accessToken: 'mock-access-token',
      }),
      acquireTokenSilent: jest.fn().mockResolvedValue({
        account: { homeAccountId: 'home-id-123' },
        idTokenClaims: { name: 'Test User' },
        accessToken: 'refreshed-access-token',
      }),
      getTokenCache: jest.fn().mockReturnValue({
        getAccountByHomeId: jest.fn().mockResolvedValue({ homeAccountId: 'home-id-123' }),
        removeAccount: jest.fn().mockResolvedValue(undefined),
      }),
    })),
    InteractionRequiredAuthError,
  };
});

const authService = require('../auth/authService');

describe('AuthService', () => {
  describe('getAuthCodeUrl', () => {
    it('returns the authorization URL', async () => {
      const url = await authService.getAuthCodeUrl('csrf-state-123');
      expect(url).toBe('https://login.example.com/auth');
    });
  });

  describe('acquireTokenByCode', () => {
    it('exchanges code for tokens', async () => {
      const result = await authService.acquireTokenByCode('auth-code', 'state');
      expect(result.accessToken).toBe('mock-access-token');
      expect(result.account.homeAccountId).toBe('home-id-123');
    });
  });

  describe('acquireTokenSilent', () => {
    it('returns null when account is null', async () => {
      const result = await authService.acquireTokenSilent(null);
      expect(result).toBeNull();
    });

    it('returns refreshed tokens for a valid account', async () => {
      const result = await authService.acquireTokenSilent({ homeAccountId: 'home-id-123' });
      expect(result.accessToken).toBe('refreshed-access-token');
    });

    it('returns null when InteractionRequiredAuthError is thrown', async () => {
      const msal = require('@azure/msal-node');
      const msalInstance = msal.ConfidentialClientApplication.mock.results[0].value;
      msalInstance.acquireTokenSilent.mockRejectedValueOnce(
        new msal.InteractionRequiredAuthError('interaction required')
      );

      const result = await authService.acquireTokenSilent({ homeAccountId: 'home-id-123' });
      expect(result).toBeNull();
    });
  });

  describe('getLogoutUrl', () => {
    it('returns a logout URL containing the post_logout_redirect_uri', async () => {
      const url = await authService.getLogoutUrl('home-id-123');
      expect(url).toContain('post_logout_redirect_uri=');
      expect(url).toContain('logout');
    });
  });
});
