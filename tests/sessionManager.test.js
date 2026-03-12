'use strict';

// Set environment variables before requiring any module that uses them
process.env.AZURE_CLIENT_ID = 'test-client-id';
process.env.AZURE_TENANT_ID = 'test-tenant-id';
process.env.AZURE_CLIENT_SECRET = 'test-client-secret';
process.env.AZURE_AUTHORITY = 'https://test-tenant.ciamlogin.com/test-tenant-id';
process.env.REDIRECT_URI = 'http://localhost:3000/auth/callback';
process.env.POST_LOGOUT_REDIRECT_URI = 'http://localhost:3000';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.NODE_ENV = 'test';

const sessionManager = require('../auth/sessionManager');

describe('SessionManager', () => {
  let mockReq;

  beforeEach(() => {
    mockReq = {
      session: {},
    };
  });

  describe('setAuthSession', () => {
    it('stores authentication result in session', () => {
      const authResult = {
        account: { homeAccountId: 'home-account-id-123' },
        idTokenClaims: { name: 'Test User', email: 'test@example.com', sub: 'sub-123' },
        accessToken: 'access-token-xyz',
      };

      sessionManager.setAuthSession(mockReq, authResult);

      expect(mockReq.session.isAuthenticated).toBe(true);
      expect(mockReq.session.homeAccountId).toBe('home-account-id-123');
      expect(mockReq.session.idTokenClaims).toEqual(authResult.idTokenClaims);
      expect(mockReq.session.accessToken).toBe('access-token-xyz');
    });
  });

  describe('getSessionState', () => {
    it('returns isAuthenticated false when session is empty', () => {
      const state = sessionManager.getSessionState(mockReq);
      expect(state.isAuthenticated).toBe(false);
      expect(state.claims).toBeNull();
    });

    it('returns isAuthenticated true when session is set', () => {
      mockReq.session.isAuthenticated = true;
      mockReq.session.idTokenClaims = { name: 'Test User' };

      const state = sessionManager.getSessionState(mockReq);
      expect(state.isAuthenticated).toBe(true);
      expect(state.claims).toEqual({ name: 'Test User' });
    });
  });

  describe('setCsrfState / validateAndClearCsrfState', () => {
    it('stores and validates the CSRF state', () => {
      sessionManager.setCsrfState(mockReq, 'csrf-state-abc');
      expect(mockReq.session.csrfState).toBe('csrf-state-abc');

      const valid = sessionManager.validateAndClearCsrfState(mockReq, 'csrf-state-abc');
      expect(valid).toBe(true);
      expect(mockReq.session.csrfState).toBeUndefined();
    });

    it('returns false when state does not match', () => {
      sessionManager.setCsrfState(mockReq, 'csrf-state-abc');

      const valid = sessionManager.validateAndClearCsrfState(mockReq, 'wrong-state');
      expect(valid).toBe(false);
    });

    it('returns false when no state was stored', () => {
      const valid = sessionManager.validateAndClearCsrfState(mockReq, 'any-state');
      expect(valid).toBe(false);
    });
  });

  describe('clearAuthSession', () => {
    it('removes all auth data from session', () => {
      mockReq.session.isAuthenticated = true;
      mockReq.session.homeAccountId = 'home-account-id-123';
      mockReq.session.idTokenClaims = { name: 'Test User' };
      mockReq.session.accessToken = 'access-token-xyz';

      sessionManager.clearAuthSession(mockReq);

      expect(mockReq.session.isAuthenticated).toBe(false);
      expect(mockReq.session.homeAccountId).toBeUndefined();
      expect(mockReq.session.idTokenClaims).toBeUndefined();
      expect(mockReq.session.accessToken).toBeUndefined();
    });
  });

  describe('destroySession', () => {
    it('resolves when session.destroy succeeds', async () => {
      mockReq.session.destroy = (cb) => cb(null);
      await expect(sessionManager.destroySession(mockReq)).resolves.toBeUndefined();
    });

    it('rejects when session.destroy fails', async () => {
      const err = new Error('store error');
      mockReq.session.destroy = (cb) => cb(err);
      await expect(sessionManager.destroySession(mockReq)).rejects.toThrow('store error');
    });
  });
});
