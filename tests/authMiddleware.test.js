'use strict';

process.env.AZURE_CLIENT_ID = 'test-client-id';
process.env.AZURE_TENANT_ID = 'test-tenant-id';
process.env.AZURE_CLIENT_SECRET = 'test-client-secret';
process.env.AZURE_AUTHORITY = 'https://test-tenant.ciamlogin.com/test-tenant-id';
process.env.REDIRECT_URI = 'http://localhost:3000/auth/callback';
process.env.POST_LOGOUT_REDIRECT_URI = 'http://localhost:3000';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.NODE_ENV = 'test';

jest.mock('@azure/msal-node', () => ({
  ConfidentialClientApplication: jest.fn().mockImplementation(() => ({
    getAuthCodeUrl: jest.fn(),
    acquireTokenByCode: jest.fn(),
    acquireTokenSilent: jest.fn(),
    getTokenCache: jest.fn().mockReturnValue({
      getAccountByHomeId: jest.fn(),
      removeAccount: jest.fn(),
    }),
  })),
  InteractionRequiredAuthError: class extends Error {},
}));

const { ensureAuthenticated, attachSessionState } = require('../middleware/authMiddleware');

function buildMockReqRes(sessionData = {}) {
  const req = {
    session: { ...sessionData },
    originalUrl: '/protected',
  };
  const res = {
    locals: {},
    redirect: jest.fn(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
  const next = jest.fn();
  return { req, res, next };
}

describe('attachSessionState', () => {
  it('sets isAuthenticated false when not logged in', () => {
    const { req, res, next } = buildMockReqRes();
    attachSessionState(req, res, next);
    expect(res.locals.isAuthenticated).toBe(false);
    expect(res.locals.user).toBeNull();
    expect(next).toHaveBeenCalled();
  });

  it('sets isAuthenticated true and attaches claims when logged in', () => {
    const claims = { name: 'Test User', email: 'test@example.com' };
    const { req, res, next } = buildMockReqRes({
      isAuthenticated: true,
      idTokenClaims: claims,
    });
    attachSessionState(req, res, next);
    expect(res.locals.isAuthenticated).toBe(true);
    expect(res.locals.user).toEqual(claims);
    expect(next).toHaveBeenCalled();
  });
});

describe('ensureAuthenticated', () => {
  it('calls next when session is authenticated', async () => {
    const { req, res, next } = buildMockReqRes({ isAuthenticated: true });
    await ensureAuthenticated(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.redirect).not.toHaveBeenCalled();
  });

  it('redirects to /auth/login when session is not authenticated', async () => {
    const { req, res, next } = buildMockReqRes();
    await ensureAuthenticated(req, res, next);
    expect(res.redirect).toHaveBeenCalledWith('/auth/login');
    expect(req.session.returnTo).toBe('/protected');
  });
});
