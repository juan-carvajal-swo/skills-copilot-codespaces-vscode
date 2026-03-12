'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/authRoutes');
const { ensureAuthenticated, attachSessionState } = require('./middleware/authMiddleware');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Body parsers ──────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Session ───────────────────────────────────────────────────────────────────
// In production, replace the default MemoryStore with a persistent store
// (e.g., connect-redis or connect-mongo) to survive process restarts and
// scale across multiple instances.
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: parseInt(process.env.SESSION_MAX_AGE_MS || '3600000', 10),
    },
  })
);

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(attachSessionState);

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/auth', authRoutes);

// Public home page
app.get('/', (req, res) => {
  res.json({
    message: 'Azure External ID CIAM demo',
    authenticated: res.locals.isAuthenticated,
    user: res.locals.user
      ? { name: res.locals.user.name, email: res.locals.user.preferred_username }
      : null,
  });
});

// Protected resource – requires a valid session
app.get('/profile', ensureAuthenticated, (req, res) => {
  res.json({ profile: res.locals.user });
});

// ── Error handler ─────────────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[server] Unhandled error:', err);
  res.status(500).json({ error: 'internal_server_error', message: err.message });
});

// ── Start ─────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

module.exports = app;
