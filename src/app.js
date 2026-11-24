import express from 'express';
import { createAudit } from './audit.js';
import { createSessions, createTransactions } from './sessions.js';
import { createGoogleRouter } from './google.js';
import { createSamlRouter } from './saml.js';
import { createIdpStore } from './idps.js';
import { createAdminRouter } from './admin.js';
import { createPagesRouter } from './pages.js';
import { fileURLToPath } from 'node:url';

export function createApp({ config, db, audit = createAudit() }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.secureCookies ? 1 : false);

  app.use((req, res, next) => {
    res.set({
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'",
    });
    next();
  });

  const sessions = createSessions(db, config);
  const transactions = createTransactions(db, config);
  const idps = createIdpStore(db, { allowInsecureHttp: config.allowInsecureHttp });
  const deps = { config, db, audit, sessions, transactions, idps };

  app.use('/static', express.static(fileURLToPath(new URL('../public', import.meta.url)), { index: false }));
  app.use(createPagesRouter(deps));
  app.use(createGoogleRouter(deps));
  app.use(createSamlRouter(deps));
  app.use(createAdminRouter(deps));

  app.use((err, req, res, next) => {
    audit({ event: 'internal_error', level: 'error', path: req.path, error: err?.name });
    if (res.headersSent) return next(err);
    res.status(500).type('text/plain').send('Something went wrong.');
  });

  return app;
}
