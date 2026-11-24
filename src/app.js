import express from 'express';
import { createAudit } from './audit.js';
import { createSessions, createTransactions } from './sessions.js';
import { createGoogleRouter } from './google.js';
import { createSamlRouter } from './saml.js';
import { createIdpStore } from './idps.js';

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

  app.use(createGoogleRouter(deps));
  app.use(createSamlRouter(deps));

  return app;
}
