import { Router, urlencoded } from 'express';
import { LOGIN_ERRORS } from './login-flow.js';
import { safeReturnTo } from './sessions.js';

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const layout = (title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><link rel="stylesheet" href="/static/app.css"></head>
<body><main>${body}</main></body></html>`;

function loginPage({ config, error, ref, returnTo }) {
  const rt = returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : '';
  const message = LOGIN_ERRORS[error];
  return layout('Sign in', `
  <h1>Sign in</h1>
  ${message ? `<p class="error" role="alert">${esc(message)}${/^[0-9a-f]{12}$/.test(ref ?? '') ? ` <span class="ref">Reference: ${esc(ref)}</span>` : ''}</p>` : ''}
  ${config.google.enabled ? `<p><a class="button" href="/auth/google${rt}">Sign in with Google</a></p>` : ''}
  ${config.saml.enabled ? `
  <form method="get" action="/auth/saml/login" aria-labelledby="sso-heading">
    <h2 id="sso-heading">Sign in with company SSO</h2>
    <label for="sso-email">Work email</label>
    <input id="sso-email" name="email" type="email" autocomplete="username" required>
    ${returnTo ? `<input type="hidden" name="returnTo" value="${esc(returnTo)}">` : ''}
    <button type="submit">Continue with company SSO</button>
  </form>` : ''}
  ${!config.google.enabled && !config.saml.enabled ? '<p>No sign-in method is configured.</p>' : ''}`);
}

export function createPagesRouter({ config, sessions, audit }) {
  const router = Router();

  router.get('/login', (req, res) => {
    const returnTo = typeof req.query.returnTo === 'string' ? safeReturnTo(req.query.returnTo) : undefined;
    res.type('html').send(loginPage({ config, error: req.query.error, ref: req.query.ref, returnTo }));
  });

  router.get('/portal', (req, res) => {
    const user = sessions.userFor(req);
    if (!user) return res.redirect(303, `/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
    res.type('html').send(layout('Customer portal', `
      <h1>Customer portal</h1>
      <p>Signed in as ${esc(user.email)}.</p>
      <form method="post" action="/logout"><button type="submit">Sign out</button></form>`));
  });

  // POST so that a third-party page cannot sign users out with an image or link.
  router.post('/logout', urlencoded({ extended: false }), (req, res) => {
    const user = sessions.userFor(req);
    sessions.destroy(req, res);
    if (user) audit({ event: 'logout', level: 'info', userId: user.id });
    res.redirect(303, '/login');
  });

  return router;
}
