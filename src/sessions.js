import { createHash, randomBytes } from 'node:crypto';

export const SESSION_COOKIE = 'cpr_session';
export const TX_COOKIE = 'cpr_tx';

export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    if (key && !(key in out)) out[key] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function createSessions(db, config) {
  const cookieBase = { httpOnly: true, secure: config.secureCookies, sameSite: 'lax', path: '/' };

  return {
    issue(res, userId) {
      const token = randomToken();
      const ttlMs = config.sessionTtlSeconds * 1000;
      db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
        sha256(token),
        userId,
        Date.now() + ttlMs,
      );
      res.cookie(SESSION_COOKIE, token, { ...cookieBase, maxAge: ttlMs });
    },

    userFor(req) {
      const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      if (!token) return null;
      return (
        db
          .prepare(
            `SELECT u.id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.expires_at > ?`,
          )
          .get(sha256(token), Date.now()) ?? null
      );
    },

    destroy(req, res) {
      const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
      res.clearCookie(SESSION_COOKIE, cookieBase);
    },
  };
}

// Short-lived transaction for one login attempt. `id` travels through the
// provider (OAuth `state` / SAML `RelayState`); `binder` stays in a cookie
// so only the browser that started the login can finish it.
export function createTransactions(db, config) {
  const ttlMs = 10 * 60 * 1000;
  // SAML responses come back as a cross-site POST, which SameSite=Lax cookies
  // do not accompany; SameSite=None requires Secure, i.e. https.
  const cookieOpts = {
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: config.secureCookies ? 'none' : 'lax',
    path: '/auth',
    maxAge: ttlMs,
  };

  return {
    begin(res, kind, data) {
      const id = randomToken(24);
      const binder = randomToken(24);
      db.prepare(
        'INSERT INTO auth_transactions (id, kind, binder_hash, data, expires_at) VALUES (?, ?, ?, ?, ?)',
      ).run(id, kind, sha256(binder), JSON.stringify(data), Date.now() + ttlMs);
      res.cookie(TX_COOKIE, binder, cookieOpts);
      return id;
    },

    // Single use: the row is deleted whether or not it matches.
    consume(req, res, kind, id) {
      res.clearCookie(TX_COOKIE, { ...cookieOpts, maxAge: undefined });
      if (typeof id !== 'string' || !id) return null;
      const row = db.prepare('SELECT * FROM auth_transactions WHERE id = ?').get(id);
      if (!row) return null;
      db.prepare('DELETE FROM auth_transactions WHERE id = ?').run(id);
      const binder = parseCookies(req.headers.cookie)[TX_COOKIE];
      if (row.kind !== kind || row.expires_at <= Date.now() || !binder) return null;
      if (sha256(binder) !== row.binder_hash) return null;
      return JSON.parse(row.data);
    },
  };
}

// Only same-site relative paths may be used as a post-login destination.
export function safeReturnTo(value) {
  if (typeof value !== 'string' || !value.startsWith('/')) return '/portal';
  if (value.startsWith('//') || value.includes('\\') || /[\r\n]/.test(value)) return '/portal';
  return value;
}
