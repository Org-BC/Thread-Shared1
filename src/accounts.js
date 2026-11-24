import { inTransaction } from './db.js';

export class AuthError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

export function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

// Finds, links or creates the portal account for an external identity.
// A new identity is attached to an existing account (or creates one) only
// when the email is verified; otherwise the login is rejected.
export function resolveExternalIdentity(db, { provider, subject, email, emailVerified, name }) {
  if (!provider || !subject) throw new AuthError('missing_subject');
  const normalized = normalizeEmail(email);
  const now = Date.now();

  return inTransaction(db, () => {
    const identity = db
      .prepare('SELECT user_id FROM external_identities WHERE provider = ? AND subject = ?')
      .get(provider, subject);
    if (identity) {
      const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(identity.user_id);
      return { user, created: false, linked: false };
    }

    if (!normalized || !normalized.includes('@')) throw new AuthError('missing_email');
    if (!emailVerified) throw new AuthError('unverified_email');

    let user = db.prepare('SELECT id, email, name FROM users WHERE email = ?').get(normalized);
    let created = false;
    if (!user) {
      const info = db
        .prepare('INSERT INTO users (email, name, created_at) VALUES (?, ?, ?)')
        .run(normalized, name ?? null, now);
      user = { id: Number(info.lastInsertRowid), email: normalized, name: name ?? null };
      created = true;
    }
    db.prepare(
      'INSERT INTO external_identities (user_id, provider, subject, email, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(user.id, provider, subject, normalized, now);
    return { user, created, linked: !created };
  });
}
