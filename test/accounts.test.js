import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { resolveExternalIdentity, AuthError } from '../src/accounts.js';
import { loadConfig } from '../src/config.js';
import { safeReturnTo } from '../src/sessions.js';

const google = { provider: 'google', subject: 'g-1', email: 'Ann@Example.com', emailVerified: true, name: 'Ann' };

test('creates a new account linked to the external identity', () => {
  const db = openDb();
  const r = resolveExternalIdentity(db, google);
  assert.equal(r.created, true);
  assert.equal(r.user.email, 'ann@example.com');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM external_identities').get().n, 1);
});

test('returns the same account on a repeat login', () => {
  const db = openDb();
  const a = resolveExternalIdentity(db, google);
  const b = resolveExternalIdentity(db, { ...google, emailVerified: false });
  assert.equal(b.user.id, a.user.id);
  assert.equal(b.created, false);
});

test('links to an existing account when the email is verified', () => {
  const db = openDb();
  db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)').run('ann@example.com', 1);
  const r = resolveExternalIdentity(db, google);
  assert.equal(r.created, false);
  assert.equal(r.linked, true);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 1);
});

test('rejects linking when the email is not verified', () => {
  const db = openDb();
  db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)').run('ann@example.com', 1);
  assert.throws(() => resolveExternalIdentity(db, { ...google, emailVerified: false }), (e) => {
    return e instanceof AuthError && e.reason === 'unverified_email';
  });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM external_identities').get().n, 0);
});

test('rejects missing email for a new identity', () => {
  const db = openDb();
  assert.throws(() => resolveExternalIdentity(db, { ...google, email: '' }), AuthError);
});

test('config reads secrets from env and requires https', () => {
  const cfg = loadConfig({ BASE_URL: 'https://p.example.com', GOOGLE_CLIENT_ID: 'id', GOOGLE_CLIENT_SECRET: 's' });
  assert.equal(cfg.google.enabled, true);
  assert.equal(cfg.google.redirectUri, 'https://p.example.com/auth/google/callback');
  assert.equal(cfg.saml.enabled, false);
  assert.throws(() => loadConfig({ BASE_URL: 'http://p.example.com' }));
  assert.throws(() => loadConfig({}));
});

test('safeReturnTo only allows local paths', () => {
  assert.equal(safeReturnTo('/portal/orders?x=1'), '/portal/orders?x=1');
  for (const bad of ['//evil.com', 'https://evil.com', '/\\evil.com', undefined, '/a\r\nSet-Cookie: x']) {
    assert.equal(safeReturnTo(bad), '/portal');
  }
});
