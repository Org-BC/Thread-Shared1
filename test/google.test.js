import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { listen, cookieJar, startMockOidc } from './helpers.js';

let oidc, portal, db, logs;
const CLIENT_ID = 'cid';

before(async () => {
  oidc = await startMockOidc({ clientId: CLIENT_ID });
  db = openDb();
  logs = [];
  const holder = {};
  portal = await listen((req, res) => holder.app(req, res));
  const config = loadConfig({
    BASE_URL: portal.url,
    ALLOW_INSECURE_HTTP: 'true',
    GOOGLE_CLIENT_ID: CLIENT_ID,
    GOOGLE_CLIENT_SECRET: 'super-secret-value',
    GOOGLE_ISSUER: oidc.url,
  });
  holder.app = createApp({ config, db, audit: (event) => logs.push(event) });
});
after(async () => {
  await oidc.close();
  await portal.close();
});

const claims = (over = {}) => ({ sub: 'sub-1', email: 'ann@example.com', email_verified: true, name: 'Ann', ...over });

async function startLogin(jar, returnTo) {
  const q = returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : '';
  const res = await fetch(`${portal.url}/auth/google${q}`, { redirect: 'manual' });
  jar.store(res);
  return res;
}
async function callback(jar, query) {
  const res = await fetch(`${portal.url}/auth/google/callback?${query}`, {
    redirect: 'manual',
    headers: { cookie: jar.header() },
  });
  jar.store(res);
  return res;
}

test('login redirects to Google with PKCE, state and nonce, and never leaks the secret', async () => {
  const jar = cookieJar();
  const res = await startLogin(jar);
  assert.equal(res.status, 303);
  const loc = new URL(res.headers.get('location'));
  assert.equal(loc.origin, oidc.url);
  assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(loc.searchParams.get('state') && loc.searchParams.get('nonce'));
  assert.equal(loc.searchParams.get('client_id'), CLIENT_ID);
  assert.ok(!res.headers.get('location').includes('super-secret-value'));
  assert.ok(jar.has('cpr_tx'));
});

test('full flow creates an account, a session and redirects to the requested page', async () => {
  const jar = cookieJar();
  const start = await startLogin(jar, '/portal/orders');
  const query = oidc.approve(start.headers.get('location'), claims());
  const res = await callback(jar, query);
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/portal/orders');
  assert.ok(jar.has('cpr_session'));
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get('ann@example.com');
  assert.ok(user);
  assert.equal(db.prepare('SELECT subject FROM external_identities WHERE user_id = ?').get(user.id).subject, 'sub-1');
  const success = logs.findLast((l) => l.event === 'login_success');
  assert.equal(success.method, 'oauth');
  assert.equal(success.provider, 'google');
  assert.ok(!JSON.stringify(logs).includes('super-secret-value'));
});

test('an external returnTo is replaced by the default page', async () => {
  const jar = cookieJar();
  const start = await startLogin(jar, 'https://evil.example/');
  const res = await callback(jar, oidc.approve(start.headers.get('location'), claims({ sub: 'sub-2', email: 'bob@example.com' })));
  assert.equal(res.headers.get('location'), '/portal');
});

test('links to an existing account only when Google verified the email', async () => {
  db.prepare('INSERT INTO users (email, created_at) VALUES (?, ?)').run('carl@example.com', 1);

  let jar = cookieJar();
  let start = await startLogin(jar);
  let res = await callback(jar, oidc.approve(start.headers.get('location'), claims({ sub: 'sub-3', email: 'carl@example.com', email_verified: false })));
  assert.match(res.headers.get('location'), /^\/login\?error=failed&ref=/);
  assert.ok(!jar.has('cpr_session'));

  jar = cookieJar();
  start = await startLogin(jar);
  res = await callback(jar, oidc.approve(start.headers.get('location'), claims({ sub: 'sub-3', email: 'carl@example.com' })));
  assert.equal(res.headers.get('location'), '/portal');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get('carl@example.com').n, 1);
});

test('rejects a missing or mismatched state', async () => {
  const jar = cookieJar();
  const start = await startLogin(jar);
  const query = oidc.approve(start.headers.get('location'), claims({ sub: 'sub-4' }));
  const code = new URLSearchParams(query).get('code');

  const res = await callback(jar, `code=${code}&state=wrong`);
  assert.match(res.headers.get('location'), /^\/login\?error=failed/);
  assert.ok(!jar.has('cpr_session'));
  // The transaction is single-use: the right state no longer works either.
  const again = await callback(jar, query);
  assert.match(again.headers.get('location'), /^\/login\?error=failed/);

  const noState = await callback(cookieJar(), `code=${code}`);
  assert.match(noState.headers.get('location'), /^\/login\?error=failed/);
});

test('rejects a callback from a browser that did not start the login', async () => {
  const jar = cookieJar();
  const start = await startLogin(jar);
  const query = oidc.approve(start.headers.get('location'), claims({ sub: 'sub-5' }));
  const res = await callback(cookieJar(), query);
  assert.match(res.headers.get('location'), /^\/login\?error=failed/);
});

test('rejects a wrong nonce, audience, issuer or expired token', async () => {
  const cases = [
    { nonce: 'other' },
    { aud: 'someone-else' },
    { iss: 'https://evil.example' },
    { exp: Math.floor(Date.now() / 1000) - 3600 },
  ];
  for (const override of cases) {
    oidc.state.tokenOverrides = override;
    const jar = cookieJar();
    const start = await startLogin(jar);
    const res = await callback(jar, oidc.approve(start.headers.get('location'), claims({ sub: 'sub-6', email: 'dan@example.com' })));
    assert.match(res.headers.get('location'), /^\/login\?error=/, JSON.stringify(override));
    assert.ok(!jar.has('cpr_session'), JSON.stringify(override));
  }
  oidc.state.tokenOverrides = {};
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get('dan@example.com').n, 0);
});

test('user denying consent yields a generic error and no session', async () => {
  const jar = cookieJar();
  const start = await startLogin(jar);
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const res = await callback(jar, `error=access_denied&state=${encodeURIComponent(state)}`);
  assert.match(res.headers.get('location'), /^\/login\?error=failed&ref=[0-9a-f]+$/);
  assert.ok(!jar.has('cpr_session'));
  assert.ok(logs.some((l) => l.event === 'login_failure' && /provider_error/.test(l.reason)));
});
