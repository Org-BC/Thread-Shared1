import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { listen, cookieJar, startMockOidc, makeKeyAndCert } from './helpers.js';

let oidc, portal, db, logs;

before(async () => {
  oidc = await startMockOidc({ clientId: 'cid' });
  const sp = makeKeyAndCert('sp');
  db = openDb();
  logs = [];
  const holder = {};
  portal = await listen((req, res) => holder.app(req, res));
  const config = loadConfig({
    BASE_URL: portal.url, ALLOW_INSECURE_HTTP: 'true',
    GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 'sec', GOOGLE_ISSUER: oidc.url,
    SAML_SP_PRIVATE_KEY: sp.privateKey, SAML_SP_CERT: sp.cert,
  });
  holder.app = createApp({ config, db, audit: (e) => logs.push(e) });
});
after(async () => { await oidc.close(); await portal.close(); });

test('login page offers Google and company SSO with labelled controls', async () => {
  const html = await (await fetch(`${portal.url}/login`)).text();
  assert.match(html, /Sign in with Google/);
  assert.match(html, /Sign in with company SSO/);
  assert.match(html, /<label for="sso-email">/);
  assert.match(html, /id="sso-email"[^>]*type="email"/);
  assert.match(html, /lang="en"/);
});

test('login page shows a generic error and reference, escaping input', async () => {
  const html = await (await fetch(`${portal.url}/login?error=failed&ref=abcdef012345`)).text();
  assert.match(html, /role="alert"/);
  assert.match(html, /Sign-in failed/);
  assert.match(html, /abcdef012345/);
  const evil = await (await fetch(`${portal.url}/login?error=<script>&ref=<script>alert(1)</script>`)).text();
  assert.ok(!evil.includes('<script>'));
  const unavailable = await (await fetch(`${portal.url}/login?error=unavailable`)).text();
  assert.match(unavailable, /Sign-in provider unavailable/);
});

test('an unauthenticated visit to the portal goes to login and returns afterwards; sign-out ends the session', async () => {
  const jar = cookieJar();
  let res = await fetch(`${portal.url}/portal/orders`, { redirect: 'manual' });
  assert.equal(res.status, 404, 'only /portal is a page in this service');

  res = await fetch(`${portal.url}/portal`, { redirect: 'manual' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/login?returnTo=%2Fportal');

  const start = await fetch(`${portal.url}/auth/google?returnTo=/portal`, { redirect: 'manual' });
  jar.store(start);
  const query = oidc.approve(start.headers.get('location'), { sub: 'p-1', email: 'pat@example.com', email_verified: true, name: 'Pat' });
  const cb = await fetch(`${portal.url}/auth/google/callback?${query}`, { redirect: 'manual', headers: { cookie: jar.header() } });
  jar.store(cb);
  assert.equal(cb.headers.get('location'), '/portal');

  const page = await fetch(`${portal.url}/portal`, { headers: { cookie: jar.header() } });
  assert.match(await page.text(), /pat@example\.com/);

  const sessionCookie = jar.get('cpr_session');
  const out = await fetch(`${portal.url}/logout`, { method: 'POST', redirect: 'manual', headers: { cookie: jar.header() } });
  assert.equal(out.status, 303);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
  assert.ok(logs.some((l) => l.event === 'logout'));

  // The old cookie no longer works, even if the browser kept it.
  const replay = await fetch(`${portal.url}/portal`, { redirect: 'manual', headers: { cookie: `cpr_session=${sessionCookie}` } });
  assert.equal(replay.status, 303);
  assert.match(replay.headers.get('location'), /^\/login/);
});

test('GET /logout does not sign anyone out', async () => {
  const res = await fetch(`${portal.url}/logout`, { redirect: 'manual' });
  assert.equal(res.status, 404);
});

test('session cookie is HttpOnly and SameSite=Lax; responses are not cacheable', async () => {
  const start = await fetch(`${portal.url}/auth/google`, { redirect: 'manual' });
  const jar = cookieJar(); jar.store(start);
  const q = oidc.approve(start.headers.get('location'), { sub: 'p-2', email: 'quin@example.com', email_verified: true });
  const cb = await fetch(`${portal.url}/auth/google/callback?${q}`, { redirect: 'manual', headers: { cookie: jar.header() } });
  const setCookie = cb.headers.getSetCookie().find((c) => c.startsWith('cpr_session='));
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Lax/i);
  assert.equal(cb.headers.get('cache-control'), 'no-store');
});
