import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { createAudit } from '../src/audit.js';
import { listen, cookieJar, startMockOidc } from './helpers.js';

let oidc, portal, lines;

before(async () => {
  oidc = await startMockOidc({ clientId: 'cid' });
  lines = [];
  const holder = {};
  portal = await listen((req, res) => holder.app(req, res));
  const config = loadConfig({
    BASE_URL: portal.url, ALLOW_INSECURE_HTTP: 'true',
    GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 'client-secret-xyz', GOOGLE_ISSUER: oidc.url,
  });
  holder.app = createApp({ config, db: openDb(), audit: createAudit((l) => lines.push(l)) });
});
after(async () => { await oidc.close(); await portal.close(); });

test('success and failure are logged as JSON with method and provider, and no secrets', async () => {
  const jar = cookieJar();
  const start = await fetch(`${portal.url}/auth/google`, { redirect: 'manual' });
  jar.store(start);
  const q = oidc.approve(start.headers.get('location'), { sub: 'a-1', email: 'ann@example.com', email_verified: true });
  const ok = await fetch(`${portal.url}/auth/google/callback?${q}`, { redirect: 'manual', headers: { cookie: jar.header() } });
  jar.store(ok);
  await fetch(`${portal.url}/auth/google/callback?code=abc&state=zzz`, { redirect: 'manual' });

  const events = lines.map((l) => JSON.parse(l));
  const success = events.find((e) => e.event === 'login_success');
  const failure = events.find((e) => e.event === 'login_failure');
  assert.deepEqual([success.method, success.provider], ['oauth', 'google']);
  assert.deepEqual([failure.method, failure.provider], ['oauth', 'google']);
  assert.ok(success.ts && failure.ref);

  const dump = lines.join('\n');
  assert.ok(!dump.includes('client-secret-xyz'));
  assert.ok(!dump.includes(jar.get('cpr_session')));
  assert.ok(!dump.includes(new URL(start.headers.get('location')).searchParams.get('code_challenge')));
  assert.ok(!/id_token|access_token|SAMLResponse/.test(dump));
});

test('the reference shown to the user matches the logged failure', async () => {
  const res = await fetch(`${portal.url}/auth/google/callback?code=abc&state=zzz`, { redirect: 'manual' });
  const ref = new URL(res.headers.get('location'), portal.url).searchParams.get('ref');
  assert.match(ref, /^[0-9a-f]{12}$/);
  assert.ok(lines.map((l) => JSON.parse(l)).some((e) => e.ref === ref && e.reason === 'invalid_state'));
});

async function appWith(issuer) {
  const holder = {};
  const srv = await listen((req, res) => holder.app(req, res));
  const config = loadConfig({
    BASE_URL: srv.url, ALLOW_INSECURE_HTTP: 'true',
    GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 's', GOOGLE_ISSUER: issuer,
  });
  const events = [];
  holder.app = createApp({ config, db: openDb(), audit: (e) => events.push(e) });
  return { srv, events };
}

test('when Google cannot be reached at login the user sees the "provider unavailable" message', async () => {
  const dead = await listen(() => {});
  const deadUrl = dead.url;
  await dead.close();
  const { srv, events } = await appWith(deadUrl);
  const res = await fetch(`${srv.url}/auth/google`, { redirect: 'manual' });
  assert.match(res.headers.get('location'), /^\/login\?error=unavailable&ref=/);
  const page = await (await fetch(`${srv.url}${res.headers.get('location')}`)).text();
  assert.match(page, /Sign-in provider unavailable/);
  assert.ok(events.some((e) => e.level === 'error' && /discovery_failed/.test(e.reason)));
  await srv.close();
});

test('when Google goes down during the code exchange the user sees "provider unavailable"', async () => {
  const o = await startMockOidc({ clientId: 'cid' });
  const { srv } = await appWith(o.url);
  const jar = cookieJar();
  const start = await fetch(`${srv.url}/auth/google`, { redirect: 'manual' });
  jar.store(start);
  const q = o.approve(start.headers.get('location'), { sub: 'z', email: 'z@example.com', email_verified: true });
  await o.close();
  const res = await fetch(`${srv.url}/auth/google/callback?${q}`, { redirect: 'manual', headers: { cookie: jar.header() } });
  assert.match(res.headers.get('location'), /^\/login\?error=unavailable&ref=/);
  jar.store(res);
  assert.ok(!jar.has('cpr_session'));
  await srv.close();
});
