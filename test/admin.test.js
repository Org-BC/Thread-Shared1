import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { validateIdp, ValidationError } from '../src/idps.js';
import { listen, cookieJar, makeKeyAndCert, parseAuthnRequest, buildSamlResponse } from './helpers.js';

let portal, db, logs, config, keys1, keys2, spKeys;
const TOKEN = 'admin-token-for-tests';
const auth = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };

before(async () => {
  keys1 = makeKeyAndCert('idp-old');
  keys2 = makeKeyAndCert('idp-new');
  spKeys = makeKeyAndCert('sp');
  db = openDb();
  logs = [];
  const holder = {};
  portal = await listen((req, res) => holder.app(req, res));
  config = loadConfig({
    BASE_URL: portal.url, ALLOW_INSECURE_HTTP: 'true', ADMIN_API_TOKEN: TOKEN,
    SAML_SP_PRIVATE_KEY: spKeys.privateKey, SAML_SP_CERT: spKeys.cert,
  });
  holder.app = createApp({ config, db, audit: (e) => logs.push(e) });
});
after(() => portal.close());

const put = (id, body, headers = auth) =>
  fetch(`${portal.url}/admin/idps/${id}`, { method: 'PUT', headers, body: JSON.stringify(body) });
const idpBody = (certs, extra = {}) => ({
  entityId: 'https://idp.globex.test/m', ssoUrl: 'https://idp.globex.test/sso',
  certificates: certs, emailDomains: ['globex.com'], ...extra,
});

test('admin API rejects missing or wrong tokens', async () => {
  for (const headers of [{ 'content-type': 'application/json' }, { authorization: 'Bearer nope', 'content-type': 'application/json' }]) {
    const res = await put('globex', idpBody([keys1.cert]), headers);
    assert.equal(res.status, 401);
  }
  assert.equal((await fetch(`${portal.url}/admin/idps`)).status, 401);
});

test('admin API is absent when no token is configured', async () => {
  const holder = {};
  const srv = await listen((req, res) => holder.app(req, res));
  const cfg = loadConfig({ BASE_URL: srv.url, ALLOW_INSECURE_HTTP: 'true' });
  holder.app = createApp({ config: cfg, db: openDb(), audit: () => {} });
  const res = await fetch(`${srv.url}/admin/idps`, { headers: auth });
  assert.equal(res.status, 404);
  await srv.close();
});

test('creates, reads, lists and deletes an IdP without exposing certificates', async () => {
  const created = await put('globex', idpBody([keys1.cert]));
  assert.equal(created.status, 200);
  const body = await created.json();
  assert.equal(body.certificateCount, 1);
  assert.equal(body.certificates, undefined);
  assert.equal((await (await fetch(`${portal.url}/admin/idps`, { headers: auth })).json()).length, 1);
  assert.equal((await fetch(`${portal.url}/admin/idps/globex`, { headers: auth })).status, 200);
  assert.equal((await fetch(`${portal.url}/admin/idps/missing`, { headers: auth })).status, 404);

  assert.equal((await fetch(`${portal.url}/admin/idps/globex`, { method: 'DELETE', headers: auth })).status, 204);
  assert.equal((await fetch(`${portal.url}/admin/idps/globex`, { headers: auth })).status, 404);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM idp_domains').get().n, 0);
});

test('validates input', async () => {
  const bad = [
    idpBody([]),
    idpBody(['not a certificate']),
    idpBody([keys1.cert], { ssoUrl: 'ftp://idp.globex.test/sso' }),
    idpBody([keys1.cert], { ssoUrl: 'javascript:alert(1)' }),
    idpBody([keys1.cert], { emailDomains: [] }),
    idpBody([keys1.cert], { emailDomains: ['bad domain'] }),
  ];
  for (const b of bad) assert.equal((await put('globex', b)).status, 400, JSON.stringify(b).slice(0, 80));
  assert.equal((await put('Bad_ID', idpBody([keys1.cert]))).status, 400);
  const res = await fetch(`${portal.url}/admin/idps/globex`, { method: 'PUT', headers: auth, body: '{not json' });
  assert.equal(res.status, 400);
});

test('a domain cannot be claimed by two IdPs', async () => {
  assert.equal((await put('one', idpBody([keys1.cert], { entityId: 'https://one/m' }))).status, 200);
  const res = await put('two', idpBody([keys1.cert], { entityId: 'https://two/m' }));
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /another identity provider/);
});

test('certificate rotation: old and new certificates are both accepted, then the old one is dropped', async () => {
  await put('rot', idpBody([keys1.cert, keys2.cert], { entityId: 'https://rot/m', emailDomains: ['rot.com'] }));

  async function loginSignedBy(keys, nameId) {
    const jar = cookieJar();
    const start = await fetch(`${portal.url}/auth/saml/login?idp=rot`, { redirect: 'manual' });
    jar.store(start);
    const req = parseAuthnRequest(start.headers.get('location'));
    const saml = buildSamlResponse({
      keys, idpEntityId: 'https://rot/m', spEntityId: config.saml.spEntityId, acsUrl: config.saml.acsUrl,
      inResponseTo: req.id, nameId, attributes: { email: `${nameId}@rot.com` },
    });
    const res = await fetch(`${portal.url}/auth/saml/acs`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
      body: new URLSearchParams({ SAMLResponse: saml, RelayState: req.relayState }),
    });
    jar.store(res);
    return jar.has('cpr_session');
  }

  assert.equal(await loginSignedBy(keys1, 'u1'), true);
  assert.equal(await loginSignedBy(keys2, 'u2'), true);
  // Drop the old certificate: only keys2 is trusted now. No restart needed.
  assert.equal((await put('rot', idpBody([keys2.cert], { entityId: 'https://rot/m', emailDomains: ['rot.com'] }))).status, 200);
  assert.equal(await loginSignedBy(keys1, 'u3'), false);
  assert.equal(await loginSignedBy(keys2, 'u4'), true);
});

test('a disabled IdP cannot be used to sign in', async () => {
  await put('off', idpBody([keys1.cert], { entityId: 'https://off/m', emailDomains: ['off.com'], enabled: false }));
  const res = await fetch(`${portal.url}/auth/saml/login?idp=off`, { redirect: 'manual' });
  assert.match(res.headers.get('location'), /^\/login\?error=failed/);
  const byEmail = await fetch(`${portal.url}/auth/saml/login?email=x@off.com`, { redirect: 'manual' });
  assert.match(byEmail.headers.get('location'), /^\/login\?error=failed/);
});

test('http SSO URLs are rejected unless insecure mode is on', () => {
  const input = { id: 'x', entityId: 'e', ssoUrl: 'http://idp.example/sso', certificates: [keys1.cert], emailDomains: ['x.com'] };
  assert.throws(() => validateIdp(input), ValidationError);
  assert.doesNotThrow(() => validateIdp(input, { allowInsecureHttp: true }));
});
