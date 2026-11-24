import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { createIdpStore } from '../src/idps.js';
import { listen, cookieJar, makeKeyAndCert, parseAuthnRequest, buildSamlResponse } from './helpers.js';

const IDP_ENTITY = 'https://idp.acme.test/metadata';
let portal, db, logs, spKeys, idpKeys, otherKeys, config;

before(async () => {
  spKeys = makeKeyAndCert('sp');
  idpKeys = makeKeyAndCert('acme-idp');
  otherKeys = makeKeyAndCert('attacker');
  db = openDb();
  logs = [];
  const holder = {};
  portal = await listen((req, res) => holder.app(req, res));
  config = loadConfig({
    BASE_URL: portal.url,
    ALLOW_INSECURE_HTTP: 'true',
    SAML_SP_PRIVATE_KEY: spKeys.privateKey,
    SAML_SP_CERT: spKeys.cert,
  });
  createIdpStore(db, { allowInsecureHttp: true }).upsert({
    id: 'acme', entityId: IDP_ENTITY, ssoUrl: 'https://idp.acme.test/sso',
    certificates: [idpKeys.cert], emailDomains: ['acme.com'],
    attributeMapping: { email: 'email', name: 'displayName' },
  });
  holder.app = createApp({ config, db, audit: (e) => logs.push(e) });
});
after(() => portal.close());

async function begin(jar, query = 'idp=acme') {
  const res = await fetch(`${portal.url}/auth/saml/login?${query}`, { redirect: 'manual' });
  jar.store(res);
  return res;
}
const respond = (req, over = {}) =>
  buildSamlResponse({
    keys: idpKeys, idpEntityId: IDP_ENTITY, spEntityId: config.saml.spEntityId, acsUrl: config.saml.acsUrl,
    inResponseTo: req.id, nameId: 'acme-user-1',
    attributes: { email: 'Eve@Acme.com', displayName: 'Eve' }, ...over,
  });
async function acs(jar, samlResponse, relayState) {
  const res = await fetch(`${portal.url}/auth/saml/acs`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
    body: new URLSearchParams({ SAMLResponse: samlResponse, RelayState: relayState }),
  });
  jar.store(res);
  return res;
}
async function attempt(over = {}, mutate) {
  const jar = cookieJar();
  const start = await begin(jar, `idp=acme&returnTo=${encodeURIComponent('/portal/billing')}`);
  assert.equal(start.status, 303);
  const req = parseAuthnRequest(start.headers.get('location'));
  let saml = respond(req, over);
  if (mutate) saml = mutate(saml);
  return { jar, req, saml, res: await acs(jar, saml, req.relayState) };
}
const failed = (res) => /^\/login\?error=failed&ref=/.test(res.headers.get('location') ?? '');

test('metadata publishes entity ID, ACS URL and the SP certificate', async () => {
  const res = await fetch(`${portal.url}/auth/saml/metadata`);
  assert.equal(res.status, 200);
  const xml = await res.text();
  assert.match(xml, /EntityDescriptor/);
  assert.ok(xml.includes(`entityID="${config.saml.spEntityId}"`));
  assert.ok(xml.includes(`Location="${config.saml.acsUrl}"`));
  assert.match(xml, /X509Certificate/);
  assert.ok(!xml.includes('PRIVATE KEY'));
});

test('SP-initiated login sends an AuthnRequest by HTTP-Redirect to the IdP', async () => {
  const jar = cookieJar();
  const res = await begin(jar);
  const loc = new URL(res.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, 'https://idp.acme.test/sso');
  const req = parseAuthnRequest(res.headers.get('location'));
  assert.match(req.xml, /AuthnRequest/);
  assert.ok(req.xml.includes(config.saml.acsUrl));
  assert.ok(req.relayState);
  assert.ok(req.params.get('Signature'), 'request is signed');
});

test('login resolves the IdP from a work email domain', async () => {
  const res = await begin(cookieJar(), 'email=someone@ACME.com');
  assert.equal(res.status, 303);
  assert.ok(res.headers.get('location').startsWith('https://idp.acme.test/sso'));
  const unknown = await begin(cookieJar(), 'email=someone@other.org');
  assert.match(unknown.headers.get('location'), /^\/login\?error=failed/);
});

test('a valid assertion creates the account and session and returns to the requested page', async () => {
  const { jar, res } = await attempt();
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/portal/billing');
  assert.ok(jar.has('cpr_session'));
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get('eve@acme.com');
  assert.equal(user.name, 'Eve');
  assert.equal(db.prepare('SELECT provider, subject FROM external_identities WHERE user_id = ?').get(user.id).provider, 'saml:acme');
  const ok = logs.findLast((l) => l.event === 'login_success');
  assert.equal(ok.method, 'saml');
  assert.equal(ok.provider, 'saml:acme');
});

test('rejects an assertion signed with the wrong key', async () => {
  const { jar, res } = await attempt({ keys: { ...idpKeys, privateKey: otherKeys.privateKey, cert: otherKeys.cert } });
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
});

test('rejects an unsigned assertion', async () => {
  const { jar, res } = await attempt({ sign: false });
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
});

test('rejects a tampered assertion', async () => {
  const { jar, res } = await attempt({}, (b64) =>
    Buffer.from(Buffer.from(b64, 'base64').toString().replace('Eve@Acme.com', 'ceo@acme.com')).toString('base64'));
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get('ceo@acme.com').n, 0);
});

test('rejects an expired assertion', async () => {
  const { jar, res } = await attempt({ notBeforeMs: Date.now() - 3_600_000, notOnOrAfterMs: Date.now() - 1_800_000 });
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
});

test('rejects an assertion addressed to another audience', async () => {
  const { jar, res } = await attempt({ audience: 'https://other-sp.example/metadata' });
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
});

test('rejects a response that answers a different request', async () => {
  const { jar, res } = await attempt({ inResponseTo: '_not-issued-by-us' });
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
});

test('rejects an unsolicited response without a login transaction', async () => {
  const jar = cookieJar();
  const saml = buildSamlResponse({
    keys: idpKeys, idpEntityId: IDP_ENTITY, spEntityId: config.saml.spEntityId, acsUrl: config.saml.acsUrl,
    inResponseTo: '_x', attributes: { email: 'eve@acme.com' },
  });
  const res = await acs(jar, saml, 'forged-relay-state');
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
});

test('rejects a replayed assertion', async () => {
  const first = await attempt({ assertionId: '_replay-1', attributes: { email: 'replay@acme.com' } });
  assert.equal(first.res.status, 303);
  assert.ok(first.jar.has('cpr_session'));
  // Replay the very same SAMLResponse inside a new, valid login transaction.
  const jar = cookieJar();
  const start = await begin(jar);
  parseAuthnRequest(start.headers.get('location'));
  const res = await acs(jar, first.saml, parseAuthnRequest(start.headers.get('location')).relayState);
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
  // And replaying into the original (already consumed) transaction fails too.
  const res2 = await acs(first.jar, first.saml, first.req.relayState);
  assert.ok(failed(res2));
});

test('rejects an email outside the IdP\'s configured domains', async () => {
  const { jar, res } = await attempt({ attributes: { email: 'admin@victim.com' }, assertionId: '_dom-1' });
  assert.ok(failed(res));
  assert.ok(!jar.has('cpr_session'));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE email = ?').get('admin@victim.com').n, 0);
});

test('failures are logged without the assertion contents', async () => {
  await attempt({ sign: false, assertionId: '_log-1' });
  const failure = logs.findLast((l) => l.event === 'login_failure' && l.method === 'saml');
  assert.equal(failure.provider, 'saml:acme');
  assert.ok(failure.reason);
  const dump = JSON.stringify(logs);
  assert.ok(!dump.includes('SAMLResponse') && !dump.includes('PRIVATE KEY'));
});
