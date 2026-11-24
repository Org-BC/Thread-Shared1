import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

export function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

export function cookieJar() {
  const jar = new Map();
  return {
    store(res) {
      for (const c of res.headers.getSetCookie()) {
        const [pair, ...attrs] = c.split(';');
        const i = pair.indexOf('=');
        const name = pair.slice(0, i);
        const value = pair.slice(i + 1);
        const expired = attrs.some((a) => /^\s*(max-age=0|expires=thu, 01 jan 1970)/i.test(a));
        if (expired || value === '') jar.delete(name);
        else jar.set(name, value);
      }
    },
    header: () => [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
    get: (name) => jar.get(name),
    has: (name) => jar.has(name),
    delete: (name) => jar.delete(name),
  };
}

// Minimal fake Google: discovery, JWKS, and a token endpoint that signs ID tokens.
export async function startMockOidc({ clientId }) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  const codes = new Map();
  const state = { issuer: null, tokenOverrides: {} };

  const srv = await listen(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const send = (code, body) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (u.pathname === '/.well-known/openid-configuration') {
      return send(200, {
        issuer: state.issuer,
        authorization_endpoint: `${state.issuer}/authorize`,
        token_endpoint: `${state.issuer}/token`,
        jwks_uri: `${state.issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (u.pathname === '/jwks') return send(200, { keys: [jwk] });
    if (u.pathname === '/token' && req.method === 'POST') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const entry = codes.get(form.get('code'));
      if (!entry || !form.get('code_verifier') || form.get('grant_type') !== 'authorization_code') {
        return send(400, { error: 'invalid_grant' });
      }
      codes.delete(form.get('code'));
      const o = { ...entry.claims, ...state.tokenOverrides };
      const jwt = new SignJWT({ email: o.email, email_verified: o.email_verified, name: o.name, nonce: o.nonce ?? entry.nonce })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer(o.iss ?? state.issuer)
        .setAudience(o.aud ?? clientId)
        .setSubject(o.sub)
        .setIssuedAt()
        .setExpirationTime(o.exp ?? '5m');
      return send(200, { access_token: 'at', token_type: 'Bearer', id_token: await jwt.sign(privateKey) });
    }
    send(404, {});
  });
  state.issuer = srv.url;

  return {
    ...srv,
    state,
    // Simulates the user authenticating at Google: returns the callback query string.
    approve(authUrl, claims) {
      const q = new URL(authUrl).searchParams;
      if (q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge')) throw new Error('PKCE missing');
      if (!q.get('state') || !q.get('nonce')) throw new Error('state/nonce missing');
      const code = randomUUID();
      codes.set(code, { claims, nonce: q.get('nonce') });
      return `code=${code}&state=${encodeURIComponent(q.get('state'))}`;
    },
  };
}

// ---- SAML test IdP -------------------------------------------------------
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { SignedXml } from 'xml-crypto';

export function makeKeyAndCert(cn = 'test-idp') {
  const dir = mkdtempSync(join(tmpdir(), 'cpr-cert-'));
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
      '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-subj', `/CN=${cn}`,
    ], { stdio: 'ignore' });
    return { privateKey: readFileSync(join(dir, 'k.pem'), 'utf8'), cert: readFileSync(join(dir, 'c.pem'), 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export function parseAuthnRequest(redirectUrl) {
  const q = new URL(redirectUrl).searchParams;
  const xml = inflateRawSync(Buffer.from(q.get('SAMLRequest'), 'base64')).toString('utf8');
  return {
    xml,
    id: /ID="([^"]+)"/.exec(xml)[1],
    issuer: />([^<]+)<\/saml:Issuer>/.exec(xml)?.[1],
    relayState: q.get('RelayState'),
    params: q,
  };
}

const iso = (ms) => new Date(ms).toISOString();

export function buildSamlResponse({
  keys, idpEntityId, spEntityId, acsUrl, inResponseTo, nameId = 'user-1', attributes = {},
  audience = spEntityId, notBeforeMs = Date.now() - 60_000, notOnOrAfterMs = Date.now() + 5 * 60_000,
  assertionId = `_a${randomUUID()}`, sign = true, signKey = keys.privateKey,
}) {
  const attrXml = Object.entries(attributes)
    .map(([k, v]) => `<saml:Attribute Name="${k}"><saml:AttributeValue>${v}</saml:AttributeValue></saml:Attribute>`)
    .join('');
  const now = Date.now();
  let assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${iso(now)}">` +
    `<saml:Issuer>${idpEntityId}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${iso(notOnOrAfterMs)}" Recipient="${acsUrl}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(notBeforeMs)}" NotOnOrAfter="${iso(notOnOrAfterMs)}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement>${attrXml}</saml:AttributeStatement></saml:Assertion>`;

  if (sign) {
    const sig = new SignedXml({
      privateKey: signKey,
      publicCert: keys.cert,
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    });
    sig.computeSignature(assertion, { location: { reference: "//*[local-name(.)='Issuer']", action: 'after' } });
    assertion = sig.getSignedXml();
  }

  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r${randomUUID()}" Version="2.0" IssueInstant="${iso(now)}" Destination="${acsUrl}" InResponseTo="${inResponseTo}">` +
    `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${idpEntityId}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  return Buffer.from(response).toString('base64');
}
