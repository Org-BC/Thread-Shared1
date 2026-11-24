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
