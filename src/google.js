import { Router } from 'express';
import * as oidc from 'openid-client';
import { resolveExternalIdentity, AuthError } from './accounts.js';
import { failLogin, succeedLogin } from './login-flow.js';
import { safeReturnTo } from './sessions.js';

export function createGoogleRouter({ config, db, audit, sessions, transactions }) {
  const router = Router();
  const g = config.google;
  let discovered = null;

  // Discovery is retried on the next request if Google was unreachable.
  async function getConfiguration() {
    if (!discovered) {
      const options = config.allowInsecureHttp ? { execute: [oidc.allowInsecureRequests] } : undefined;
      discovered = oidc.discovery(new URL(g.issuer), g.clientId, g.clientSecret, undefined, options).catch((err) => {
        discovered = null;
        throw err;
      });
    }
    return discovered;
  }

  router.get('/auth/google', async (req, res) => {
    if (!g.enabled) return failLogin(res, audit, { method: 'oauth', provider: 'google', reason: 'not_configured' });
    try {
      const oc = await getConfiguration();
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const nonce = oidc.randomNonce();
      const state = transactions.begin(res, 'google', {
        codeVerifier,
        nonce,
        returnTo: safeReturnTo(req.query.returnTo),
      });
      const url = oidc.buildAuthorizationUrl(oc, {
        redirect_uri: g.redirectUri,
        scope: 'openid email profile',
        response_type: 'code',
        code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: 'S256',
        state,
        nonce,
      });
      res.redirect(303, url.href);
    } catch (err) {
      failLogin(res, audit, {
        method: 'oauth', provider: 'google', reason: `discovery_failed:${err.code ?? err.name}`,
        userUnavailable: true, level: 'error',
      });
    }
  });

  router.get('/auth/google/callback', async (req, res) => {
    const fail = (reason, extra) => failLogin(res, audit, { method: 'oauth', provider: 'google', reason, ...extra });
    if (!g.enabled) return fail('not_configured');

    const tx = transactions.consume(req, res, 'google', req.query.state);
    if (!tx) return fail('invalid_state');
    if (req.query.error) return fail(`provider_error:${String(req.query.error).slice(0, 40)}`);

    try {
      const oc = await getConfiguration();
      // Rebuild the URL from configuration, not from the Host header.
      const currentUrl = new URL(g.redirectUri);
      currentUrl.search = new URLSearchParams(
        Object.entries(req.query).filter(([, v]) => typeof v === 'string'),
      ).toString();
      const tokens = await oidc.authorizationCodeGrant(oc, currentUrl, {
        pkceCodeVerifier: tx.codeVerifier,
        expectedNonce: tx.nonce,
        expectedState: req.query.state,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      const result = resolveExternalIdentity(db, {
        provider: 'google',
        subject: claims.sub,
        email: claims.email,
        emailVerified: claims.email_verified === true,
        name: claims.name,
      });
      succeedLogin(res, audit, sessions, {
        method: 'oauth', provider: 'google', userId: result.user.id,
        created: result.created, linked: result.linked, returnTo: tx.returnTo,
      });
    } catch (err) {
      if (err instanceof AuthError) return fail(err.reason);
      const network = err instanceof TypeError || err?.code === 'OAUTH_RESPONSE_IS_NOT_JSON';
      fail(`token_validation_failed:${err?.code ?? err?.name}`, { userUnavailable: network, level: 'warn' });
    }
  });

  return router;
}
