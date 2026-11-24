import { Router, urlencoded } from 'express';
import { SAML, generateServiceProviderMetadata, ValidateInResponseTo } from '@node-saml/node-saml';
import { resolveExternalIdentity, AuthError, normalizeEmail } from './accounts.js';
import { failLogin, succeedLogin } from './login-flow.js';
import { safeReturnTo } from './sessions.js';
import { createSqlCache } from './sql-cache.js';

const first = (v) => (Array.isArray(v) ? v.find((x) => typeof x === 'string') : typeof v === 'string' ? v : undefined);

export function createSamlRouter({ config, db, audit, sessions, transactions, idps }) {
  const router = Router();
  const s = config.saml;

  // One SAML instance per IdP and request. State lives in the shared SQL cache.
  function samlFor(idp) {
    return new SAML({
      callbackUrl: s.acsUrl,
      entryPoint: idp.ssoUrl,
      issuer: s.spEntityId,
      audience: s.spEntityId,
      idpIssuer: idp.entityId,
      idpCert: idp.certificates,
      privateKey: s.privateKey,
      decryptionPvk: s.privateKey,
      signatureAlgorithm: 'sha256',
      digestAlgorithm: 'sha256',
      identifierFormat: null,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.always,
      rejectReplayedAssertions: true,
      acceptedClockSkewMs: s.clockSkewMs,
      requestIdExpirationPeriodMs: s.requestTtlMs,
      cacheProvider: createSqlCache(db, `saml:${idp.id}`, s.requestTtlMs),
    });
  }

  router.get('/auth/saml/metadata', (req, res) => {
    if (!s.enabled) return res.status(404).type('text/plain').send('SAML is not configured');
    const xml = generateServiceProviderMetadata({
      issuer: s.spEntityId,
      callbackUrl: s.acsUrl,
      publicCerts: s.cert,
      decryptionCert: s.cert,
      decryptionPvk: s.privateKey,
      wantAssertionsSigned: true,
      identifierFormat: null,
    });
    res.type('application/samlmetadata+xml').send(xml);
  });

  // Starts SP-initiated SSO, for an IdP named explicitly or found through the user's email domain.
  router.get('/auth/saml/login', async (req, res) => {
    const fail = (reason, extra) => failLogin(res, audit, { method: 'saml', provider: 'saml', reason, ...extra });
    if (!s.enabled) return fail('not_configured');

    const idp =
      typeof req.query.idp === 'string'
        ? idps.get(req.query.idp)
        : typeof req.query.email === 'string'
          ? idps.findByEmail(req.query.email)
          : null;
    if (!idp || !idp.enabled) return fail('unknown_idp');

    try {
      const relayState = transactions.begin(res, 'saml', { idpId: idp.id, returnTo: safeReturnTo(req.query.returnTo) });
      const url = await samlFor(idp).getAuthorizeUrlAsync(relayState, undefined);
      res.redirect(303, url);
    } catch (err) {
      failLogin(res, audit, {
        method: 'saml', provider: `saml:${idp.id}`, reason: `authn_request_failed:${err?.name}`,
        userUnavailable: true, level: 'error',
      });
    }
  });

  router.post('/auth/saml/acs', urlencoded({ extended: false, limit: '512kb' }), async (req, res) => {
    const fail = (reason, provider = 'saml', extra) => failLogin(res, audit, { method: 'saml', provider, reason, ...extra });
    if (!s.enabled) return fail('not_configured');

    const tx = transactions.consume(req, res, 'saml', req.body?.RelayState);
    if (!tx) return fail('invalid_relay_state');
    const idp = idps.get(tx.idpId);
    if (!idp || !idp.enabled) return fail('unknown_idp');
    const provider = `saml:${idp.id}`;
    if (typeof req.body.SAMLResponse !== 'string') return fail('missing_response', provider);

    try {
      const { profile } = await samlFor(idp).validatePostResponseAsync({ SAMLResponse: req.body.SAMLResponse });
      if (!profile) return fail('no_profile', provider);

      const emailAttr = first(profile[idp.attributeMapping.email]) ?? first(profile.email) ?? first(profile.mail);
      const nameId = typeof profile.nameID === 'string' ? profile.nameID : undefined;
      const email = normalizeEmail(emailAttr ?? (nameId?.includes('@') ? nameId : ''));
      // The IdP may only vouch for addresses in the domains it is configured for.
      const domain = email.split('@')[1];
      if (!domain || !idp.emailDomains.includes(domain)) return fail('domain_not_allowed', provider);

      const result = resolveExternalIdentity(db, {
        provider,
        subject: nameId,
        email,
        emailVerified: true,
        name: first(profile[idp.attributeMapping.name]),
      });
      succeedLogin(res, audit, sessions, {
        method: 'saml', provider, userId: result.user.id,
        created: result.created, linked: result.linked, returnTo: tx.returnTo,
      });
    } catch (err) {
      if (err instanceof AuthError) return fail(err.reason, provider);
      fail(`assertion_rejected:${String(err?.message ?? err?.name).slice(0, 80)}`, provider);
    }
  });

  return router;
}
