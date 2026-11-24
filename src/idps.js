import { X509Certificate } from 'node:crypto';
import { inTransaction } from './db.js';

const ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const ATTR_RE = /^[\w.:/@+#-]{1,200}$/;

export class ValidationError extends Error {}

export function normalizePem(cert) {
  const body = String(cert).replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  if (!body) throw new ValidationError('certificate is empty');
  const pem = `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  try {
    new X509Certificate(pem);
  } catch {
    throw new ValidationError('certificate is not a valid X.509 certificate');
  }
  return pem;
}

export function validateIdp(input, { allowInsecureHttp = false } = {}) {
  const v = (cond, msg) => {
    if (!cond) throw new ValidationError(msg);
  };
  v(input && typeof input === 'object', 'body must be an object');
  v(ID_RE.test(input.id ?? ''), 'id must be lowercase letters, digits and dashes');
  v(typeof input.entityId === 'string' && input.entityId.length > 0 && input.entityId.length <= 500, 'entityId is required');

  let ssoUrl;
  try {
    ssoUrl = new URL(input.ssoUrl);
  } catch {
    throw new ValidationError('ssoUrl must be a URL');
  }
  v(ssoUrl.protocol === 'https:' || (allowInsecureHttp && ssoUrl.protocol === 'http:'), 'ssoUrl must use https');

  const certs = Array.isArray(input.certificates) ? input.certificates : [];
  v(certs.length >= 1 && certs.length <= 5, 'provide 1 to 5 certificates');
  const certificates = certs.map(normalizePem);

  const domains = (Array.isArray(input.emailDomains) ? input.emailDomains : []).map((d) => String(d).trim().toLowerCase());
  v(domains.length >= 1 && domains.length <= 50, 'provide at least one email domain');
  v(domains.every((d) => DOMAIN_RE.test(d)), 'emailDomains contains an invalid domain');

  const mapping = { email: 'email', name: 'name', ...(input.attributeMapping ?? {}) };
  v(ATTR_RE.test(mapping.email) && ATTR_RE.test(mapping.name), 'attributeMapping names are invalid');

  return {
    id: input.id,
    entityId: input.entityId,
    ssoUrl: ssoUrl.href,
    certificates,
    attributeMapping: { email: mapping.email, name: mapping.name },
    emailDomains: [...new Set(domains)],
    enabled: input.enabled !== false,
  };
}

const fromRow = (row) =>
  row && {
    id: row.id,
    entityId: row.entity_id,
    ssoUrl: row.sso_url,
    certificates: JSON.parse(row.certificates),
    attributeMapping: JSON.parse(row.attribute_mapping),
    emailDomains: JSON.parse(row.email_domains),
    enabled: row.enabled === 1,
  };

export function createIdpStore(db, options = {}) {
  return {
    list: () => db.prepare('SELECT * FROM saml_idps ORDER BY id').all().map(fromRow),
    get: (id) => fromRow(db.prepare('SELECT * FROM saml_idps WHERE id = ?').get(id)),

    findByEmail(email) {
      const domain = String(email).trim().toLowerCase().split('@')[1];
      if (!domain) return null;
      const row = db
        .prepare(
          `SELECT i.* FROM idp_domains d JOIN saml_idps i ON i.id = d.idp_id
           WHERE d.domain = ? AND i.enabled = 1`,
        )
        .get(domain);
      return fromRow(row);
    },

    upsert(input) {
      const idp = validateIdp(input, options);
      return inTransaction(db, () => {
        const clash = db.prepare('SELECT id FROM saml_idps WHERE entity_id = ? AND id != ?').get(idp.entityId, idp.id);
        if (clash) throw new ValidationError('entityId is already used by another identity provider');
        for (const domain of idp.emailDomains) {
          const owner = db.prepare('SELECT idp_id FROM idp_domains WHERE domain = ?').get(domain);
          if (owner && owner.idp_id !== idp.id) throw new ValidationError(`domain ${domain} belongs to another identity provider`);
        }
        db.prepare(
          `INSERT INTO saml_idps (id, entity_id, sso_url, certificates, attribute_mapping, email_domains, enabled, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET entity_id = excluded.entity_id, sso_url = excluded.sso_url,
             certificates = excluded.certificates, attribute_mapping = excluded.attribute_mapping,
             email_domains = excluded.email_domains, enabled = excluded.enabled, updated_at = excluded.updated_at`,
        ).run(
          idp.id, idp.entityId, idp.ssoUrl, JSON.stringify(idp.certificates),
          JSON.stringify(idp.attributeMapping), JSON.stringify(idp.emailDomains), idp.enabled ? 1 : 0, Date.now(),
        );
        db.prepare('DELETE FROM idp_domains WHERE idp_id = ?').run(idp.id);
        const insert = db.prepare('INSERT INTO idp_domains (domain, idp_id) VALUES (?, ?)');
        for (const domain of idp.emailDomains) insert.run(domain, idp.id);
        return idp;
      });
    },

    remove: (id) => db.prepare('DELETE FROM saml_idps WHERE id = ?').run(id).changes > 0,
  };
}
