import { Router, json } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { sha256 } from './sessions.js';
import { ValidationError } from './idps.js';

const publicView = ({ certificates, ...rest }) => ({ ...rest, certificateCount: certificates.length });

function tokenMatches(provided, expected) {
  // Hash first so both buffers have equal length for timingSafeEqual.
  return timingSafeEqual(Buffer.from(sha256(provided), 'hex'), Buffer.from(sha256(expected), 'hex'));
}

export function createAdminRouter({ config, audit, idps }) {
  const router = Router();

  // The API does not exist unless an admin token is configured.
  if (!config.adminApiToken) return router;

  router.use('/admin', (req, res, next) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
    if (!m || !tokenMatches(m[1], config.adminApiToken)) {
      audit({ event: 'admin_denied', level: 'warn', path: req.path });
      return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'unauthorized' });
    }
    next();
  });
  router.use('/admin', json({ limit: '100kb' }));

  router.get('/admin/idps', (req, res) => res.json(idps.list().map(publicView)));

  router.get('/admin/idps/:id', (req, res) => {
    const idp = idps.get(req.params.id);
    return idp ? res.json(publicView(idp)) : res.status(404).json({ error: 'not_found' });
  });

  router.put('/admin/idps/:id', (req, res) => {
    try {
      const idp = idps.upsert({ ...req.body, id: req.params.id });
      audit({ event: 'idp_saved', level: 'info', idp: idp.id });
      res.json(publicView(idp));
    } catch (err) {
      if (!(err instanceof ValidationError)) throw err;
      res.status(400).json({ error: 'invalid', message: err.message });
    }
  });

  router.delete('/admin/idps/:id', (req, res) => {
    if (!idps.remove(req.params.id)) return res.status(404).json({ error: 'not_found' });
    audit({ event: 'idp_removed', level: 'info', idp: req.params.id });
    res.status(204).end();
  });

  router.use('/admin', (err, req, res, next) => {
    if (err?.type === 'entity.parse.failed' || err?.status === 400) return res.status(400).json({ error: 'invalid_json' });
    next(err);
  });

  return router;
}
