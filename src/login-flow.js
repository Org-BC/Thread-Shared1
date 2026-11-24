import { newCorrelationId } from './audit.js';

// Generic error messages shown on the login page. Detailed reasons only go to the audit log.
export const LOGIN_ERRORS = {
  failed: 'Sign-in failed. Please try again or use another method.',
  unavailable: 'Sign-in provider unavailable, try again or use another method.',
  not_configured: 'This sign-in method is not available.',
};

export function failLogin(res, audit, { method, provider, reason, userUnavailable = false, level = 'warn' }) {
  const ref = newCorrelationId();
  audit({ event: 'login_failure', level, method, provider, reason, ref });
  const error = userUnavailable ? 'unavailable' : 'failed';
  res.redirect(303, `/login?error=${error}&ref=${ref}`);
}

export function succeedLogin(res, audit, sessions, { method, provider, userId, created, linked, returnTo }) {
  sessions.issue(res, userId);
  audit({ event: 'login_success', level: 'info', method, provider, userId, created, linked });
  res.redirect(303, returnTo);
}
