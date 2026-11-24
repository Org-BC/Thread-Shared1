import { readFileSync } from 'node:fs';

function secretFromEnv(env, name) {
  const file = env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8');
  const value = env[name];
  return value ? value.replace(/\\n/g, '\n') : undefined;
}

export function loadConfig(env = process.env) {
  if (!env.BASE_URL) throw new Error('BASE_URL is required');
  const baseUrl = new URL(env.BASE_URL);
  const origin = baseUrl.origin;
  const allowInsecureHttp = env.ALLOW_INSECURE_HTTP === 'true';
  if (allowInsecureHttp && env.NODE_ENV === 'production') {
    throw new Error('ALLOW_INSECURE_HTTP cannot be enabled in production');
  }
  if (baseUrl.protocol !== 'https:' && !allowInsecureHttp) {
    throw new Error('BASE_URL must use https (set ALLOW_INSECURE_HTTP=true for local development only)');
  }

  const googleEnabled = Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
  const samlPrivateKey = secretFromEnv(env, 'SAML_SP_PRIVATE_KEY');
  const samlCert = secretFromEnv(env, 'SAML_SP_CERT');
  const samlEnabled = Boolean(samlPrivateKey && samlCert);

  return {
    baseUrl: origin,
    port: Number(env.PORT ?? 3000),
    databasePath: env.DATABASE_PATH ?? './data/cpr.sqlite',
    sessionTtlSeconds: Number(env.SESSION_TTL_SECONDS ?? 8 * 3600),
    secureCookies: baseUrl.protocol === 'https:',
    allowInsecureHttp,
    adminApiToken: env.ADMIN_API_TOKEN || null,
    google: {
      enabled: googleEnabled,
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      redirectUri: env.GOOGLE_REDIRECT_URI ?? `${origin}/auth/google/callback`,
      issuer: env.GOOGLE_ISSUER ?? 'https://accounts.google.com',
    },
    saml: {
      enabled: samlEnabled,
      spEntityId: env.SAML_SP_ENTITY_ID ?? `${origin}/auth/saml/metadata`,
      acsUrl: `${origin}/auth/saml/acs`,
      privateKey: samlPrivateKey,
      cert: samlCert,
      clockSkewMs: 2 * 60 * 1000,
      requestTtlMs: 10 * 60 * 1000,
    },
  };
}
