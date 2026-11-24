# CPR portal sign-in: Google OAuth and SAML 2.0 SSO

Sign-in service for the Customer Portal Redesign. Customers sign in with Google (OpenID Connect,
authorization-code flow with PKCE) or through their company's SAML 2.0 identity provider (IdP).
Both end in the same step: find, link or create the portal account, then issue the portal session.

Stack: Node 22.13+, Express 5, `openid-client`, `@node-saml/node-saml`, `node:sqlite`.

## Routes

| Route | Purpose |
|---|---|
| `GET /login` | Login page (Google button, company-SSO email form) |
| `GET /auth/google` / `GET /auth/google/callback` | Google OAuth start and redirect URI |
| `GET /auth/saml/metadata` | SP metadata to give to the customer's IdP |
| `GET /auth/saml/login?email=…` or `?idp=<id>` | Start SP-initiated SAML SSO |
| `POST /auth/saml/acs` | SAML Assertion Consumer Service (HTTP-POST binding) |
| `POST /logout` | End the portal session |
| `/admin/idps` | IdP administration API (bearer token) |

`/portal` is a placeholder page that shows who is signed in. The real portal reuses the session
through `sessions.userFor(req)` (`src/sessions.js`).

## Configuration

Copy `.env.example` and set the values. Nothing secret belongs in the repository (`.env` and
`*.pem` are git-ignored). In production `BASE_URL` must be `https`.

### Google
1. Google Cloud console > APIs & Services > Credentials > Create OAuth client ID > Web application.
2. Add the authorized redirect URI `BASE_URL/auth/google/callback`.
3. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. The secret is only used server-side.

### SAML service provider
1. Create an SP key pair, for example:
   `openssl req -x509 -newkey rsa:2048 -nodes -days 730 -keyout sp.key -out sp.crt -subj "/CN=portal"`
2. Set `SAML_SP_PRIVATE_KEY_FILE` and `SAML_SP_CERT_FILE` (or the inline `SAML_SP_PRIVATE_KEY` / `SAML_SP_CERT`).
3. Give the customer `BASE_URL/auth/saml/metadata` (entity ID, ACS URL, certificate).

### Onboarding an identity provider
Set `ADMIN_API_TOKEN` (a long random value; the admin API does not exist without it), then:

```sh
curl -X PUT "$BASE_URL/admin/idps/acme" \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "entityId": "https://idp.acme.com/metadata",
    "ssoUrl": "https://idp.acme.com/sso",
    "certificates": ["-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"],
    "emailDomains": ["acme.com"],
    "attributeMapping": { "email": "email", "name": "displayName" }
  }'
```

- Users typing an `@acme.com` address on the login page are sent to this IdP.
- The IdP may only sign in users whose email is in its `emailDomains`.
- `certificates` takes up to 5. For rotation, PUT old and new together, then PUT again with only the new one. No restart needed.
- `"enabled": false` disables an IdP. `DELETE /admin/idps/<id>` removes it.

## Behavior to know

- **Account linking:** a Google or SAML identity is attached to an existing account with the same email only when the provider vouches for the email (Google `email_verified`; for SAML, the address is in the IdP's configured domains). Accounts are created automatically on first sign-in.
- **SAML checks:** signed assertion (required), issuer, audience, `InResponseTo` bound to a request we issued, `NotBefore`/`NotOnOrAfter` (2 min skew) and assertion replay protection, all stored in SQLite so they survive restarts.
- **Logging:** one JSON line per event on stdout (`login_success`, `login_failure`, `logout`, …) with `method` and `provider`. Tokens, assertions and secrets are never logged. Users see a generic message plus a `ref` that matches the log line.
- **Out of scope:** SAML single logout, IdP-initiated SSO, other OAuth providers, SCIM.

## Development

```sh
npm install
npm test
ALLOW_INSECURE_HTTP=true BASE_URL=http://localhost:3000 npm start   # local only
```
