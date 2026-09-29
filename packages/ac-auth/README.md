# @alternatefutures/ac-auth

Sign in with Alternate Clouds, framework-free. Works in browsers, Node 20+
and edge runtimes. React components live in `@alternatefutures/ac-auth-react`,
Next.js server helpers in `@alternatefutures/ac-auth-next`, and an Auth.js
provider in `@alternatefutures/ac-auth-js`. This package is what they are
built on, and what you use when none of them fits.

## Install

```bash
npm install @alternatefutures/ac-auth
```

## What you need first

An OAuth client, created under **Organization › Developer** in the Alternate
Clouds web app: a **public** client for browser and native apps (PKCE, no
secret) or a **confidential** one for servers. Register the exact redirect
URI of your app; `http://localhost:<port>/...` is allowed for development.

## Browser app in four calls

```ts
import { createAuthClient } from '@alternatefutures/ac-auth';

const auth = createAuthClient({
  clientId: 'ac_...',
  redirectUri: `${window.location.origin}/callback`,
  scope: ['openid', 'profile', 'email', 'wallet'],
});

// 1. Send the user to sign in (a button click).
await auth.signIn({ returnTo: '/dashboard' });

// 2. On /callback: finish the sign-in.
const { session, returnTo } = await auth.handleCallback();

// 3. Anywhere: the user, or a token for an API call. Refresh happens for you.
const user = await auth.getUser();
const token = await auth.getAccessToken();

// 4. Sign out.
await auth.signOut({ redirect: true });
```

`session.user` is typed:

| Field | Meaning |
|---|---|
| `key` | Store your local user under this. The wallet DID when the user has a verified wallet, otherwise the account id. |
| `id` | The issuer subject (`sub`). |
| `name`, `email`, `emailVerified`, `picture` | From the `profile` and `email` scopes. |
| `org` | `{ id, slug, name, role }` of the organization chosen at consent (`org` scope). |
| `wallet`, `wallets` | `did:pkh:eip155:1:<address>` and every verified address (`wallet` scope). |

## What the client guarantees

- **PKCE S256, `state` and `nonce`** on every sign-in; the ID token is verified
  offline (EdDSA or ES256, issuer, audience, nonce, time).
- **Refresh rotation done safely.** Every refresh returns a new refresh token
  and the old one dies; presenting an old one again revokes the whole grant.
  The client refreshes single-flight, hands the new tokens to late callers,
  and never sends a rotated token twice. A definitive `invalid_grant` means
  signed out; the client clears the session and tells subscribers.
- **Survives an issuer outage.** Public keys are cached, served stale on
  error, and a snapshot embedded at build time is the last resort. When the
  issuer cannot be reached, an expired session stays usable in `grace`
  status for up to 24 hours, never more than 7 days after the tokens were
  issued (`grace` option; `false` disables it).
- **Discovery with a fallback.** The issuer's discovery document is fetched
  and cached; if it cannot be fetched, the known endpoint layout is used.

## Lower-level pieces

Everything the client does is exported on its own, for servers and custom
flows:

```ts
import {
  discover, createPkcePair, buildAuthorizationUrl, parseAuthorizationResponse,
  exchangeAuthorizationCode, refreshTokenGrant, RefreshCoordinator,
  createJwksResolver, verifyIdToken, userFromClaims,
  evaluateGrace, startDeviceAuthorization, pollDeviceToken,
} from '@alternatefutures/ac-auth';
```

### Device flow (CLIs, TVs)

Enable the device flow on the client, then:

```ts
const metadata = await discover('https://auth.alternatefutures.ai');
const device = await startDeviceAuthorization({ metadata, clientId, scope: 'openid email' });
console.log(`Open ${device.verification_uri_complete}`);
const tokens = await pollDeviceToken({ metadata, clientId, deviceCode: device.device_code, intervalSeconds: device.interval, expiresInSeconds: device.expires_in });
```

## Errors

Every failure is an `AuthError` with a `code`; issuer refusals are an
`OAuthError` with the RFC 6749 `error` string. Two helpers decide what to do:
`isSignedOutError(e)` (clear the session, show the button) and
`isTransientError(e)` (keep the session, try later).

## Options worth knowing

| Option | Default | Notes |
|---|---|---|
| `issuer` | `https://auth.alternatefutures.ai` | Never changes; use the staging issuer for staging clients. |
| `scope` | `openid profile email` | Add `org` (organization picker at consent) and `wallet`. |
| `sessionStorage` | `memory` | `session` or `local` keep the session across reloads; any script on the origin can read them. Apps with a server should keep tokens server-side (`@alternatefutures/ac-auth-next`). |
| `clientAuthentication` | `{ method: 'none' }` | Confidential clients: `client_secret_basic` (the issuer default) or `client_secret_post`. Never in a browser. |
| `grace` | 24 h / 7 d cap | `false` to expire with the access token. |
| `embeddedKeys` | the build-time snapshot | Public keys trusted before the first JWKS fetch. |

## License

MIT
