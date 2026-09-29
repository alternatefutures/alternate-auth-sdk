# @alternatefutures/ac-auth-next

**Sign in with Alternate Clouds** for the Next.js App Router. The session is
an encrypted httpOnly cookie; the browser never sees a token; refresh with
rotation happens in the proxy only; `auth()` reads the session anywhere on
the server. Ships the React components of `@alternatefutures/ac-auth-react`
for the client side.

Fastest path: the starter.

```bash
npx create-next-app@latest my-app -e https://github.com/alternatefutures/alternate-auth-starter-next
```

## Install into an existing app

```bash
npm install @alternatefutures/ac-auth-next
```

Environment (`.env.local`):

```
ALTERNATE_CLOUDS_CLIENT_ID=ac_...        # Organization > Developer, redirect URI http://localhost:3000/api/auth/callback
ALTERNATE_CLOUDS_CLIENT_SECRET=          # confidential clients only
AUTH_SECRET=                             # openssl rand -base64 32
```

Four files:

```ts
// lib/auth-config.ts
import type { AcAuthConfig } from '@alternatefutures/ac-auth-next';
export const authConfig: AcAuthConfig = { scope: ['openid', 'profile', 'email', 'wallet'] };

// lib/auth.ts
import { createAuth } from '@alternatefutures/ac-auth-next';
import { authConfig } from './auth-config';
export const { auth, handlers, signInPath, toClientSession } = createAuth(authConfig);

// app/api/auth/[...auth]/route.ts
import { handlers } from '@/lib/auth';
export const { GET, POST } = handlers;

// proxy.ts   (middleware.ts on Next.js 15)
import { createAuthProxy } from '@alternatefutures/ac-auth-next/proxy';
import { authConfig } from '@/lib/auth-config';
export const proxy = createAuthProxy(authConfig, { protect: ['/dashboard'] });
// Next.js needs a literal here (an imported constant is not accepted): everything except static assets.
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js|map|txt|xml|json|woff2?)$).*)'] };
```

Wrap the client tree once, with the session the server already knows:

```tsx
// app/layout.tsx
import '@alternatefutures/ac-auth-react/styles.css';
import { AuthProvider } from '@alternatefutures/ac-auth-next/react';
import { auth, toClientSession } from '@/lib/auth';

export default async function RootLayout({ children }) {
  const session = await auth();
  return <html><body><AuthProvider initialSession={toClientSession(session)}>{children}</AuthProvider></body></html>;
}
```

Then anywhere:

```tsx
// a Server Component or Route Handler
const session = await auth();          // { user, status, accessToken, ... } or null
if (!session) redirect(signInPath('/dashboard'));

// a Client Component
import { SignInButton, SignedIn, SignedOut, UserButton, useUser } from '@alternatefutures/ac-auth-next/react';
```

## Routes

| Route | Does |
|---|---|
| `GET /api/auth/signin?returnTo=/path` | Starts the code + PKCE flow. Also `scope`, `prompt`, `login_hint`. |
| `GET /api/auth/callback` | Finishes it, sets the session cookie, redirects to `returnTo`. Failures land on `returnTo?auth_error=<code>`. |
| `POST /api/auth/signout` | Clears the cookie; with `postLogoutRedirectUri` configured, sends the browser to the issuer to end its session too. `Accept: application/json` gets `{ redirectTo }`. |
| `GET /api/auth/session` | `{ session }` without tokens, for the client. |

## Options

`createAuth(config)` and `createAuthProxy(config)` take the same object:

| Option | Default | Notes |
|---|---|---|
| `issuer` | `ALTERNATE_CLOUDS_ISSUER` or production | |
| `clientId`, `clientSecret` | from the environment | No secret = public client (PKCE only). |
| `secret` | `AUTH_SECRET` | 16+ characters; seals the cookies (HKDF + A256GCM). |
| `basePath` | `/api/auth` | Where the handlers are mounted. |
| `scope` | `openid profile email` | Add `wallet`, `org`. |
| `redirectUri` | `<origin>/api/auth/callback` | Set it when the app's public origin differs from what the server sees. |
| `postLogoutRedirectUri` | none | Registered on the client; enables issuer logout. |
| `afterSignOutPath` | `/` | Local sign-out landing. |
| `revokeOnSignOut` | `false` | Also revoke the refresh token (disconnects the app on every device). |
| `cookie` | `ac_auth.session`, Lax, 30 days | `secure` follows the request scheme; over https the session cookie is `__Host-ac_auth.session` (Path=/, no Domain) and the transaction cookie `__Secure-…`. `SameSite=Lax`, not Strict: the callback is a cross-site top-level navigation from the issuer and must carry the transaction cookie. |
| `grace` | 24 h, 7 d cap | Session survives an unreachable issuer; `false` disables. |

A prefetched link to `/api/auth/signin` (Next.js `<Link>`, browser speculation) gets a 204 and starts no flow.

## How refresh works

The proxy sees every request. When the access token is within 30 s of expiry
it refreshes once (single flight, with a successor cache for requests that
still carry the old cookie), writes the new cookie on the response and
forwards it to the request, so Server Components render with the fresh
session immediately. A definitive `invalid_grant` clears the cookie; an
unreachable issuer leaves it in place and `auth()` answers with status
`grace` until the cap.

Without the proxy, `auth()` still works until the access token expires plus
the grace window; install the proxy to keep sessions alive for the refresh
token's 30 days.

## License

MIT
