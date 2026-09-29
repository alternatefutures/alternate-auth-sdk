# @alternatefutures/ac-auth-js

**Sign in with Alternate Clouds** as an [Auth.js](https://authjs.dev) provider.
Works with next-auth v5 and every framework Auth.js supports (SvelteKit,
SolidStart, Express, Qwik, ...). One line in `providers`, no other code.

## Install

```bash
npm install @alternatefutures/ac-auth-js next-auth@beta
```

## Use (Next.js App Router)

Register a client under **Organization › Developer** with the callback URL
`http://localhost:3000/api/auth/callback/alternate-clouds` (and your
production origin later). A **public** client needs no secret.

```
# .env.local
AUTH_SECRET=                      # npx auth secret
AUTH_ALTERNATE_CLOUDS_ID=ac_...   # the client id
# AUTH_ALTERNATE_CLOUDS_SECRET=   # confidential clients only
# AUTH_ALTERNATE_CLOUDS_ISSUER=   # default https://auth.alternatefutures.ai
```

```ts
// auth.ts
import NextAuth from 'next-auth';
import AlternateClouds from '@alternatefutures/ac-auth-js';

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [AlternateClouds()],
});

// app/api/auth/[...nextauth]/route.ts
import { handlers } from '@/auth';
export const { GET, POST } = handlers;
```

Then `await auth()` anywhere on the server, `signIn('alternate-clouds')` to
start, `signOut()` to end. The Auth.js default sign-in page shows a
"Sign in with Alternate Clouds" button in the brand color.

## Options

```ts
AlternateClouds({
  clientId, clientSecret,          // or the AUTH_ALTERNATE_CLOUDS_* variables
  issuer: 'https://auth.staging.alternatefutures.ai',
  scope: 'openid profile email wallet org',
  // plus anything Auth.js accepts for an OIDC provider (profile, allowDangerousEmailAccountLinking, ...)
});
```

The Auth.js `user.id` is the user's wallet DID (`did:pkh:eip155:1:0x...`)
when they have a verified wallet, otherwise the account id: the same rule as
`@alternatefutures/ac-auth`. Keep the raw claims (`org`, `wallets`) with a
`jwt` callback:

```ts
callbacks: {
  jwt({ token, profile }) {
    if (profile) token.org = profile.org;
    return token;
  },
}
```

## What is configured for you

PKCE S256, `state` and `nonce` (the issuer requires all three), ID token
verification through discovery, `token_endpoint_auth_method` `none` for
public clients and `client_secret_basic` when a secret is given.

## License

MIT
