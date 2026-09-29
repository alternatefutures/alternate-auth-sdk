# alternate-auth-sdk

The developer SDK for **Sign in with Alternate Clouds**: let users of your
app sign in with the accounts, organizations and wallets they already have
on Alternate Clouds, through standard OpenID Connect.

A **layered set of independently versioned packages** published to the
`@alternatefutures/*` npm scope, developed in one repo with shared tooling and
a single Changesets pipeline (the same shape as `alternate-ui`).

```
@alternatefutures/ac-auth          framework-free core: discovery, PKCE, tokens,   <- packages/ac-auth
        ▲                       refresh rotation, JWKS cache, grace, device flow
        ├── @alternatefutures/ac-auth-react    <AuthProvider>, <SignIn>, <SignInButton>,   <- packages/ac-auth-react
        │                                   <UserButton>, <SignedIn>/<SignedOut>, hooks
        ├── @alternatefutures/ac-auth-next     BFF for Next.js: httpOnly cookies, refresh   <- packages/ac-auth-next
        │                                   in the proxy, auth() helper, route handlers
        └── @alternatefutures/ac-auth-js   Auth.js provider object                      <- packages/ac-auth-js
```

Starters: `alternate-auth-starter-next` and `alternate-auth-starter-vite-react`
(sibling repos). Guides: docs.alternatefutures.ai, "Add sign in" and
"Sign in with Auth.js".

## Packages

| Package | Purpose |
|---|---|
| [`@alternatefutures/ac-auth`](packages/ac-auth) | Core. Browser, Node 20+, edge. |
| `@alternatefutures/ac-auth-react` | React 19 components and hooks built from the Alternate Clouds web app's own shadcn primitives, palette and typeface. |
| `@alternatefutures/ac-auth-next` | Next.js 16 App Router server session (BFF). |
| `@alternatefutures/ac-auth-js` | Provider for Auth.js (next-auth v5, @auth/core). |

## Develop

```bash
npm install            # workspace + shared dev tooling
npm run build          # build all packages
npm run typecheck      # typecheck all packages
npm test               # unit tests (no network)
npm run test:integration   # against a live issuer, see packages/ac-auth/test/integration
npm run embed-keys     # refresh the embedded last-known issuer keys
npm run changeset      # record a version bump after a change
```

## Release

Independent per-package semver via Changesets:

1. Add a changeset (`npm run changeset`) in your PR.
2. On merge to `main`, the version workflow bumps and commits the affected packages.
3. Cut a GitHub Release (or run the publish workflow): the workflow embeds
   the issuer's current public keys, builds, tests and runs
   `changeset publish` with provenance.

Requires the `NPM_TOKEN` Actions secret (same setup as `alternate-ui`).

## Conventions

- `react`, `react-dom`, `next` and `@auth/core` are **peerDependencies** of the
  packages that need them; `jose` is the only runtime dependency of the core.
- No compute vendor names and no em-dashes in copy or docs.
- Every protocol decision the SDK relies on is documented in the source
  next to the code that relies on it; the issuer is the issuer's
  `src/oidc/` (the platform's auth plan).
