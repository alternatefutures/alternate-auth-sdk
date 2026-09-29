# Auth.js providers-list PR: files and steps

The three files under `files/` are ready to drop into a fork of
https://github.com/nextauthjs/next-auth (branch from `main`):

| File here | Destination in next-auth |
|---|---|
| `files/alternate-clouds.ts` | `packages/core/src/providers/alternate-clouds.ts` |
| `files/alternate-clouds.mdx` | `docs/pages/getting-started/providers/alternate-clouds.mdx` |
| `files/alternate-clouds.svg` | `docs/public/img/providers/alternate-clouds.svg` |

No registry edits are needed: the providers folder, the docs sidebar and the
logo directory are picked up by file name (checked against the `asgardeo`
provider on 2026-09-30). The repo has no changesets.

Context (2026-09-30): the Auth.js README says the project "is now part of
Better Auth" and recommends Better Auth for new projects; the last provider
feature PR merged in 2025-10. Expect a slow review. `@alternatefutures/ac-auth-js`
already gives Auth.js users the same provider today.

## PR title

```
feat(providers): add Alternate Clouds
```

## PR body (their template)

```
## ☕️ Reasoning

Adds a built-in OIDC provider for Alternate Clouds (https://clouds.alternatefutures.ai),
the identity behind the Alternate Clouds platform: issuer https://auth.alternatefutures.ai,
authorization code + PKCE (S256) only, `state` and `nonce` required, ID tokens
signed with EdDSA (ES256 also published). Public clients authenticate with
`token_endpoint_auth_method: "none"`; passing a client secret switches to
`client_secret_basic`. The Auth.js user id is the wallet DID when the account
has a verified wallet, else the subject.

Provider file, docs page (Next.js, Qwik, SvelteKit, Express tabs) and logo,
following the existing OIDC providers. Verified against the live issuer with
`@auth/core` 0.41 (csrf → signin → callback → session) before opening this PR.

## 🧢 Checklist

- [x] Documentation
- [ ] Tests (none of the existing OIDC providers ship tests)
- [x] Ready to be merged

## 🎫 Affected issues

None.
```

## Steps (og)

1. Fork `nextauthjs/next-auth`, branch `feat/alternate-clouds-provider` from `main`.
2. Copy the three files to their destinations (table above).
3. `pnpm install && pnpm --filter @auth/core build` (or the repo's `pnpm build`) to be sure the provider compiles; `pnpm --filter next-auth-docs dev` renders the page under Getting started › Providers.
4. Commit `feat(providers): add Alternate Clouds`, push, open the PR with the body above.
