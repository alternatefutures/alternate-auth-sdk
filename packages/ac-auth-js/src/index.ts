/**
 * @alternatefutures/ac-auth-js
 *
 * Sign in with Alternate Clouds as an Auth.js provider (next-auth v5,
 * @auth/core, and every framework Auth.js supports: SvelteKit, SolidStart,
 * Express, ...). One line in `providers`, nothing else:
 *
 *   import NextAuth from 'next-auth';
 *   import AlternateClouds from '@alternatefutures/ac-auth-js';
 *
 *   export const { handlers, auth, signIn, signOut } = NextAuth({
 *     providers: [AlternateClouds({ clientId: process.env.AUTH_ALTERNATE_CLOUDS_ID })],
 *   });
 *
 * The callback URL to register on the client is
 * `<origin>/api/auth/callback/alternate-clouds`.
 *
 * What the provider asks Auth.js for, and why:
 * - `type: "oidc"`: discovery, ID token verification (EdDSA / ES256 through
 *   oauth4webapi) and the userinfo fallback come from the issuer document.
 * - `checks: ["pkce", "state", "nonce"]`: the issuer requires all three.
 * - `client.token_endpoint_auth_method`: `none` for a public client (no
 *   secret), `client_secret_basic` (the issuer's default) when a secret is
 *   given. Auth.js would otherwise assume Basic and the issuer would answer
 *   `invalid_client` for a public client.
 * - `profile()`: the Auth.js user is keyed on the wallet DID when the user
 *   has a verified wallet, else the subject, the same rule as
 *   `@alternatefutures/ac-auth` (`userFromClaims`).
 *
 * @packageDocumentation
 */

import { DEFAULT_ISSUER, DEFAULT_SCOPES, userFromClaims, type IdTokenClaims } from '@alternatefutures/ac-auth';
import type { OIDCConfig, OIDCUserConfig } from '@auth/core/providers';

/** The claims the issuer puts in the ID token and the userinfo answer. */
export type AlternateCloudsProfile = IdTokenClaims;

export interface AlternateCloudsOptions extends OIDCUserConfig<AlternateCloudsProfile> {
  /** Issuer identifier. Default the production issuer; use the staging issuer for a staging client. */
  issuer?: string;
  /** Space-separated scopes. Default `openid profile email`. Add `wallet` and `org`. */
  scope?: string;
}

export const ALTERNATE_CLOUDS_PROVIDER_ID = 'alternate-clouds';

/** The brand accent, for the Auth.js default sign-in page button. */
export const BRAND_COLOR = '#a5b2ff';

export default function AlternateClouds(options: AlternateCloudsOptions = {}): OIDCConfig<AlternateCloudsProfile> {
  const { issuer: givenIssuer, scope, ...rest } = options;
  const issuer = (givenIssuer ?? process.env.AUTH_ALTERNATE_CLOUDS_ISSUER ?? DEFAULT_ISSUER).replace(/\/+$/, '');
  const clientSecret = rest.clientSecret ?? process.env.AUTH_ALTERNATE_CLOUDS_SECRET;
  const clientId = rest.clientId ?? process.env.AUTH_ALTERNATE_CLOUDS_ID;

  return {
    id: ALTERNATE_CLOUDS_PROVIDER_ID,
    name: 'Alternate Clouds',
    type: 'oidc',
    issuer,
    authorization: { params: { scope: scope ?? DEFAULT_SCOPES.join(' ') } },
    checks: ['pkce', 'state', 'nonce'],
    idToken: true,
    client: {
      token_endpoint_auth_method: clientSecret ? 'client_secret_basic' : 'none',
      // The issuer signs with EdDSA by default; oauth4webapi verifies whatever the header names among these.
      id_token_signed_response_alg: 'EdDSA',
    },
    profile(profile) {
      const user = userFromClaims(profile);
      return {
        id: user.key,
        name: user.name ?? user.email ?? null,
        email: user.email,
        image: user.picture,
      };
    },
    style: { brandColor: BRAND_COLOR, text: '#000000' },
    options: { ...rest, ...(clientId ? { clientId } : {}), ...(clientSecret ? { clientSecret } : {}) },
  };
}

export { AlternateClouds };
