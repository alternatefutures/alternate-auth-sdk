/**
 * <div class="provider" style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
 * <span style={{fontSize: "1.35rem" }}>
 *  Built-in sign in with <b>Alternate Clouds</b> integration.
 * </span>
 * <a href="https://clouds.alternatefutures.ai" style={{backgroundColor: "#ECEFF1", padding: "12px", borderRadius: "100%" }}>
 *   <img style={{display: "block"}} src="https://authjs.dev/img/providers/alternate-clouds.svg" width="24"/>
 * </a>
 * </div>
 *
 * @module providers/alternate-clouds
 */

import type { OIDCConfig, OIDCUserConfig } from "./index.js"

/** The organization the user picked at consent (`org` scope). */
export interface AlternateCloudsOrganization {
  id: string
  name: string
  slug: string
  role: string
}

/** The claims Alternate Clouds puts in the ID token and the userinfo answer. */
export interface AlternateCloudsProfile extends Record<string, any> {
  /** Stable user id at this issuer. */
  sub: string
  /** `profile` scope */
  name?: string
  picture?: string
  updated_at?: number
  /** `email` scope */
  email?: string
  email_verified?: boolean
  /** `org` scope */
  org?: AlternateCloudsOrganization
  /**
   * `wallet` scope: `did:pkh:eip155:1:<address>` of the user's primary
   * verified wallet, and every verified address. Present only for users
   * who signed up or linked a wallet.
   */
  wallet?: string
  wallets?: string[]
}

/**
 * Sign in with Alternate Clouds: the accounts, organizations and wallets of
 * the Alternate Clouds platform, exposed as a standard OpenID Connect issuer.
 *
 * ### Setup
 *
 * #### Callback URL
 * ```
 * https://example.com/api/auth/callback/alternate-clouds
 * ```
 *
 * #### Configuration
 *```ts
 * import { Auth } from "@auth/core"
 * import AlternateClouds from "@auth/core/providers/alternate-clouds"
 *
 * const request = new Request(origin)
 * const response = await Auth(request, {
 *   providers: [
 *     AlternateClouds({
 *       clientId: AUTH_ALTERNATE_CLOUDS_ID,
 *       // Only for a confidential client; leave it out for a public one.
 *       clientSecret: AUTH_ALTERNATE_CLOUDS_SECRET,
 *     }),
 *   ],
 * })
 * ```
 *
 * ### Configuring Alternate Clouds
 *
 * 1. Sign in to the [Alternate Clouds web app](https://clouds.alternatefutures.ai) and open **Organization › Developer**.
 * 2. Create an app. Pick **public** (PKCE, no secret) for browser and serverless apps, or **confidential** to get a client secret.
 * 3. Add the **redirect URI** `http://localhost:3000/api/auth/callback/alternate-clouds` (development) and `https://{YOUR_DOMAIN}/api/auth/callback/alternate-clouds` (production).
 * 4. Copy the client id (and the secret, shown once) into your environment:
 *
 * ```
 * AUTH_ALTERNATE_CLOUDS_ID="ac_..."
 * AUTH_ALTERNATE_CLOUDS_SECRET="acs_..."   # confidential clients only
 * ```
 *
 * The issuer is `https://auth.alternatefutures.ai`; set `AUTH_ALTERNATE_CLOUDS_ISSUER` only to point at another deployment of the platform.
 *
 * ### Resources
 *
 * - [Add sign in with Alternate Clouds](https://docs.alternatefutures.ai/guides/add-sign-in)
 * - [Sign in with Alternate Clouds and Auth.js](https://docs.alternatefutures.ai/guides/sign-in-with-authjs)
 * - [Learn more about OAuth](https://authjs.dev/concepts/oauth)
 *
 * ### Notes
 *
 * - The issuer allows the authorization code flow with PKCE (S256) only and
 *   requires `state` and `nonce`, so all three checks are on.
 * - ID tokens are signed with EdDSA (Ed25519); ES256 is also published for
 *   libraries without EdDSA support.
 * - A public client authenticates with `token_endpoint_auth_method: "none"`.
 *   Passing a `clientSecret` (or `AUTH_ALTERNATE_CLOUDS_SECRET`) switches to
 *   `client_secret_basic`.
 * - The Auth.js user id is the wallet DID when the user has a verified
 *   wallet, else the subject, so an account keeps its identity across
 *   issuers.
 * - Add the `wallet` and `org` scopes to receive the wallet addresses and
 *   the organization picked at consent.
 *
 * The Alternate Clouds provider comes with a [default configuration](https://github.com/nextauthjs/next-auth/blob/main/packages/core/src/providers/alternate-clouds.ts). To override the defaults for your use case, check out [customizing a built-in OAuth provider](https://authjs.dev/guides/configuring-oauth-providers).
 *
 * :::info
 * By default, Auth.js assumes that the Alternate Clouds provider is based on the [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) spec
 * :::
 *
 * ## Help
 *
 * If you think you found a bug in the default configuration, you can [open an issue](https://authjs.dev/new/provider-issue).
 *
 * Auth.js strictly adheres to the specification and it cannot take responsibility for any deviation from
 * the spec by the provider. You can open an issue, but if the problem is non-compliance with the spec,
 * we might not pursue a resolution. You can ask for more help in [Discussions](https://authjs.dev/new/github-discussions).
 */
export default function AlternateClouds(
  config: OIDCUserConfig<AlternateCloudsProfile>
): OIDCConfig<AlternateCloudsProfile> {
  const issuer = (config?.issuer ?? "https://auth.alternatefutures.ai").replace(
    /\/+$/,
    ""
  )
  return {
    id: "alternate-clouds",
    name: "Alternate Clouds",
    type: "oidc",
    issuer,
    authorization: { params: { scope: "openid profile email" } },
    checks: ["pkce", "state", "nonce"],
    idToken: true,
    client: {
      // Public clients (no secret) must not send client authentication.
      token_endpoint_auth_method: config?.clientSecret
        ? "client_secret_basic"
        : "none",
      id_token_signed_response_alg: "EdDSA",
    },
    profile(profile) {
      const wallet =
        typeof profile.wallet === "string" && profile.wallet
          ? profile.wallet
          : null
      return {
        id: wallet ?? profile.sub,
        name: profile.name ?? profile.email ?? null,
        email: profile.email ?? null,
        image: profile.picture ?? null,
      }
    },
    style: { brandColor: "#a5b2ff", text: "#000" },
    options: config,
  }
}
