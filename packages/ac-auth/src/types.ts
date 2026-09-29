/**
 * Public types. The claim shapes mirror what the issuer puts in ID tokens
 * (the issuer): `sub` is the account id, `org` is
 * the organization picked at consent, `wallet` is a did:pkh of the primary
 * verified wallet. Balances are never claims.
 */

/** OpenID Connect discovery document (RFC 8414 / OIDC Discovery 1.0), the fields the SDK relies on plus passthrough. */
export interface IssuerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  device_authorization_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  response_modes_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  subject_types_supported?: string[];
  claims_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
  [key: string]: unknown;
}

/** Raw token endpoint answer (RFC 6749 §5.1). */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  [key: string]: unknown;
}

export type OrganizationRole = 'OWNER' | 'ADMIN' | 'MEMBER';

/** The `org` claim: the organization the user bound the grant to at consent, with their role in it. */
export interface OrganizationClaim {
  id: string;
  slug: string;
  name: string;
  role: OrganizationRole | (string & {});
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  at_hash?: string;
  azp?: string;
  sid?: string;
  /** `profile` scope */
  name?: string;
  picture?: string;
  updated_at?: number;
  /** `email` scope */
  email?: string;
  email_verified?: boolean;
  /** `org` scope */
  org?: OrganizationClaim;
  /** `wallet` scope: `did:pkh:eip155:1:<address>` of the primary verified wallet, and every verified address. */
  wallet?: string;
  wallets?: string[];
  [key: string]: unknown;
}

/** The signed-in user as an application sees it. Derived from ID token claims by {@link userFromClaims}. */
export interface AuthUser {
  /**
   * The key to store the local user under. The wallet DID when the user has
   * a verified wallet, otherwise the issuer subject. A wallet-anchored key
   * survives an issuer replacement (plan §3, §4 M4); a `sub` does not.
   */
  key: string;
  /** The issuer subject (`sub`): the account id, pairwise per client when the client opted in. */
  id: string;
  name: string | null;
  email: string | null;
  emailVerified: boolean;
  picture: string | null;
  wallet: string | null;
  wallets: string[];
  org: OrganizationClaim | null;
  updatedAt: Date | null;
}

/** Normalized tokens with absolute times (epoch milliseconds). */
export interface TokenSet {
  accessToken: string;
  tokenType: string;
  scope: string | null;
  refreshToken: string | null;
  idToken: string | null;
  /** When the access token stops being valid. */
  expiresAt: number;
  /** When this set was issued (a refresh yields a new set with a new `issuedAt`). */
  issuedAt: number;
  /** Verified ID token claims, when an ID token was issued and verified. */
  claims: IdTokenClaims | null;
}

/**
 * `active`: the access token is valid.
 * `grace`: the access token expired and a refresh could not be completed because the
 * issuer could not be reached; the session is still treated as signed in under the
 * {@link SessionGracePolicy} until the cap.
 */
export type SessionStatus = 'active' | 'grace';

export interface Session {
  status: SessionStatus;
  user: AuthUser;
  tokens: TokenSet;
  /** Mirrors `tokens.expiresAt`. */
  expiresAt: number;
  /** Mirrors `tokens.issuedAt`. */
  issuedAt: number;
}

/** How a client authenticates at the token, revocation and introspection endpoints. */
export type ClientAuthentication =
  | { method: 'none' }
  | { method: 'client_secret_basic'; clientSecret: string }
  | { method: 'client_secret_post'; clientSecret: string };

/** RFC 8628 §3.2 device authorization response. */
export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval?: number;
  [key: string]: unknown;
}
