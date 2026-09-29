/**
 * @alternatefutures/ac-auth
 *
 * Sign in with Alternate Clouds, framework-free. Start with
 * {@link createAuthClient} for a browser app; use the lower-level functions
 * to build a server-side session (see @alternatefutures/ac-auth-next).
 *
 * @packageDocumentation
 */

export { AuthClient, createAuthClient } from './client';
export type { AuthClientOptions, CallbackResult, SessionListener, SignInOptions, SignOutOptions } from './client';

export {
  DEFAULT_ISSUER,
  DEFAULT_SCOPES,
  ID_TOKEN_ALGORITHMS,
  ISSUER_PATHS,
  SUPPORTED_SCOPES,
  createDiscoveryCache,
  discover,
  knownIssuerMetadata,
} from './discovery';
export type { DiscoverOptions, DiscoveryCacheOptions } from './discovery';

export { computeCodeChallenge, createPkcePair, generateCodeVerifier, generateNonce, generateState } from './pkce';
export type { PkcePair } from './pkce';

export { buildAuthorizationUrl, buildEndSessionUrl, isAuthorizationResponse, parseAuthorizationResponse } from './authorize';
export type { AuthorizationRequestParams, AuthorizationResponse, EndSessionParams } from './authorize';

export {
  clientAuthenticationParts,
  exchangeAuthorizationCode,
  fetchUserInfo,
  introspectToken,
  refreshTokenGrant,
  revokeToken,
  tokenSetFromResponse,
} from './token';
export type {
  CodeExchangeParams,
  IntrospectionParams,
  IntrospectionResponse,
  RefreshParams,
  RevocationParams,
  TokenEndpointClient,
  UserInfoParams,
} from './token';

export { RefreshCoordinator } from './refresh';
export type { RefreshCoordinatorOptions } from './refresh';

export { createJwksResolver, isPublicSigningJwk } from './jwks';
export type { JwksResolver, JwksResolverOptions, JwksSnapshot, JwksSource } from './jwks';

export { EMBEDDED_JWKS, embeddedKeysFor } from './embedded-keys';

export { decodeIdToken, verifyIdToken } from './verify';
export type { VerifyIdTokenOptions } from './verify';

export { shortWallet, userFromClaims, userInitials } from './claims';

export { DEFAULT_GRACE_POLICY, NO_GRACE_POLICY, evaluateGrace, graceDeadline, resolveGracePolicy } from './grace';
export type { GraceVerdict, SessionGracePolicy } from './grace';

export { DEVICE_CODE_GRANT, pollDeviceToken, startDeviceAuthorization } from './device';
export type { DeviceAuthorizationParams, DevicePollParams } from './device';

export { memoryStorage, resolveStorage, webStorage, withLock } from './storage';
export type { AuthStorage, StorageKind } from './storage';

export { AuthError, OAuthError, isSignedOutError, isTransientError, oauthErrorFromBody } from './errors';
export type { AuthErrorCode, OAuthErrorBody } from './errors';

export type {
  AuthUser,
  ClientAuthentication,
  DeviceAuthorizationResponse,
  IdTokenClaims,
  IssuerMetadata,
  OrganizationClaim,
  OrganizationRole,
  Session,
  SessionStatus,
  TokenResponse,
  TokenSet,
} from './types';

export type { FetchLike } from './util';
export type { JWK } from 'jose';
