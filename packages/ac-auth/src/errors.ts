/**
 * Error model. Every failure the SDK raises is an {@link AuthError} with a
 * stable `code`; protocol-level refusals from the issuer are an
 * {@link OAuthError} that also carries the RFC 6749 `error` string.
 *
 * Two questions callers ask are answered by helpers here:
 * - {@link isSignedOutError}: did the issuer (or the SDK) decide the user is
 *   no longer signed in? Then clear the local session and show the sign-in
 *   button. Retrying never helps.
 * - {@link isTransientError}: did the request simply not get through? Then
 *   keep the current session under the grace policy and try again later.
 */

export type AuthErrorCode =
  /** A required option is missing or the runtime lacks Web Crypto. */
  | 'configuration'
  /** The discovery document could not be fetched or is not for this issuer. */
  | 'discovery_failed'
  /** The request never received an HTTP answer (offline, DNS, timeout). */
  | 'network_error'
  /** An HTTP answer arrived but is not what the protocol promised (HTML from a proxy, malformed JSON). */
  | 'invalid_response'
  /** The issuer answered with an OAuth error object (see {@link OAuthError}). */
  | 'oauth_error'
  /** The `state` returned to the callback does not match a pending sign-in. */
  | 'invalid_state'
  /** The ID token failed signature, issuer, audience, nonce or time checks. */
  | 'invalid_id_token'
  /** No usable public key: the JWKS is unreachable and nothing is cached or embedded. */
  | 'jwks_unavailable'
  /** A refresh token that was already rotated was presented again locally. Never sent to the issuer. */
  | 'refresh_token_consumed'
  /** The issuer definitively refused the refresh token: the grant was revoked or reused. Sign in again. */
  | 'signed_out'
  /** The session outlived the grace cap without a successful refresh. Sign in again. */
  | 'session_expired'
  /** The callback carried no pending sign-in transaction (different browser, storage cleared, or a replay). */
  | 'no_transaction'
  /** The callback URL has neither a code nor an error. */
  | 'invalid_callback'
  /** The device code expired before the user approved it. */
  | 'device_flow_expired'
  /** The user declined. */
  | 'access_denied'
  /** The issuer or runtime does not support what was asked. */
  | 'unsupported';

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AuthError';
    this.code = code;
  }
}

/** RFC 6749 §5.2 error object shape. */
export interface OAuthErrorBody {
  error: string;
  error_description?: string;
  error_uri?: string;
}

export class OAuthError extends AuthError {
  /** The `error` string from the issuer (`invalid_grant`, `invalid_client`, ...). */
  readonly error: string;
  readonly errorDescription: string | undefined;
  readonly errorUri: string | undefined;
  /** HTTP status of the answer, or 0 when the error came back on a redirect. */
  readonly status: number;

  constructor(body: OAuthErrorBody, status: number, options?: { cause?: unknown }) {
    super('oauth_error', body.error_description ? `${body.error}: ${body.error_description}` : body.error, options);
    this.name = 'OAuthError';
    this.error = body.error;
    this.errorDescription = body.error_description;
    this.errorUri = body.error_uri;
    this.status = status;
  }
}

/** Parse an OAuth error body if that is what `body` is. */
export function oauthErrorFromBody(body: unknown, status: number): OAuthError | null {
  if (!body || typeof body !== 'object') return null;
  const candidate = body as Record<string, unknown>;
  if (typeof candidate.error !== 'string' || candidate.error.length === 0) return null;
  return new OAuthError(
    {
      error: candidate.error,
      error_description: typeof candidate.error_description === 'string' ? candidate.error_description : undefined,
      error_uri: typeof candidate.error_uri === 'string' ? candidate.error_uri : undefined,
    },
    status,
  );
}

/** Refresh refusals that mean "sign in again": the local session must be cleared. */
const SIGNED_OUT_OAUTH_ERRORS = new Set(['invalid_grant', 'invalid_client', 'unauthorized_client', 'invalid_scope', 'invalid_target']);

export function isSignedOutError(error: unknown): boolean {
  if (error instanceof OAuthError) return SIGNED_OUT_OAUTH_ERRORS.has(error.error);
  if (error instanceof AuthError) {
    return error.code === 'signed_out' || error.code === 'session_expired' || error.code === 'refresh_token_consumed';
  }
  return false;
}

/**
 * The request did not get a usable answer: offline, DNS, timeout, a gateway
 * page, a 5xx or a 429. The session should be kept (grace) and the call
 * retried later. Never true for an OAuth error object with a 4xx status.
 */
export function isTransientError(error: unknown): boolean {
  if (error instanceof OAuthError) return error.status >= 500 || error.status === 429;
  if (error instanceof AuthError) {
    return error.code === 'network_error' || error.code === 'invalid_response' || error.code === 'jwks_unavailable' || error.code === 'discovery_failed';
  }
  return false;
}
