/**
 * Authorization request and response (authorization code + PKCE) and the
 * RP-initiated logout URL.
 *
 * Issuer rules honoured here (the issuer):
 * `response_type=code` only, `code_challenge_method=S256`, `state` and
 * `nonce` required, exact redirect URI match, `iss` echoed in the response.
 */

import { AuthError, OAuthError } from './errors';
import { DEFAULT_SCOPES } from './discovery';
import type { IssuerMetadata } from './types';
import { safeEqual, toScopeString } from './util';

export interface AuthorizationRequestParams {
  metadata: Pick<IssuerMetadata, 'authorization_endpoint'>;
  clientId: string;
  redirectUri: string;
  /** Space-separated string or list. `openid` is added when missing. Default `openid profile email`. */
  scope?: string | readonly string[];
  state: string;
  nonce: string;
  codeChallenge: string;
  /** `login` forces the sign-in page; `consent` re-asks; `none` is not supported by the issuer yet (M3). */
  prompt?: 'login' | 'consent' | 'select_account' | 'none';
  loginHint?: string;
  /** Resource indicator (RFC 8707). Only first-party clients may name the platform API. */
  resource?: string;
  /** Anything else, verbatim (`ui_locales`, `max_age`, ...). */
  extraParams?: Record<string, string>;
}

export function buildAuthorizationUrl(params: AuthorizationRequestParams): string {
  const url = new URL(params.metadata.authorization_endpoint);
  const search = url.searchParams;
  for (const [key, value] of Object.entries(params.extraParams ?? {})) search.set(key, value);
  search.set('client_id', params.clientId);
  search.set('redirect_uri', params.redirectUri);
  search.set('response_type', 'code');
  search.set('scope', toScopeString(params.scope, DEFAULT_SCOPES));
  search.set('state', params.state);
  search.set('nonce', params.nonce);
  search.set('code_challenge', params.codeChallenge);
  search.set('code_challenge_method', 'S256');
  if (params.prompt) search.set('prompt', params.prompt);
  if (params.loginHint) search.set('login_hint', params.loginHint);
  if (params.resource) search.set('resource', params.resource);
  return url.toString();
}

export interface AuthorizationResponse {
  code: string;
  state: string;
  /** Present when the issuer echoes its identifier (RFC 9207). */
  iss: string | null;
}

/** Where the authorization response parameters can be: query (default) or fragment. */
function responseParams(url: URL): URLSearchParams {
  if (url.searchParams.has('code') || url.searchParams.has('error') || url.searchParams.has('state')) return url.searchParams;
  if (url.hash.length > 1) return new URLSearchParams(url.hash.slice(1));
  return url.searchParams;
}

/** True when `url` looks like an authorization response (a code or an error with a state). */
export function isAuthorizationResponse(url: string | URL): boolean {
  const parsed = typeof url === 'string' ? new URL(url) : url;
  const params = responseParams(parsed);
  return params.has('state') && (params.has('code') || params.has('error'));
}

/**
 * Validate the redirect back from the issuer. Throws {@link OAuthError} for
 * an error response (after checking `state`), {@link AuthError}
 * `invalid_state` when the state does not match, `invalid_callback` when
 * there is neither code nor error, and `invalid_response` when an `iss` is
 * present but wrong (mix-up defence).
 */
export function parseAuthorizationResponse(
  url: string | URL,
  expected: { state: string; issuer?: string },
): AuthorizationResponse {
  const parsed = typeof url === 'string' ? new URL(url) : url;
  const params = responseParams(parsed);
  const state = params.get('state');
  if (!state || !safeEqual(state, expected.state)) {
    throw new AuthError('invalid_state', 'The state returned by the issuer does not match the pending sign-in');
  }
  const iss = params.get('iss');
  if (expected.issuer && iss !== null && iss !== expected.issuer) {
    throw new AuthError('invalid_response', 'The authorization response names a different issuer');
  }
  const error = params.get('error');
  if (error) {
    throw new OAuthError(
      {
        error,
        error_description: params.get('error_description') ?? undefined,
        error_uri: params.get('error_uri') ?? undefined,
      },
      0,
    );
  }
  const code = params.get('code');
  if (!code) {
    throw new AuthError('invalid_callback', 'The authorization response carries neither a code nor an error');
  }
  return { code, state, iss };
}

export interface EndSessionParams {
  metadata: Pick<IssuerMetadata, 'end_session_endpoint'>;
  /** The ID token of the session to end. The issuer renders a confirm page without it. */
  idTokenHint?: string | null;
  clientId?: string;
  /** Must be registered on the client. */
  postLogoutRedirectUri?: string;
  state?: string;
}

/** The RP-initiated logout URL, or null when the issuer publishes no end-session endpoint. */
export function buildEndSessionUrl(params: EndSessionParams): string | null {
  const endpoint = params.metadata.end_session_endpoint;
  if (!endpoint) return null;
  const url = new URL(endpoint);
  if (params.idTokenHint) url.searchParams.set('id_token_hint', params.idTokenHint);
  if (params.clientId) url.searchParams.set('client_id', params.clientId);
  if (params.postLogoutRedirectUri) url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
  if (params.state) url.searchParams.set('state', params.state);
  return url.toString();
}
