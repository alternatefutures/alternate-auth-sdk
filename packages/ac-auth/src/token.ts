/**
 * Token endpoint, revocation, introspection and userinfo.
 *
 * Client authentication: public clients send `client_id` in the body
 * (`none`); confidential clients use `client_secret_basic` (the issuer's
 * default) or `client_secret_post`. The issuer refuses more than one
 * mechanism per request and requires the mechanism to match the client's
 * registration, so the caller states the method explicitly.
 */

import { AuthError, OAuthError, oauthErrorFromBody } from './errors';
import type { ClientAuthentication, IdTokenClaims, TokenResponse, TokenSet } from './types';
import { readJson, request, resolveFetch, type FetchLike } from './util';

export interface TokenEndpointClient {
  tokenEndpoint: string;
  clientId: string;
  /** Default `{ method: 'none' }` (public client). */
  clientAuthentication?: ClientAuthentication;
  fetch?: FetchLike;
  /** Per request. Default 15 s. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

function encodeForBasic(value: string): string {
  // RFC 6749 §2.3.1: form-encode before base64.
  return encodeURIComponent(value).replace(/%20/g, '+');
}

/** Body fields and headers that authenticate the client for one request. */
export function clientAuthenticationParts(
  clientId: string,
  authentication: ClientAuthentication | undefined,
): { headers: Record<string, string>; body: Record<string, string> } {
  const method = authentication?.method ?? 'none';
  switch (method) {
    case 'none':
      return { headers: {}, body: { client_id: clientId } };
    case 'client_secret_post':
      return { headers: {}, body: { client_id: clientId, client_secret: (authentication as { clientSecret: string }).clientSecret } };
    case 'client_secret_basic': {
      const secret = (authentication as { clientSecret: string }).clientSecret;
      const credentials = btoa(`${encodeForBasic(clientId)}:${encodeForBasic(secret)}`);
      return { headers: { authorization: `Basic ${credentials}` }, body: { client_id: clientId } };
    }
    default:
      throw new AuthError('unsupported', `Unsupported client authentication method ${String(method)}`);
  }
}

/** POST a form and interpret the answer per RFC 6749 §5. */
export async function postForm<T = Record<string, unknown>>(
  endpoint: string,
  fields: Record<string, string>,
  options: { headers?: Record<string, string>; fetch?: FetchLike; timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<T> {
  const fetchImpl = resolveFetch(options.fetch);
  const body = new URLSearchParams(fields).toString();
  const response = await request(fetchImpl, endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...(options.headers ?? {}),
    },
    body,
    signal: options.signal,
    timeoutMs: options.timeoutMs ?? 15_000,
  });
  const json = await readJson(response);
  if (!response.ok) {
    const oauth = oauthErrorFromBody(json, response.status);
    if (oauth) throw oauth;
    throw new AuthError('invalid_response', `${new URL(endpoint).pathname} answered HTTP ${response.status} without an OAuth error body`);
  }
  if (json === null || typeof json !== 'object') {
    throw new AuthError('invalid_response', `${new URL(endpoint).pathname} answered HTTP ${response.status} without a JSON body`);
  }
  return json as T;
}

function assertTokenResponse(body: Record<string, unknown>): TokenResponse {
  if (typeof body.access_token !== 'string' || !body.access_token) {
    throw new AuthError('invalid_response', 'The token response has no access_token');
  }
  if (typeof body.token_type !== 'string') {
    throw new AuthError('invalid_response', 'The token response has no token_type');
  }
  return body as TokenResponse;
}

export interface CodeExchangeParams {
  code: string;
  redirectUri: string;
  codeVerifier: string;
  resource?: string;
}

/** `grant_type=authorization_code` with PKCE. */
export async function exchangeAuthorizationCode(client: TokenEndpointClient, params: CodeExchangeParams): Promise<TokenResponse> {
  const auth = clientAuthenticationParts(client.clientId, client.clientAuthentication);
  const body = await postForm<Record<string, unknown>>(
    client.tokenEndpoint,
    {
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
      ...(params.resource ? { resource: params.resource } : {}),
      ...auth.body,
    },
    { headers: auth.headers, fetch: client.fetch, timeoutMs: client.timeoutMs, signal: client.signal },
  );
  return assertTokenResponse(body);
}

export interface RefreshParams {
  refreshToken: string;
  /** Narrow the scope of the new tokens (never widen). */
  scope?: string;
  resource?: string;
}

/**
 * `grant_type=refresh_token`. The issuer ALWAYS rotates: the answer carries
 * a new refresh token and the presented one is dead. Presenting it again
 * revokes the whole grant. Use {@link RefreshCoordinator} rather than
 * calling this directly from application code.
 */
export async function refreshTokenGrant(client: TokenEndpointClient, params: RefreshParams): Promise<TokenResponse> {
  const auth = clientAuthenticationParts(client.clientId, client.clientAuthentication);
  const body = await postForm<Record<string, unknown>>(
    client.tokenEndpoint,
    {
      grant_type: 'refresh_token',
      refresh_token: params.refreshToken,
      ...(params.scope ? { scope: params.scope } : {}),
      ...(params.resource ? { resource: params.resource } : {}),
      ...auth.body,
    },
    { headers: auth.headers, fetch: client.fetch, timeoutMs: client.timeoutMs, signal: client.signal },
  );
  return assertTokenResponse(body);
}

export interface RevocationParams {
  revocationEndpoint: string;
  clientId: string;
  clientAuthentication?: ClientAuthentication;
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
  fetch?: FetchLike;
  timeoutMs?: number;
}

/** RFC 7009. Revoking a refresh token ends every token of its grant. Unknown tokens answer 200. */
export async function revokeToken(params: RevocationParams): Promise<void> {
  const auth = clientAuthenticationParts(params.clientId, params.clientAuthentication);
  const fetchImpl = resolveFetch(params.fetch);
  const response = await request(fetchImpl, params.revocationEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...auth.headers },
    body: new URLSearchParams({
      token: params.token,
      ...(params.tokenTypeHint ? { token_type_hint: params.tokenTypeHint } : {}),
      ...auth.body,
    }).toString(),
    timeoutMs: params.timeoutMs ?? 15_000,
  });
  if (!response.ok) {
    const oauth = oauthErrorFromBody(await readJson(response), response.status);
    throw oauth ?? new AuthError('invalid_response', `Revocation answered HTTP ${response.status}`);
  }
}

export interface IntrospectionParams {
  introspectionEndpoint: string;
  clientId: string;
  clientAuthentication?: ClientAuthentication;
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
  fetch?: FetchLike;
  timeoutMs?: number;
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  sub?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  token_type?: string;
  [key: string]: unknown;
}

/** RFC 7662. A client may introspect its own tokens. */
export async function introspectToken(params: IntrospectionParams): Promise<IntrospectionResponse> {
  const auth = clientAuthenticationParts(params.clientId, params.clientAuthentication);
  const body = await postForm<IntrospectionResponse>(
    params.introspectionEndpoint,
    {
      token: params.token,
      ...(params.tokenTypeHint ? { token_type_hint: params.tokenTypeHint } : {}),
      ...auth.body,
    },
    { headers: auth.headers, fetch: params.fetch, timeoutMs: params.timeoutMs },
  );
  return { ...body, active: body.active === true };
}

export interface UserInfoParams {
  userinfoEndpoint: string;
  accessToken: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/** The userinfo endpoint answers the same claims the ID token carries, filtered by the granted scopes. */
export async function fetchUserInfo(params: UserInfoParams): Promise<Partial<IdTokenClaims> & { sub: string }> {
  const fetchImpl = resolveFetch(params.fetch);
  const response = await request(fetchImpl, params.userinfoEndpoint, {
    method: 'GET',
    headers: { authorization: `Bearer ${params.accessToken}`, accept: 'application/json' },
    timeoutMs: params.timeoutMs ?? 15_000,
  });
  const json = await readJson(response);
  if (!response.ok) {
    const oauth = oauthErrorFromBody(json, response.status);
    if (oauth) throw oauth;
    // RFC 6750: the error lives in the WWW-Authenticate header.
    const challenge = response.headers.get('www-authenticate') ?? '';
    const match = /error="([^"]+)"/.exec(challenge);
    if (match?.[1]) throw new OAuthError({ error: match[1] }, response.status);
    throw new AuthError('invalid_response', `userinfo answered HTTP ${response.status}`);
  }
  if (!json || typeof json !== 'object' || typeof (json as { sub?: unknown }).sub !== 'string') {
    throw new AuthError('invalid_response', 'userinfo did not return a subject');
  }
  return json as Partial<IdTokenClaims> & { sub: string };
}

/** Normalize a token response into absolute times. `claims` are attached by the caller after verification. */
export function tokenSetFromResponse(response: TokenResponse, options: { now?: number; claims?: IdTokenClaims | null; defaultExpiresInSeconds?: number } = {}): TokenSet {
  const now = options.now ?? Date.now();
  const expiresIn = typeof response.expires_in === 'number' && Number.isFinite(response.expires_in)
    ? response.expires_in
    : options.defaultExpiresInSeconds ?? 3600;
  return {
    accessToken: response.access_token,
    tokenType: response.token_type,
    scope: typeof response.scope === 'string' ? response.scope : null,
    refreshToken: typeof response.refresh_token === 'string' ? response.refresh_token : null,
    idToken: typeof response.id_token === 'string' ? response.id_token : null,
    expiresAt: now + expiresIn * 1000,
    issuedAt: now,
    claims: options.claims ?? null,
  };
}
