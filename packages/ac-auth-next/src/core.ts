/**
 * The server-side session for Next.js, framework-agnostic at its core so it
 * can be unit tested with plain `Request` objects and reused by other
 * server frameworks later.
 *
 * Shape (the BFF pattern, the auth plan and the Next.js 16
 * rule "token refresh belongs in the proxy only"):
 *
 * - tokens live in ONE encrypted httpOnly cookie; the browser only ever sees
 *   the user and the session status through `GET <basePath>/session`;
 * - the sign-in starts at `GET <basePath>/signin` (PKCE state in a short
 *   sealed transaction cookie scoped to the base path) and finishes at
 *   `GET <basePath>/callback`;
 * - refresh with rotation happens in the proxy ({@link refreshSessionCookie}),
 *   single-flight with a successor cache, and the fresh cookie is also
 *   forwarded to the request so Server Components see it at once;
 * - `auth()` reads and never writes: an expired session inside the grace
 *   window still answers (status `grace`) until the cap.
 */

import {
  DEFAULT_ISSUER,
  DEFAULT_SCOPES,
  RefreshCoordinator,
  buildAuthorizationUrl,
  buildEndSessionUrl,
  createDiscoveryCache,
  createJwksResolver,
  createPkcePair,
  decodeIdToken,
  embeddedKeysFor,
  evaluateGrace,
  exchangeAuthorizationCode,
  generateNonce,
  generateState,
  isSignedOutError,
  isTransientError,
  parseAuthorizationResponse,
  refreshTokenGrant,
  resolveGracePolicy,
  revokeToken,
  userFromClaims,
  verifyIdToken,
  AuthError,
  NO_GRACE_POLICY,
  type AuthUser,
  type ClientAuthentication,
  type FetchLike,
  type IdTokenClaims,
  type IssuerMetadata,
  type JWK,
  type JwksResolver,
  type SessionGracePolicy,
  type TokenResponse,
} from '@alternatefutures/ac-auth';
import { expireCookie, readCookie, serializeCookie, type CookieAttributes } from './cookies';
import { seal, unseal } from './seal';

export interface AcAuthConfig {
  /** Issuer identifier. Default `ALTERNATE_CLOUDS_ISSUER`, else the production issuer. */
  issuer?: string;
  /** Default `ALTERNATE_CLOUDS_CLIENT_ID`. */
  clientId?: string;
  /** Confidential clients only. Default `ALTERNATE_CLOUDS_CLIENT_SECRET`. Absent means a public client (PKCE only). */
  clientSecret?: string;
  /** How the secret is sent. Default `client_secret_basic` (the issuer's default for new clients). */
  clientAuthenticationMethod?: 'client_secret_basic' | 'client_secret_post';
  /** Seals the cookies. Default `AUTH_SECRET`. At least 16 characters. */
  secret?: string;
  /** Where the route handlers are mounted. Default `/api/auth`. */
  basePath?: string;
  /** Default `openid profile email`. */
  scope?: string | readonly string[];
  /** Absolute redirect URI registered on the client. Default `<origin><basePath>/callback` of the incoming request. */
  redirectUri?: string;
  /** Registered post-logout redirect URI. When set, sign-out also ends the issuer session. */
  postLogoutRedirectUri?: string;
  /** Same-origin path to land on after a local sign-out. Default `/`. */
  afterSignOutPath?: string;
  /** Also revoke the refresh token at the issuer on sign-out (disconnects the app on every device). Default false. */
  revokeOnSignOut?: boolean;
  cookie?: {
    /** Default `ac_auth.session`; the transaction cookie is `<name>.txn`. */
    name?: string;
    /** Default: secure when the request is https. */
    secure?: boolean;
    sameSite?: 'lax' | 'strict';
    domain?: string;
    /** Session cookie lifetime. Default 30 days (the refresh token's lifetime). */
    maxAgeSeconds?: number;
  };
  grace?: Partial<SessionGracePolicy> | false;
  embeddedKeys?: readonly JWK[];
  metadata?: IssuerMetadata;
  fetch?: FetchLike;
  /** Refresh this long before the access token expires. Default 30 s. */
  refreshLeewayMs?: number;
  /** Trust `x-forwarded-proto` / `x-forwarded-host` to compute the origin. Default true. */
  trustHost?: boolean;
  now?: () => number;
  onWarning?: (message: string, cause?: unknown) => void;
  env?: Record<string, string | undefined>;
}

export interface ResolvedConfig {
  issuer: string;
  clientId: string;
  clientAuthentication: ClientAuthentication;
  secret: string;
  basePath: string;
  scope: string | readonly string[];
  redirectUri: string | undefined;
  postLogoutRedirectUri: string | undefined;
  afterSignOutPath: string;
  revokeOnSignOut: boolean;
  cookieName: string;
  txnCookieName: string;
  cookieSecure: boolean | undefined;
  cookieSameSite: 'lax' | 'strict';
  cookieDomain: string | undefined;
  cookieMaxAgeSeconds: number;
  grace: SessionGracePolicy;
  refreshLeewayMs: number;
  trustHost: boolean;
  now: () => number;
  fetch: FetchLike | undefined;
  onWarning: ((message: string, cause?: unknown) => void) | undefined;
}

/** The sealed session cookie. */
export interface SessionPayload extends Record<string, unknown> {
  v: 1;
  at: string;
  rt: string | null;
  idt: string | null;
  /** Access token expiry, epoch ms. */
  exp_ms: number;
  /** Issued at, epoch ms. */
  iat_ms: number;
  scope: string | null;
}

interface TransactionPayload extends Record<string, unknown> {
  v: 1;
  state: string;
  nonce: string;
  verifier: string;
  redirectUri: string;
  returnTo: string;
}

/** What `auth()` returns on the server. */
export interface ServerSession {
  status: 'active' | 'grace';
  user: AuthUser;
  claims: IdTokenClaims;
  /** Epoch ms. */
  expiresAt: number;
  issuedAt: number;
  accessToken: string;
  idToken: string | null;
  scope: string | null;
}

/** What the browser is allowed to see. */
export interface ClientSession {
  status: 'active' | 'grace';
  user: AuthUser;
  expiresAt: number;
  issuedAt: number;
}

export function toClientSession(session: ServerSession | null): ClientSession | null {
  if (!session) return null;
  return { status: session.status, user: session.user, expiresAt: session.expiresAt, issuedAt: session.issuedAt };
}

export function resolveConfig(config: AcAuthConfig = {}): ResolvedConfig {
  const env = config.env ?? (typeof process !== 'undefined' ? process.env : {});
  const issuer = (config.issuer ?? env.ALTERNATE_CLOUDS_ISSUER ?? DEFAULT_ISSUER).replace(/\/+$/, '');
  const clientId = config.clientId ?? env.ALTERNATE_CLOUDS_CLIENT_ID ?? '';
  const clientSecret = config.clientSecret ?? env.ALTERNATE_CLOUDS_CLIENT_SECRET;
  const secret = config.secret ?? env.AUTH_SECRET ?? '';
  if (!clientId) throw new AuthError('configuration', 'clientId is required (ALTERNATE_CLOUDS_CLIENT_ID)');
  if (secret.length < 16) throw new AuthError('configuration', 'secret must be at least 16 characters (AUTH_SECRET)');
  const basePath = `/${(config.basePath ?? '/api/auth').replace(/^\/+|\/+$/g, '')}`;
  const cookieName = config.cookie?.name ?? 'ac_auth.session';
  return {
    issuer,
    clientId,
    clientAuthentication: clientSecret
      ? { method: config.clientAuthenticationMethod ?? 'client_secret_basic', clientSecret }
      : { method: 'none' },
    secret,
    basePath,
    scope: config.scope ?? DEFAULT_SCOPES,
    redirectUri: config.redirectUri,
    postLogoutRedirectUri: config.postLogoutRedirectUri,
    afterSignOutPath: safeReturnTo(config.afterSignOutPath) ?? '/',
    revokeOnSignOut: config.revokeOnSignOut === true,
    cookieName,
    txnCookieName: `${cookieName}.txn`,
    cookieSecure: config.cookie?.secure,
    cookieSameSite: config.cookie?.sameSite ?? 'lax',
    cookieDomain: config.cookie?.domain,
    cookieMaxAgeSeconds: config.cookie?.maxAgeSeconds ?? 30 * 24 * 60 * 60,
    grace: config.grace === false ? NO_GRACE_POLICY : resolveGracePolicy(config.grace),
    refreshLeewayMs: config.refreshLeewayMs ?? 30_000,
    trustHost: config.trustHost !== false,
    now: config.now ?? (() => Date.now()),
    fetch: config.fetch,
    onWarning: config.onWarning,
  };
}

/** Only same-origin paths may be used as a return target. */
export function safeReturnTo(value: string | null | undefined): string | null {
  if (!value || typeof value !== 'string') return null;
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return null;
  if (/[\r\n]/.test(value)) return null;
  return value;
}

export function requestOrigin(request: Request, config: ResolvedConfig): string {
  const url = new URL(request.url);
  if (config.trustHost) {
    const proto = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim();
    const host = request.headers.get('x-forwarded-host')?.split(',')[0]?.trim() ?? request.headers.get('host');
    if (host) return `${proto || url.protocol.replace(':', '')}://${host}`;
  }
  return url.origin;
}

const TXN_TTL_SECONDS = 15 * 60;

export class AcAuthCore {
  readonly config: ResolvedConfig;
  private readonly discovery = createDiscoveryCache();
  private readonly resolver: JwksResolver;
  private readonly coordinator: RefreshCoordinator<SessionPayload>;
  private readonly staticMetadata: IssuerMetadata | undefined;

  constructor(config: AcAuthConfig = {}) {
    this.config = resolveConfig(config);
    this.staticMetadata = config.metadata;
    this.resolver = createJwksResolver({
      jwksUri: config.metadata?.jwks_uri ?? `${this.config.issuer}/.well-known/jwks.json`,
      fetch: this.config.fetch,
      initialKeys: config.embeddedKeys ?? embeddedKeysFor(this.config.issuer),
      now: this.config.now,
      onWarning: this.config.onWarning,
    });
    this.coordinator = new RefreshCoordinator<SessionPayload>({
      refresh: (rt) => this.performRefresh(rt),
      refreshTokenOf: (payload) => payload.rt,
      now: this.config.now,
    });
  }

  metadata(): Promise<IssuerMetadata> {
    if (this.staticMetadata) return Promise.resolve(this.staticMetadata);
    return this.discovery.get(this.config.issuer, { fetch: this.config.fetch, onWarning: this.config.onWarning });
  }

  // ------------------------------------------------------------ cookies

  private isSecure(request: Request): boolean {
    return this.config.cookieSecure ?? requestOrigin(request, this.config).startsWith('https://');
  }

  private cookieAttributes(request: Request, path: string, maxAge: number): CookieAttributes {
    return { path, maxAge, httpOnly: true, secure: this.isSecure(request), sameSite: this.config.cookieSameSite, domain: this.config.cookieDomain };
  }

  /**
   * Cookie names carry a browser-enforced prefix over https (OAuth for
   * browser-based apps, BFF cookies): `__Host-` for the session cookie
   * (Secure, Path=/, no Domain, so no subdomain can set or widen it) and
   * `__Secure-` for the transaction cookie (its path is the base path, which
   * `__Host-` forbids). Plain names over http (local development).
   */
  sessionCookieName(request: Request): string {
    if (this.isSecure(request) && !this.config.cookieDomain) return `__Host-${this.config.cookieName}`;
    return this.config.cookieName;
  }

  private txnCookieName(request: Request): string {
    return this.isSecure(request) ? `__Secure-${this.config.txnCookieName}` : this.config.txnCookieName;
  }

  /** The session cookie value of a request, whichever prefix it was set with. */
  readSessionCookie(cookieHeader: string | null | undefined): string | null {
    for (const name of [`__Host-${this.config.cookieName}`, this.config.cookieName]) {
      const value = readCookie(cookieHeader, name);
      if (value) return value;
    }
    return null;
  }

  async sealSession(payload: SessionPayload): Promise<string> {
    const nowSeconds = Math.floor(this.config.now() / 1000);
    return seal(payload, { secret: this.config.secret, purpose: 'session', expiresAt: nowSeconds + this.config.cookieMaxAgeSeconds, now: this.config.now });
  }

  unsealSession(value: string | null | undefined): Promise<SessionPayload | null> {
    return unseal<SessionPayload>(value, { secret: this.config.secret, purpose: 'session', now: this.config.now }).then((p) => (p && p.v === 1 && typeof p.at === 'string' ? p : null));
  }

  sessionCookie(request: Request, value: string): string {
    return serializeCookie(this.sessionCookieName(request), value, this.cookieAttributes(request, '/', this.config.cookieMaxAgeSeconds));
  }

  clearSessionCookie(request: Request): string {
    const attrs = this.cookieAttributes(request, '/', 0);
    return expireCookie(this.sessionCookieName(request), { path: '/', domain: attrs.domain, secure: attrs.secure, sameSite: attrs.sameSite });
  }

  private clearTxnCookie(request: Request): string {
    const attrs = this.cookieAttributes(request, this.config.basePath, 0);
    return expireCookie(this.txnCookieName(request), { path: this.config.basePath, domain: attrs.domain, secure: attrs.secure, sameSite: attrs.sameSite });
  }

  // ------------------------------------------------------------ session read

  /** Interpret a sealed payload at `now`: null when expired past the grace cap. */
  sessionFromPayload(payload: SessionPayload | null): ServerSession | null {
    if (!payload) return null;
    const verdict = evaluateGrace({ expiresAt: payload.exp_ms, issuedAt: payload.iat_ms }, this.config.now(), this.config.grace);
    if (verdict === 'expired') return null;
    if (!payload.idt) return null;
    let claims: IdTokenClaims;
    try {
      claims = decodeIdToken(payload.idt);
    } catch {
      return null;
    }
    return {
      status: verdict,
      user: userFromClaims(claims),
      claims,
      expiresAt: payload.exp_ms,
      issuedAt: payload.iat_ms,
      accessToken: payload.at,
      idToken: payload.idt,
      scope: payload.scope,
    };
  }

  /** The session carried by a `Cookie` header value. */
  async sessionFromCookieHeader(cookieHeader: string | null | undefined): Promise<ServerSession | null> {
    return this.sessionFromPayload(await this.unsealSession(this.readSessionCookie(cookieHeader)));
  }

  // ------------------------------------------------------------ sign-in

  signInPath(returnTo?: string | null, extra: Record<string, string> = {}): string {
    const params = new URLSearchParams(extra);
    const safe = safeReturnTo(returnTo);
    if (safe) params.set('returnTo', safe);
    const query = params.toString();
    return `${this.config.basePath}/signin${query ? `?${query}` : ''}`;
  }

  signOutPath(): string {
    return `${this.config.basePath}/signout`;
  }

  /** `GET <basePath>/signin`: start the code + PKCE flow. */
  async handleSignIn(request: Request): Promise<Response> {
    // A prefetched link (Next.js <Link>, browser speculation) must not start a
    // flow: answer 204 like the browser expects and do nothing.
    const purpose = request.headers.get('purpose') ?? request.headers.get('sec-purpose') ?? request.headers.get('x-purpose');
    if (request.headers.has('next-router-prefetch') || (purpose && /prefetch|preview/i.test(purpose))) {
      return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    }
    const url = new URL(request.url);
    const returnTo = safeReturnTo(url.searchParams.get('returnTo')) ?? '/';
    const metadata = await this.metadata();
    const state = generateState();
    const nonce = generateNonce();
    const pkce = await createPkcePair();
    const redirectUri = this.config.redirectUri ?? `${requestOrigin(request, this.config)}${this.config.basePath}/callback`;
    const txn: TransactionPayload = { v: 1, state, nonce, verifier: pkce.codeVerifier, redirectUri, returnTo };
    const nowSeconds = Math.floor(this.config.now() / 1000);
    const sealed = await seal(txn, { secret: this.config.secret, purpose: 'transaction', expiresAt: nowSeconds + TXN_TTL_SECONDS, now: this.config.now });
    const prompt = url.searchParams.get('prompt');
    const loginHint = url.searchParams.get('login_hint');
    const scope = url.searchParams.get('scope');
    const location = buildAuthorizationUrl({
      metadata,
      clientId: this.config.clientId,
      redirectUri,
      scope: scope ?? this.config.scope,
      state,
      nonce,
      codeChallenge: pkce.codeChallenge,
      prompt: prompt === 'login' || prompt === 'consent' || prompt === 'select_account' ? prompt : undefined,
      loginHint: loginHint ?? undefined,
    });
    const headers = new Headers({ location, 'cache-control': 'no-store' });
    headers.append('set-cookie', serializeCookie(this.txnCookieName(request), sealed, this.cookieAttributes(request, this.config.basePath, TXN_TTL_SECONDS)));
    return new Response(null, { status: 302, headers });
  }

  /** `GET <basePath>/callback`: finish the flow, seal the session, go to `returnTo`. */
  async handleCallback(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const cookieHeader = request.headers.get('cookie');
    const txn = await unseal<TransactionPayload>(readCookie(cookieHeader, this.txnCookieName(request)) ?? readCookie(cookieHeader, this.config.txnCookieName), { secret: this.config.secret, purpose: 'transaction', now: this.config.now });
    const headers = new Headers({ 'cache-control': 'no-store' });
    headers.append('set-cookie', this.clearTxnCookie(request));

    const fail = (code: string, returnTo = '/') => {
      const target = new URL(returnTo, 'http://local');
      target.searchParams.set('auth_error', code);
      headers.set('location', `${target.pathname}${target.search}`);
      return new Response(null, { status: 302, headers });
    };

    if (!txn || txn.v !== 1) return fail('no_transaction');
    let code: string;
    try {
      code = parseAuthorizationResponse(url, { state: txn.state, issuer: this.config.issuer }).code;
    } catch (error) {
      const oauth = (error as { error?: string }).error;
      return fail(oauth ?? ((error as AuthError).code || 'invalid_callback'), txn.returnTo);
    }
    try {
      const metadata = await this.metadata();
      const raw = await exchangeAuthorizationCode(
        { tokenEndpoint: metadata.token_endpoint, clientId: this.config.clientId, clientAuthentication: this.config.clientAuthentication, fetch: this.config.fetch },
        { code, redirectUri: txn.redirectUri, codeVerifier: txn.verifier },
      );
      if (!raw.id_token) throw new AuthError('invalid_response', 'The token response carries no ID token');
      await verifyIdToken(raw.id_token, {
        issuer: this.config.issuer,
        clientId: this.config.clientId,
        resolver: this.resolver,
        nonce: txn.nonce,
        currentTimeSeconds: Math.floor(this.config.now() / 1000),
      });
      const payload = this.payloadFromResponse(raw);
      headers.append('set-cookie', this.sessionCookie(request, await this.sealSession(payload)));
      headers.set('location', txn.returnTo);
      return new Response(null, { status: 302, headers });
    } catch (error) {
      this.config.onWarning?.('sign-in callback failed', error);
      const code = error instanceof AuthError ? ((error as { error?: string }).error ?? error.code) : 'sign_in_failed';
      return fail(code, txn.returnTo);
    }
  }

  private payloadFromResponse(raw: TokenResponse, previous?: SessionPayload | null): SessionPayload {
    const now = this.config.now();
    const expiresIn = typeof raw.expires_in === 'number' ? raw.expires_in : 3600;
    return {
      v: 1,
      at: raw.access_token,
      rt: typeof raw.refresh_token === 'string' ? raw.refresh_token : previous?.rt ?? null,
      idt: typeof raw.id_token === 'string' ? raw.id_token : previous?.idt ?? null,
      exp_ms: now + expiresIn * 1000,
      iat_ms: now,
      scope: typeof raw.scope === 'string' ? raw.scope : previous?.scope ?? null,
    };
  }

  // ------------------------------------------------------------ refresh (proxy)

  private async performRefresh(refreshToken: string): Promise<SessionPayload> {
    const metadata = await this.metadata();
    const raw = await refreshTokenGrant(
      { tokenEndpoint: metadata.token_endpoint, clientId: this.config.clientId, clientAuthentication: this.config.clientAuthentication, fetch: this.config.fetch },
      { refreshToken },
    );
    if (raw.id_token) {
      await verifyIdToken(raw.id_token, {
        issuer: this.config.issuer,
        clientId: this.config.clientId,
        resolver: this.resolver,
        currentTimeSeconds: Math.floor(this.config.now() / 1000),
      });
    }
    return this.payloadFromResponse(raw, this.lastPayloadFor.get(refreshToken) ?? null);
  }

  /** The payload a refresh started from, so a refresh answer without an ID token keeps the previous one. */
  private readonly lastPayloadFor = new Map<string, SessionPayload>();

  /**
   * Decide what the proxy should do with the incoming session cookie:
   * `keep` (valid or no session), `set` (refreshed: write this value),
   * `clear` (definitively signed out).
   */
  async refreshSessionCookie(cookieValue: string | null | undefined): Promise<{ action: 'keep' } | { action: 'set'; value: string; payload: SessionPayload } | { action: 'clear' }> {
    if (!cookieValue) return { action: 'keep' };
    const payload = await this.unsealSession(cookieValue);
    if (!payload) return { action: 'clear' };
    const now = this.config.now();
    if (now < payload.exp_ms - this.config.refreshLeewayMs) return { action: 'keep' };
    if (!payload.rt) {
      return evaluateGrace({ expiresAt: payload.exp_ms, issuedAt: payload.iat_ms }, now, this.config.grace) === 'expired' ? { action: 'clear' } : { action: 'keep' };
    }
    this.lastPayloadFor.set(payload.rt, payload);
    try {
      const next = await this.coordinator.refresh(payload.rt);
      return { action: 'set', value: await this.sealSession(next), payload: next };
    } catch (error) {
      if (isSignedOutError(error)) return { action: 'clear' };
      if (isTransientError(error)) {
        this.config.onWarning?.('token refresh failed; keeping the session under the grace policy', error);
        return evaluateGrace({ expiresAt: payload.exp_ms, issuedAt: payload.iat_ms }, now, this.config.grace) === 'expired' ? { action: 'clear' } : { action: 'keep' };
      }
      throw error;
    } finally {
      this.lastPayloadFor.delete(payload.rt);
    }
  }

  // ------------------------------------------------------------ sign-out

  /** `POST <basePath>/signout` (also GET): clear the session, optionally end it at the issuer. */
  async handleSignOut(request: Request): Promise<Response> {
    const payload = await this.unsealSession(this.readSessionCookie(request.headers.get('cookie')));
    const headers = new Headers({ 'cache-control': 'no-store' });
    headers.append('set-cookie', this.clearSessionCookie(request));
    let redirectTo: string = this.config.afterSignOutPath;
    if (payload) {
      if (this.config.revokeOnSignOut && payload.rt) {
        try {
          const metadata = await this.metadata();
          if (metadata.revocation_endpoint) {
            await revokeToken({
              revocationEndpoint: metadata.revocation_endpoint,
              clientId: this.config.clientId,
              clientAuthentication: this.config.clientAuthentication,
              token: payload.rt,
              tokenTypeHint: 'refresh_token',
              fetch: this.config.fetch,
            });
          }
        } catch (error) {
          this.config.onWarning?.('refresh token revocation failed', error);
        }
      }
      if (this.config.postLogoutRedirectUri && payload.idt) {
        try {
          const metadata = await this.metadata();
          redirectTo = buildEndSessionUrl({ metadata, idTokenHint: payload.idt, clientId: this.config.clientId, postLogoutRedirectUri: this.config.postLogoutRedirectUri }) ?? redirectTo;
        } catch (error) {
          this.config.onWarning?.('could not build the end-session URL', error);
        }
      }
    }
    const wantsJson = request.headers.get('accept')?.includes('application/json');
    if (wantsJson) {
      headers.set('content-type', 'application/json');
      return new Response(JSON.stringify({ redirectTo }), { status: 200, headers });
    }
    headers.set('location', redirectTo);
    return new Response(null, { status: 302, headers });
  }

  /** `GET <basePath>/session`: the client-safe session. */
  async handleSession(request: Request): Promise<Response> {
    const session = await this.sessionFromCookieHeader(request.headers.get('cookie'));
    return new Response(JSON.stringify({ session: toClientSession(session) }), {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  }

  /** Route a request under `basePath` to the handler for its last segment. */
  async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const rest = url.pathname.startsWith(this.config.basePath) ? url.pathname.slice(this.config.basePath.length) : url.pathname;
    const action = rest.replace(/^\/+|\/+$/g, '');
    switch (action) {
      case 'signin':
        return this.handleSignIn(request);
      case 'callback':
        return this.handleCallback(request);
      case 'signout':
        return this.handleSignOut(request);
      case 'session':
        return this.handleSession(request);
      default:
        return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers: { 'content-type': 'application/json' } });
    }
  }
}
