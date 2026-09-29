/**
 * `AuthClient`: the whole sign-in lifecycle for an app without a server
 * (SPA, extension, desktop shell) or as the engine behind a server session.
 *
 *   const auth = createAuthClient({ clientId, redirectUri })
 *   await auth.signIn()                      // redirects to the issuer
 *   const { session } = await auth.handleCallback()   // on the redirect URI
 *   const token = await auth.getAccessToken() // refreshes when needed
 *   await auth.signOut({ redirect: true })
 *
 * Refresh is single-flight with rotation safety ({@link RefreshCoordinator}),
 * ID tokens are verified offline with a JWKS cache that survives outages
 * ({@link createJwksResolver}), and an unreachable issuer keeps the session
 * alive under the grace policy ({@link evaluateGrace}).
 */

import type { JWK } from 'jose';
import { buildAuthorizationUrl, buildEndSessionUrl, isAuthorizationResponse, parseAuthorizationResponse, type AuthorizationRequestParams } from './authorize';
import { userFromClaims } from './claims';
import { DEFAULT_ISSUER, DEFAULT_SCOPES, createDiscoveryCache, type DiscoverOptions } from './discovery';
import { embeddedKeysFor } from './embedded-keys';
import { AuthError, OAuthError, isSignedOutError, isTransientError } from './errors';
import { evaluateGrace, resolveGracePolicy, NO_GRACE_POLICY, type SessionGracePolicy } from './grace';
import { createJwksResolver, type JwksResolver } from './jwks';
import { createPkcePair, generateNonce, generateState } from './pkce';
import { RefreshCoordinator } from './refresh';
import { resolveStorage, withLock, type AuthStorage, type StorageKind } from './storage';
import { exchangeAuthorizationCode, refreshTokenGrant, revokeToken, tokenSetFromResponse } from './token';
import type { AuthUser, ClientAuthentication, IdTokenClaims, IssuerMetadata, Session, TokenSet } from './types';
import { resolveFetch, stripTrailingSlash, toScopeString, type FetchLike } from './util';
import { verifyIdToken } from './verify';

export interface AuthClientOptions {
  /** Issuer identifier. Default the production issuer. */
  issuer?: string;
  clientId: string;
  /** Must be registered on the client, exactly. */
  redirectUri: string;
  /** Default `openid profile email`. Add `org` for the organization picker and `wallet` for wallet claims. */
  scope?: string | readonly string[];
  /** Default `{ method: 'none' }`. Confidential clients belong on a server; never ship a secret to a browser. */
  clientAuthentication?: ClientAuthentication;
  /** Registered post-logout redirect URI used by `signOut({ redirect: true })`. */
  postLogoutRedirectUri?: string;
  /** Skip discovery entirely. */
  metadata?: IssuerMetadata;
  /** Mirrors of the discovery document (plan M4). */
  alternateDiscoveryLocations?: string[];
  fetch?: FetchLike;
  /** Where tokens live. Default `memory`. */
  sessionStorage?: StorageKind | AuthStorage;
  /** Where the pending sign-in lives across the redirect. Default `session` (sessionStorage), memory outside a browser. */
  transactionStorage?: StorageKind | AuthStorage;
  /** Prefix for storage keys. Default `af_auth.<clientId>`. */
  storageKeyPrefix?: string;
  /** Grace policy for an unreachable issuer. `false` disables grace. */
  grace?: Partial<SessionGracePolicy> | false;
  /** Public keys to trust before the first JWKS fetch. Default: the snapshot embedded at build time for this issuer. */
  embeddedKeys?: readonly JWK[];
  jwksTtlMs?: number;
  /** Refresh this long before the access token expires. Default 30 s. */
  refreshLeewayMs?: number;
  clockToleranceSeconds?: number;
  /** Pending sign-ins older than this are discarded. Default 15 min. */
  transactionTtlMs?: number;
  now?: () => number;
  onWarning?: (message: string, cause?: unknown) => void;
  /** How to leave the page. Default `window.location.assign`. */
  navigate?: (url: string) => void;
}

export interface SignInOptions {
  /** Same-origin path (or any string) handed back by `handleCallback`. */
  returnTo?: string;
  scope?: string | readonly string[];
  prompt?: AuthorizationRequestParams['prompt'];
  loginHint?: string;
  extraParams?: Record<string, string>;
  /** Override the registered redirect URI for this sign-in. */
  redirectUri?: string;
}

export interface CallbackResult {
  session: Session;
  returnTo: string | null;
}

export interface SignOutOptions {
  /** Navigate to the issuer's end-session page (needs an ID token; ends the issuer session, confirm page). Default false. */
  redirect?: boolean;
  postLogoutRedirectUri?: string;
  /**
   * Also revoke the refresh token at the issuer (best effort). The issuer
   * revokes the whole grant with it, which disconnects the app for this user
   * on every device, the same as "Disconnect" under Connected apps. Default
   * false: signing out of this app instance only.
   */
  revoke?: boolean;
}

export type SessionListener = (session: Session | null) => void;

interface Transaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  scope: string;
  returnTo: string | null;
  createdAt: number;
}

const TXN_INDEX = 'txn-index';

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.location !== 'undefined';
}

export class AuthClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;

  private readonly options: AuthClientOptions;
  private readonly fetchImpl: FetchLike;
  private readonly sessionStore: AuthStorage;
  private readonly txnStore: AuthStorage;
  private readonly prefix: string;
  private readonly grace: SessionGracePolicy;
  private readonly discovery = createDiscoveryCache();
  private readonly resolver: JwksResolver;
  private readonly coordinator: RefreshCoordinator<TokenSet>;
  private readonly listeners = new Set<SessionListener>();
  private readonly now: () => number;
  private metadataPromise: Promise<IssuerMetadata> | null = null;

  constructor(options: AuthClientOptions) {
    if (!options.clientId) throw new AuthError('configuration', 'clientId is required');
    if (!options.redirectUri) throw new AuthError('configuration', 'redirectUri is required');
    this.options = options;
    this.issuer = stripTrailingSlash(options.issuer ?? DEFAULT_ISSUER);
    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.fetchImpl = resolveFetch(options.fetch);
    this.now = options.now ?? (() => Date.now());
    this.prefix = options.storageKeyPrefix ?? `af_auth.${options.clientId}`;
    this.sessionStore = resolveStorage(options.sessionStorage, 'memory');
    this.txnStore = resolveStorage(options.transactionStorage, isBrowser() ? 'session' : 'memory');
    this.grace = options.grace === false ? NO_GRACE_POLICY : resolveGracePolicy(options.grace);
    const jwksUri = options.metadata?.jwks_uri ?? `${this.issuer}/.well-known/jwks.json`;
    this.resolver = createJwksResolver({
      jwksUri,
      fetch: this.fetchImpl,
      ttlMs: options.jwksTtlMs,
      initialKeys: options.embeddedKeys ?? embeddedKeysFor(this.issuer),
      now: this.now,
      onWarning: options.onWarning,
    });
    this.coordinator = new RefreshCoordinator<TokenSet>({
      refresh: (refreshToken) => this.performRefresh(refreshToken),
      now: this.now,
    });
  }

  // ---------------------------------------------------------------- metadata

  private discoverOptions(): DiscoverOptions {
    return {
      fetch: this.fetchImpl,
      alternateLocations: this.options.alternateDiscoveryLocations,
      onWarning: this.options.onWarning,
    };
  }

  /** The issuer's metadata (discovered once, cached, stale-on-error, known layout as the last resort). */
  metadata(): Promise<IssuerMetadata> {
    if (this.options.metadata) return Promise.resolve(this.options.metadata);
    if (!this.metadataPromise) {
      this.metadataPromise = this.discovery.get(this.issuer, this.discoverOptions()).catch((error) => {
        this.metadataPromise = null;
        throw error;
      });
    }
    return this.metadataPromise;
  }

  /** The JWKS resolver (for verifying tokens outside the client). */
  jwks(): JwksResolver {
    return this.resolver;
  }

  // ---------------------------------------------------------------- sign-in

  async createSignInUrl(options: SignInOptions = {}): Promise<{ url: string; state: string }> {
    const metadata = await this.metadata();
    const state = generateState();
    const nonce = generateNonce();
    const pkce = await createPkcePair();
    const redirectUri = options.redirectUri ?? this.redirectUri;
    const scope = toScopeString(options.scope ?? this.options.scope, DEFAULT_SCOPES);
    this.pruneTransactions();
    this.saveTransaction({
      state,
      nonce,
      codeVerifier: pkce.codeVerifier,
      redirectUri,
      scope,
      returnTo: options.returnTo ?? null,
      createdAt: this.now(),
    });
    const url = buildAuthorizationUrl({
      metadata,
      clientId: this.clientId,
      redirectUri,
      scope,
      state,
      nonce,
      codeChallenge: pkce.codeChallenge,
      prompt: options.prompt,
      loginHint: options.loginHint,
      extraParams: options.extraParams,
    });
    return { url, state };
  }

  /** Start the sign-in: build the URL and leave the page. */
  async signIn(options: SignInOptions = {}): Promise<void> {
    const { url } = await this.createSignInUrl(options);
    this.navigate(url);
  }

  private navigate(url: string): void {
    if (this.options.navigate) {
      this.options.navigate(url);
      return;
    }
    if (isBrowser()) {
      window.location.assign(url);
      return;
    }
    throw new AuthError('configuration', 'No way to navigate outside a browser; use createSignInUrl() and open the URL yourself');
  }

  /** Whether `url` (default: the current page) is a redirect back from the issuer. */
  isCallback(url?: string | URL): boolean {
    const target = url ?? (isBrowser() ? window.location.href : null);
    if (!target) return false;
    try {
      return isAuthorizationResponse(target);
    } catch {
      return false;
    }
  }

  /**
   * Finish the sign-in on the redirect URI: match the state to the pending
   * transaction, exchange the code with PKCE, verify the ID token (nonce
   * included), store the tokens.
   */
  async handleCallback(url?: string | URL): Promise<CallbackResult> {
    const target = url ?? (isBrowser() ? window.location.href : null);
    if (!target) throw new AuthError('invalid_callback', 'No callback URL given and no browser location available');
    const parsed = typeof target === 'string' ? new URL(target) : target;
    const state = parsed.searchParams.get('state') ?? new URLSearchParams(parsed.hash.slice(1)).get('state');
    if (!state) throw new AuthError('invalid_callback', 'The callback URL carries no state');
    const txn = this.loadTransaction(state);
    if (!txn) throw new AuthError('no_transaction', 'No pending sign-in matches this callback (was it started in another browser, or already completed?)');
    if (this.now() - txn.createdAt > (this.options.transactionTtlMs ?? 15 * 60 * 1000)) {
      this.removeTransaction(state);
      throw new AuthError('no_transaction', 'The pending sign-in expired; start again');
    }

    let response;
    try {
      response = parseAuthorizationResponse(parsed, { state: txn.state, issuer: this.issuer });
    } catch (error) {
      this.removeTransaction(state);
      throw error;
    }

    const metadata = await this.metadata();
    let tokenSet: TokenSet;
    try {
      const raw = await exchangeAuthorizationCode(
        {
          tokenEndpoint: metadata.token_endpoint,
          clientId: this.clientId,
          clientAuthentication: this.options.clientAuthentication,
          fetch: this.fetchImpl,
        },
        { code: response.code, redirectUri: txn.redirectUri, codeVerifier: txn.codeVerifier },
      );
      if (!raw.id_token) throw new AuthError('invalid_response', 'The token response carries no ID token');
      const claims = await verifyIdToken(raw.id_token, {
        issuer: this.issuer,
        clientId: this.clientId,
        resolver: this.resolver,
        nonce: txn.nonce,
        clockToleranceSeconds: this.options.clockToleranceSeconds,
        currentTimeSeconds: Math.floor(this.now() / 1000),
      });
      tokenSet = tokenSetFromResponse(raw, { now: this.now(), claims });
    } finally {
      // A code is single use: whatever happened, the transaction is spent.
      this.removeTransaction(state);
    }
    this.saveTokens(tokenSet);
    const session = this.toSession(tokenSet, 'active');
    this.emit(session);
    return { session, returnTo: txn.returnTo };
  }

  // ---------------------------------------------------------------- session

  /**
   * The current session, refreshed when the access token is (about to be)
   * expired. `refresh: 'never'` answers from storage only; `'force'` always
   * refreshes. Returns null when signed out.
   */
  async getSession(options: { refresh?: 'auto' | 'force' | 'never' } = {}): Promise<Session | null> {
    const mode = options.refresh ?? 'auto';
    const stored = this.loadTokens();
    if (!stored) return null;
    const now = this.now();
    const leeway = this.options.refreshLeewayMs ?? 30_000;
    const fresh = now < stored.expiresAt - leeway;

    if (mode === 'never' || (mode === 'auto' && fresh) || !stored.refreshToken) {
      return this.sessionFromVerdict(stored, now);
    }

    try {
      const next = await withLock(`${this.prefix}.refresh`, async () => {
        // Another tab may have rotated already: prefer what storage holds now.
        const latest = this.loadTokens();
        if (latest && latest.refreshToken && latest.refreshToken !== stored.refreshToken && this.now() < latest.expiresAt - leeway) {
          return latest;
        }
        const token = latest?.refreshToken ?? stored.refreshToken;
        if (!token) throw new AuthError('signed_out', 'No refresh token; sign in again');
        return this.coordinator.refresh(token);
      });
      this.saveTokens(next);
      const session = this.toSession(next, 'active');
      this.emit(session);
      return session;
    } catch (error) {
      if (isSignedOutError(error)) {
        this.clear();
        return null;
      }
      if (isTransientError(error)) {
        this.options.onWarning?.('token refresh failed; applying the grace policy', error);
        return this.sessionFromVerdict(stored, now);
      }
      throw error;
    }
  }

  /** A valid access token, refreshing when needed. Null when signed out (a grace session still answers its last token). */
  async getAccessToken(): Promise<string | null> {
    const session = await this.getSession();
    return session?.tokens.accessToken ?? null;
  }

  async getUser(): Promise<AuthUser | null> {
    return (await this.getSession())?.user ?? null;
  }

  /** Force a refresh now. */
  refresh(): Promise<Session | null> {
    return this.getSession({ refresh: 'force' });
  }

  /** The session as stored, without any network call. Null when nothing is stored or the grace cap passed. */
  peekSession(): Session | null {
    const stored = this.loadTokens();
    if (!stored) return null;
    const verdict = evaluateGrace(stored, this.now(), this.grace);
    if (verdict === 'expired') return null;
    return this.toSession(stored, verdict);
  }

  /** Replace the stored tokens (server-side sessions, tests). */
  setTokens(tokens: TokenSet): Session {
    this.saveTokens(tokens);
    const session = this.toSession(tokens, evaluateGrace(tokens, this.now(), this.grace) === 'active' ? 'active' : 'grace');
    this.emit(session);
    return session;
  }

  /** End the local session; optionally revoke the refresh token and leave for the issuer's end-session page. */
  async signOut(options: SignOutOptions = {}): Promise<{ endSessionUrl: string | null }> {
    const stored = this.loadTokens();
    this.clear();
    let endSessionUrl: string | null = null;
    if (stored) {
      if (options.revoke === true && stored.refreshToken) {
        try {
          const metadata = await this.metadata();
          if (metadata.revocation_endpoint) {
            await revokeToken({
              revocationEndpoint: metadata.revocation_endpoint,
              clientId: this.clientId,
              clientAuthentication: this.options.clientAuthentication,
              token: stored.refreshToken,
              tokenTypeHint: 'refresh_token',
              fetch: this.fetchImpl,
            });
          }
        } catch (error) {
          this.options.onWarning?.('refresh token revocation failed', error);
        }
      }
      try {
        const metadata = await this.metadata();
        endSessionUrl = buildEndSessionUrl({
          metadata,
          idTokenHint: stored.idToken,
          clientId: this.clientId,
          postLogoutRedirectUri: options.postLogoutRedirectUri ?? this.options.postLogoutRedirectUri,
        });
      } catch (error) {
        this.options.onWarning?.('could not build the end-session URL', error);
      }
    }
    if (options.redirect && endSessionUrl) this.navigate(endSessionUrl);
    return { endSessionUrl };
  }

  /** Forget the stored tokens without telling the issuer. */
  clear(): void {
    this.sessionStore.remove(`${this.prefix}.session`);
    this.coordinator.reset();
    this.emit(null);
  }

  subscribe(listener: SessionListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  // ---------------------------------------------------------------- internals

  private async performRefresh(refreshToken: string): Promise<TokenSet> {
    const metadata = await this.metadata();
    const raw = await refreshTokenGrant(
      {
        tokenEndpoint: metadata.token_endpoint,
        clientId: this.clientId,
        clientAuthentication: this.options.clientAuthentication,
        fetch: this.fetchImpl,
      },
      { refreshToken },
    );
    const previous = this.loadTokens();
    let claims: IdTokenClaims | null = previous?.claims ?? null;
    if (raw.id_token) {
      claims = await verifyIdToken(raw.id_token, {
        issuer: this.issuer,
        clientId: this.clientId,
        resolver: this.resolver,
        clockToleranceSeconds: this.options.clockToleranceSeconds,
        currentTimeSeconds: Math.floor(this.now() / 1000),
      });
    }
    const next = tokenSetFromResponse(raw, { now: this.now(), claims });
    if (!next.idToken && previous?.idToken) next.idToken = previous.idToken;
    return next;
  }

  private sessionFromVerdict(tokens: TokenSet, now: number): Session | null {
    const verdict = evaluateGrace(tokens, now, this.grace);
    if (verdict === 'expired') {
      this.clear();
      return null;
    }
    return this.toSession(tokens, verdict);
  }

  private toSession(tokens: TokenSet, status: 'active' | 'grace'): Session {
    if (!tokens.claims) throw new AuthError('invalid_id_token', 'The stored session has no verified claims');
    return {
      status,
      user: userFromClaims(tokens.claims),
      tokens,
      expiresAt: tokens.expiresAt,
      issuedAt: tokens.issuedAt,
    };
  }

  private emit(session: Session | null): void {
    for (const listener of this.listeners) {
      try {
        listener(session);
      } catch (error) {
        this.options.onWarning?.('a session listener threw', error);
      }
    }
  }

  private loadTokens(): TokenSet | null {
    const raw = this.sessionStore.get(`${this.prefix}.session`);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as TokenSet;
      if (typeof parsed.accessToken !== 'string' || typeof parsed.expiresAt !== 'number' || typeof parsed.issuedAt !== 'number') return null;
      return parsed;
    } catch {
      return null;
    }
  }

  private saveTokens(tokens: TokenSet): void {
    this.sessionStore.set(`${this.prefix}.session`, JSON.stringify(tokens));
  }

  private txnKey(state: string): string {
    return `${this.prefix}.txn.${state}`;
  }

  private saveTransaction(txn: Transaction): void {
    this.txnStore.set(this.txnKey(txn.state), JSON.stringify(txn));
    const index = this.transactionIndex();
    index.push(txn.state);
    this.txnStore.set(`${this.prefix}.${TXN_INDEX}`, JSON.stringify(index.slice(-10)));
  }

  private loadTransaction(state: string): Transaction | null {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(state)) return null;
    const raw = this.txnStore.get(this.txnKey(state));
    if (!raw) return null;
    try {
      const txn = JSON.parse(raw) as Transaction;
      return typeof txn.codeVerifier === 'string' && typeof txn.nonce === 'string' ? txn : null;
    } catch {
      return null;
    }
  }

  private removeTransaction(state: string): void {
    this.txnStore.remove(this.txnKey(state));
    const index = this.transactionIndex().filter((s) => s !== state);
    this.txnStore.set(`${this.prefix}.${TXN_INDEX}`, JSON.stringify(index));
  }

  private transactionIndex(): string[] {
    try {
      const parsed = JSON.parse(this.txnStore.get(`${this.prefix}.${TXN_INDEX}`) ?? '[]') as unknown;
      return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === 'string') : [];
    } catch {
      return [];
    }
  }

  private pruneTransactions(): void {
    const ttl = this.options.transactionTtlMs ?? 15 * 60 * 1000;
    for (const state of this.transactionIndex()) {
      const txn = this.loadTransaction(state);
      if (!txn || this.now() - txn.createdAt > ttl) this.removeTransaction(state);
    }
  }
}

export function createAuthClient(options: AuthClientOptions): AuthClient {
  return new AuthClient(options);
}

export { OAuthError };
