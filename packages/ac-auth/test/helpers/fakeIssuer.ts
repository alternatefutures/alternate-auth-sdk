/**
 * An in-memory issuer that behaves like the Alternate Clouds issuer for the
 * parts the SDK talks to: discovery, JWKS, authorization code + PKCE (the
 * interaction step is skipped: `authorize()` hands the code straight back),
 * refresh with rotation and reuse detection, revocation, userinfo and the
 * device flow. Served through a `fetch` function the SDK receives as an
 * option, so tests need no ports. Failure modes are switches on the object.
 */

import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { computeCodeChallenge } from '../../src/pkce';

export interface FakeIssuerOptions {
  issuer?: string;
  now?: () => number;
  /** Access token lifetime in seconds. Default 3600. */
  accessTokenTtl?: number;
  /** Claims returned for every subject unless overridden per code. */
  claims?: Record<string, unknown>;
}

interface Grant {
  id: string;
  sub: string;
  clientId: string;
  scope: string;
  revoked: boolean;
}

interface PendingCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  nonce: string;
  scope: string;
  sub: string;
  grantId: string;
  used: boolean;
}

interface PendingDevice {
  clientId: string;
  scope: string;
  userCode: string;
  approvedSub: string | null;
  denied: boolean;
  expired: boolean;
  polls: number;
  lastPollAt: number;
}

export class FakeIssuer {
  readonly issuer: string;
  readonly now: () => number;
  readonly accessTokenTtl: number;

  private eddsa!: { kid: string; privateKey: CryptoKey; publicJwk: JWK };
  private es256!: { kid: string; privateKey: CryptoKey; publicJwk: JWK };
  /** Keys currently published (rotation tests replace this). */
  publishedKeys: JWK[] = [];
  /** Alg used to sign the next ID tokens. */
  signWith: 'EdDSA' | 'ES256' = 'EdDSA';

  readonly codes = new Map<string, PendingCode>();
  readonly grants = new Map<string, Grant>();
  /** refresh token -> { grantId, consumed } */
  readonly refreshTokens = new Map<string, { grantId: string; consumed: boolean }>();
  readonly accessTokens = new Map<string, { grantId: string; sub: string; scope: string; expiresAt: number }>();
  readonly devices = new Map<string, PendingDevice>();

  /** Every refresh token value ever presented at the token endpoint, in order. */
  readonly presentedRefreshTokens: string[] = [];
  readonly calls = { discovery: 0, jwks: 0, token: 0, revocation: 0, userinfo: 0, device: 0 };
  readonly lastRequest: { url: string; headers: Record<string, string>; body: string } = { url: '', headers: {}, body: '' };

  /** Switches. */
  offline = false;
  discoveryStatus: number | null = null;
  jwksStatus: number | null = null;
  tokenStatus: number | null = null;
  /** Answer HTML instead of JSON from the token endpoint (gateway page). */
  tokenHtml = false;
  /** Extra claims for the next issued ID tokens. */
  claims: Record<string, unknown>;
  private counter = 0;

  constructor(options: FakeIssuerOptions = {}) {
    this.issuer = options.issuer ?? 'https://issuer.test';
    this.now = options.now ?? (() => Date.now());
    this.accessTokenTtl = options.accessTokenTtl ?? 3600;
    this.claims = options.claims ?? {
      name: 'Dev One',
      email: 'dev@example.com',
      email_verified: true,
      picture: 'https://img.test/dev.png',
      updated_at: 1_700_000_000,
      org: { id: 'org_1', slug: 'acme', name: 'Acme', role: 'OWNER' },
      wallet: 'did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001',
      wallets: ['0xabcdef0000000000000000000000000000000001'],
    };
  }

  static async create(options: FakeIssuerOptions = {}): Promise<FakeIssuer> {
    const issuer = new FakeIssuer(options);
    await issuer.rotateKeys();
    return issuer;
  }

  /** Generate a fresh key pair per algorithm and publish them (old keys are dropped unless kept by the caller). */
  async rotateKeys(): Promise<{ eddsaKid: string; es256Kid: string }> {
    const ed = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    const es = await generateKeyPair('ES256', { extractable: true });
    const edPub = await exportJWK(ed.publicKey);
    const esPub = await exportJWK(es.publicKey);
    const eddsaKid = `ed-${++this.counter}`;
    const es256Kid = `es-${++this.counter}`;
    this.eddsa = { kid: eddsaKid, privateKey: ed.privateKey, publicJwk: { ...edPub, kid: eddsaKid, alg: 'EdDSA', use: 'sig' } };
    this.es256 = { kid: es256Kid, privateKey: es.privateKey, publicJwk: { ...esPub, kid: es256Kid, alg: 'ES256', use: 'sig' } };
    this.publishedKeys = [this.eddsa.publicJwk, this.es256.publicJwk];
    return { eddsaKid, es256Kid };
  }

  get jwks(): { keys: JWK[] } {
    return { keys: this.publishedKeys };
  }

  get metadata(): Record<string, unknown> {
    const base = this.issuer;
    return {
      issuer: base,
      authorization_endpoint: `${base}/oidc/auth`,
      token_endpoint: `${base}/oidc/token`,
      userinfo_endpoint: `${base}/oidc/me`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      end_session_endpoint: `${base}/oidc/session/end`,
      revocation_endpoint: `${base}/oidc/token/revocation`,
      introspection_endpoint: `${base}/oidc/token/introspection`,
      device_authorization_endpoint: `${base}/oidc/device/auth`,
      code_challenge_methods_supported: ['S256'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
      scopes_supported: ['openid', 'offline_access', 'profile', 'email', 'org', 'wallet'],
      id_token_signing_alg_values_supported: ['EdDSA', 'ES256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      subject_types_supported: ['public', 'pairwise'],
      authorization_response_iss_parameter_supported: true,
    };
  }

  private token(prefix: string): string {
    return `${prefix}_${(++this.counter).toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
  }

  async signIdToken(params: { sub: string; aud: string | string[]; nonce?: string; alg?: 'EdDSA' | 'ES256'; extra?: Record<string, unknown>; expiresIn?: number }): Promise<string> {
    const alg = params.alg ?? this.signWith;
    const key = alg === 'EdDSA' ? this.eddsa : this.es256;
    const iat = Math.floor(this.now() / 1000);
    const jwt = new SignJWT({ ...this.claims, ...(params.extra ?? {}), ...(params.nonce ? { nonce: params.nonce } : {}) })
      .setProtectedHeader({ alg, kid: key.kid, typ: 'JWT' })
      .setIssuer(this.issuer)
      .setSubject(params.sub)
      .setAudience(params.aud)
      .setIssuedAt(iat)
      .setExpirationTime(iat + (params.expiresIn ?? 3600));
    return jwt.sign(key.privateKey);
  }

  /**
   * Simulate the browser leg: take the authorization URL the SDK built,
   * validate it like the provider would and answer with the callback URL.
   */
  async authorize(authorizationUrl: string, options: { sub?: string; error?: string } = {}): Promise<string> {
    const url = new URL(authorizationUrl);
    const p = url.searchParams;
    const required = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'];
    for (const name of required) if (!p.get(name)) throw new Error(`authorize: missing ${name}`);
    if (p.get('response_type') !== 'code') throw new Error('authorize: response_type must be code');
    if (p.get('code_challenge_method') !== 'S256') throw new Error('authorize: only S256');
    if (!p.get('scope')!.split(' ').includes('openid')) throw new Error('authorize: openid scope required');
    const redirect = new URL(p.get('redirect_uri')!);
    redirect.searchParams.set('state', p.get('state')!);
    redirect.searchParams.set('iss', this.issuer);
    if (options.error) {
      redirect.searchParams.set('error', options.error);
      return redirect.toString();
    }
    const sub = options.sub ?? 'user_1';
    const clientId = p.get('client_id')!;
    let grant = [...this.grants.values()].find((g) => g.sub === sub && g.clientId === clientId && !g.revoked);
    if (!grant) {
      grant = { id: this.token('grant'), sub, clientId, scope: p.get('scope')!, revoked: false };
      this.grants.set(grant.id, grant);
    }
    const code = this.token('code');
    this.codes.set(code, {
      clientId,
      redirectUri: p.get('redirect_uri')!,
      codeChallenge: p.get('code_challenge')!,
      nonce: p.get('nonce')!,
      scope: p.get('scope')!,
      sub,
      grantId: grant.id,
      used: false,
    });
    redirect.searchParams.set('code', code);
    return redirect.toString();
  }

  /** Approve a pending device code (the user typed the code and confirmed). */
  approveDevice(userCode: string, sub = 'user_1'): void {
    for (const device of this.devices.values()) {
      if (device.userCode === userCode) device.approvedSub = sub;
    }
  }

  /** Revoke a grant (Connected apps "Disconnect"). */
  revokeGrant(grantId: string): void {
    const grant = this.grants.get(grantId);
    if (grant) grant.revoked = true;
    for (const [token, rt] of this.refreshTokens) if (rt.grantId === grantId) this.refreshTokens.set(token, { ...rt, consumed: true });
  }

  private async issueForGrant(grant: Grant, extra: { nonce?: string; withIdToken?: boolean } = {}): Promise<Record<string, unknown>> {
    const accessToken = this.token('at');
    const refreshToken = this.token('rt');
    this.accessTokens.set(accessToken, { grantId: grant.id, sub: grant.sub, scope: grant.scope, expiresAt: this.now() + this.accessTokenTtl * 1000 });
    this.refreshTokens.set(refreshToken, { grantId: grant.id, consumed: false });
    const response: Record<string, unknown> = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.accessTokenTtl,
      refresh_token: refreshToken,
      scope: grant.scope,
    };
    if (extra.withIdToken !== false && grant.scope.split(' ').includes('openid')) {
      response.id_token = await this.signIdToken({ sub: grant.sub, aud: grant.clientId, nonce: extra.nonce });
    }
    return response;
  }

  private json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  }

  private oauthError(error: string, description?: string, status = 400): Response {
    return this.json({ error, ...(description ? { error_description: description } : {}) }, status);
  }

  private parseClient(headers: Headers, form: URLSearchParams): { clientId: string; method: 'none' | 'client_secret_basic' | 'client_secret_post'; secret?: string } | null {
    const auth = headers.get('authorization');
    if (auth?.toLowerCase().startsWith('basic ')) {
      const decoded = atob(auth.slice(6));
      const idx = decoded.indexOf(':');
      return { clientId: decodeURIComponent(decoded.slice(0, idx)), method: 'client_secret_basic', secret: decodeURIComponent(decoded.slice(idx + 1)) };
    }
    if (form.get('client_secret')) return { clientId: form.get('client_id') ?? '', method: 'client_secret_post', secret: form.get('client_secret')! };
    const clientId = form.get('client_id');
    return clientId ? { clientId, method: 'none' } : null;
  }

  /** The `fetch` the SDK is given. */
  readonly fetch = async (input: string | URL, init: RequestInit = {}): Promise<Response> => {
    if (this.offline) throw new TypeError('fetch failed: ECONNREFUSED');
    const url = new URL(typeof input === 'string' ? input : input.toString());
    const method = (init.method ?? 'GET').toUpperCase();
    const headers = new Headers(init.headers ?? {});
    let body = '';
    if (typeof init.body === 'string') body = init.body;
    else if (init.body instanceof URLSearchParams) body = init.body.toString();
    else if (init.body) body = await new Response(init.body as BodyInit).text();
    this.lastRequest.url = url.toString();
    this.lastRequest.headers = Object.fromEntries(headers.entries());
    this.lastRequest.body = body;
    const path = url.pathname;

    if (path === '/.well-known/openid-configuration') {
      this.calls.discovery++;
      if (this.discoveryStatus) return new Response('<html>gateway</html>', { status: this.discoveryStatus, headers: { 'content-type': 'text/html' } });
      return this.json(this.metadata);
    }
    if (path === '/.well-known/jwks.json') {
      this.calls.jwks++;
      if (this.jwksStatus) return new Response('down', { status: this.jwksStatus });
      return this.json(this.jwks, 200, { 'cache-control': 'public, max-age=300' });
    }
    if (path === '/oidc/token' && method === 'POST') return this.handleToken(headers, new URLSearchParams(body));
    if (path === '/oidc/token/revocation' && method === 'POST') {
      this.calls.revocation++;
      const form = new URLSearchParams(body);
      const token = form.get('token') ?? '';
      const rt = this.refreshTokens.get(token);
      if (rt) this.revokeGrant(rt.grantId);
      return new Response('', { status: 200 });
    }
    if (path === '/oidc/me') {
      this.calls.userinfo++;
      const bearer = headers.get('authorization')?.replace(/^Bearer /, '') ?? '';
      const at = this.accessTokens.get(bearer);
      if (!at || at.expiresAt <= this.now()) {
        return new Response('', { status: 401, headers: { 'www-authenticate': 'Bearer error="invalid_token"' } });
      }
      return this.json({ sub: at.sub, ...this.claims });
    }
    if (path === '/oidc/device/auth' && method === 'POST') {
      this.calls.device++;
      const form = new URLSearchParams(body);
      const client = this.parseClient(headers, form);
      if (!client) return this.oauthError('invalid_client', 'no client', 401);
      const deviceCode = this.token('dc');
      const userCode = `${this.counter}ABCD`;
      this.devices.set(deviceCode, { clientId: client.clientId, scope: form.get('scope') ?? 'openid', userCode, approvedSub: null, denied: false, expired: false, polls: 0, lastPollAt: 0 });
      return this.json({
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: `${this.issuer}/oidc/device`,
        verification_uri_complete: `${this.issuer}/oidc/device?user_code=${userCode}`,
        expires_in: 600,
        interval: 5,
      });
    }
    return new Response('not found', { status: 404 });
  };

  private async handleToken(headers: Headers, form: URLSearchParams): Promise<Response> {
    this.calls.token++;
    if (form.get('grant_type') === 'refresh_token') this.presentedRefreshTokens.push(form.get('refresh_token') ?? '');
    if (this.tokenStatus) {
      return this.tokenHtml
        ? new Response('<html>502 bad gateway</html>', { status: this.tokenStatus, headers: { 'content-type': 'text/html' } })
        : this.oauthError('server_error', 'try later', this.tokenStatus);
    }
    const client = this.parseClient(headers, form);
    if (!client) return this.oauthError('invalid_client', 'client authentication required', 401);
    const grantType = form.get('grant_type');

    if (grantType === 'authorization_code') {
      const code = this.codes.get(form.get('code') ?? '');
      if (!code || code.used) return this.oauthError('invalid_grant', 'authorization code invalid or used');
      code.used = true;
      if (code.clientId !== client.clientId) return this.oauthError('invalid_grant', 'client mismatch');
      if (code.redirectUri !== form.get('redirect_uri')) return this.oauthError('invalid_grant', 'redirect_uri mismatch');
      const verifier = form.get('code_verifier') ?? '';
      if (!verifier || (await computeCodeChallenge(verifier)) !== code.codeChallenge) return this.oauthError('invalid_grant', 'PKCE verification failed');
      const grant = this.grants.get(code.grantId)!;
      return this.json(await this.issueForGrant(grant, { nonce: code.nonce }));
    }

    if (grantType === 'refresh_token') {
      const presented = form.get('refresh_token') ?? '';
      const rt = this.refreshTokens.get(presented);
      if (!rt) return this.oauthError('invalid_grant', 'refresh token not found');
      const grant = this.grants.get(rt.grantId)!;
      if (rt.consumed || grant.revoked) {
        // Reuse of a rotated token: the whole grant dies (provider behaviour).
        this.revokeGrant(rt.grantId);
        return this.oauthError('invalid_grant', 'refresh token already used; grant revoked');
      }
      if (grant.clientId !== client.clientId) return this.oauthError('invalid_grant', 'client mismatch');
      rt.consumed = true;
      return this.json(await this.issueForGrant(grant));
    }

    if (grantType === 'urn:ietf:params:oauth:grant-type:device_code') {
      const device = this.devices.get(form.get('device_code') ?? '');
      if (!device) return this.oauthError('invalid_grant', 'unknown device code');
      device.polls++;
      if (device.expired) return this.oauthError('expired_token');
      if (device.denied) return this.oauthError('access_denied');
      if (!device.approvedSub) return this.oauthError('authorization_pending');
      const grant: Grant = { id: this.token('grant'), sub: device.approvedSub, clientId: device.clientId, scope: device.scope, revoked: false };
      this.grants.set(grant.id, grant);
      this.devices.delete(form.get('device_code')!);
      return this.json(await this.issueForGrant(grant));
    }

    return this.oauthError('unsupported_grant_type');
  }
}
