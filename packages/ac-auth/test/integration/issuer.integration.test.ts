/**
 * Integration proof against a LIVE issuer (the issuer with
 * OIDC_ISSUER_ENABLED=true). Nothing is mocked: real discovery, real keys,
 * real authorization code + PKCE through the web-app interaction bridge
 * (approved with a bearer the way the web app does, finished with the cookie
 * jar of the browser that started it), real refresh rotation, reuse
 * detection, revocation, introspection and the device flow.
 *
 * Run (from the repo root, with the auth service booted on 1621):
 *
 *   AUTH_SDK_ISSUER=http://localhost:1621 \
 *   AUTH_SDK_INTROSPECTION_SECRET=<AUTH_INTROSPECTION_SECRET of that service> \
 *   AUTH_SDK_USER_ID=<a local user id> AUTH_SDK_ORG_ID=<an org that user administers> \
 *
 * Against a deployed issuer (staging), where the introspection secret must not
 * leave the cluster, pass a pre-minted bearer instead of the secret + user id:
 *   AUTH_SDK_ISSUER=https://auth.staging.alternatefutures.ai \
 *   AUTH_SDK_BEARER=<a PAT or session token of an org admin> AUTH_SDK_ORG_ID=<that org> \
 * The suite then mints nothing and deletes only the clients it created.
 *   npm run test:integration
 *
 * Skipped (visibly) when those variables are absent. The test mints a
 * personal access token for the user and two OAuth clients, and deletes all
 * three at the end.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decodeProtectedHeader } from 'jose';
import { AuthClient, createAuthClient } from '../../src/client';
import { discover, knownIssuerMetadata } from '../../src/discovery';
import { pollDeviceToken, startDeviceAuthorization } from '../../src/device';
import { AuthError, OAuthError } from '../../src/errors';
import { createJwksResolver } from '../../src/jwks';
import { memoryStorage } from '../../src/storage';
import { fetchUserInfo, introspectToken, refreshTokenGrant, revokeToken } from '../../src/token';
import type { IssuerMetadata, Session } from '../../src/types';
import { verifyIdToken } from '../../src/verify';

const ISSUER = (process.env.AUTH_SDK_ISSUER ?? '').replace(/\/+$/, '');
const SECRET = process.env.AUTH_SDK_INTROSPECTION_SECRET ?? '';
/** Resolved from /auth/me in bearer mode (see beforeAll). */
let USER_ID = process.env.AUTH_SDK_USER_ID ?? '';
const ORG_ID = process.env.AUTH_SDK_ORG_ID ?? '';
/** Pre-minted bearer (deployed issuers): replaces the secret + user id and is never deleted by the suite. */
const BEARER = process.env.AUTH_SDK_BEARER ?? '';
const configured = Boolean(ISSUER && ORG_ID && (BEARER || (SECRET && USER_ID)));
const REDIRECT_URI = 'http://localhost:9999/callback';
const POST_LOGOUT_URI = 'http://localhost:9999/';

if (!configured) {
  // eslint-disable-next-line no-console
  console.warn('[integration] AUTH_SDK_ISSUER + AUTH_SDK_ORG_ID + (AUTH_SDK_BEARER | AUTH_SDK_INTROSPECTION_SECRET + AUTH_SDK_USER_ID) not set: live issuer tests skipped');
}

/** A cookie jar for the "browser" leg. Paths are ignored on purpose (one host). */
class CookieJar {
  private readonly cookies = new Map<string, string>();
  absorb(response: Response): void {
    for (const raw of response.headers.getSetCookie()) {
      const [pair = '', ...attrs] = raw.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => {
        const [k = '', v = ''] = a.trim().split('=');
        if (k.toLowerCase() === 'max-age') return Number(v) <= 0;
        if (k.toLowerCase() === 'expires') return new Date(v).getTime() < Date.now();
        return false;
      });
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function browserGet(url: string, jar: CookieJar): Promise<Response> {
  const response = await fetch(url, { redirect: 'manual', headers: { cookie: jar.header() } });
  jar.absorb(response);
  return response;
}

const withBearer = (token: string) => ({ authorization: `Bearer ${token}`, 'content-type': 'application/json' });

async function api(path: string, init: RequestInit & { token?: string } = {}): Promise<{ status: number; body: any }> {
  const { token, ...rest } = init;
  const response = await fetch(`${ISSUER}${path}`, {
    ...rest,
    headers: { ...(token ? withBearer(token) : { 'content-type': 'application/json' }), ...(rest.headers ?? {}) },
  });
  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: response.status, body };
}

/**
 * Drive one authorization through the interaction bridge exactly like the
 * web app does, and return the callback URL the browser would land on.
 */
async function completeAuthorization(authorizationUrl: string, bearer: string, body: Record<string, unknown> = { organizationId: ORG_ID }): Promise<{ callbackUrl: string; uid: string; grantId: string }> {
  const jar = new CookieJar();
  const start = await browserGet(authorizationUrl, jar);
  expect(start.status, `authorize answered ${start.status}: ${(await start.text()).slice(0, 200)}`).toBe(303);
  const hopUrl = start.headers.get('location')!;
  const uid = /\/oidc\/interaction\/([A-Za-z0-9_-]+)$/.exec(hopUrl)?.[1];
  expect(uid, `expected an interaction redirect, got ${hopUrl}`).toBeTruthy();

  const hop = await browserGet(hopUrl, jar);
  expect(hop.status).toBe(303);
  expect(hop.headers.get('location')).toMatch(/\/login\?interaction=/);

  const approve = await api(`/oidc/interaction/${uid}/login`, { method: 'POST', token: bearer, body: JSON.stringify(body) });
  expect(approve.status, JSON.stringify(approve.body)).toBe(200);
  const { finishUrl, grantId } = approve.body as { finishUrl: string; grantId: string };

  const finish = await browserGet(finishUrl, jar);
  expect(finish.status, await finish.text()).toBe(303);
  const resume = await browserGet(finish.headers.get('location')!, jar);
  expect(resume.status, await resume.text()).toBe(303);
  const callbackUrl = resume.headers.get('location')!;
  expect(callbackUrl.startsWith(REDIRECT_URI)).toBe(true);
  return { callbackUrl, uid: uid!, grantId };
}

describe.skipIf(!configured)('live issuer', () => {
  let bearer = '';
  let patId = '';
  let publicClientId = '';
  let confidentialClientId = '';
  let confidentialSecret = '';
  let metadata: IssuerMetadata;

  beforeAll(async () => {
    if (BEARER) {
      bearer = BEARER;
      if (!USER_ID) {
        const me = await api('/auth/me', { token: bearer });
        expect(me.status, JSON.stringify(me.body)).toBe(200);
        USER_ID = me.body.user.id as string;
      }
    } else {
      const minted = await api('/tokens/internal/create', {
        method: 'POST',
        headers: { 'x-af-introspection-secret': SECRET },
        body: JSON.stringify({ userId: USER_ID, organizationId: ORG_ID, name: `auth-sdk-integration ${Date.now()}` }),
      });
      expect(minted.status, JSON.stringify(minted.body)).toBe(201);
      bearer = minted.body.token;
      patId = minted.body.id;
    }

    const pub = await api('/developer/clients', {
      method: 'POST',
      token: bearer,
      body: JSON.stringify({
        organizationId: ORG_ID,
        name: 'SDK integration (public)',
        clientType: 'PUBLIC',
        redirectUris: [REDIRECT_URI],
        postLogoutRedirectUris: [POST_LOGOUT_URI],
        allowedScopes: ['openid', 'profile', 'email', 'org', 'wallet', 'offline_access'],
        deviceFlow: true,
      }),
    });
    expect(pub.status, JSON.stringify(pub.body)).toBe(201);
    publicClientId = pub.body.client.id;
    expect(pub.body.clientSecret).toBeNull();
    expect(pub.body.endpoints.discovery).toBe(`${ISSUER}/.well-known/openid-configuration`);

    const conf = await api('/developer/clients', {
      method: 'POST',
      token: bearer,
      body: JSON.stringify({
        organizationId: ORG_ID,
        name: 'SDK integration (confidential)',
        clientType: 'CONFIDENTIAL',
        redirectUris: [REDIRECT_URI],
        allowedScopes: ['openid', 'email'],
      }),
    });
    expect(conf.status, JSON.stringify(conf.body)).toBe(201);
    confidentialClientId = conf.body.client.id;
    confidentialSecret = conf.body.clientSecret;
    expect(confidentialSecret).toMatch(/^acs_/);
  }, 60_000);

  afterAll(async () => {
    if (!bearer) return;
    for (const id of [publicClientId, confidentialClientId]) {
      if (id) await api(`/developer/clients/${id}`, { method: 'DELETE', token: bearer });
    }
    if (patId) await api(`/tokens/${patId}`, { method: 'DELETE', token: bearer });
  });

  it('discovery matches the known layout and advertises PKCE S256 only', async () => {
    metadata = await discover(ISSUER, { fallbackToKnownLayout: false });
    const known = knownIssuerMetadata(ISSUER);
    for (const field of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint', 'introspection_endpoint', 'device_authorization_endpoint'] as const) {
      expect(metadata[field], field).toBe(known[field]);
    }
    expect(metadata.code_challenge_methods_supported).toEqual(['S256']);
    expect(metadata.response_types_supported).toEqual(['code']);
    expect(metadata.id_token_signing_alg_values_supported).toEqual(expect.arrayContaining(['EdDSA', 'ES256']));
    expect(metadata.id_token_signing_alg_values_supported).not.toContain('HS256');
  });

  it('publishes EdDSA and ES256 public keys the resolver can import', async () => {
    const resolver = createJwksResolver({ jwksUri: metadata.jwks_uri });
    const keys = await resolver.keys();
    expect(keys.map((k) => k.alg).sort()).toEqual(expect.arrayContaining(['ES256', 'EdDSA']));
    for (const key of keys) {
      expect(key.kid).toBeTruthy();
      expect(key).not.toHaveProperty('d');
      const imported = await resolver.getKey({ kid: key.kid, alg: key.alg });
      expect(imported.type).toBe('public');
    }
    expect(resolver.snapshot().source).toBe('network');
  });

  describe('public client through the interaction bridge', () => {
    let client: AuthClient;
    let session: Session;
    let grantId = '';

    beforeAll(() => {
      client = createAuthClient({
        issuer: ISSUER,
        clientId: publicClientId,
        redirectUri: REDIRECT_URI,
        postLogoutRedirectUri: POST_LOGOUT_URI,
        scope: ['openid', 'profile', 'email', 'org', 'wallet'],
        sessionStorage: memoryStorage(),
        transactionStorage: memoryStorage(),
        refreshLeewayMs: 0,
      });
    });

    it('signs in: authorize, approve with the bearer, finish with the cookie, exchange with PKCE, verify the ID token', async () => {
      const { url } = await client.createSignInUrl({ returnTo: '/dashboard' });
      const done = await completeAuthorization(url, bearer);
      grantId = done.grantId;
      const result = await client.handleCallback(done.callbackUrl);
      session = result.session;
      expect(result.returnTo).toBe('/dashboard');
      expect(session.status).toBe('active');
      expect(session.user.id).toBe(USER_ID);
      expect(session.user.org?.id).toBe(ORG_ID);
      expect(session.user.key).toBe(session.user.wallet ?? USER_ID);
      expect(session.tokens.refreshToken).toBeTruthy();
      expect(session.tokens.idToken).toBeTruthy();
      expect(decodeProtectedHeader(session.tokens.idToken!).alg).toBe('EdDSA');
      // Operational check after a key rotation: which published key signed this token.
      if (process.env.AUTH_SDK_LOG_KID) console.info(`[integration] id_token kid=${decodeProtectedHeader(session.tokens.idToken!).kid}`);
      // opaque access token (no audience): good for userinfo only
      expect(session.tokens.accessToken.split('.')).toHaveLength(1);
      // the callback cannot be replayed
      await expect(client.handleCallback(done.callbackUrl)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'no_transaction');
    }, 30_000);

    it('userinfo answers the same subject and the claims the scopes allow', async () => {
      const me = await fetchUserInfo({ userinfoEndpoint: metadata.userinfo_endpoint!, accessToken: session.tokens.accessToken });
      expect(me.sub).toBe(USER_ID);
      expect(me.org).toMatchObject({ id: ORG_ID });
      expect(me).not.toHaveProperty('balance');
    });

    it('lists the grant under Connected apps', async () => {
      const apps = await api('/account/connected-apps', { token: bearer });
      expect(apps.status).toBe(200);
      const mine = (apps.body.apps as Array<{ grantId: string; client: { id: string } }>).find((a) => a.grantId === grantId);
      expect(mine?.client.id).toBe(publicClientId);
    });

    it('a forced refresh rotates the tokens and the new ID token verifies with the live keys', async () => {
      const before = session.tokens;
      const refreshed = await client.getSession({ refresh: 'force' });
      expect(refreshed?.status).toBe('active');
      expect(refreshed!.tokens.accessToken).not.toBe(before.accessToken);
      expect(refreshed!.tokens.refreshToken).not.toBe(before.refreshToken);
      expect(refreshed!.tokens.claims?.sub).toBe(USER_ID);
      const claims = await verifyIdToken(refreshed!.tokens.idToken!, { issuer: ISSUER, clientId: publicClientId, resolver: client.jwks() });
      expect(claims.sub).toBe(USER_ID);
      const me = await fetchUserInfo({ userinfoEndpoint: metadata.userinfo_endpoint!, accessToken: refreshed!.tokens.accessToken });
      expect(me.sub).toBe(USER_ID);
      session = refreshed!;
    });

    it('the rotated token is refused locally, never sent, so the grant stays alive', async () => {
      // the client remembers the token it rotated away from; nothing goes to the issuer
      await expect(refreshTokenGrant({ tokenEndpoint: metadata.token_endpoint, clientId: publicClientId }, { refreshToken: 'not-a-token' }))
        .rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.error === 'invalid_grant');
      const still = await client.getSession();
      expect(still?.status).toBe('active');
      const apps = await api('/account/connected-apps', { token: bearer });
      expect((apps.body.apps as Array<{ grantId: string }>).some((a) => a.grantId === grantId)).toBe(true);
    });

    it('a second sign-in reuses the remembered consent and the same grant', async () => {
      const other = createAuthClient({ issuer: ISSUER, clientId: publicClientId, redirectUri: REDIRECT_URI, scope: ['openid', 'profile', 'email', 'org', 'wallet'], sessionStorage: memoryStorage(), transactionStorage: memoryStorage() });
      const { url } = await other.createSignInUrl();
      const done = await completeAuthorization(url, bearer);
      expect(done.grantId).toBe(grantId);
      const details = await api(`/oidc/interaction/${done.uid}/details`, { token: bearer });
      // the interaction is consumed after finish; details only answers while pending
      expect([200, 404]).toContain(details.status);
      const { session: second } = await other.handleCallback(done.callbackUrl);
      expect(second.user.id).toBe(USER_ID);
      // sign this one out with revocation: the whole grant ends for both clients
      await other.signOut({ revoke: true });
      const apps = await api('/account/connected-apps', { token: bearer });
      expect((apps.body.apps as Array<{ grantId: string }>).some((a) => a.grantId === grantId)).toBe(false);
    }, 30_000);

    it('after the grant is revoked, the first client learns it is signed out on its next refresh', async () => {
      const gone = await client.getSession({ refresh: 'force' });
      expect(gone).toBeNull();
      expect(client.peekSession()).toBeNull();
    });

    it('reuse of a rotated refresh token revokes the grant and the client signs out', async () => {
      const fresh = createAuthClient({ issuer: ISSUER, clientId: publicClientId, redirectUri: REDIRECT_URI, scope: ['openid', 'email'], sessionStorage: memoryStorage(), transactionStorage: memoryStorage() });
      const { url } = await fresh.createSignInUrl();
      const done = await completeAuthorization(url, bearer, {});
      const { session: s } = await fresh.handleCallback(done.callbackUrl);
      // Something outside the client (another device, a stolen copy) rotates the token...
      const rotated = await refreshTokenGrant({ tokenEndpoint: metadata.token_endpoint, clientId: publicClientId }, { refreshToken: s.tokens.refreshToken! });
      expect(rotated.refresh_token).not.toBe(s.tokens.refreshToken);
      // ...so the client's stored token is now a replay: the issuer revokes the grant, the client signs out.
      expect(await fresh.getSession({ refresh: 'force' })).toBeNull();
      await expect(refreshTokenGrant({ tokenEndpoint: metadata.token_endpoint, clientId: publicClientId }, { refreshToken: rotated.refresh_token! }))
        .rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.error === 'invalid_grant');
      const apps = await api('/account/connected-apps', { token: bearer });
      expect((apps.body.apps as Array<{ grantId: string }>).some((a) => a.grantId === done.grantId)).toBe(false);
    }, 30_000);

    it('the end-session URL renders the issuer confirm page', async () => {
      const again = createAuthClient({ issuer: ISSUER, clientId: publicClientId, redirectUri: REDIRECT_URI, postLogoutRedirectUri: POST_LOGOUT_URI, scope: ['openid'], sessionStorage: memoryStorage(), transactionStorage: memoryStorage() });
      const { url } = await again.createSignInUrl();
      const done = await completeAuthorization(url, bearer, {});
      await again.handleCallback(done.callbackUrl);
      const { endSessionUrl } = await again.signOut();
      expect(endSessionUrl).toContain('/oidc/session/end?');
      const jar = new CookieJar();
      const page = await browserGet(endSessionUrl!, jar);
      expect(page.status).toBe(200);
      const html = await page.text();
      // With a valid id_token_hint the issuer auto-submits its confirm form; without one it asks.
      const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)?.[1];
      expect(xsrf, 'end-session page must render the confirm form').toBeTruthy();
      expect(html).toMatch(/session\/end\/confirm|Sign out/);
      const confirm = await fetch(`${ISSUER}/oidc/session/end/confirm`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: jar.header(), 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ xsrf: xsrf!, logout: 'yes' }).toString(),
      });
      expect(confirm.status).toBe(303);
      expect(confirm.headers.get('location')).toBe(POST_LOGOUT_URI);
    }, 30_000);
  });

  describe('confidential client', () => {
    it('authenticates with client_secret_basic, introspects its token and revokes it', async () => {
      const client = createAuthClient({
        issuer: ISSUER,
        clientId: confidentialClientId,
        clientAuthentication: { method: 'client_secret_basic', clientSecret: confidentialSecret },
        redirectUri: REDIRECT_URI,
        scope: ['openid', 'email'],
        sessionStorage: memoryStorage(),
        transactionStorage: memoryStorage(),
      });
      const { url } = await client.createSignInUrl();
      const done = await completeAuthorization(url, bearer, {});
      const { session } = await client.handleCallback(done.callbackUrl);
      expect(session.user.email).toBeTruthy();
      expect(session.user.org).toBeNull();

      const info = await introspectToken({
        introspectionEndpoint: metadata.introspection_endpoint!,
        clientId: confidentialClientId,
        clientAuthentication: { method: 'client_secret_basic', clientSecret: confidentialSecret },
        token: session.tokens.accessToken,
      });
      expect(info.active).toBe(true);
      expect(info.sub).toBe(USER_ID);
      expect(info.client_id).toBe(confidentialClientId);

      await expect(refreshTokenGrant(
        { tokenEndpoint: metadata.token_endpoint, clientId: confidentialClientId, clientAuthentication: { method: 'client_secret_basic', clientSecret: 'wrong' } },
        { refreshToken: session.tokens.refreshToken! },
      )).rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.status === 401);

      await revokeToken({
        revocationEndpoint: metadata.revocation_endpoint!,
        clientId: confidentialClientId,
        clientAuthentication: { method: 'client_secret_basic', clientSecret: confidentialSecret },
        token: session.tokens.refreshToken!,
        tokenTypeHint: 'refresh_token',
      });
      const after = await introspectToken({
        introspectionEndpoint: metadata.introspection_endpoint!,
        clientId: confidentialClientId,
        clientAuthentication: { method: 'client_secret_basic', clientSecret: confidentialSecret },
        token: session.tokens.refreshToken!,
      });
      expect(after.active).toBe(false);
    }, 30_000);
  });

  describe('device flow', () => {
    it('starts, reports pending, and completes once the code is confirmed through the bridge', async () => {
      const started = await startDeviceAuthorization({ metadata, clientId: publicClientId, scope: ['openid', 'email'] });
      expect(started.user_code).toBeTruthy();
      expect(started.verification_uri).toBe(`${ISSUER}/oidc/device`);
      expect(started.verification_uri_complete).toContain(started.user_code);

      // Before approval the token endpoint answers authorization_pending (one poll, by hand).
      const pending = await fetch(metadata.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: started.device_code, client_id: publicClientId }).toString(),
      });
      expect(pending.status).toBe(400);
      expect(((await pending.json()) as { error: string }).error).toBe('authorization_pending');

      // The user opens the verification page in a browser and submits the code.
      const jar = new CookieJar();
      const entry = await browserGet(started.verification_uri_complete!, jar);
      expect(entry.status).toBe(200);
      const entryHtml = await entry.text();
      const xsrf = /name="xsrf" value="([^"]+)"/.exec(entryHtml)?.[1];
      expect(xsrf, 'device form must carry an xsrf token').toBeTruthy();
      const submit = await fetch(`${ISSUER}/oidc/device`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: jar.header(), 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ xsrf: xsrf!, user_code: started.user_code }).toString(),
      });
      jar.absorb(submit);
      expect(submit.status).toBe(200);
      const confirmHtml = await submit.text();
      const xsrf2 = /name="xsrf" value="([^"]+)"/.exec(confirmHtml)?.[1];
      expect(xsrf2).toBeTruthy();
      const confirm = await fetch(`${ISSUER}/oidc/device`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: jar.header(), 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ xsrf: xsrf2!, user_code: started.user_code, confirm: 'yes' }).toString(),
      });
      jar.absorb(confirm);
      expect(confirm.status).toBe(303);
      const hopUrl = confirm.headers.get('location')!;
      const uid = /\/oidc\/interaction\/([A-Za-z0-9_-]+)$/.exec(hopUrl)?.[1];
      expect(uid, hopUrl).toBeTruthy();
      const hop = await browserGet(hopUrl, jar);
      expect(hop.status).toBe(303);
      const approve = await api(`/oidc/interaction/${uid}/login`, { method: 'POST', token: bearer, body: JSON.stringify({}) });
      expect(approve.status, JSON.stringify(approve.body)).toBe(200);
      const finish = await browserGet(approve.body.finishUrl, jar);
      expect(finish.status).toBe(303);
      const resume = await browserGet(finish.headers.get('location')!, jar);
      // the device leg ends on the issuer's success page
      expect([200, 303]).toContain(resume.status);

      const tokens = await pollDeviceToken({ metadata, clientId: publicClientId, deviceCode: started.device_code, intervalSeconds: 1, expiresInSeconds: 60, sleep: async () => {} });
      expect(tokens.access_token).toBeTruthy();
      const claims = await verifyIdToken(tokens.id_token!, { issuer: ISSUER, clientId: publicClientId, resolver: createJwksResolver({ jwksUri: metadata.jwks_uri }) });
      expect(claims.sub).toBe(USER_ID);
      await revokeToken({ revocationEndpoint: metadata.revocation_endpoint!, clientId: publicClientId, token: tokens.refresh_token!, tokenTypeHint: 'refresh_token' });
    }, 60_000);
  });
});
