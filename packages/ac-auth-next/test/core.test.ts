import { NextRequest } from 'next/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FakeIssuer } from '../../ac-auth/test/helpers/fakeIssuer';
import { readCookie } from '../src/cookies';
import { AcAuthCore, resolveConfig, safeReturnTo, toClientSession } from '../src/core';
import { createAuthProxy } from '../src/proxy';
import { seal, unseal } from '../src/seal';

const mockCookieStore = new Map<string, string>();
vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (mockCookieStore.has(name) ? { name, value: mockCookieStore.get(name)! } : undefined),
  }),
}));

const SECRET = 'a-secret-of-at-least-sixteen-chars';
const ORIGIN = 'http://localhost:3000';

async function harness(extra: Partial<ConstructorParameters<typeof AcAuthCore>[0]> = {}) {
  let now = 1_700_000_000_000;
  const clock = () => now;
  const issuer = await FakeIssuer.create({ now: clock });
  const onWarning = vi.fn();
  const core = new AcAuthCore({
    issuer: issuer.issuer,
    clientId: 'ac_next',
    secret: SECRET,
    fetch: issuer.fetch,
    now: clock,
    scope: ['openid', 'profile', 'email', 'wallet'],
    onWarning,
    env: {},
    ...extra,
  });
  return { issuer, core, onWarning, advance: (ms: number) => { now += ms; }, now: () => now };
}

function setCookies(response: Response): Record<string, { value: string; raw: string }> {
  const out: Record<string, { value: string; raw: string }> = {};
  for (const raw of response.headers.getSetCookie()) {
    const [pair = ''] = raw.split(';');
    const eq = pair.indexOf('=');
    out[pair.slice(0, eq)] = { value: decodeURIComponent(pair.slice(eq + 1)), raw };
  }
  return out;
}

/** Sign in end to end through the handlers and return the session cookie value. */
async function signIn(h: Awaited<ReturnType<typeof harness>>, returnTo = '/dashboard') {
  const start = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin?returnTo=${encodeURIComponent(returnTo)}`));
  expect(start.status).toBe(302);
  const txn = setCookies(start)['ac_auth.session.txn']!;
  const callbackUrl = await h.issuer.authorize(start.headers.get('location')!);
  const callback = await h.core.handleCallback(new Request(callbackUrl, { headers: { cookie: `ac_auth.session.txn=${encodeURIComponent(txn.value)}` } }));
  expect(callback.status, callback.headers.get('location') ?? '').toBe(302);
  const cookies = setCookies(callback);
  return { callback, cookies, sessionCookie: cookies['ac_auth.session']!.value };
}

describe('configuration', () => {
  it('reads the environment, validates the secret and normalizes the base path', () => {
    const cfg = resolveConfig({ env: { ALTERNATE_CLOUDS_CLIENT_ID: 'ac_env', AUTH_SECRET: SECRET, ALTERNATE_CLOUDS_CLIENT_SECRET: 'acs_x' }, basePath: 'auth/' });
    expect(cfg.clientId).toBe('ac_env');
    expect(cfg.issuer).toBe('https://auth.alternatefutures.ai');
    expect(cfg.basePath).toBe('/auth');
    expect(cfg.clientAuthentication).toEqual({ method: 'client_secret_basic', clientSecret: 'acs_x' });
    expect(cfg.txnCookieName).toBe('ac_auth.session.txn');
    expect(() => resolveConfig({ env: {}, clientId: 'x', secret: 'short' })).toThrow(/AUTH_SECRET/);
    expect(() => resolveConfig({ env: {}, secret: SECRET })).toThrow(/ALTERNATE_CLOUDS_CLIENT_ID/);
    expect(resolveConfig({ env: {}, clientId: 'x', secret: SECRET }).clientAuthentication).toEqual({ method: 'none' });
  });

  it('only accepts same-origin paths as return targets', () => {
    expect(safeReturnTo('/dashboard?x=1')).toBe('/dashboard?x=1');
    expect(safeReturnTo('//evil.test')).toBeNull();
    expect(safeReturnTo('/\\evil.test')).toBeNull();
    expect(safeReturnTo('https://evil.test')).toBeNull();
    expect(safeReturnTo('/a\r\nb')).toBeNull();
    expect(safeReturnTo(undefined)).toBeNull();
  });
});

describe('sealed cookies', () => {
  it('round-trips, refuses other purposes, other secrets, tampering and expiry', async () => {
    let now = 1_700_000_000_000;
    const token = await seal({ hello: 'world' }, { secret: SECRET, purpose: 'session', expiresAt: Math.floor(now / 1000) + 60, now: () => now });
    expect(await unseal(token, { secret: SECRET, purpose: 'session', now: () => now })).toMatchObject({ hello: 'world' });
    expect(await unseal(token, { secret: SECRET, purpose: 'transaction', now: () => now })).toBeNull();
    expect(await unseal(token, { secret: 'another-secret-of-sixteen-chars', purpose: 'session', now: () => now })).toBeNull();
    expect(await unseal(`${token.slice(0, -4)}AAAA`, { secret: SECRET, purpose: 'session', now: () => now })).toBeNull();
    now += 120_000;
    expect(await unseal(token, { secret: SECRET, purpose: 'session', now: () => now })).toBeNull();
    expect(await unseal('garbage', { secret: SECRET, purpose: 'session' })).toBeNull();
  });
});

describe('sign-in and callback handlers', () => {
  it('signin redirects to the issuer with PKCE S256, state, nonce and a sealed transaction cookie scoped to the base path', async () => {
    const h = await harness();
    const response = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin?returnTo=%2Fafter&prompt=login`));
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(`${h.issuer.issuer}/oidc/auth`);
    expect(location.searchParams.get('code_challenge_method')).toBe('S256');
    expect(location.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/api/auth/callback`);
    expect(location.searchParams.get('scope')).toBe('openid profile email wallet');
    expect(location.searchParams.get('prompt')).toBe('login');
    const txn = setCookies(response)['ac_auth.session.txn']!;
    expect(txn.raw).toMatch(/Path=\/api\/auth;/);
    expect(txn.raw).toMatch(/HttpOnly/);
    expect(txn.raw).toMatch(/SameSite=Lax/);
    expect(txn.raw).toMatch(/Max-Age=900/);
    expect(txn.raw).not.toMatch(/Secure/);
    const payload = await unseal<{ state: string; returnTo: string }>(txn.value, { secret: SECRET, purpose: 'transaction', now: h.now });
    expect(payload?.state).toBe(location.searchParams.get('state'));
    expect(payload?.returnTo).toBe('/after');
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('behind https: Secure cookies with the __Secure-/__Host- prefixes, forwarded headers for the redirect URI, and the whole flow', async () => {
    const h = await harness();
    const https = { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'app.example' };
    const start = await h.core.handleSignIn(new Request('http://internal:3000/api/auth/signin?returnTo=%2Fhome', { headers: https }));
    expect(new URL(start.headers.get('location')!).searchParams.get('redirect_uri')).toBe('https://app.example/api/auth/callback');
    const txn = setCookies(start)['__Secure-ac_auth.session.txn']!;
    expect(txn.raw).toMatch(/Secure/);
    expect(txn.raw).toMatch(/Path=\/api\/auth;/);
    const callbackUrl = await h.issuer.authorize(start.headers.get('location')!);
    const callback = await h.core.handleCallback(new Request(callbackUrl, { headers: { ...https, cookie: `__Secure-ac_auth.session.txn=${encodeURIComponent(txn.value)}` } }));
    expect(callback.headers.get('location')).toBe('/home');
    const session = setCookies(callback)['__Host-ac_auth.session']!;
    expect(session.raw).toMatch(/Secure/);
    expect(session.raw).toMatch(/Path=\/;/);
    expect(session.raw).not.toMatch(/Domain=/);
    expect((await h.core.sessionFromCookieHeader(`__Host-ac_auth.session=${encodeURIComponent(session.value)}`))?.user.id).toBe('user_1');
    const out = await h.core.handleSignOut(new Request('http://internal:3000/api/auth/signout', { headers: { ...https, cookie: `__Host-ac_auth.session=${encodeURIComponent(session.value)}` } }));
    expect(setCookies(out)['__Host-ac_auth.session']!.raw).toMatch(/Max-Age=0/);
  });

  it('answers a prefetch of the sign-in route with 204 and starts nothing', async () => {
    const h = await harness();
    const cases: Record<string, string>[] = [{ 'next-router-prefetch': '1' }, { purpose: 'prefetch' }, { 'sec-purpose': 'prefetch;prerender' }];
    for (const headers of cases) {
      const response = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin`, { headers }));
      expect(response.status).toBe(204);
      expect(response.headers.getSetCookie()).toHaveLength(0);
    }
  });

  it('ignores an open-redirect returnTo', async () => {
    const h = await harness();
    const response = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin?returnTo=https%3A%2F%2Fevil.test`));
    const payload = await unseal<{ returnTo: string }>(setCookies(response)['ac_auth.session.txn']!.value, { secret: SECRET, purpose: 'transaction', now: h.now });
    expect(payload?.returnTo).toBe('/');
  });

  it('callback exchanges the code, verifies the ID token, seals the session and lands on returnTo', async () => {
    const h = await harness();
    const { callback, cookies, sessionCookie } = await signIn(h);
    expect(callback.headers.get('location')).toBe('/dashboard');
    expect(cookies['ac_auth.session']!.raw).toMatch(/Path=\/;/);
    expect(cookies['ac_auth.session']!.raw).toMatch(/HttpOnly/);
    expect(cookies['ac_auth.session']!.raw).toMatch(/Max-Age=2592000/);
    expect(cookies['ac_auth.session.txn']!.raw).toMatch(/Max-Age=0/);

    const session = await h.core.sessionFromCookieHeader(`ac_auth.session=${encodeURIComponent(sessionCookie)}`);
    expect(session?.status).toBe('active');
    expect(session?.user.email).toBe('dev@example.com');
    expect(session?.user.key).toMatch(/^did:pkh:/);
    expect(session?.accessToken).toBeTruthy();
    expect(session?.claims.sub).toBe('user_1');
    expect(toClientSession(session)).not.toHaveProperty('accessToken');
    expect(toClientSession(session)).not.toHaveProperty('claims');

    const json = await h.core.handleSession(new Request(`${ORIGIN}/api/auth/session`, { headers: { cookie: `ac_auth.session=${encodeURIComponent(sessionCookie)}` } }));
    const body = (await json.json()) as { session: Record<string, unknown> | null };
    expect(body.session?.user).toMatchObject({ id: 'user_1' });
    expect(JSON.stringify(body)).not.toContain(session!.accessToken);
    expect(json.headers.get('cache-control')).toBe('no-store');
  });

  it('reports callback failures as auth_error on the return path and never sets a session', async () => {
    const h = await harness();
    const noTxn = await h.core.handleCallback(new Request(`${ORIGIN}/api/auth/callback?code=x&state=y`));
    expect(noTxn.status).toBe(302);
    expect(noTxn.headers.get('location')).toBe('/?auth_error=no_transaction');
    expect(setCookies(noTxn)['ac_auth.session']).toBeUndefined();

    const start = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin?returnTo=%2Fdashboard`));
    const txn = setCookies(start)['ac_auth.session.txn']!.value;
    const cookie = `ac_auth.session.txn=${encodeURIComponent(txn)}`;
    const denied = await h.core.handleCallback(new Request(await h.issuer.authorize(start.headers.get('location')!, { error: 'access_denied' }), { headers: { cookie } }));
    expect(denied.headers.get('location')).toBe('/dashboard?auth_error=access_denied');

    const start2 = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin`));
    const txn2 = setCookies(start2)['ac_auth.session.txn']!.value;
    const tampered = new URL(await h.issuer.authorize(start2.headers.get('location')!));
    tampered.searchParams.set('state', 'not-the-state-not-the-state');
    const bad = await h.core.handleCallback(new Request(tampered, { headers: { cookie: `ac_auth.session.txn=${encodeURIComponent(txn2)}` } }));
    expect(bad.headers.get('location')).toBe('/?auth_error=invalid_state');
  });

  it('the callback is single use: a replay finds no transaction', async () => {
    const h = await harness();
    const start = await h.core.handleSignIn(new Request(`${ORIGIN}/api/auth/signin`));
    const txn = setCookies(start)['ac_auth.session.txn']!.value;
    const url = await h.issuer.authorize(start.headers.get('location')!);
    const first = await h.core.handleCallback(new Request(url, { headers: { cookie: `ac_auth.session.txn=${encodeURIComponent(txn)}` } }));
    expect(first.headers.get('location')).toBe('/');
    // the browser no longer has the txn cookie (Max-Age=0), a replay carries none
    const replay = await h.core.handleCallback(new Request(url));
    expect(replay.headers.get('location')).toBe('/?auth_error=no_transaction');
  });
});

describe('refresh in the proxy', () => {
  it('keeps a valid cookie, rotates an expired one exactly once for concurrent requests, and clears a revoked grant', async () => {
    const h = await harness();
    const { sessionCookie } = await signIn(h);
    expect((await h.core.refreshSessionCookie(sessionCookie)).action).toBe('keep');

    h.advance(3600 * 1000);
    const decisions = await Promise.all([h.core.refreshSessionCookie(sessionCookie), h.core.refreshSessionCookie(sessionCookie), h.core.refreshSessionCookie(sessionCookie)]);
    expect(decisions.map((d) => d.action)).toEqual(['set', 'set', 'set']);
    expect(h.issuer.presentedRefreshTokens).toHaveLength(1);
    const values = new Set(decisions.map((d) => (d as { value: string }).value));
    expect(values.size).toBe(3); // three seals of the same payload (fresh IVs)
    const payloads = decisions.map((d) => (d as { payload: { at: string; rt: string } }).payload);
    expect(new Set(payloads.map((p) => p.rt)).size).toBe(1);
    const fresh = await h.core.sessionFromCookieHeader(`ac_auth.session=${encodeURIComponent((decisions[0] as { value: string }).value)}`);
    expect(fresh?.status).toBe('active');
    expect(fresh?.user.id).toBe('user_1');

    // a late request still carrying the OLD cookie gets the successor, not a second rotation
    h.advance(10_000);
    const late = await h.core.refreshSessionCookie(sessionCookie);
    expect(late.action).toBe('set');
    expect(h.issuer.presentedRefreshTokens).toHaveLength(1);

    // the grant is revoked (Connected apps): the next refresh clears the cookie
    h.advance(3600 * 1000);
    h.issuer.revokeGrant([...h.issuer.grants.keys()][0]!);
    expect((await h.core.refreshSessionCookie((decisions[0] as { value: string }).value)).action).toBe('clear');
  });

  it('keeps the session under grace while the issuer is unreachable and clears it past the cap', async () => {
    const h = await harness({ grace: { graceMs: 2 * 3600 * 1000, maxSessionMs: 7 * 24 * 3600 * 1000 } });
    const { sessionCookie } = await signIn(h);
    h.advance(3600 * 1000 + 60_000);
    h.issuer.offline = true;
    expect((await h.core.refreshSessionCookie(sessionCookie)).action).toBe('keep');
    const graced = await h.core.sessionFromCookieHeader(`ac_auth.session=${encodeURIComponent(sessionCookie)}`);
    expect(graced?.status).toBe('grace');
    expect(h.onWarning).toHaveBeenCalledWith(expect.stringMatching(/grace/), expect.anything());
    h.advance(2 * 3600 * 1000);
    expect((await h.core.refreshSessionCookie(sessionCookie)).action).toBe('clear');
    expect(await h.core.sessionFromCookieHeader(`ac_auth.session=${encodeURIComponent(sessionCookie)}`)).toBeNull();
  });

  it('clears garbage and foreign cookies', async () => {
    const h = await harness();
    expect((await h.core.refreshSessionCookie('not-a-cookie')).action).toBe('clear');
    expect((await h.core.refreshSessionCookie(undefined)).action).toBe('keep');
  });
});

describe('sign-out', () => {
  it('clears the cookie and answers JSON with the end-session URL when a post-logout URI is registered', async () => {
    const h = await harness({ postLogoutRedirectUri: `${ORIGIN}/` });
    const { sessionCookie } = await signIn(h);
    const response = await h.core.handleSignOut(new Request(`${ORIGIN}/api/auth/signout`, { method: 'POST', headers: { accept: 'application/json', cookie: `ac_auth.session=${encodeURIComponent(sessionCookie)}` } }));
    expect(response.status).toBe(200);
    const { redirectTo } = (await response.json()) as { redirectTo: string };
    const url = new URL(redirectTo);
    expect(url.pathname).toBe('/oidc/session/end');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe(`${ORIGIN}/`);
    expect(url.searchParams.get('id_token_hint')).toBeTruthy();
    expect(setCookies(response)['ac_auth.session']!.raw).toMatch(/Max-Age=0/);
    expect(h.issuer.calls.revocation).toBe(0);
  });

  it('redirects to the after-sign-out path otherwise, and revokes when asked', async () => {
    const h = await harness({ afterSignOutPath: '/bye', revokeOnSignOut: true });
    const { sessionCookie } = await signIn(h);
    const response = await h.core.handleSignOut(new Request(`${ORIGIN}/api/auth/signout`, { headers: { cookie: `ac_auth.session=${encodeURIComponent(sessionCookie)}` } }));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('/bye');
    expect(h.issuer.calls.revocation).toBe(1);
    const grant = [...h.issuer.grants.values()][0]!;
    expect(grant.revoked).toBe(true);
  });

  it('routes by the last path segment', async () => {
    const h = await harness();
    expect((await h.core.handle(new Request(`${ORIGIN}/api/auth/nope`))).status).toBe(404);
    expect((await h.core.handle(new Request(`${ORIGIN}/api/auth/session`))).status).toBe(200);
    expect((await h.core.handle(new Request(`${ORIGIN}/api/auth/signin`))).status).toBe(302);
  });
});

describe('Next.js integration', () => {
  beforeEach(() => mockCookieStore.clear());

  it('auth() reads the request cookies and the proxy refreshes, forwards and protects', async () => {
    const h = await harness();
    const { createAuth } = await import('../src/index');
    const { auth, handlers, createProxy } = createAuth({ issuer: h.issuer.issuer, clientId: 'ac_next', secret: SECRET, fetch: h.issuer.fetch, now: h.now, env: {}, scope: ['openid', 'email'] });
    expect(await auth()).toBeNull();

    const start = await handlers.GET(new Request(`${ORIGIN}/api/auth/signin?returnTo=%2Fdashboard`));
    const txn = setCookies(start)['ac_auth.session.txn']!.value;
    const callback = await handlers.GET(new Request(await h.issuer.authorize(start.headers.get('location')!), { headers: { cookie: `ac_auth.session.txn=${encodeURIComponent(txn)}` } }));
    const sessionCookie = setCookies(callback)['ac_auth.session']!.value;
    mockCookieStore.set('ac_auth.session', sessionCookie);
    const session = await auth();
    expect(session?.user.email).toBe('dev@example.com');

    const proxy = createProxy({ protect: ['/dashboard'] });
    // valid session: pass through untouched
    const ok = await proxy(new NextRequest(`${ORIGIN}/dashboard`, { headers: { cookie: `ac_auth.session=${encodeURIComponent(sessionCookie)}` } }));
    expect(ok.status).toBe(200);
    expect(ok.headers.getSetCookie()).toHaveLength(0);

    // expired: refreshed, new cookie on the response AND on the forwarded request
    h.advance(3600 * 1000);
    const refreshed = await proxy(new NextRequest(`${ORIGIN}/dashboard`, { headers: { cookie: `other=1; ac_auth.session=${encodeURIComponent(sessionCookie)}` } }));
    expect(refreshed.status).toBe(200);
    const setCookie = refreshed.headers.getSetCookie()[0]!;
    expect(setCookie).toMatch(/^ac_auth\.session=/);
    const forwarded = refreshed.headers.get('x-middleware-request-cookie') ?? '';
    const forwardedValue = readCookie(forwarded, 'ac_auth.session');
    expect(forwardedValue).toBeTruthy();
    expect(forwardedValue).not.toBe(sessionCookie);
    expect(forwarded).toContain('other=1');
    expect(h.issuer.presentedRefreshTokens).toHaveLength(1);

    // no session on a protected path: redirect to sign-in with returnTo
    const anonymous = await proxy(new NextRequest(`${ORIGIN}/dashboard?tab=2`));
    expect(anonymous.status).toBe(307);
    const location = new URL(anonymous.headers.get('location')!);
    expect(location.pathname).toBe('/api/auth/signin');
    expect(location.searchParams.get('returnTo')).toBe('/dashboard?tab=2');
    // public path: pass through
    expect((await proxy(new NextRequest(`${ORIGIN}/`))).status).toBe(200);
    // the auth routes are never touched
    expect((await proxy(new NextRequest(`${ORIGIN}/api/auth/callback?code=1&state=2`))).status).toBe(200);
  });

  it('a standalone proxy from a config shares nothing but behaves the same', async () => {
    const h = await harness();
    const { sessionCookie } = await signIn(h);
    const proxy = createAuthProxy({ issuer: h.issuer.issuer, clientId: 'ac_next', secret: SECRET, fetch: h.issuer.fetch, now: h.now, env: {} });
    h.advance(3600 * 1000);
    const response = await proxy(new NextRequest(`${ORIGIN}/`, { headers: { cookie: `ac_auth.session=${encodeURIComponent(sessionCookie)}` } }));
    expect(response.headers.getSetCookie()[0]).toMatch(/^ac_auth\.session=/);
  });
});
