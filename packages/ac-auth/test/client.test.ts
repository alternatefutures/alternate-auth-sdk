import { describe, expect, it, vi } from 'vitest';
import { AuthClient, createAuthClient } from '../src/client';
import { AuthError, OAuthError } from '../src/errors';
import { memoryStorage } from '../src/storage';
import { FakeIssuer } from './helpers/fakeIssuer';

async function harness(options: { scope?: string[]; sessionStorage?: ReturnType<typeof memoryStorage> } = {}) {
  let now = 1_700_000_000_000;
  const clock = () => now;
  const issuer = await FakeIssuer.create({ now: clock });
  const navigate = vi.fn();
  const onWarning = vi.fn();
  const client = createAuthClient({
    issuer: issuer.issuer,
    clientId: 'ac_1',
    redirectUri: 'http://localhost:3000/callback',
    postLogoutRedirectUri: 'http://localhost:3000/',
    scope: options.scope ?? ['openid', 'profile', 'email', 'org', 'wallet'],
    fetch: issuer.fetch,
    sessionStorage: options.sessionStorage ?? memoryStorage(),
    transactionStorage: memoryStorage(),
    now: clock,
    navigate,
    onWarning,
  });
  return { issuer, client, navigate, onWarning, advance: (ms: number) => { now += ms; } };
}

describe('AuthClient sign-in', () => {
  it('signIn stores a transaction and leaves for the issuer with PKCE S256, state and nonce', async () => {
    const { client, navigate, issuer } = await harness();
    await client.signIn({ returnTo: '/dashboard' });
    expect(navigate).toHaveBeenCalledTimes(1);
    const url = new URL(navigate.mock.calls[0]![0] as string);
    expect(url.origin + url.pathname).toBe(`${issuer.issuer}/oidc/auth`);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('scope')).toBe('openid profile email org wallet');
    expect(url.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(url.searchParams.get('nonce')).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(issuer.calls.discovery).toBe(1);
  });

  it('handleCallback exchanges the code, verifies the ID token and keys the user on the wallet', async () => {
    const { client, issuer } = await harness();
    const { url } = await client.createSignInUrl({ returnTo: '/after' });
    const callback = await issuer.authorize(url);
    expect(client.isCallback(callback)).toBe(true);
    const { session, returnTo } = await client.handleCallback(callback);
    expect(returnTo).toBe('/after');
    expect(session.status).toBe('active');
    expect(session.user).toMatchObject({
      key: 'did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001',
      id: 'user_1',
      name: 'Dev One',
      email: 'dev@example.com',
      emailVerified: true,
      wallet: 'did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001',
      wallets: ['0xabcdef0000000000000000000000000000000001'],
      org: { id: 'org_1', slug: 'acme', name: 'Acme', role: 'OWNER' },
    });
    expect(session.tokens.claims?.nonce).toBe(new URL(url).searchParams.get('nonce'));
    expect(session.tokens.refreshToken).toBeTruthy();
    expect(await client.getAccessToken()).toBe(session.tokens.accessToken);
    expect(client.peekSession()?.user.id).toBe('user_1');
    // the transaction is spent: the same callback cannot be replayed
    await expect(client.handleCallback(callback)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'no_transaction');
  });

  it('keys the user on the subject when there is no wallet', async () => {
    const { client, issuer } = await harness();
    issuer.claims = { name: 'No Wallet', email: 'nw@example.com', email_verified: false };
    const { url } = await client.createSignInUrl();
    const { session } = await client.handleCallback(await issuer.authorize(url, { sub: 'user_9' }));
    expect(session.user.key).toBe('user_9');
    expect(session.user.wallet).toBeNull();
    expect(session.user.emailVerified).toBe(false);
  });

  it('refuses a callback whose state matches no pending sign-in, and one with a tampered state', async () => {
    const { client, issuer } = await harness();
    await expect(client.handleCallback('http://localhost:3000/callback?code=x&state=unknownunknownunknown'))
      .rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'no_transaction');
    const { url } = await client.createSignInUrl();
    const callback = new URL(await issuer.authorize(url));
    callback.searchParams.set('iss', 'https://evil.test');
    await expect(client.handleCallback(callback)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'invalid_response');
  });

  it('surfaces access_denied from the issuer and spends the transaction', async () => {
    const { client, issuer } = await harness();
    const { url } = await client.createSignInUrl();
    const callback = await issuer.authorize(url, { error: 'access_denied' });
    await expect(client.handleCallback(callback)).rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.error === 'access_denied');
    await expect(client.handleCallback(callback)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'no_transaction');
    expect(client.peekSession()).toBeNull();
  });

  it('rejects an ID token with the wrong nonce (a swapped code)', async () => {
    const { client, issuer } = await harness();
    const a = await client.createSignInUrl();
    const b = await client.createSignInUrl();
    const callbackA = new URL(await issuer.authorize(a.url));
    const callbackB = new URL(await issuer.authorize(b.url));
    // Code from flow B delivered to the callback of flow A (state A): the PKCE
    // verifier of A does not match B's challenge, so the issuer refuses.
    callbackA.searchParams.set('code', callbackB.searchParams.get('code')!);
    await expect(client.handleCallback(callbackA)).rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.error === 'invalid_grant');
  });

  it('expired transactions are pruned', async () => {
    const { client, issuer, advance } = await harness();
    const { url } = await client.createSignInUrl();
    const callback = await issuer.authorize(url);
    advance(16 * 60 * 1000);
    await expect(client.handleCallback(callback)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'no_transaction');
  });
});

describe('AuthClient session lifecycle', () => {
  async function signedIn() {
    const h = await harness();
    const { url } = await h.client.createSignInUrl();
    const { session } = await h.client.handleCallback(await h.issuer.authorize(url));
    return { ...h, session };
  }

  it('refreshes near expiry with rotation, single flight, and never resends a rotated token', async () => {
    const { client, issuer, session, advance } = await signedIn();
    advance(3600 * 1000 - 10_000);
    const [a, b, c] = await Promise.all([client.getSession(), client.getSession(), client.getAccessToken()]);
    expect(a?.tokens.accessToken).toBe(b?.tokens.accessToken);
    expect(c).toBe(a?.tokens.accessToken);
    expect(a?.tokens.accessToken).not.toBe(session.tokens.accessToken);
    expect(a?.tokens.refreshToken).not.toBe(session.tokens.refreshToken);
    expect(a?.tokens.claims?.sub).toBe('user_1');
    expect(issuer.presentedRefreshTokens).toEqual([session.tokens.refreshToken]);

    advance(3600 * 1000);
    const later = await client.getSession();
    expect(issuer.presentedRefreshTokens).toEqual([session.tokens.refreshToken, a!.tokens.refreshToken]);
    expect(later?.tokens.refreshToken).not.toBe(a?.tokens.refreshToken);
    // every grant still alive: no reuse ever happened
    expect([...issuer.grants.values()].every((g) => !g.revoked)).toBe(true);
  });

  it('notifies subscribers on every change', async () => {
    const h = await harness();
    const listener = vi.fn();
    h.client.subscribe(listener);
    const { url } = await h.client.createSignInUrl();
    await h.client.handleCallback(await h.issuer.authorize(url));
    expect(listener).toHaveBeenLastCalledWith(expect.objectContaining({ status: 'active' }));
    await h.client.signOut();
    expect(listener).toHaveBeenLastCalledWith(null);
  });

  it('signOut clears the session and hands back the end-session URL; revoke is opt-in', async () => {
    const { client, issuer, session } = await signedIn();
    const { endSessionUrl } = await client.signOut();
    expect(client.peekSession()).toBeNull();
    expect(await client.getSession()).toBeNull();
    const url = new URL(endSessionUrl!);
    expect(url.origin + url.pathname).toBe(`${issuer.issuer}/oidc/session/end`);
    expect(url.searchParams.get('id_token_hint')).toBe(session.tokens.idToken);
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:3000/');
    expect(issuer.calls.revocation).toBe(0);
  });

  it('signOut with revoke ends the grant at the issuer and with redirect leaves for the issuer', async () => {
    const { client, issuer, session, navigate } = await signedIn();
    await client.signOut({ revoke: true, redirect: true });
    expect(issuer.calls.revocation).toBe(1);
    expect(issuer.refreshTokens.get(session.tokens.refreshToken!)?.consumed).toBe(true);
    expect(navigate).toHaveBeenCalledWith(expect.stringContaining('/oidc/session/end'));
  });

  it('works from the known endpoint layout when discovery is down', async () => {
    const { client, issuer, onWarning } = await harness();
    issuer.discoveryStatus = 503;
    const { url } = await client.createSignInUrl();
    expect(url.startsWith(`${issuer.issuer}/oidc/auth?`)).toBe(true);
    expect(onWarning).toHaveBeenCalledWith(expect.stringMatching(/known endpoint layout/), expect.anything());
    const { session } = await client.handleCallback(await issuer.authorize(url));
    expect(session.user.id).toBe('user_1');
  });

  it('shares a session across clients on the same storage and picks up a rotation done elsewhere', async () => {
    const shared = memoryStorage();
    const a = await harness({ sessionStorage: shared });
    const { url } = await a.client.createSignInUrl();
    const { session } = await a.client.handleCallback(await a.issuer.authorize(url));
    const b = new AuthClient({
      issuer: a.issuer.issuer, clientId: 'ac_1', redirectUri: 'http://localhost:3000/callback', fetch: a.issuer.fetch,
      sessionStorage: shared, transactionStorage: memoryStorage(), now: () => 1_700_000_000_000 + 3600 * 1000,
    });
    // b sees the session a created, refreshes it (rotation) and writes it back
    const fromB = await b.getSession();
    expect(fromB?.tokens.refreshToken).not.toBe(session.tokens.refreshToken);
    // a, asked later, must not present the old token: storage now holds b's rotation
    a.advance(3600 * 1000);
    const fromA = await a.client.getSession();
    expect(fromA?.tokens.accessToken).toBe(fromB?.tokens.accessToken);
    expect(a.issuer.presentedRefreshTokens).toEqual([session.tokens.refreshToken]);
  });
});

describe('configuration', () => {
  it('requires a client id and a redirect URI', () => {
    expect(() => new AuthClient({ clientId: '', redirectUri: 'x' })).toThrow(AuthError);
    expect(() => new AuthClient({ clientId: 'c', redirectUri: '' })).toThrow(AuthError);
  });

  it('defaults to the production issuer', () => {
    const client = new AuthClient({ clientId: 'c', redirectUri: 'https://app/cb' });
    expect(client.issuer).toBe('https://auth.alternatefutures.ai');
  });
});
