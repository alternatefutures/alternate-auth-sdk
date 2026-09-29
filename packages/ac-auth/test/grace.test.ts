import { describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../src/client';
import { DEFAULT_GRACE_POLICY, NO_GRACE_POLICY, evaluateGrace, graceDeadline } from '../src/grace';
import { memoryStorage } from '../src/storage';
import { FakeIssuer } from './helpers/fakeIssuer';

const H = 60 * 60 * 1000;
const D = 24 * H;

describe('evaluateGrace', () => {
  const tokens = { issuedAt: 0, expiresAt: H };

  it('is active before expiry, grace after, expired past the window', () => {
    expect(evaluateGrace(tokens, H - 1)).toBe('active');
    expect(evaluateGrace(tokens, H)).toBe('grace');
    expect(evaluateGrace(tokens, H + D)).toBe('grace');
    expect(evaluateGrace(tokens, H + D + 1)).toBe('expired');
  });

  it('the cap since issuance beats the grace window', () => {
    const policy = { graceMs: 30 * D, maxSessionMs: 7 * D };
    expect(evaluateGrace(tokens, 7 * D, policy)).toBe('grace');
    expect(evaluateGrace(tokens, 7 * D + 1, policy)).toBe('expired');
    expect(graceDeadline(tokens, policy)).toBe(7 * D);
    expect(graceDeadline(tokens, DEFAULT_GRACE_POLICY)).toBe(H + D);
  });

  it('a zero grace policy expires with the access token', () => {
    expect(evaluateGrace(tokens, H, NO_GRACE_POLICY)).toBe('expired');
    expect(evaluateGrace(tokens, H - 1, NO_GRACE_POLICY)).toBe('active');
  });
});

describe('AuthClient under an issuer outage', () => {
  async function signedInClient(options: { grace?: { graceMs: number; maxSessionMs: number } | false } = {}) {
    let now = 1_700_000_000_000;
    const clock = () => now;
    const issuer = await FakeIssuer.create({ now: clock, accessTokenTtl: 3600 });
    const onWarning = vi.fn();
    const client = new AuthClient({
      issuer: issuer.issuer,
      clientId: 'ac_1',
      redirectUri: 'http://localhost:3000/callback',
      fetch: issuer.fetch,
      sessionStorage: memoryStorage(),
      transactionStorage: memoryStorage(),
      now: clock,
      onWarning,
      ...(options.grace !== undefined ? { grace: options.grace } : {}),
    });
    const { url } = await client.createSignInUrl();
    const callback = await issuer.authorize(url);
    const { session } = await client.handleCallback(callback);
    return { issuer, client, session, onWarning, advance: (ms: number) => { now += ms; } };
  }

  it('keeps the session in grace while the issuer is unreachable, then refreshes when it is back', async () => {
    const { issuer, client, session, advance, onWarning } = await signedInClient();
    advance(2 * H);
    issuer.offline = true;
    const graced = await client.getSession();
    expect(graced?.status).toBe('grace');
    expect(graced?.tokens.accessToken).toBe(session.tokens.accessToken);
    expect(onWarning).toHaveBeenCalledWith(expect.stringMatching(/grace/), expect.anything());

    issuer.offline = false;
    const refreshed = await client.getSession();
    expect(refreshed?.status).toBe('active');
    expect(refreshed?.tokens.accessToken).not.toBe(session.tokens.accessToken);
    expect(issuer.presentedRefreshTokens).toEqual([session.tokens.refreshToken]);
  });

  it('a 503 from the token endpoint is grace too; a stale answer never consumes the token', async () => {
    const { issuer, client, session, advance } = await signedInClient();
    advance(2 * H);
    issuer.tokenStatus = 503;
    expect((await client.getSession())?.status).toBe('grace');
    expect((await client.getSession())?.status).toBe('grace');
    issuer.tokenStatus = null;
    expect((await client.getSession())?.status).toBe('active');
    // the same refresh token went out three times: the two failures never reached a rotation
    expect(issuer.presentedRefreshTokens).toEqual([session.tokens.refreshToken, session.tokens.refreshToken, session.tokens.refreshToken]);
  });

  it('signs out at the grace cap even though the issuer is still unreachable', async () => {
    const { issuer, client, advance } = await signedInClient({ grace: { graceMs: 2 * H, maxSessionMs: 30 * D } });
    issuer.offline = true;
    advance(H + H);
    expect((await client.getSession())?.status).toBe('grace');
    advance(H + 1);
    expect(await client.getSession()).toBeNull();
    expect(client.peekSession()).toBeNull();
  });

  it('invalid_grant ends the session at once, grace or not', async () => {
    const { issuer, client, session, advance } = await signedInClient();
    advance(2 * H);
    issuer.revokeGrant([...issuer.grants.keys()][0]!);
    const listener = vi.fn();
    client.subscribe(listener);
    expect(await client.getSession()).toBeNull();
    expect(listener).toHaveBeenCalledWith(null);
    expect(issuer.presentedRefreshTokens).toEqual([session.tokens.refreshToken]);
    // nothing is retried afterwards
    expect(await client.getSession()).toBeNull();
    expect(issuer.presentedRefreshTokens).toHaveLength(1);
  });

  it('with grace disabled an expired token and an unreachable issuer mean signed out', async () => {
    const { issuer, client, advance } = await signedInClient({ grace: false });
    advance(2 * H);
    issuer.offline = true;
    expect(await client.getSession()).toBeNull();
  });
});
