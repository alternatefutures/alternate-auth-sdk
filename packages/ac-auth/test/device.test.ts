import { describe, expect, it, vi } from 'vitest';
import { pollDeviceToken, startDeviceAuthorization } from '../src/device';
import { AuthError, OAuthError } from '../src/errors';
import { FakeIssuer } from './helpers/fakeIssuer';

describe('device flow', () => {
  it('starts the flow with the scope and client id and returns the codes', async () => {
    const issuer = await FakeIssuer.create();
    const response = await startDeviceAuthorization({
      metadata: issuer.metadata as never,
      clientId: 'ac_cli',
      scope: 'openid email',
      fetch: issuer.fetch,
    });
    expect(response.device_code).toBeTruthy();
    expect(response.user_code).toBeTruthy();
    expect(response.verification_uri).toBe(`${issuer.issuer}/oidc/device`);
    expect(response.verification_uri_complete).toContain(response.user_code);
    const sent = new URLSearchParams(issuer.lastRequest.body);
    expect(sent.get('scope')).toBe('openid email');
    expect(sent.get('client_id')).toBe('ac_cli');
  });

  it('polls through pending and slow_down and returns tokens once approved', async () => {
    const issuer = await FakeIssuer.create();
    const started = await startDeviceAuthorization({ metadata: issuer.metadata as never, clientId: 'ac_cli', fetch: issuer.fetch });
    const waits: number[] = [];
    let polls = 0;
    const originalFetch = issuer.fetch;
    const fetchWithSlowDown = async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/oidc/token')) {
        polls++;
        if (polls === 2) return new Response(JSON.stringify({ error: 'slow_down' }), { status: 400, headers: { 'content-type': 'application/json' } });
        if (polls === 3) issuer.approveDevice(started.user_code);
      }
      return originalFetch(input, init);
    };
    const tokens = await pollDeviceToken({
      metadata: issuer.metadata as never,
      clientId: 'ac_cli',
      deviceCode: started.device_code,
      intervalSeconds: 5,
      expiresInSeconds: 600,
      fetch: fetchWithSlowDown,
      sleep: async (ms) => { waits.push(ms / 1000); },
      onPending: vi.fn(),
    });
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    // pending (5 s), slow_down (interval becomes 10 s), approved on the next poll
    expect(waits).toEqual([5, 5, 10]);
    expect(polls).toBe(3);
  });

  it('maps expired_token and access_denied, and gives up at the deadline without polling', async () => {
    const issuer = await FakeIssuer.create();
    const started = await startDeviceAuthorization({ metadata: issuer.metadata as never, clientId: 'ac_cli', fetch: issuer.fetch });
    const base = { metadata: issuer.metadata as never, clientId: 'ac_cli', deviceCode: started.device_code, fetch: issuer.fetch, sleep: async () => {} };

    issuer.devices.get(started.device_code)!.denied = true;
    await expect(pollDeviceToken(base)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'access_denied');

    issuer.devices.get(started.device_code)!.denied = false;
    issuer.devices.get(started.device_code)!.expired = true;
    await expect(pollDeviceToken(base)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'device_flow_expired');

    const before = issuer.calls.token;
    let now = 0;
    await expect(pollDeviceToken({ ...base, expiresInSeconds: 1, now: () => now, sleep: async () => { now += 5000; } }))
      .rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'device_flow_expired');
    expect(issuer.calls.token - before).toBeLessThanOrEqual(1);
  });

  it('propagates other OAuth errors unchanged', async () => {
    const issuer = await FakeIssuer.create();
    await expect(pollDeviceToken({ metadata: issuer.metadata as never, clientId: 'ac_cli', deviceCode: 'unknown', fetch: issuer.fetch, sleep: async () => {} }))
      .rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.error === 'invalid_grant');
  });
});
