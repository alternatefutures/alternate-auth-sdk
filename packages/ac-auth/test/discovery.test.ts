import { describe, expect, it, vi } from 'vitest';
import { createDiscoveryCache, discover, knownIssuerMetadata } from '../src/discovery';
import { AuthError } from '../src/errors';
import { FakeIssuer } from './helpers/fakeIssuer';

describe('discover', () => {
  it('returns the fetched document when it names the issuer', async () => {
    const issuer = await FakeIssuer.create();
    const metadata = await discover(issuer.issuer, { fetch: issuer.fetch });
    expect(metadata.token_endpoint).toBe(`${issuer.issuer}/oidc/token`);
    const known = knownIssuerMetadata(issuer.issuer);
    for (const field of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint', 'device_authorization_endpoint'] as const) {
      expect(metadata[field]).toBe(known[field]);
    }
  });

  it('refuses a document for another issuer even when a fallback is allowed', async () => {
    const issuer = await FakeIssuer.create({ issuer: 'https://other.test' });
    await expect(discover('https://issuer.test', { fetch: issuer.fetch })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'discovery_failed' && /names issuer/.test(e.message));
  });

  it('falls back to the known layout when the document cannot be fetched, unless disabled', async () => {
    const issuer = await FakeIssuer.create();
    issuer.discoveryStatus = 502;
    const onWarning = vi.fn();
    const metadata = await discover(issuer.issuer, { fetch: issuer.fetch, onWarning });
    expect(metadata).toEqual(knownIssuerMetadata(issuer.issuer));
    expect(onWarning).toHaveBeenCalled();
    await expect(discover(issuer.issuer, { fetch: issuer.fetch, fallbackToKnownLayout: false })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'discovery_failed');
  });

  it('tries alternate locations that mirror the canonical document', async () => {
    const issuer = await FakeIssuer.create({ issuer: 'https://issuer.test' });
    const mirrorFetch = async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.origin === 'https://issuer.test') throw new TypeError('blocked');
      if (url.origin === 'https://mirror.test') return issuer.fetch(`https://issuer.test${url.pathname}`, init);
      throw new TypeError('unknown host');
    };
    const metadata = await discover('https://issuer.test', { fetch: mirrorFetch, alternateLocations: ['https://mirror.test'], fallbackToKnownLayout: false });
    expect(metadata.issuer).toBe('https://issuer.test');
    expect(metadata.token_endpoint).toBe('https://issuer.test/oidc/token');
  });

  it('rejects a non-URL issuer', async () => {
    await expect(discover('issuer.test')).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'configuration');
  });
});

describe('discovery cache', () => {
  it('de-duplicates in-flight requests, honours the TTL and serves stale on error', async () => {
    let now = 0;
    const issuer = await FakeIssuer.create();
    const cache = createDiscoveryCache({ ttlMs: 1000, now: () => now });
    await Promise.all([cache.get(issuer.issuer, { fetch: issuer.fetch }), cache.get(issuer.issuer, { fetch: issuer.fetch })]);
    expect(issuer.calls.discovery).toBe(1);
    await cache.get(issuer.issuer, { fetch: issuer.fetch });
    expect(issuer.calls.discovery).toBe(1);
    now = 2000;
    issuer.discoveryStatus = 503;
    const stale = await cache.get(issuer.issuer, { fetch: issuer.fetch });
    expect(stale.issuer).toBe(issuer.issuer);
    expect(issuer.calls.discovery).toBe(2);
  });

  it('retries discovery after a fallback answer instead of caching the fallback', async () => {
    const issuer = await FakeIssuer.create();
    const cache = createDiscoveryCache();
    issuer.discoveryStatus = 503;
    await cache.get(issuer.issuer, { fetch: issuer.fetch });
    issuer.discoveryStatus = null;
    await cache.get(issuer.issuer, { fetch: issuer.fetch });
    expect(issuer.calls.discovery).toBe(2);
    await cache.get(issuer.issuer, { fetch: issuer.fetch });
    expect(issuer.calls.discovery).toBe(2);
  });
});
