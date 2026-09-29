import { SignJWT, generateKeyPair, generateSecret } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import { AuthError } from '../src/errors';
import { createJwksResolver, isPublicSigningJwk } from '../src/jwks';
import { decodeIdToken, verifyIdToken } from '../src/verify';
import { FakeIssuer } from './helpers/fakeIssuer';

describe('JWKS resolver', () => {
  it('fetches once within the TTL and refetches after it', async () => {
    let now = 1_000_000;
    const issuer = await FakeIssuer.create({ now: () => now });
    const resolver = createJwksResolver({ jwksUri: `${issuer.issuer}/.well-known/jwks.json`, fetch: issuer.fetch, ttlMs: 300_000, now: () => now });
    await resolver.keys();
    await resolver.keys();
    expect(issuer.calls.jwks).toBe(1);
    expect(resolver.snapshot().source).toBe('network');
    now += 300_001;
    await resolver.keys();
    expect(issuer.calls.jwks).toBe(2);
  });

  it('serves stale keys when the refetch fails, with a warning', async () => {
    let now = 1_000_000;
    const issuer = await FakeIssuer.create({ now: () => now });
    const onWarning = vi.fn();
    const resolver = createJwksResolver({ jwksUri: `${issuer.issuer}/.well-known/jwks.json`, fetch: issuer.fetch, ttlMs: 1000, now: () => now, onWarning });
    const first = await resolver.keys();
    now += 5000;
    issuer.jwksStatus = 503;
    const stale = await resolver.keys();
    expect(stale.map((k) => k.kid)).toEqual(first.map((k) => k.kid));
    expect(resolver.snapshot().source).toBe('stale');
    expect(onWarning).toHaveBeenCalledWith(expect.stringMatching(/stale/), expect.anything());
    // and the stale keys still verify a token signed before the outage
    const token = await issuer.signIdToken({ sub: 'u', aud: 'c' });
    const claims = await verifyIdToken(token, { issuer: issuer.issuer, clientId: 'c', resolver, currentTimeSeconds: Math.floor(now / 1000) });
    expect(claims.sub).toBe('u');
  });

  it('falls back to the embedded keys when the network never answered', async () => {
    const issuer = await FakeIssuer.create();
    const embedded = issuer.publishedKeys;
    issuer.offline = true;
    const resolver = createJwksResolver({ jwksUri: `${issuer.issuer}/.well-known/jwks.json`, fetch: issuer.fetch, initialKeys: embedded });
    const keys = await resolver.keys();
    expect(keys).toHaveLength(2);
    expect(resolver.snapshot().source).toBe('initial');
    const token = await issuer.signIdToken({ sub: 'u', aud: 'c' });
    const claims = await verifyIdToken(token, { issuer: issuer.issuer, clientId: 'c', resolver });
    expect(claims.sub).toBe('u');
  });

  it('throws jwks_unavailable when nothing is cached, embedded or reachable', async () => {
    const issuer = await FakeIssuer.create();
    issuer.offline = true;
    const resolver = createJwksResolver({ jwksUri: `${issuer.issuer}/.well-known/jwks.json`, fetch: issuer.fetch });
    await expect(resolver.keys()).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'jwks_unavailable');
  });

  it('an unknown kid forces one refetch (rotation) and is rate-limited afterwards', async () => {
    let now = 1_000_000;
    const issuer = await FakeIssuer.create({ now: () => now });
    const resolver = createJwksResolver({ jwksUri: `${issuer.issuer}/.well-known/jwks.json`, fetch: issuer.fetch, ttlMs: 300_000, minRefetchIntervalMs: 30_000, now: () => now });
    await resolver.keys();
    expect(issuer.calls.jwks).toBe(1);

    now += 31_000;
    const { eddsaKid } = await issuer.rotateKeys();
    const token = await issuer.signIdToken({ sub: 'u', aud: 'c' });
    const claims = await verifyIdToken(token, { issuer: issuer.issuer, clientId: 'c', resolver, currentTimeSeconds: Math.floor(now / 1000) });
    expect(claims.sub).toBe('u');
    expect(issuer.calls.jwks).toBe(2);
    expect(resolver.snapshot().keys.map((k) => k.kid)).toContain(eddsaKid);

    // a token with a kid that is nowhere does not trigger another fetch within the interval
    await expect(resolver.getKey({ kid: 'ghost', alg: 'EdDSA' })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'invalid_id_token');
    expect(issuer.calls.jwks).toBe(2);
  });

  it('never accepts private key material or symmetric keys', async () => {
    expect(isPublicSigningJwk({ kty: 'OKP', crv: 'Ed25519', x: 'a', d: 'secret', kid: 'k' })).toBe(false);
    expect(isPublicSigningJwk({ kty: 'oct', k: 'secret', kid: 'k' })).toBe(false);
    expect(isPublicSigningJwk({ kty: 'OKP', crv: 'Ed25519', x: 'a', kid: 'k', use: 'enc' })).toBe(false);
    expect(isPublicSigningJwk({ kty: 'OKP', crv: 'Ed25519', x: 'a', kid: 'k' })).toBe(true);
    const resolver = createJwksResolver({ jwksUri: 'https://x/jwks', fetch: async () => new Response(JSON.stringify({ keys: [{ kty: 'oct', k: 'AAAA', kid: 'h', alg: 'HS256' }] }), { status: 200 }) });
    await expect(resolver.keys()).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'jwks_unavailable');
  });
});

describe('ID token verification', () => {
  async function setup() {
    const issuer = await FakeIssuer.create();
    const resolver = createJwksResolver({ jwksUri: `${issuer.issuer}/.well-known/jwks.json`, fetch: issuer.fetch });
    return { issuer, resolver };
  }

  it('verifies EdDSA and ES256 tokens with nonce, issuer and audience', async () => {
    const { issuer, resolver } = await setup();
    for (const alg of ['EdDSA', 'ES256'] as const) {
      const token = await issuer.signIdToken({ sub: 'user_1', aud: 'ac_1', nonce: 'n1', alg });
      const claims = await verifyIdToken(token, { issuer: issuer.issuer, clientId: 'ac_1', resolver, nonce: 'n1' });
      expect(claims.sub).toBe('user_1');
      expect(claims.wallet).toBe('did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001');
      expect(claims.org).toEqual({ id: 'org_1', slug: 'acme', name: 'Acme', role: 'OWNER' });
    }
  });

  it('rejects HS256 and none before touching the keys', async () => {
    const { issuer, resolver } = await setup();
    const secret = await generateSecret('HS256', { extractable: true });
    const hs = await new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setIssuer(issuer.issuer).setSubject('u').setAudience('ac_1').setIssuedAt().setExpirationTime('1h').sign(secret);
    await expect(verifyIdToken(hs, { issuer: issuer.issuer, clientId: 'ac_1', resolver })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && /HS256/.test(e.message));
    const unsigned = `${btoa(JSON.stringify({ alg: 'none' }))}.${btoa(JSON.stringify({ sub: 'u' }))}.`;
    await expect(verifyIdToken(unsigned, { issuer: issuer.issuer, clientId: 'ac_1', resolver })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'invalid_id_token');
    expect(issuer.calls.jwks).toBe(0);
  });

  it('rejects a wrong nonce, audience, issuer, an expired token and a foreign key', async () => {
    const { issuer, resolver } = await setup();
    const token = await issuer.signIdToken({ sub: 'u', aud: 'ac_1', nonce: 'n1' });
    const base = { issuer: issuer.issuer, clientId: 'ac_1', resolver };
    await expect(verifyIdToken(token, { ...base, nonce: 'other' })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && /nonce/.test(e.message));
    await expect(verifyIdToken(token, { ...base, clientId: 'ac_2' })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'invalid_id_token');
    await expect(verifyIdToken(token, { ...base, issuer: 'https://evil.test' })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'invalid_id_token');
    const expired = await issuer.signIdToken({ sub: 'u', aud: 'ac_1', expiresIn: -3600 });
    await expect(verifyIdToken(expired, base)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && /exp/.test(e.message));

    const foreign = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const forged = await new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', kid: issuer.publishedKeys[0]!.kid }).setIssuer(issuer.issuer).setSubject('u').setAudience('ac_1').setIssuedAt().setExpirationTime('1h').sign(foreign.privateKey);
    await expect(verifyIdToken(forged, base)).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'invalid_id_token');
  });

  it('requires azp when several audiences are present', async () => {
    const { issuer, resolver } = await setup();
    const multi = await issuer.signIdToken({ sub: 'u', aud: ['ac_1', 'other'] });
    await expect(verifyIdToken(multi, { issuer: issuer.issuer, clientId: 'ac_1', resolver })).rejects.toSatisfy((e: unknown) => e instanceof AuthError && /azp/.test(e.message));
    const withAzp = await issuer.signIdToken({ sub: 'u', aud: ['ac_1', 'other'], extra: { azp: 'ac_1' } });
    expect((await verifyIdToken(withAzp, { issuer: issuer.issuer, clientId: 'ac_1', resolver })).sub).toBe('u');
  });

  it('decodes without verifying', async () => {
    const { issuer } = await setup();
    const token = await issuer.signIdToken({ sub: 'u', aud: 'ac_1' });
    expect(decodeIdToken(token).sub).toBe('u');
    expect(() => decodeIdToken('nope')).toThrow(AuthError);
  });
});
