import { Auth, type AuthConfig } from '@auth/core';
import { customFetch } from '@auth/core';
import { afterEach, describe, expect, it } from 'vitest';
import { FakeIssuer } from '../../ac-auth/test/helpers/fakeIssuer';
import AlternateClouds, { ALTERNATE_CLOUDS_PROVIDER_ID, BRAND_COLOR } from '../src/index';

const ENV_KEYS = ['AUTH_ALTERNATE_CLOUDS_ID', 'AUTH_ALTERNATE_CLOUDS_SECRET', 'AUTH_ALTERNATE_CLOUDS_ISSUER'] as const;

afterEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
});

describe('the provider object', () => {
  it('is an OIDC provider with PKCE, state and nonce, the production issuer and the default scope', () => {
    const provider = AlternateClouds({ clientId: 'ac_1' });
    expect(provider.id).toBe(ALTERNATE_CLOUDS_PROVIDER_ID);
    expect(provider.name).toBe('Alternate Clouds');
    expect(provider.type).toBe('oidc');
    expect(provider.issuer).toBe('https://auth.alternatefutures.ai');
    expect(provider.checks).toEqual(['pkce', 'state', 'nonce']);
    expect(provider.idToken).toBe(true);
    expect((provider.authorization as { params: Record<string, string> }).params.scope).toBe('openid profile email');
    expect(provider.client?.token_endpoint_auth_method).toBe('none');
    expect(provider.style?.brandColor).toBe(BRAND_COLOR);
    expect(provider.options?.clientId).toBe('ac_1');
  });

  it('switches to client_secret_basic when a secret is given, and reads the environment', () => {
    expect(AlternateClouds({ clientId: 'ac_1', clientSecret: 'acs_x' }).client?.token_endpoint_auth_method).toBe('client_secret_basic');
    process.env.AUTH_ALTERNATE_CLOUDS_ID = 'ac_env';
    process.env.AUTH_ALTERNATE_CLOUDS_SECRET = 'acs_env';
    process.env.AUTH_ALTERNATE_CLOUDS_ISSUER = 'https://auth.staging.alternatefutures.ai/';
    const provider = AlternateClouds();
    expect(provider.issuer).toBe('https://auth.staging.alternatefutures.ai');
    expect(provider.client?.token_endpoint_auth_method).toBe('client_secret_basic');
    expect(provider.options?.clientId).toBe('ac_env');
    expect(provider.options?.clientSecret).toBe('acs_env');
  });

  it('honours scope and issuer options', () => {
    const provider = AlternateClouds({ clientId: 'ac_1', issuer: 'http://localhost:1621', scope: 'openid email wallet org' });
    expect(provider.issuer).toBe('http://localhost:1621');
    expect((provider.authorization as { params: Record<string, string> }).params.scope).toBe('openid email wallet org');
  });

  it('keys the Auth.js user on the wallet DID when present, else on the subject', () => {
    const provider = AlternateClouds({ clientId: 'ac_1' });
    const profile = provider.profile!;
    const withWallet = profile({ iss: 'i', sub: 'user_1', aud: 'ac_1', exp: 1, iat: 1, wallet: 'did:pkh:eip155:1:0xabc', name: 'Dev', email: 'd@x', picture: 'p' }, {} as never);
    expect(withWallet).toEqual({ id: 'did:pkh:eip155:1:0xabc', name: 'Dev', email: 'd@x', image: 'p' });
    const bare = profile({ iss: 'i', sub: 'user_2', aud: 'ac_1', exp: 1, iat: 1, email: 'e@x' }, {} as never);
    expect(bare).toEqual({ id: 'user_2', name: 'e@x', email: 'e@x', image: null });
  });
});

describe('inside Auth.js core (@auth/core) against a fake issuer', () => {
  async function setup() {
    const issuer = await FakeIssuer.create();
    const provider = AlternateClouds({ clientId: 'ac_1', issuer: issuer.issuer, scope: 'openid profile email wallet' });
    // Route Auth.js's outbound requests (discovery, token, jwks) to the fake issuer.
    (provider as unknown as Record<symbol, unknown>)[customFetch] = issuer.fetch;
    const config: AuthConfig = {
      secret: 'a-test-secret-at-least-32-characters-long',
      trustHost: true,
      basePath: '/api/auth',
      providers: [provider],
      callbacks: {
        jwt({ token, profile }) {
          if (profile) token.wallet = (profile as { wallet?: string }).wallet;
          return token;
        },
        session({ session, token }) {
          (session as { wallet?: string }).wallet = token.wallet as string | undefined;
          return session;
        },
      },
    };
    return { issuer, config };
  }

  function cookieJar() {
    const jar = new Map<string, string>();
    return {
      absorb(res: Response) {
        for (const raw of res.headers.getSetCookie()) {
          const [pair = '', ...attrs] = raw.split(';');
          const eq = pair.indexOf('=');
          const name = pair.slice(0, eq);
          const value = pair.slice(eq + 1);
          if (attrs.some((a) => /max-age=0/i.test(a)) || !value) jar.delete(name);
          else jar.set(name, value);
        }
      },
      header: () => [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
      has: (name: string) => jar.has(name),
    };
  }

  it('signs in end to end: csrf, signin, callback with pkce + state + nonce, then a session', async () => {
    const { issuer, config } = await setup();
    const origin = 'http://localhost:3001';
    const jar = cookieJar();

    const csrfRes = await Auth(new Request(`${origin}/api/auth/csrf`), config);
    jar.absorb(csrfRes);
    const { csrfToken } = (await csrfRes.json()) as { csrfToken: string };

    const signin = await Auth(
      new Request(`${origin}/api/auth/signin/${ALTERNATE_CLOUDS_PROVIDER_ID}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
        body: new URLSearchParams({ csrfToken, callbackUrl: `${origin}/` }).toString(),
      }),
      config,
    );
    jar.absorb(signin);
    expect(signin.status).toBe(302);
    const authorizeUrl = new URL(signin.headers.get('location')!);
    expect(authorizeUrl.origin + authorizeUrl.pathname).toBe(`${issuer.issuer}/oidc/auth`);
    expect(authorizeUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorizeUrl.searchParams.get('nonce')).toBeTruthy();
    expect(authorizeUrl.searchParams.get('state')).toBeTruthy();
    expect(authorizeUrl.searchParams.get('redirect_uri')).toBe(`${origin}/api/auth/callback/${ALTERNATE_CLOUDS_PROVIDER_ID}`);
    expect(authorizeUrl.searchParams.get('scope')).toBe('openid profile email wallet');

    const callbackUrl = await issuer.authorize(authorizeUrl.toString());
    const callback = await Auth(new Request(callbackUrl, { headers: { cookie: jar.header() } }), config);
    jar.absorb(callback);
    expect(callback.status, await callback.clone().text()).toBe(302);
    expect(callback.headers.get('location')).toBe(`${origin}/`);
    expect(jar.has('authjs.session-token')).toBe(true);

    const session = await Auth(new Request(`${origin}/api/auth/session`, { headers: { cookie: jar.header() } }), config);
    const body = (await session.json()) as { user?: { name?: string; email?: string; image?: string }; wallet?: string };
    expect(body.user?.email).toBe('dev@example.com');
    expect(body.user?.name).toBe('Dev One');
    expect(body.wallet).toBe('did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001');
    // the public client never sent a secret: the fake issuer saw client_id in the body only
    expect(issuer.lastRequest.headers.authorization).toBeUndefined();
  });
});
