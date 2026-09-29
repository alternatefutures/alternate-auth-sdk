import { describe, expect, it } from 'vitest';
import { AuthError, OAuthError, isSignedOutError, isTransientError } from '../src/errors';
import { clientAuthenticationParts, exchangeAuthorizationCode, fetchUserInfo, refreshTokenGrant, revokeToken, tokenSetFromResponse } from '../src/token';
import { FakeIssuer } from './helpers/fakeIssuer';

describe('client authentication', () => {
  it('public clients send client_id in the body only', () => {
    expect(clientAuthenticationParts('ac_1', undefined)).toEqual({ headers: {}, body: { client_id: 'ac_1' } });
    expect(clientAuthenticationParts('ac_1', { method: 'none' })).toEqual({ headers: {}, body: { client_id: 'ac_1' } });
  });

  it('client_secret_basic form-encodes id and secret before base64 (RFC 6749 §2.3.1)', () => {
    const parts = clientAuthenticationParts('ac 1', { method: 'client_secret_basic', clientSecret: 'p+s=/w' });
    expect(parts.body).toEqual({ client_id: 'ac 1' });
    const decoded = atob(parts.headers.authorization!.replace(/^Basic /, ''));
    expect(decoded).toBe('ac+1:p%2Bs%3D%2Fw');
  });

  it('client_secret_post puts the secret in the body', () => {
    expect(clientAuthenticationParts('ac_1', { method: 'client_secret_post', clientSecret: 's' })).toEqual({
      headers: {},
      body: { client_id: 'ac_1', client_secret: 's' },
    });
  });
});

describe('token endpoint', () => {
  it('exchanges a code with PKCE and returns the token response', async () => {
    const issuer = await FakeIssuer.create();
    const { createPkcePair } = await import('../src/pkce');
    const pkce = await createPkcePair();
    const callback = await issuer.authorize(
      `${issuer.issuer}/oidc/auth?client_id=ac_1&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&response_type=code&scope=openid%20email&state=st&nonce=nc&code_challenge=${pkce.codeChallenge}&code_challenge_method=S256`,
    );
    const code = new URL(callback).searchParams.get('code')!;
    const response = await exchangeAuthorizationCode(
      { tokenEndpoint: `${issuer.issuer}/oidc/token`, clientId: 'ac_1', fetch: issuer.fetch },
      { code, redirectUri: 'http://localhost:3000/cb', codeVerifier: pkce.codeVerifier },
    );
    expect(response.token_type).toBe('Bearer');
    expect(response.id_token).toBeTruthy();
    expect(response.refresh_token).toBeTruthy();
    const sent = new URLSearchParams(issuer.lastRequest.body);
    expect(sent.get('grant_type')).toBe('authorization_code');
    expect(sent.get('code_verifier')).toBe(pkce.codeVerifier);
    expect(sent.get('redirect_uri')).toBe('http://localhost:3000/cb');
    expect(sent.get('client_id')).toBe('ac_1');
    expect(issuer.lastRequest.headers['content-type']).toBe('application/x-www-form-urlencoded');
  });

  it('a wrong verifier is an invalid_grant OAuthError with the HTTP status', async () => {
    const issuer = await FakeIssuer.create();
    const { createPkcePair } = await import('../src/pkce');
    const pkce = await createPkcePair();
    const callback = await issuer.authorize(
      `${issuer.issuer}/oidc/auth?client_id=ac_1&redirect_uri=http%3A%2F%2Fl%2Fcb&response_type=code&scope=openid&state=st&nonce=nc&code_challenge=${pkce.codeChallenge}&code_challenge_method=S256`,
    );
    const code = new URL(callback).searchParams.get('code')!;
    let caught: unknown;
    try {
      await exchangeAuthorizationCode(
        { tokenEndpoint: `${issuer.issuer}/oidc/token`, clientId: 'ac_1', fetch: issuer.fetch },
        { code, redirectUri: 'http://l/cb', codeVerifier: 'x'.repeat(43) },
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(OAuthError);
    expect((caught as OAuthError).error).toBe('invalid_grant');
    expect((caught as OAuthError).status).toBe(400);
    expect(isSignedOutError(caught)).toBe(true);
    expect(isTransientError(caught)).toBe(false);
  });

  it('a gateway page (HTML 502) is a transient invalid_response, not an OAuth error', async () => {
    const issuer = await FakeIssuer.create();
    issuer.tokenStatus = 502;
    issuer.tokenHtml = true;
    let caught: unknown;
    try {
      await refreshTokenGrant({ tokenEndpoint: `${issuer.issuer}/oidc/token`, clientId: 'ac_1', fetch: issuer.fetch }, { refreshToken: 'rt' });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AuthError);
    expect((caught as AuthError).code).toBe('invalid_response');
    expect(isTransientError(caught)).toBe(true);
    expect(isSignedOutError(caught)).toBe(false);
  });

  it('a 503 OAuth body is transient; no answer at all is a network_error', async () => {
    const issuer = await FakeIssuer.create();
    issuer.tokenStatus = 503;
    await expect(refreshTokenGrant({ tokenEndpoint: `${issuer.issuer}/oidc/token`, clientId: 'ac_1', fetch: issuer.fetch }, { refreshToken: 'rt' }))
      .rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.status === 503 && isTransientError(e));
    issuer.tokenStatus = null;
    issuer.offline = true;
    await expect(refreshTokenGrant({ tokenEndpoint: `${issuer.issuer}/oidc/token`, clientId: 'ac_1', fetch: issuer.fetch }, { refreshToken: 'rt' }))
      .rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'network_error' && isTransientError(e));
  });

  it('revocation posts the token with its hint and the client id', async () => {
    const issuer = await FakeIssuer.create();
    await revokeToken({ revocationEndpoint: `${issuer.issuer}/oidc/token/revocation`, clientId: 'ac_1', token: 'rt_x', tokenTypeHint: 'refresh_token', fetch: issuer.fetch });
    const sent = new URLSearchParams(issuer.lastRequest.body);
    expect(sent.get('token')).toBe('rt_x');
    expect(sent.get('token_type_hint')).toBe('refresh_token');
    expect(sent.get('client_id')).toBe('ac_1');
    expect(issuer.calls.revocation).toBe(1);
  });

  it('userinfo answers the claims for a live access token and an OAuth error for a dead one', async () => {
    const issuer = await FakeIssuer.create();
    const { createPkcePair } = await import('../src/pkce');
    const pkce = await createPkcePair();
    const callback = await issuer.authorize(
      `${issuer.issuer}/oidc/auth?client_id=ac_1&redirect_uri=http%3A%2F%2Fl%2Fcb&response_type=code&scope=openid&state=st&nonce=nc&code_challenge=${pkce.codeChallenge}&code_challenge_method=S256`,
    );
    const code = new URL(callback).searchParams.get('code')!;
    const tokens = await exchangeAuthorizationCode(
      { tokenEndpoint: `${issuer.issuer}/oidc/token`, clientId: 'ac_1', fetch: issuer.fetch },
      { code, redirectUri: 'http://l/cb', codeVerifier: pkce.codeVerifier },
    );
    const me = await fetchUserInfo({ userinfoEndpoint: `${issuer.issuer}/oidc/me`, accessToken: tokens.access_token, fetch: issuer.fetch });
    expect(me.sub).toBe('user_1');
    expect(me.email).toBe('dev@example.com');
    await expect(fetchUserInfo({ userinfoEndpoint: `${issuer.issuer}/oidc/me`, accessToken: 'nope', fetch: issuer.fetch }))
      .rejects.toSatisfy((e: unknown) => e instanceof OAuthError && e.error === 'invalid_token' && e.status === 401);
  });

  it('normalizes a token response into absolute times', () => {
    const set = tokenSetFromResponse({ access_token: 'a', token_type: 'Bearer', expires_in: 60, refresh_token: 'r', id_token: 'i', scope: 'openid' }, { now: 1_000_000 });
    expect(set).toMatchObject({ accessToken: 'a', refreshToken: 'r', idToken: 'i', scope: 'openid', issuedAt: 1_000_000, expiresAt: 1_060_000, claims: null });
    const noExpiry = tokenSetFromResponse({ access_token: 'a', token_type: 'Bearer' }, { now: 0, defaultExpiresInSeconds: 10 });
    expect(noExpiry.expiresAt).toBe(10_000);
    expect(noExpiry.refreshToken).toBeNull();
  });
});
