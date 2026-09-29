import { describe, expect, it } from 'vitest';
import { buildAuthorizationUrl, buildEndSessionUrl, isAuthorizationResponse, parseAuthorizationResponse } from '../src/authorize';
import { AuthError, OAuthError } from '../src/errors';
import { computeCodeChallenge, createPkcePair, generateCodeVerifier, generateNonce, generateState } from '../src/pkce';

describe('PKCE (RFC 7636)', () => {
  it('computes the S256 challenge of the RFC appendix B vector', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await computeCodeChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('generates 43-character unreserved verifiers that differ every time', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const v = generateCodeVerifier();
      expect(v).toMatch(/^[A-Za-z0-9\-_]{43}$/);
      seen.add(v);
    }
    expect(seen.size).toBe(50);
  });

  it('refuses verifiers outside the 43..128 unreserved range', async () => {
    await expect(computeCodeChallenge('short')).rejects.toThrow(RangeError);
    await expect(computeCodeChallenge(`${'a'.repeat(43)}+`)).rejects.toThrow(RangeError);
  });

  it('pairs verifier and challenge with method S256', async () => {
    const pair = await createPkcePair();
    expect(pair.codeChallengeMethod).toBe('S256');
    expect(pair.codeChallenge).toBe(await computeCodeChallenge(pair.codeVerifier));
  });

  it('state and nonce are unpredictable url-safe strings', () => {
    expect(generateState()).toMatch(/^[A-Za-z0-9\-_]{32}$/);
    expect(generateNonce()).toMatch(/^[A-Za-z0-9\-_]{32}$/);
    expect(generateState()).not.toBe(generateState());
  });
});

describe('authorization request', () => {
  const metadata = { authorization_endpoint: 'https://issuer.test/oidc/auth' };

  it('builds a code + PKCE S256 request with state and nonce and adds openid to the scope', () => {
    const url = new URL(buildAuthorizationUrl({
      metadata,
      clientId: 'ac_1',
      redirectUri: 'http://localhost:3000/callback',
      scope: ['profile', 'email', 'wallet'],
      state: 'st',
      nonce: 'nc',
      codeChallenge: 'ch',
      extraParams: { ui_locales: 'de', response_type: 'token' },
      loginHint: 'dev@example.com',
    }));
    const p = url.searchParams;
    expect(url.origin + url.pathname).toBe('https://issuer.test/oidc/auth');
    expect(p.get('response_type')).toBe('code');
    expect(p.get('client_id')).toBe('ac_1');
    expect(p.get('redirect_uri')).toBe('http://localhost:3000/callback');
    expect(p.get('scope')).toBe('openid profile email wallet');
    expect(p.get('state')).toBe('st');
    expect(p.get('nonce')).toBe('nc');
    expect(p.get('code_challenge')).toBe('ch');
    expect(p.get('code_challenge_method')).toBe('S256');
    expect(p.get('ui_locales')).toBe('de');
    expect(p.get('login_hint')).toBe('dev@example.com');
  });

  it('defaults the scope to openid profile email', () => {
    const url = new URL(buildAuthorizationUrl({ metadata, clientId: 'c', redirectUri: 'https://a/cb', state: 's', nonce: 'n', codeChallenge: 'x' }));
    expect(url.searchParams.get('scope')).toBe('openid profile email');
  });
});

describe('authorization response', () => {
  it('accepts a matching state and returns the code and iss', () => {
    const r = parseAuthorizationResponse('http://localhost:3000/callback?code=abc&state=st&iss=https%3A%2F%2Fissuer.test', { state: 'st', issuer: 'https://issuer.test' });
    expect(r).toEqual({ code: 'abc', state: 'st', iss: 'https://issuer.test' });
    expect(isAuthorizationResponse('http://localhost:3000/callback?code=abc&state=st')).toBe(true);
    expect(isAuthorizationResponse('http://localhost:3000/')).toBe(false);
  });

  it('reads fragment responses too', () => {
    const r = parseAuthorizationResponse('http://localhost:3000/callback#code=abc&state=st', { state: 'st' });
    expect(r.code).toBe('abc');
  });

  it('refuses a state mismatch before looking at anything else', () => {
    expect(() => parseAuthorizationResponse('http://localhost:3000/callback?error=access_denied&state=other', { state: 'st' }))
      .toThrow(expect.objectContaining({ code: 'invalid_state' }));
  });

  it('turns an error response into an OAuthError', () => {
    let caught: unknown;
    try {
      parseAuthorizationResponse('http://localhost:3000/callback?error=access_denied&error_description=nope&state=st', { state: 'st' });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(OAuthError);
    expect((caught as OAuthError).error).toBe('access_denied');
    expect((caught as OAuthError).errorDescription).toBe('nope');
  });

  it('refuses a response from another issuer (mix-up defence) and one without a code', () => {
    expect(() => parseAuthorizationResponse('http://a/cb?code=x&state=st&iss=https://evil.test', { state: 'st', issuer: 'https://issuer.test' }))
      .toThrow(expect.objectContaining({ code: 'invalid_response' }));
    let caught: unknown;
    try {
      parseAuthorizationResponse('http://a/cb?state=st', { state: 'st' });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AuthError);
    expect((caught as AuthError).code).toBe('invalid_callback');
  });
});

describe('end session URL', () => {
  it('carries the id_token_hint, client_id and post_logout_redirect_uri', () => {
    const url = new URL(buildEndSessionUrl({
      metadata: { end_session_endpoint: 'https://issuer.test/oidc/session/end' },
      idTokenHint: 'id.tok.en',
      clientId: 'ac_1',
      postLogoutRedirectUri: 'http://localhost:3000/',
      state: 'bye',
    })!);
    expect(url.searchParams.get('id_token_hint')).toBe('id.tok.en');
    expect(url.searchParams.get('client_id')).toBe('ac_1');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('http://localhost:3000/');
    expect(url.searchParams.get('state')).toBe('bye');
    expect(buildEndSessionUrl({ metadata: {} })).toBeNull();
  });
});
