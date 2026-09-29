/**
 * PKCE (RFC 7636), S256 only: the issuer refuses `plain` and refuses requests
 * without a challenge (plan §5 "Protocol").
 */

import { base64UrlEncode, randomUrlSafeString, sha256 } from './util';

/** 32 random bytes as base64url: 43 characters, inside the 43..128 range the RFC requires. */
export function generateCodeVerifier(): string {
  return randomUrlSafeString(32);
}

/** `BASE64URL(SHA256(ASCII(verifier)))`. */
export async function computeCodeChallenge(codeVerifier: string): Promise<string> {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) {
    throw new RangeError('code_verifier must be 43 to 128 unreserved characters');
  }
  return base64UrlEncode(await sha256(codeVerifier));
}

export function generateState(): string {
  return randomUrlSafeString(24);
}

export function generateNonce(): string {
  return randomUrlSafeString(24);
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

export async function createPkcePair(): Promise<PkcePair> {
  const codeVerifier = generateCodeVerifier();
  return { codeVerifier, codeChallenge: await computeCodeChallenge(codeVerifier), codeChallengeMethod: 'S256' };
}
