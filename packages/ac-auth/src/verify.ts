/**
 * ID token verification (OpenID Connect Core §3.1.3.7) with the issuer's
 * published keys: signature (EdDSA or ES256, nothing else), `iss`, `aud`
 * (+ `azp` when several audiences), `exp`/`iat` with tolerance, and the
 * `nonce` of the pending sign-in.
 */

import { decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { AuthError } from './errors';
import { ID_TOKEN_ALGORITHMS } from './discovery';
import type { JwksResolver } from './jwks';
import type { IdTokenClaims } from './types';
import { safeEqual } from './util';

export interface VerifyIdTokenOptions {
  issuer: string;
  clientId: string;
  resolver: JwksResolver;
  /** The nonce sent in the authorization request. Required for tokens from the code flow; omit for refresh-issued tokens. */
  nonce?: string;
  /** Seconds of clock skew to tolerate. Default 60. */
  clockToleranceSeconds?: number;
  /** Reject tokens whose `auth_time` is older than this many seconds. */
  maxAuthAgeSeconds?: number;
  /** Epoch seconds "now" (tests). */
  currentTimeSeconds?: number;
}

export async function verifyIdToken(idToken: string, options: VerifyIdTokenOptions): Promise<IdTokenClaims> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(idToken);
  } catch (cause) {
    throw new AuthError('invalid_id_token', 'The ID token is not a compact JWS', { cause });
  }
  if (!header.alg || !(ID_TOKEN_ALGORITHMS as readonly string[]).includes(header.alg)) {
    throw new AuthError('invalid_id_token', `ID token algorithm ${header.alg ?? '(none)'} is not accepted`);
  }

  let payload: IdTokenClaims;
  try {
    const result = await jwtVerify<IdTokenClaims>(
      idToken,
      (protectedHeader) => options.resolver.getKey({ kid: protectedHeader.kid, alg: protectedHeader.alg }),
      {
        issuer: options.issuer,
        audience: options.clientId,
        algorithms: [...ID_TOKEN_ALGORITHMS],
        clockTolerance: options.clockToleranceSeconds ?? 60,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
        ...(options.currentTimeSeconds !== undefined ? { currentDate: new Date(options.currentTimeSeconds * 1000) } : {}),
      },
    );
    payload = result.payload;
  } catch (cause) {
    if (cause instanceof AuthError) throw cause;
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new AuthError('invalid_id_token', `ID token verification failed: ${reason}`, { cause });
  }

  if (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== options.clientId) {
    throw new AuthError('invalid_id_token', 'ID token has several audiences but azp is not this client');
  }
  if (options.nonce !== undefined) {
    if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, options.nonce)) {
      throw new AuthError('invalid_id_token', 'ID token nonce does not match the pending sign-in');
    }
  }
  if (options.maxAuthAgeSeconds !== undefined) {
    const now = options.currentTimeSeconds ?? Math.floor(Date.now() / 1000);
    if (typeof payload.auth_time !== 'number' || now - payload.auth_time > options.maxAuthAgeSeconds) {
      throw new AuthError('invalid_id_token', 'ID token auth_time is too old');
    }
  }
  return payload;
}

/** Claims without verification. Only for display of data you already verified once (never for trust decisions). */
export function decodeIdToken(idToken: string): IdTokenClaims {
  try {
    return decodeJwt<IdTokenClaims>(idToken);
  } catch (cause) {
    throw new AuthError('invalid_id_token', 'The ID token could not be decoded', { cause });
  }
}
