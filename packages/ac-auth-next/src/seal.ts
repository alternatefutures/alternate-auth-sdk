/**
 * Sealed cookies: the session and the pending sign-in travel in the
 * browser as compact JWE (dir + A256GCM) under a key derived from
 * `AUTH_SECRET` with HKDF, so the browser can neither read nor forge them.
 * Works in Node, edge and browsers alike (Web Crypto only).
 */

import { EncryptJWT, jwtDecrypt, type JWTPayload } from 'jose';

const encoder = new TextEncoder();
const keyCache = new Map<string, Promise<Uint8Array>>();

async function deriveKey(secret: string, info: string): Promise<Uint8Array> {
  const cacheKey = `${info}\u0000${secret}`;
  let pending = keyCache.get(cacheKey);
  if (!pending) {
    pending = (async () => {
      const material = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: encoder.encode('@alternatefutures/ac-auth-next'), info: encoder.encode(info) },
        material,
        256,
      );
      return new Uint8Array(bits);
    })();
    keyCache.set(cacheKey, pending);
    if (keyCache.size > 8) keyCache.delete(keyCache.keys().next().value as string);
  }
  return pending;
}

export interface SealOptions {
  secret: string;
  /** Distinguishes cookie kinds so a transaction can never be replayed as a session. */
  purpose: 'session' | 'transaction';
  /** Epoch seconds. */
  expiresAt: number;
  now?: () => number;
}

export async function seal(payload: Record<string, unknown>, options: SealOptions): Promise<string> {
  const key = await deriveKey(options.secret, options.purpose);
  const nowSeconds = Math.floor((options.now?.() ?? Date.now()) / 1000);
  return new EncryptJWT(payload as JWTPayload)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: options.purpose })
    .setIssuedAt(nowSeconds)
    .setExpirationTime(options.expiresAt)
    .encrypt(key);
}

/** Null for anything that does not decrypt, is of another purpose, or is expired. */
export async function unseal<T extends Record<string, unknown>>(token: string | undefined | null, options: Omit<SealOptions, 'expiresAt'>): Promise<T | null> {
  if (!token) return null;
  try {
    const key = await deriveKey(options.secret, options.purpose);
    const { payload, protectedHeader } = await jwtDecrypt(token, key, {
      contentEncryptionAlgorithms: ['A256GCM'],
      keyManagementAlgorithms: ['dir'],
      clockTolerance: 5,
      ...(options.now ? { currentDate: new Date(options.now()) } : {}),
    });
    if (protectedHeader.cty !== options.purpose) return null;
    return payload as unknown as T;
  } catch {
    return null;
  }
}
