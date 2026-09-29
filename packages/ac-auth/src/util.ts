/**
 * Small runtime-neutral helpers (browser, Node 20+, edge). Nothing here
 * touches `Buffer` or `node:` modules so the same build runs everywhere.
 */

import { AuthError } from './errors';

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export function getCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle || typeof c.getRandomValues !== 'function') {
    throw new AuthError('configuration', 'Web Crypto (globalThis.crypto.subtle) is not available in this runtime');
  }
  return c;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] as number);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input: string): Uint8Array {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  getCrypto().getRandomValues(out);
  return out;
}

/** `byteLength` random bytes as a base64url string (32 bytes give 43 characters). */
export function randomUrlSafeString(byteLength = 32): string {
  return base64UrlEncode(randomBytes(byteLength));
}

export async function sha256(input: string | Uint8Array): Promise<Uint8Array> {
  const data = typeof input === 'string' ? utf8Encode(input) : input;
  const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  return new Uint8Array(await getCrypto().subtle.digest('SHA-256', buffer));
}

export function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

/** Constant-time comparison for short secrets such as `state`. */
export function safeEqual(a: string, b: string): boolean {
  const ab = utf8Encode(a);
  const bb = utf8Encode(b);
  let diff = ab.length ^ bb.length;
  const length = Math.max(ab.length, bb.length);
  for (let i = 0; i < length; i++) diff |= ((ab[i] ?? 0) ^ (bb[i] ?? 0));
  return diff === 0;
}

export type Clock = () => number;

export const systemClock: Clock = () => Date.now();

export function nowSeconds(clock: Clock = systemClock): number {
  return Math.floor(clock() / 1000);
}

/** Combine a caller signal with a timeout. Returns undefined when neither applies. */
export function timeoutSignal(signal: AbortSignal | undefined, timeoutMs: number | undefined): AbortSignal | undefined {
  const parts: AbortSignal[] = [];
  if (signal) parts.push(signal);
  if (timeoutMs && timeoutMs > 0 && typeof AbortSignal.timeout === 'function') parts.push(AbortSignal.timeout(timeoutMs));
  if (parts.length === 0) return undefined;
  if (parts.length === 1) return parts[0];
  if (typeof AbortSignal.any === 'function') return AbortSignal.any(parts);
  const controller = new AbortController();
  for (const part of parts) {
    if (part.aborted) {
      controller.abort(part.reason);
      break;
    }
    part.addEventListener('abort', () => controller.abort(part.reason), { once: true });
  }
  return controller.signal;
}

export function resolveFetch(fetchImpl: FetchLike | undefined): FetchLike {
  if (fetchImpl) return fetchImpl;
  if (typeof globalThis.fetch === 'function') return (input, init) => globalThis.fetch(input, init);
  throw new AuthError('configuration', 'No fetch implementation available; pass one in the options');
}

/**
 * Perform a request and turn "no HTTP answer" into a `network_error`.
 * Everything else (any status) is returned for the caller to interpret.
 */
export async function request(fetchImpl: FetchLike, url: string, init: RequestInit & { timeoutMs?: number }): Promise<Response> {
  const { timeoutMs, signal, ...rest } = init;
  const combined = timeoutSignal(signal ?? undefined, timeoutMs);
  try {
    return await fetchImpl(url, { ...rest, ...(combined ? { signal: combined } : {}) });
  } catch (cause) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    throw new AuthError('network_error', `Request to ${safeUrlForMessage(url)} failed: ${reason}`, { cause });
  }
}

/** Read a JSON body without throwing on a non-JSON answer (returns null). */
export async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** URL without query or fragment: never echo a code, ticket or token into an error message. */
export function safeUrlForMessage(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return '<url>';
  }
}

export function toScopeString(scope: string | readonly string[] | undefined, fallback: readonly string[]): string {
  const list = scope === undefined ? [...fallback] : typeof scope === 'string' ? scope.split(/\s+/) : [...scope];
  const cleaned = [...new Set(list.map((s) => s.trim()).filter(Boolean))];
  if (!cleaned.includes('openid')) cleaned.unshift('openid');
  return cleaned.join(' ');
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new AuthError('access_denied', 'aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason instanceof Error ? signal.reason : new AuthError('access_denied', 'aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
