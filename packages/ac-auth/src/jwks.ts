/**
 * JWKS cache that keeps verifying through an outage.
 *
 * Order of preference for a key: a fresh network copy (refetched after the
 * TTL, the issuer serves the document with `max-age=300`), then the last
 * network copy however old (stale-on-error), then keys given at construction
 * (`initialKeys`, typically the snapshot embedded at build time). An unknown
 * `kid` forces one refetch, rate-limited so a stream of bad tokens cannot
 * hammer the issuer. Private key material is never accepted.
 */

import { importJWK, type CryptoKey, type JWK } from 'jose';
import { AuthError, oauthErrorFromBody } from './errors';
import { ID_TOKEN_ALGORITHMS } from './discovery';
import { readJson, request, resolveFetch, type FetchLike } from './util';

export type JwksSource = 'network' | 'stale' | 'initial' | 'none';

export interface JwksResolverOptions {
  jwksUri: string;
  fetch?: FetchLike;
  /** How long a fetched document is trusted without a refetch. Default 5 min. */
  ttlMs?: number;
  /** Minimum time between forced refetches for unknown kids. Default 30 s. */
  minRefetchIntervalMs?: number;
  /** Keys to use before the first fetch and when the network never answers (embedded snapshot). */
  initialKeys?: readonly JWK[];
  /** Per request. Default 10 s. */
  timeoutMs?: number;
  now?: () => number;
  onWarning?: (message: string, cause?: unknown) => void;
}

export interface JwksSnapshot {
  keys: JWK[];
  source: JwksSource;
  fetchedAt: number | null;
}

export interface JwksResolver {
  /** Resolve the key a token header names. Throws `invalid_id_token` when no published key matches. */
  getKey(header: { kid?: string; alg?: string }): Promise<CryptoKey>;
  /** The keys currently trusted, fetching if nothing is cached. */
  keys(): Promise<JWK[]>;
  /** Force a refetch; on failure keeps what is cached and rethrows. */
  refresh(): Promise<JWK[]>;
  snapshot(): JwksSnapshot;
}

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;

export function isPublicSigningJwk(jwk: unknown): jwk is JWK {
  if (!jwk || typeof jwk !== 'object') return false;
  const key = jwk as Record<string, unknown>;
  if (typeof key.kty !== 'string') return false;
  for (const member of PRIVATE_MEMBERS) if (member in key) return false;
  if (key.use !== undefined && key.use !== 'sig') return false;
  return true;
}

export function createJwksResolver(options: JwksResolverOptions): JwksResolver {
  const ttlMs = options.ttlMs ?? 5 * 60 * 1000;
  const minRefetchIntervalMs = options.minRefetchIntervalMs ?? 30_000;
  const now = options.now ?? (() => Date.now());
  const fetchImpl = resolveFetch(options.fetch);
  const initial = (options.initialKeys ?? []).filter(isPublicSigningJwk).map((k) => ({ ...k }));

  let keys: JWK[] = initial;
  let source: JwksSource = initial.length ? 'initial' : 'none';
  let fetchedAt: number | null = null;
  let lastAttemptAt: number | null = null;
  let inflight: Promise<JWK[]> | null = null;
  const imported = new Map<string, Promise<CryptoKey>>();

  async function fetchOnce(): Promise<JWK[]> {
    lastAttemptAt = now();
    const response = await request(fetchImpl, options.jwksUri, {
      method: 'GET',
      headers: { accept: 'application/json' },
      timeoutMs: options.timeoutMs ?? 10_000,
    });
    const body = await readJson(response);
    if (!response.ok) {
      const oauth = oauthErrorFromBody(body, response.status);
      throw oauth ?? new AuthError('invalid_response', `JWKS answered HTTP ${response.status}`);
    }
    const list = (body as { keys?: unknown } | null)?.keys;
    if (!Array.isArray(list)) throw new AuthError('invalid_response', 'The JWKS document has no keys array');
    const publicKeys = list.filter(isPublicSigningJwk);
    if (publicKeys.length === 0) throw new AuthError('invalid_response', 'The JWKS document has no public signing keys');
    keys = publicKeys;
    source = 'network';
    fetchedAt = now();
    imported.clear();
    return keys;
  }

  function refetch(): Promise<JWK[]> {
    if (inflight) return inflight;
    inflight = fetchOnce().finally(() => {
      inflight = null;
    });
    return inflight;
  }

  async function resolveKeys(force: boolean): Promise<JWK[]> {
    const fresh = fetchedAt !== null && now() - fetchedAt < ttlMs;
    if (fresh && !force) return keys;
    try {
      return await refetch();
    } catch (error) {
      if (keys.length > 0) {
        if (source === 'network') source = 'stale';
        options.onWarning?.(`JWKS refresh failed; using ${source} keys`, error);
        return keys;
      }
      throw new AuthError('jwks_unavailable', 'The JWKS could not be fetched and no keys are cached or embedded', { cause: error });
    }
  }

  function findKey(list: JWK[], header: { kid?: string; alg?: string }): JWK | undefined {
    const candidates = list.filter((k) => !header.alg || !k.alg || k.alg === header.alg);
    if (header.kid) return candidates.find((k) => k.kid === header.kid);
    return candidates.length === 1 ? candidates[0] : undefined;
  }

  function importKey(jwk: JWK, alg: string): Promise<CryptoKey> {
    const cacheKey = `${jwk.kid ?? ''}:${alg}`;
    let pending = imported.get(cacheKey);
    if (!pending) {
      pending = importJWK(jwk, alg).then((key) => {
        if (key instanceof Uint8Array) throw new AuthError('invalid_id_token', 'Symmetric keys are never accepted');
        return key as CryptoKey;
      });
      imported.set(cacheKey, pending);
    }
    return pending;
  }

  return {
    async getKey(header) {
      const alg = header.alg ?? '';
      if (!(ID_TOKEN_ALGORITHMS as readonly string[]).includes(alg)) {
        throw new AuthError('invalid_id_token', `Unsupported token algorithm ${alg || '(none)'}`);
      }
      let list = await resolveKeys(false);
      let jwk = findKey(list, header);
      if (!jwk) {
        // Unknown kid: maybe a rotation we have not seen. One forced refetch,
        // rate-limited, then the keys we started with as a last resort.
        const mayRefetch = lastAttemptAt === null || now() - lastAttemptAt >= minRefetchIntervalMs;
        if (mayRefetch) {
          list = await resolveKeys(true);
          jwk = findKey(list, header);
        }
        if (!jwk && initial.length) jwk = findKey(initial, header);
      }
      if (!jwk) throw new AuthError('invalid_id_token', `No published key matches kid ${header.kid ?? '(none)'}`);
      return importKey(jwk, alg);
    },
    keys: () => resolveKeys(false),
    refresh: () => resolveKeys(true),
    snapshot: () => ({ keys: keys.map((k) => ({ ...k })), source, fetchedAt }),
  };
}
