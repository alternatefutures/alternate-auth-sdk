/**
 * Issuer discovery.
 *
 * The issuer publishes `/.well-known/openid-configuration`. The SDK also
 * knows the layout the issuer uses (every endpoint under `/oidc`, the JWKS at
 * `/.well-known/jwks.json`, the issuer's published route layout),
 * so when discovery cannot be fetched it can fall back to that layout instead
 * of failing the sign-in: the issuer identifier never changes, transports may
 * (plan §3 "Issuer identifier", §4 M4).
 */

import { AuthError, oauthErrorFromBody } from './errors';
import type { IssuerMetadata } from './types';
import { readJson, request, resolveFetch, stripTrailingSlash, type FetchLike } from './util';

/** Paths of the issuer, relative to the issuer identifier. */
export const ISSUER_PATHS = {
  discovery: '/.well-known/openid-configuration',
  jwks: '/.well-known/jwks.json',
  authorization: '/oidc/auth',
  token: '/oidc/token',
  userinfo: '/oidc/me',
  revocation: '/oidc/token/revocation',
  introspection: '/oidc/token/introspection',
  endSession: '/oidc/session/end',
  deviceAuthorization: '/oidc/device/auth',
} as const;

/** The production issuer identifier. */
export const DEFAULT_ISSUER = 'https://auth.alternatefutures.ai';

/** Scopes the issuer understands. */
export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'org', 'wallet', 'offline_access'] as const;

/** What a sign-in asks for when the app does not say. */
export const DEFAULT_SCOPES = ['openid', 'profile', 'email'] as const;

/** ID token algorithms the issuer signs with; nothing else is ever accepted. */
export const ID_TOKEN_ALGORITHMS = ['EdDSA', 'ES256'] as const;

/** Metadata for an issuer that follows the known layout, without a network round trip. */
export function knownIssuerMetadata(issuer: string): IssuerMetadata {
  const base = stripTrailingSlash(issuer);
  return {
    issuer: base,
    authorization_endpoint: `${base}${ISSUER_PATHS.authorization}`,
    token_endpoint: `${base}${ISSUER_PATHS.token}`,
    jwks_uri: `${base}${ISSUER_PATHS.jwks}`,
    userinfo_endpoint: `${base}${ISSUER_PATHS.userinfo}`,
    end_session_endpoint: `${base}${ISSUER_PATHS.endSession}`,
    revocation_endpoint: `${base}${ISSUER_PATHS.revocation}`,
    introspection_endpoint: `${base}${ISSUER_PATHS.introspection}`,
    device_authorization_endpoint: `${base}${ISSUER_PATHS.deviceAuthorization}`,
    scopes_supported: [...SUPPORTED_SCOPES],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    code_challenge_methods_supported: ['S256'],
    id_token_signing_alg_values_supported: [...ID_TOKEN_ALGORITHMS],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    subject_types_supported: ['public', 'pairwise'],
    authorization_response_iss_parameter_supported: true,
  };
}

export interface DiscoverOptions {
  fetch?: FetchLike;
  signal?: AbortSignal;
  /** Per request. Default 10 s. */
  timeoutMs?: number;
  /**
   * When the document cannot be fetched (network, gateway page, 5xx), answer
   * with {@link knownIssuerMetadata} instead of throwing. Default true. A
   * document that IS fetched but names another issuer always throws.
   */
  fallbackToKnownLayout?: boolean;
  /**
   * Other base URLs that mirror the discovery document (a second domain, an
   * onion service, an IPFS gateway; plan §4 M4). Tried in order after the
   * issuer itself. The mirrored document must still name the canonical issuer.
   */
  alternateLocations?: string[];
  onWarning?: (message: string, cause?: unknown) => void;
}

export interface DiscoveryResult {
  metadata: IssuerMetadata;
  /** False when the known layout was used because no location answered. */
  fromNetwork: boolean;
}

function assertMetadata(doc: unknown, issuer: string): IssuerMetadata {
  if (!doc || typeof doc !== 'object') {
    throw new AuthError('discovery_failed', 'The discovery document is not a JSON object');
  }
  const metadata = doc as Record<string, unknown>;
  if (metadata.issuer !== issuer) {
    throw new AuthError('discovery_failed', `The discovery document names issuer ${String(metadata.issuer)} but ${issuer} was expected`);
  }
  for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    if (typeof metadata[field] !== 'string' || !(metadata[field] as string)) {
      throw new AuthError('discovery_failed', `The discovery document has no ${field}`);
    }
  }
  const methods = metadata.code_challenge_methods_supported;
  if (Array.isArray(methods) && !methods.includes('S256')) {
    throw new AuthError('unsupported', 'The issuer does not support PKCE S256');
  }
  return metadata as IssuerMetadata;
}

/** Errors that no fallback may hide: the document was fetched and is wrong for this issuer. */
function isDefinitive(error: unknown): boolean {
  return error instanceof AuthError
    && (error.code === 'unsupported' || (error.code === 'discovery_failed' && /names issuer|has no /.test(error.message)));
}

async function fetchDocument(base: string, issuer: string, options: DiscoverOptions): Promise<IssuerMetadata> {
  const fetchImpl = resolveFetch(options.fetch);
  const url = `${stripTrailingSlash(base)}${ISSUER_PATHS.discovery}`;
  const response = await request(fetchImpl, url, {
    method: 'GET',
    headers: { accept: 'application/json' },
    signal: options.signal,
    timeoutMs: options.timeoutMs ?? 10_000,
  });
  const body = await readJson(response);
  if (!response.ok) {
    const oauth = oauthErrorFromBody(body, response.status);
    throw oauth ?? new AuthError('invalid_response', `Discovery at ${url} answered HTTP ${response.status}`);
  }
  if (body === null) {
    throw new AuthError('invalid_response', `Discovery at ${url} did not return JSON`);
  }
  return assertMetadata(body, issuer);
}

/** Like {@link discover}, and says whether the answer came from the network. */
export async function discoverDetailed(issuer: string, options: DiscoverOptions = {}): Promise<DiscoveryResult> {
  const canonical = stripTrailingSlash(issuer);
  if (!/^https?:\/\//.test(canonical)) {
    throw new AuthError('configuration', `issuer must be an absolute http(s) URL, got "${issuer}"`);
  }
  const locations = [canonical, ...(options.alternateLocations ?? [])];
  let lastError: unknown;
  for (const location of locations) {
    try {
      return { metadata: await fetchDocument(location, canonical, options), fromNetwork: true };
    } catch (error) {
      if (isDefinitive(error)) throw error;
      lastError = error;
      options.onWarning?.(`discovery at ${location} failed`, error);
    }
  }
  if (options.fallbackToKnownLayout !== false) {
    options.onWarning?.(`using the known endpoint layout for ${canonical}`, lastError);
    return { metadata: knownIssuerMetadata(canonical), fromNetwork: false };
  }
  throw new AuthError('discovery_failed', `Could not fetch the discovery document for ${canonical}`, { cause: lastError });
}

/**
 * Fetch and validate the issuer's discovery document. Tries alternate
 * locations when given, then falls back to the known layout unless disabled.
 */
export async function discover(issuer: string, options: DiscoverOptions = {}): Promise<IssuerMetadata> {
  return (await discoverDetailed(issuer, options)).metadata;
}

export interface DiscoveryCacheOptions {
  /** How long a fetched document is reused. Default 1 hour. */
  ttlMs?: number;
  now?: () => number;
}

/**
 * One document per issuer, refetched after the TTL, with in-flight
 * de-duplication and stale-on-error: a document that was fetched once is
 * kept for as long as the issuer cannot be reached again. A fallback (known
 * layout) answer is not cached past the next call, so discovery is retried.
 */
export function createDiscoveryCache(cacheOptions: DiscoveryCacheOptions = {}) {
  const ttlMs = cacheOptions.ttlMs ?? 60 * 60 * 1000;
  const now = cacheOptions.now ?? (() => Date.now());
  const entries = new Map<string, { metadata: IssuerMetadata; fetchedAt: number; fromNetwork: boolean }>();
  const inflight = new Map<string, Promise<IssuerMetadata>>();

  async function load(issuer: string, options: DiscoverOptions = {}): Promise<IssuerMetadata> {
    const canonical = stripTrailingSlash(issuer);
    const cached = entries.get(canonical);
    if (cached?.fromNetwork && now() - cached.fetchedAt < ttlMs) return cached.metadata;
    const pending = inflight.get(canonical);
    if (pending) return pending;
    const run = (async () => {
      try {
        // With a stale network copy in hand, that copy beats the known-layout fallback.
        const result = await discoverDetailed(canonical, {
          ...options,
          fallbackToKnownLayout: cached?.fromNetwork ? false : options.fallbackToKnownLayout,
        });
        entries.set(canonical, { metadata: result.metadata, fetchedAt: now(), fromNetwork: result.fromNetwork });
        return result.metadata;
      } catch (error) {
        if (cached) {
          options.onWarning?.(`discovery refresh for ${canonical} failed; using the cached document`, error);
          return cached.metadata;
        }
        throw error;
      } finally {
        inflight.delete(canonical);
      }
    })();
    inflight.set(canonical, run);
    return run;
  }

  return {
    get: load,
    clear: () => {
      entries.clear();
    },
    peek: (issuer: string) => entries.get(stripTrailingSlash(issuer))?.metadata ?? null,
  };
}
