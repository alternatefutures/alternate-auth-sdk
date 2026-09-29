/**
 * Device authorization grant (RFC 8628) for CLIs, TVs and anything without a
 * browser. The client must have the device flow enabled on the Developer
 * page. The user opens `verification_uri` (or `verification_uri_complete`),
 * types the code, signs in on the web app and confirms; the poll then
 * answers with tokens.
 */

import { AuthError, OAuthError } from './errors';
import { DEFAULT_SCOPES } from './discovery';
import { clientAuthenticationParts, postForm } from './token';
import type { ClientAuthentication, DeviceAuthorizationResponse, IssuerMetadata, TokenResponse } from './types';
import { sleep, toScopeString, type FetchLike } from './util';

export const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export interface DeviceAuthorizationParams {
  metadata: Pick<IssuerMetadata, 'device_authorization_endpoint' | 'token_endpoint'>;
  clientId: string;
  clientAuthentication?: ClientAuthentication;
  scope?: string | readonly string[];
  fetch?: FetchLike;
  timeoutMs?: number;
}

export async function startDeviceAuthorization(params: DeviceAuthorizationParams): Promise<DeviceAuthorizationResponse> {
  const endpoint = params.metadata.device_authorization_endpoint;
  if (!endpoint) throw new AuthError('unsupported', 'The issuer publishes no device authorization endpoint');
  const auth = clientAuthenticationParts(params.clientId, params.clientAuthentication);
  const body = await postForm<Record<string, unknown>>(
    endpoint,
    { scope: toScopeString(params.scope, DEFAULT_SCOPES), ...auth.body },
    { headers: auth.headers, fetch: params.fetch, timeoutMs: params.timeoutMs },
  );
  for (const field of ['device_code', 'user_code', 'verification_uri'] as const) {
    if (typeof body[field] !== 'string') throw new AuthError('invalid_response', `The device authorization response has no ${field}`);
  }
  if (typeof body.expires_in !== 'number') throw new AuthError('invalid_response', 'The device authorization response has no expires_in');
  return body as unknown as DeviceAuthorizationResponse;
}

export interface DevicePollParams {
  metadata: Pick<IssuerMetadata, 'token_endpoint'>;
  clientId: string;
  clientAuthentication?: ClientAuthentication;
  deviceCode: string;
  /** Seconds between polls; the issuer's `interval` (default 5). */
  intervalSeconds?: number;
  /** Give up after this many seconds; the issuer's `expires_in`. */
  expiresInSeconds?: number;
  signal?: AbortSignal;
  fetch?: FetchLike;
  timeoutMs?: number;
  /** Called before each wait with the seconds about to be slept (progress UI). */
  onPending?: (waitSeconds: number) => void;
  /** Injectable for tests. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  now?: () => number;
}

/**
 * Poll the token endpoint until the user approves. Honours
 * `authorization_pending` (wait), `slow_down` (wait 5 s more each time),
 * `expired_token` (`device_flow_expired`) and `access_denied`.
 */
export async function pollDeviceToken(params: DevicePollParams): Promise<TokenResponse> {
  const wait = params.sleep ?? sleep;
  const now = params.now ?? (() => Date.now());
  let interval = Math.max(1, params.intervalSeconds ?? 5);
  const deadline = params.expiresInSeconds ? now() + params.expiresInSeconds * 1000 : null;
  const auth = clientAuthenticationParts(params.clientId, params.clientAuthentication);

  for (;;) {
    if (deadline !== null && now() >= deadline) {
      throw new AuthError('device_flow_expired', 'The device code expired before the sign-in was approved');
    }
    params.onPending?.(interval);
    await wait(interval * 1000, params.signal);
    try {
      const body = await postForm<Record<string, unknown>>(
        params.metadata.token_endpoint,
        { grant_type: DEVICE_CODE_GRANT, device_code: params.deviceCode, ...auth.body },
        { headers: auth.headers, fetch: params.fetch, timeoutMs: params.timeoutMs, signal: params.signal },
      );
      if (typeof body.access_token !== 'string') throw new AuthError('invalid_response', 'The token response has no access_token');
      return body as TokenResponse;
    } catch (error) {
      if (error instanceof OAuthError) {
        if (error.status === 429) {
          // The issuer's per-IP limit: the HTTP-level cousin of slow_down.
          interval += 5;
          continue;
        }
        switch (error.error) {
          case 'authorization_pending':
            continue;
          case 'slow_down':
            interval += 5;
            continue;
          case 'expired_token':
            throw new AuthError('device_flow_expired', 'The device code expired before the sign-in was approved', { cause: error });
          case 'access_denied':
            throw new AuthError('access_denied', 'The sign-in was declined', { cause: error });
          default:
            throw error;
        }
      }
      throw error;
    }
  }
}
