/**
 * Refresh with rotation, done safely.
 *
 * The issuer rotates on every refresh and treats a second presentation of a
 * rotated token as theft: the whole grant is revoked and every token in it
 * dies. Three rules follow, all enforced here so callers cannot get them wrong:
 *
 * 1. Single flight. Concurrent refreshes for the same token share one request.
 * 2. Successor cache. A caller that still holds the old token shortly after a
 *    rotation gets the new set back instead of a second request.
 * 3. Never resend. Once a token was accepted by the issuer, or definitively
 *    refused, it is marked consumed and any later attempt with it throws
 *    `refresh_token_consumed` locally.
 *
 * A transient failure (no answer, 5xx) does NOT consume the token: the
 * request may never have reached the issuer, and a token that was rotated
 * server-side while the answer was lost is unrecoverable either way. Retrying
 * is the only move that can succeed.
 */

import { AuthError, isSignedOutError, isTransientError } from './errors';
import type { TokenSet } from './types';

export interface RefreshCoordinatorOptions<T = TokenSet> {
  /** Performs the actual refresh_token grant. Must throw for failures. */
  refresh: (refreshToken: string) => Promise<T>;
  /** Extract the refresh token from a result (to mark it as the successor). */
  refreshTokenOf?: (result: T) => string | null;
  /** How long a successor is handed out to holders of the old token. Default 60 s. */
  successorTtlMs?: number;
  /** How many consumed tokens to remember. Default 200. */
  maxRemembered?: number;
  now?: () => number;
}

interface Remembered<T> {
  at: number;
  successor: T | null;
}

export class RefreshCoordinator<T = TokenSet> {
  private readonly inflight = new Map<string, Promise<T>>();
  private readonly consumed = new Map<string, Remembered<T>>();
  private readonly options: Required<Pick<RefreshCoordinatorOptions<T>, 'successorTtlMs' | 'maxRemembered' | 'now' | 'refreshTokenOf'>> & RefreshCoordinatorOptions<T>;

  constructor(options: RefreshCoordinatorOptions<T>) {
    this.options = {
      successorTtlMs: 60_000,
      maxRemembered: 200,
      now: () => Date.now(),
      refreshTokenOf: (result: T) => (result as unknown as TokenSet).refreshToken ?? null,
      ...options,
    };
  }

  /** Whether this token was already used (or refused) and must not be sent again. */
  isConsumed(refreshToken: string): boolean {
    return this.consumed.has(refreshToken);
  }

  refresh(refreshToken: string): Promise<T> {
    if (!refreshToken) {
      return Promise.reject(new AuthError('signed_out', 'No refresh token; sign in again'));
    }
    const remembered = this.consumed.get(refreshToken);
    if (remembered) {
      if (remembered.successor && this.options.now() - remembered.at <= this.options.successorTtlMs) {
        return Promise.resolve(remembered.successor);
      }
      return Promise.reject(new AuthError('refresh_token_consumed', 'This refresh token was already rotated; sign in again'));
    }
    const pending = this.inflight.get(refreshToken);
    if (pending) return pending;

    const run = (async () => {
      try {
        const result = await this.options.refresh(refreshToken);
        this.remember(refreshToken, result);
        return result;
      } catch (error) {
        // A definitive refusal (or a malformed request of ours) means this
        // token must never be presented again. A transient failure leaves it
        // usable: the request may never have reached the issuer.
        if (isSignedOutError(error) || !isTransientError(error)) this.remember(refreshToken, null);
        throw error;
      } finally {
        this.inflight.delete(refreshToken);
      }
    })();
    this.inflight.set(refreshToken, run);
    return run;
  }

  private remember(refreshToken: string, successor: T | null): void {
    this.consumed.set(refreshToken, { at: this.options.now(), successor });
    while (this.consumed.size > this.options.maxRemembered) {
      const oldest = this.consumed.keys().next().value;
      if (oldest === undefined) break;
      this.consumed.delete(oldest);
    }
  }

  /** Forget everything (sign-out, tests). */
  reset(): void {
    this.inflight.clear();
    this.consumed.clear();
  }
}
