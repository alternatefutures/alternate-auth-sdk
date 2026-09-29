import { describe, expect, it, vi } from 'vitest';
import { AuthError, OAuthError } from '../src/errors';
import { RefreshCoordinator } from '../src/refresh';
import type { TokenSet } from '../src/types';

function set(refreshToken: string, n: number): TokenSet {
  return { accessToken: `at${n}`, tokenType: 'Bearer', scope: null, refreshToken, idToken: null, expiresAt: n * 1000, issuedAt: 0, claims: null };
}

/** A refresh backend that rotates and refuses reuse like the issuer. */
function rotatingBackend() {
  const consumed = new Set<string>();
  const presented: string[] = [];
  let counter = 0;
  const refresh = vi.fn(async (token: string) => {
    presented.push(token);
    if (consumed.has(token)) throw new OAuthError({ error: 'invalid_grant', error_description: 'reuse' }, 400);
    consumed.add(token);
    counter++;
    return set(`rt${counter}`, counter);
  });
  return { refresh, presented, consumed };
}

describe('RefreshCoordinator', () => {
  it('collapses concurrent refreshes of the same token into one request', async () => {
    const backend = rotatingBackend();
    const coordinator = new RefreshCoordinator({ refresh: backend.refresh });
    const results = await Promise.all(Array.from({ length: 5 }, () => coordinator.refresh('rt0')));
    expect(backend.refresh).toHaveBeenCalledTimes(1);
    for (const r of results) expect(r.refreshToken).toBe('rt1');
    expect(backend.presented).toEqual(['rt0']);
  });

  it('hands the successor to late holders of the rotated token, then refuses locally', async () => {
    let now = 0;
    const backend = rotatingBackend();
    const coordinator = new RefreshCoordinator({ refresh: backend.refresh, successorTtlMs: 60_000, now: () => now });
    const first = await coordinator.refresh('rt0');
    expect(first.refreshToken).toBe('rt1');

    now = 30_000;
    const late = await coordinator.refresh('rt0');
    expect(late).toBe(first);
    expect(backend.refresh).toHaveBeenCalledTimes(1);

    now = 61_000;
    await expect(coordinator.refresh('rt0')).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'refresh_token_consumed');
    expect(backend.refresh).toHaveBeenCalledTimes(1);
    expect(backend.presented).toEqual(['rt0']);
  });

  it('a chain of rotations presents every token to the issuer exactly once', async () => {
    const backend = rotatingBackend();
    const coordinator = new RefreshCoordinator({ refresh: backend.refresh });
    let current = 'rt0';
    for (let i = 0; i < 5; i++) {
      const next = await coordinator.refresh(current);
      // A second concurrent caller with the token we just used gets the same set.
      expect(await coordinator.refresh(current)).toBe(next);
      current = next.refreshToken!;
    }
    expect(backend.presented).toEqual(['rt0', 'rt1', 'rt2', 'rt3', 'rt4']);
    expect(new Set(backend.presented).size).toBe(backend.presented.length);
  });

  it('invalid_grant is final: the token is consumed and never sent again', async () => {
    const refresh = vi.fn(async () => {
      throw new OAuthError({ error: 'invalid_grant' }, 400);
    });
    const coordinator = new RefreshCoordinator({ refresh });
    await expect(coordinator.refresh('dead')).rejects.toBeInstanceOf(OAuthError);
    await expect(coordinator.refresh('dead')).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'refresh_token_consumed');
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(coordinator.isConsumed('dead')).toBe(true);
  });

  it('a transient failure keeps the token usable and the next attempt goes through', async () => {
    let fail = true;
    const refresh = vi.fn(async (token: string) => {
      if (fail) throw new AuthError('network_error', 'offline');
      return set(`${token}-next`, 1);
    });
    const coordinator = new RefreshCoordinator({ refresh });
    await expect(coordinator.refresh('rt0')).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'network_error');
    expect(coordinator.isConsumed('rt0')).toBe(false);
    fail = false;
    const result = await coordinator.refresh('rt0');
    expect(result.refreshToken).toBe('rt0-next');
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('a 5xx OAuth answer is transient too', async () => {
    let status = 503;
    const refresh = vi.fn(async (token: string) => {
      if (status >= 500) throw new OAuthError({ error: 'server_error' }, status);
      return set(`${token}-next`, 1);
    });
    const coordinator = new RefreshCoordinator({ refresh });
    await expect(coordinator.refresh('rt0')).rejects.toBeInstanceOf(OAuthError);
    status = 200;
    expect((await coordinator.refresh('rt0')).refreshToken).toBe('rt0-next');
  });

  it('refuses an empty token without calling the backend', async () => {
    const refresh = vi.fn();
    const coordinator = new RefreshCoordinator({ refresh });
    await expect(coordinator.refresh('')).rejects.toSatisfy((e: unknown) => e instanceof AuthError && e.code === 'signed_out');
    expect(refresh).not.toHaveBeenCalled();
  });

  it('bounds its memory of consumed tokens', async () => {
    const backend = rotatingBackend();
    const coordinator = new RefreshCoordinator({ refresh: backend.refresh, maxRemembered: 3 });
    let current = 'rt0';
    for (let i = 0; i < 6; i++) current = (await coordinator.refresh(current)).refreshToken!;
    expect(coordinator.isConsumed('rt0')).toBe(false);
    expect(coordinator.isConsumed('rt5')).toBe(true);
  });
});
