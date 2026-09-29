/**
 * Session grace (plan §4 M4 "cheap first").
 *
 * The issuer must not be a chokepoint: when the access token has expired and
 * a refresh cannot be completed because the issuer is unreachable, the app
 * keeps treating the user as signed in for a bounded time. Two bounds, both
 * absolute:
 *
 * - `graceMs` after the access token expired (default 24 h);
 * - `maxSessionMs` after the tokens were last issued (default 7 days),
 *   whichever comes first.
 *
 * Grace never applies to a definitive refusal (`invalid_grant`): a revoked
 * grant signs the user out at once.
 */

export interface SessionGracePolicy {
  /** How long past `expiresAt` a session stays usable while the issuer is unreachable. */
  graceMs: number;
  /** Hard cap measured from `issuedAt`; grace never extends past it. */
  maxSessionMs: number;
}

export const DEFAULT_GRACE_POLICY: SessionGracePolicy = {
  graceMs: 24 * 60 * 60 * 1000,
  maxSessionMs: 7 * 24 * 60 * 60 * 1000,
};

/** A policy with no grace at all: an expired access token is an expired session. */
export const NO_GRACE_POLICY: SessionGracePolicy = { graceMs: 0, maxSessionMs: 0 };

export type GraceVerdict = 'active' | 'grace' | 'expired';

export function resolveGracePolicy(policy: Partial<SessionGracePolicy> | undefined): SessionGracePolicy {
  return { ...DEFAULT_GRACE_POLICY, ...(policy ?? {}) };
}

/**
 * Where a token set stands at `now` (epoch ms).
 * `active`: not expired. `grace`: expired, but inside both bounds.
 * `expired`: outside the grace window or past the cap.
 */
export function evaluateGrace(
  tokens: { expiresAt: number; issuedAt: number },
  now: number,
  policy: Partial<SessionGracePolicy> = DEFAULT_GRACE_POLICY,
): GraceVerdict {
  const resolved = resolveGracePolicy(policy);
  if (now < tokens.expiresAt) return 'active';
  if (resolved.graceMs <= 0) return 'expired';
  if (now - tokens.expiresAt > resolved.graceMs) return 'expired';
  if (now - tokens.issuedAt > resolved.maxSessionMs) return 'expired';
  return 'grace';
}

/** Epoch ms after which a set can no longer be in grace (for cookie Max-Age and timers). */
export function graceDeadline(tokens: { expiresAt: number; issuedAt: number }, policy: Partial<SessionGracePolicy> = DEFAULT_GRACE_POLICY): number {
  const resolved = resolveGracePolicy(policy);
  return Math.min(tokens.expiresAt + resolved.graceMs, tokens.issuedAt + resolved.maxSessionMs);
}
