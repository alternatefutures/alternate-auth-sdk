/**
 * From claims to an application user.
 */

import type { AuthUser, IdTokenClaims, OrganizationClaim } from './types';

function isOrganizationClaim(value: unknown): value is OrganizationClaim {
  if (!value || typeof value !== 'object') return false;
  const org = value as Record<string, unknown>;
  return typeof org.id === 'string' && typeof org.slug === 'string' && typeof org.name === 'string' && typeof org.role === 'string';
}

/**
 * Build the {@link AuthUser} an app stores. `key` is the wallet DID when the
 * user has a verified wallet, otherwise the subject: wallet-anchored
 * identities survive a change of issuer.
 */
export function userFromClaims(claims: Pick<IdTokenClaims, 'sub'> & Partial<IdTokenClaims>): AuthUser {
  const wallet = typeof claims.wallet === 'string' && claims.wallet ? claims.wallet : null;
  const wallets = Array.isArray(claims.wallets) ? claims.wallets.filter((w): w is string => typeof w === 'string') : [];
  return {
    key: wallet ?? claims.sub,
    id: claims.sub,
    name: typeof claims.name === 'string' ? claims.name : null,
    email: typeof claims.email === 'string' ? claims.email : null,
    emailVerified: claims.email_verified === true,
    picture: typeof claims.picture === 'string' ? claims.picture : null,
    wallet,
    wallets,
    org: isOrganizationClaim(claims.org) ? claims.org : null,
    updatedAt: typeof claims.updated_at === 'number' ? new Date(claims.updated_at * 1000) : null,
  };
}

/** Initials for an avatar fallback: two letters from the name, else one from the email, else the wallet's first hex digits. */
export function userInitials(user: Pick<AuthUser, 'name' | 'email' | 'wallet'>): string {
  const name = user.name?.trim();
  if (name) {
    const parts = name.split(/\s+/).filter(Boolean);
    const first = parts[0]?.[0] ?? '';
    const last = parts.length > 1 ? parts[parts.length - 1]?.[0] ?? '' : '';
    return (first + last).toUpperCase();
  }
  if (user.email) return user.email[0]?.toUpperCase() ?? '?';
  if (user.wallet) {
    const address = user.wallet.split(':').pop() ?? '';
    return address.replace(/^0x/, '').slice(0, 2).toUpperCase() || '?';
  }
  return '?';
}

/** `0x1234...abcd` for a wallet address or did:pkh. */
export function shortWallet(walletOrDid: string): string {
  const address = walletOrDid.split(':').pop() ?? walletOrDid;
  if (address.length <= 12) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}
