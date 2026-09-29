import { describe, expect, it } from 'vitest';
import { shortWallet, userFromClaims, userInitials } from '../src/claims';

describe('userFromClaims', () => {
  it('keys on the wallet DID when present, else on sub, and normalizes the optional claims', () => {
    const withWallet = userFromClaims({ sub: 'u1', wallet: 'did:pkh:eip155:1:0xabc', wallets: ['0xabc'], name: 'A', email: 'a@x', email_verified: true, picture: 'p', updated_at: 100, org: { id: 'o', slug: 's', name: 'n', role: 'ADMIN' } });
    expect(withWallet).toEqual({
      key: 'did:pkh:eip155:1:0xabc', id: 'u1', name: 'A', email: 'a@x', emailVerified: true, picture: 'p',
      wallet: 'did:pkh:eip155:1:0xabc', wallets: ['0xabc'], org: { id: 'o', slug: 's', name: 'n', role: 'ADMIN' }, updatedAt: new Date(100_000),
    });
    const bare = userFromClaims({ sub: 'u2', org: { id: 'x' } as never, wallets: 'nope' as never });
    expect(bare).toEqual({ key: 'u2', id: 'u2', name: null, email: null, emailVerified: false, picture: null, wallet: null, wallets: [], org: null, updatedAt: null });
  });

  it('derives initials and short wallets for avatars', () => {
    expect(userInitials({ name: 'Dev One', email: null, wallet: null })).toBe('DO');
    expect(userInitials({ name: 'Solo', email: null, wallet: null })).toBe('S');
    expect(userInitials({ name: null, email: 'zed@x', wallet: null })).toBe('Z');
    expect(userInitials({ name: null, email: null, wallet: 'did:pkh:eip155:1:0xabcdef' })).toBe('AB');
    expect(userInitials({ name: null, email: null, wallet: null })).toBe('?');
    expect(shortWallet('did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001')).toBe('0xabcd...0001');
    expect(shortWallet('0x1234')).toBe('0x1234');
  });
});
