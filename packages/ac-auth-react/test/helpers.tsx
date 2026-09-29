import type { AuthUser } from '@alternatefutures/ac-auth';
import * as React from 'react';
import { vi } from 'vitest';
import { AuthProvider, type AuthAdapter, type AuthProviderProps, type AuthSession } from '../src/context';

export const user: AuthUser = {
  key: 'did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001',
  id: 'user_1',
  name: 'Dev One',
  email: 'dev@example.com',
  emailVerified: true,
  picture: null,
  wallet: 'did:pkh:eip155:1:0xabcdef0000000000000000000000000000000001',
  wallets: ['0xabcdef0000000000000000000000000000000001'],
  org: { id: 'org_1', slug: 'acme', name: 'Acme', role: 'OWNER' },
  updatedAt: null,
};

export function session(overrides: Partial<AuthSession> = {}): AuthSession {
  return { status: 'active', user, expiresAt: Date.now() + 3600_000, issuedAt: Date.now(), ...overrides };
}

/** An adapter whose session can be driven from the test. */
export function fakeAdapter(initial: AuthSession | null = null) {
  let current = initial;
  const listeners = new Set<(s: AuthSession | null) => void>();
  const adapter: AuthAdapter & { set(next: AuthSession | null): void; signIn: ReturnType<typeof vi.fn>; signOut: ReturnType<typeof vi.fn>; getSession: ReturnType<typeof vi.fn>; completeCallback: ReturnType<typeof vi.fn> } = {
    peek: () => current,
    getSession: vi.fn(async () => current),
    signIn: vi.fn(async () => {}),
    signOut: vi.fn(async () => {
      current = null;
    }),
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    completeCallback: vi.fn(async () => null),
    set(next) {
      current = next;
      for (const l of listeners) l(next);
    },
  };
  return adapter;
}

export function Wrapper({ adapter, children, ...rest }: { adapter: AuthAdapter; children: React.ReactNode } & Partial<AuthProviderProps>) {
  return <AuthProvider adapter={adapter} {...rest}>{children}</AuthProvider>;
}
