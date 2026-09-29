'use client';

/**
 * `<AuthProvider>` holds the session for the React tree. It runs on either:
 *
 * - an {@link AuthClient} (browser app without a server: PKCE in the
 *   browser, tokens in memory), or
 * - an {@link AuthAdapter} (an app with a server that keeps the tokens, such
 *   as @alternatefutures/ac-auth-next, where the browser only ever sees the
 *   user and the session status).
 *
 * The provider also finishes a sign-in when it mounts on the redirect URI
 * (client mode) so a single-page app needs no callback code of its own.
 */

import type { AuthClient, AuthUser, OrganizationClaim, Session, SignInOptions, TokenSet } from '@alternatefutures/ac-auth';
import { AuthError } from '@alternatefutures/ac-auth';
import * as React from 'react';

/** A session as the React tree sees it. Tokens are present only in client mode. */
export interface AuthSession {
  status: 'active' | 'grace';
  user: AuthUser;
  /** Epoch ms. */
  expiresAt: number;
  issuedAt: number;
  tokens?: TokenSet;
}

export type AuthStatus = 'loading' | 'signed-in' | 'signed-out';

export interface AuthSignInOptions {
  /** Where to land after the sign-in completes. Same-origin path. */
  returnTo?: string;
  scope?: SignInOptions['scope'];
  prompt?: SignInOptions['prompt'];
  loginHint?: string;
}

export interface AuthSignOutOptions {
  /** Where to land after signing out (client mode: the registered post-logout redirect URI is used when set). */
  returnTo?: string;
}

/** What the provider needs from a session source. Implemented by auth-next for the server-side session. */
export interface AuthAdapter {
  /** Synchronous snapshot for the first render, if the adapter has one. */
  peek?(): AuthSession | null;
  getSession(): Promise<AuthSession | null>;
  signIn(options?: AuthSignInOptions): Promise<void> | void;
  signOut(options?: AuthSignOutOptions): Promise<void> | void;
  subscribe?(listener: (session: AuthSession | null) => void): () => void;
  /**
   * Client mode only: finish a sign-in when the current page is the
   * redirect URI. Returns the path to continue on, or null when the page is
   * not a callback.
   */
  completeCallback?(): Promise<{ session: AuthSession; returnTo: string | null } | null>;
}

export interface AuthContextValue {
  status: AuthStatus;
  session: AuthSession | null;
  user: AuthUser | null;
  error: Error | null;
  isLoaded: boolean;
  isSignedIn: boolean;
  signIn(options?: AuthSignInOptions): Promise<void>;
  signOut(options?: AuthSignOutOptions): Promise<void>;
  /** Re-read the session from its source (refreshing tokens when needed). */
  refresh(): Promise<AuthSession | null>;
  theme: AuthTheme;
}

export type AuthTheme = 'light' | 'dark' | 'system' | 'inherit';

const AuthContext = React.createContext<AuthContextValue | null>(null);

export interface AuthProviderProps {
  /** Browser-only mode: the client does PKCE and holds the tokens. */
  client?: AuthClient;
  /** Server-session mode (auth-next) or any custom source. */
  adapter?: AuthAdapter;
  /** A session known at render time (from the server) so the first paint is right. */
  initialSession?: AuthSession | null;
  /**
   * `dark` (default, the Alternate Clouds web app's scheme) or `light` force a
   * scheme, `system` follows the OS, `inherit` sets no variables so the host's
   * own design tokens apply (an app running the web app's stylesheet).
   */
  theme?: AuthTheme;
  /** Client mode: called with the path to continue on after a sign-in completed on this page. Default: `history.replaceState`. */
  onSignedIn?: (returnTo: string | null, session: AuthSession) => void;
  onError?: (error: Error) => void;
  children?: React.ReactNode;
}

function sessionFromClient(session: Session | null): AuthSession | null {
  if (!session) return null;
  return { status: session.status, user: session.user, expiresAt: session.expiresAt, issuedAt: session.issuedAt, tokens: session.tokens };
}

/** Wrap an {@link AuthClient} as an adapter. */
export function clientAdapter(client: AuthClient): AuthAdapter {
  return {
    peek: () => sessionFromClient(client.peekSession()),
    getSession: async () => sessionFromClient(await client.getSession()),
    signIn: (options) => client.signIn(options),
    signOut: async (options) => {
      await client.signOut({ redirect: true, ...(options?.returnTo ? { postLogoutRedirectUri: options.returnTo } : {}) });
    },
    subscribe: (listener) => client.subscribe((session) => listener(sessionFromClient(session))),
    completeCallback: async () => {
      if (!client.isCallback()) return null;
      const result = await client.handleCallback();
      return { session: sessionFromClient(result.session)!, returnTo: result.returnTo };
    },
  };
}

function defaultOnSignedIn(returnTo: string | null): void {
  if (typeof window === 'undefined') return;
  const target = returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : window.location.pathname;
  window.history.replaceState(null, '', target);
}

export function AuthProvider(props: AuthProviderProps) {
  const { client, adapter: givenAdapter, initialSession, theme = 'dark', onSignedIn, onError, children } = props;
  if (!client && !givenAdapter) {
    throw new AuthError('configuration', '<AuthProvider> needs a `client` or an `adapter`');
  }
  const adapter = React.useMemo(() => givenAdapter ?? clientAdapter(client!), [givenAdapter, client]);

  const [session, setSession] = React.useState<AuthSession | null>(() => {
    if (initialSession !== undefined) return initialSession;
    return adapter.peek?.() ?? null;
  });
  const [status, setStatus] = React.useState<AuthStatus>(() => {
    if (initialSession !== undefined) return initialSession ? 'signed-in' : 'signed-out';
    const peeked = adapter.peek?.();
    return peeked ? 'signed-in' : 'loading';
  });
  const [error, setError] = React.useState<Error | null>(null);

  const apply = React.useCallback((next: AuthSession | null) => {
    setSession(next);
    setStatus(next ? 'signed-in' : 'signed-out');
  }, []);

  const fail = React.useCallback((cause: unknown) => {
    const err = cause instanceof Error ? cause : new Error(String(cause));
    setError(err);
    onError?.(err);
  }, [onError]);

  // Bootstrap: finish a callback, else load the session. Ignore stale results.
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const completed = await adapter.completeCallback?.();
        if (cancelled) return;
        if (completed) {
          apply(completed.session);
          (onSignedIn ?? defaultOnSignedIn)(completed.returnTo, completed.session);
          return;
        }
        const current = await adapter.getSession();
        if (!cancelled) apply(current);
      } catch (cause) {
        if (cancelled) return;
        fail(cause);
        // A failed callback or load means "not signed in" for the UI.
        apply(null);
      }
    })();
    return () => {
      cancelled = true;
    };
    // The adapter identity drives this effect; initialSession is only the first paint.
  }, [adapter, apply, fail, onSignedIn]);

  React.useEffect(() => {
    if (!adapter.subscribe) return;
    return adapter.subscribe((next) => apply(next));
  }, [adapter, apply]);

  const signIn = React.useCallback(async (options?: AuthSignInOptions) => {
    setError(null);
    try {
      await adapter.signIn(options);
    } catch (cause) {
      fail(cause);
      throw cause;
    }
  }, [adapter, fail]);

  const signOut = React.useCallback(async (options?: AuthSignOutOptions) => {
    setError(null);
    try {
      await adapter.signOut(options);
      apply(null);
    } catch (cause) {
      fail(cause);
      throw cause;
    }
  }, [adapter, apply, fail]);

  const refresh = React.useCallback(async () => {
    try {
      const next = await adapter.getSession();
      apply(next);
      return next;
    } catch (cause) {
      fail(cause);
      return null;
    }
  }, [adapter, apply, fail]);

  const value = React.useMemo<AuthContextValue>(() => ({
    status,
    session,
    user: session?.user ?? null,
    error,
    isLoaded: status !== 'loading',
    isSignedIn: status === 'signed-in',
    signIn,
    signOut,
    refresh,
    theme,
  }), [status, session, error, signIn, signOut, refresh, theme]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = React.useContext(AuthContext);
  if (!value) throw new AuthError('configuration', 'useAuth() must be used inside <AuthProvider>');
  return value;
}

export function useUser(): { user: AuthUser | null; isLoaded: boolean; isSignedIn: boolean } {
  const { user, isLoaded, isSignedIn } = useAuth();
  return { user, isLoaded, isSignedIn };
}

export function useSession(): { session: AuthSession | null; status: AuthStatus; isLoaded: boolean; refresh: () => Promise<AuthSession | null> } {
  const { session, status, isLoaded, refresh } = useAuth();
  return { session, status, isLoaded, refresh };
}

export function useOrganization(): { organization: OrganizationClaim | null; role: string | null; isLoaded: boolean } {
  const { user, isLoaded } = useAuth();
  return { organization: user?.org ?? null, role: user?.org?.role ?? null, isLoaded };
}
