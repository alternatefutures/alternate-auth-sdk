'use client';

/**
 * Client side of @alternatefutures/ac-auth-next: an `<AuthProvider>` that
 * talks to the route handlers (the browser never holds a token) and the
 * React components from @alternatefutures/ac-auth-react, re-exported so an
 * app imports everything from one place.
 *
 *   // app/layout.tsx (Server Component)
 *   const session = await auth();
 *   <AuthProvider initialSession={toClientSession(session)}>{children}</AuthProvider>
 */

import { AuthError } from '@alternatefutures/ac-auth';
import { AuthProvider as BaseAuthProvider, type AuthAdapter, type AuthProviderProps as BaseAuthProviderProps, type AuthSession } from '@alternatefutures/ac-auth-react';
import * as React from 'react';

export {
  Mark,
  SIGN_IN_LABEL,
  SignIn,
  SignInButton,
  SignedIn,
  SignedOut,
  UserButton,
  UserButtonItem,
  useAuth,
  useOrganization,
  useSession,
  useUser,
} from '@alternatefutures/ac-auth-react';
export type {
  AuthSession,
  AuthSignInOptions,
  AuthSignOutOptions,
  AuthStatus,
  AuthTheme,
  SignInButtonProps,
  SignInMethod,
  SignInProps,
  SignedProps,
  UserButtonItemProps,
  UserButtonProps,
} from '@alternatefutures/ac-auth-react';

export interface AuthProviderProps extends Omit<BaseAuthProviderProps, 'client' | 'adapter'> {
  /** Must match `createAuth({ basePath })`. Default `/api/auth`. */
  basePath?: string;
  /** From `toClientSession(await auth())` in a Server Component, so the first paint is right. */
  initialSession?: AuthSession | null;
}

const ERROR_PARAM = 'auth_error';

/** Adapter over the route handlers. */
export function serverAdapter(basePath = '/api/auth'): AuthAdapter {
  const base = `/${basePath.replace(/^\/+|\/+$/g, '')}`;
  return {
    async getSession() {
      const response = await fetch(`${base}/session`, { credentials: 'same-origin', cache: 'no-store', headers: { accept: 'application/json' } });
      if (!response.ok) throw new AuthError('invalid_response', `session endpoint answered HTTP ${response.status}`);
      const body = (await response.json()) as { session: AuthSession | null };
      return body.session ?? null;
    },
    signIn(options) {
      const params = new URLSearchParams();
      if (options?.returnTo) params.set('returnTo', options.returnTo);
      else if (typeof window !== 'undefined') params.set('returnTo', `${window.location.pathname}${window.location.search}`);
      if (options?.scope) params.set('scope', Array.isArray(options.scope) ? options.scope.join(' ') : String(options.scope));
      if (options?.prompt) params.set('prompt', options.prompt);
      if (options?.loginHint) params.set('login_hint', options.loginHint);
      const query = params.toString();
      window.location.assign(`${base}/signin${query ? `?${query}` : ''}`);
      // Keep the caller's busy state until the page unloads.
      return new Promise<void>(() => {});
    },
    async signOut() {
      const response = await fetch(`${base}/signout`, { method: 'POST', credentials: 'same-origin', headers: { accept: 'application/json' } });
      if (!response.ok) throw new AuthError('invalid_response', `sign-out endpoint answered HTTP ${response.status}`);
      const body = (await response.json()) as { redirectTo?: string };
      window.location.assign(body.redirectTo || '/');
    },
    async completeCallback() {
      // The callback ran on the server; the only thing left on this page is a failure code.
      if (typeof window === 'undefined') return null;
      const url = new URL(window.location.href);
      const code = url.searchParams.get(ERROR_PARAM);
      if (!code) return null;
      url.searchParams.delete(ERROR_PARAM);
      window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
      const error = new AuthError(code === 'access_denied' ? 'access_denied' : 'invalid_callback', `Sign-in failed: ${code}`);
      Object.assign(error, { error: code });
      throw error;
    },
  };
}

export function AuthProvider({ basePath, initialSession, children, ...rest }: AuthProviderProps) {
  const adapter = React.useMemo(() => serverAdapter(basePath), [basePath]);
  return (
    <BaseAuthProvider adapter={adapter} initialSession={initialSession} {...rest}>
      {children}
    </BaseAuthProvider>
  );
}
