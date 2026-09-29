/**
 * @alternatefutures/ac-auth-next
 *
 * Sign in with Alternate Clouds for the Next.js App Router. Create one
 * instance in `lib/auth.ts` and wire three files:
 *
 *   // lib/auth.ts
 *   export const { auth, handlers, signInPath, toClientSession } = createAuth(authConfig);
 *
 *   // app/api/auth/[...auth]/route.ts
 *   export const { GET, POST } = handlers;
 *
 *   // proxy.ts (Next.js 16; middleware.ts on 15)
 *   export const proxy = createAuthProxy(authConfig);   // from '@alternatefutures/ac-auth-next/proxy'
 *   export const config = { matcher: [...] };          // a literal: Next.js does not accept an imported constant
 *
 * Then `await auth()` in Server Components and Route Handlers, and
 * `<AuthProvider>` from `@alternatefutures/ac-auth-next/react` around the
 * client tree.
 *
 * @packageDocumentation
 */

import { cookies as nextCookies } from 'next/headers';
import { AcAuthCore, toClientSession, type AcAuthConfig, type ServerSession } from './core';
import { createAuthProxy, type AuthProxy, type ProxyOptions } from './proxy';

export type { AcAuthConfig, ClientSession, ServerSession, SessionPayload } from './core';
export { AcAuthCore, safeReturnTo, toClientSession } from './core';
export { seal, unseal } from './seal';
export { PROXY_MATCHER, createAuthProxy } from './proxy';
export type { AuthProxy, ProxyOptions } from './proxy';

export interface AcAuth {
  core: AcAuthCore;
  /** The session for the current request (Server Components, Server Actions, Route Handlers). Never refreshes. */
  auth(): Promise<ServerSession | null>;
  /** Route handlers for `app/<basePath>/[...auth]/route.ts`. */
  handlers: { GET: (request: Request) => Promise<Response>; POST: (request: Request) => Promise<Response> };
  /** The proxy that refreshes the session cookie, sharing this instance's refresh coordinator. */
  proxy: AuthProxy;
  /** Build a proxy with options (protected paths). */
  createProxy(options?: ProxyOptions): AuthProxy;
  /** `<basePath>/signin?returnTo=...` */
  signInPath(returnTo?: string | null): string;
  signOutPath(): string;
  toClientSession: typeof toClientSession;
}

export function createAuth(config: AcAuthConfig = {}): AcAuth {
  const core = new AcAuthCore(config);

  const auth = async (): Promise<ServerSession | null> => {
    const store = await nextCookies();
    const value = store.get(`__Host-${core.config.cookieName}`)?.value ?? store.get(core.config.cookieName)?.value;
    return core.sessionFromPayload(await core.unsealSession(value));
  };

  const handler = (request: Request) => core.handle(request);

  return {
    core,
    auth,
    handlers: { GET: handler, POST: handler },
    proxy: createAuthProxy(core),
    createProxy: (options) => createAuthProxy(core, options),
    signInPath: (returnTo) => core.signInPath(returnTo),
    signOutPath: () => core.signOutPath(),
    toClientSession,
  };
}
