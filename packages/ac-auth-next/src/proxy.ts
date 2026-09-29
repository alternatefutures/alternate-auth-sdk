/**
 * The proxy (Next.js 16 `proxy.ts`, `middleware.ts` on 15): the one place
 * the session cookie is refreshed. Imports only `next/server`, so it runs in
 * the proxy runtime without pulling `next/headers` in.
 *
 *   // proxy.ts
 *   import { createAuthProxy } from '@alternatefutures/ac-auth-next/proxy';
 *   import { authConfig } from '@/lib/auth-config';
 *   export const proxy = createAuthProxy(authConfig, { protect: ['/dashboard'] });
 *   // Next.js needs a literal matcher here (an imported constant is not accepted); copy PROXY_MATCHER's value.
 *   export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js|map|txt|xml|json|woff2?)$).*)'] };
 */

import { NextResponse, type NextRequest } from 'next/server';
import { withCookie } from './cookies';
import { AcAuthCore, safeReturnTo, type AcAuthConfig } from './core';

export interface ProxyOptions {
  /**
   * Paths (or a predicate) that require a session. A visitor without one is
   * sent to the sign-in with `returnTo` set. Default: nothing is protected;
   * pages decide with `auth()`.
   */
  protect?: string[] | ((pathname: string) => boolean);
}

/** The recommended matcher (skips static assets). Copy its VALUE into `proxy.ts`: Next.js only accepts a literal there. */
export const PROXY_MATCHER = ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js|map|txt|xml|json|woff2?)$).*)'];

export type AuthProxy = (request: NextRequest) => Promise<NextResponse>;

function isProtected(pathname: string, protect: ProxyOptions['protect']): boolean {
  if (!protect) return false;
  if (typeof protect === 'function') return protect(pathname);
  return protect.some((p) => pathname === p || pathname.startsWith(p.endsWith('/') ? p : `${p}/`));
}

/** Build the proxy from an existing core (shared with `createAuth`) or a config. */
export function createAuthProxy(configOrCore: AcAuthConfig | AcAuthCore = {}, options: ProxyOptions = {}): AuthProxy {
  const core = configOrCore instanceof AcAuthCore ? configOrCore : new AcAuthCore(configOrCore);
  const { cookieName, basePath } = core.config;

  return async (request: NextRequest): Promise<NextResponse> => {
    const pathname = request.nextUrl.pathname;
    if (pathname.startsWith(basePath)) return NextResponse.next();
    const current = request.cookies.get(`__Host-${cookieName}`)?.value ?? request.cookies.get(cookieName)?.value;
    const decision = await core.refreshSessionCookie(current);

    let response: NextResponse;
    let hasSession: boolean;
    if (decision.action === 'set') {
      // Forward the fresh cookie to this request too, so Server Components
      // rendering right now see the new session, not the one just rotated.
      const headers = new Headers(request.headers);
      headers.set('cookie', withCookie(request.headers.get('cookie'), core.sessionCookieName(request), decision.value));
      response = NextResponse.next({ request: { headers } });
      response.headers.append('set-cookie', core.sessionCookie(request, decision.value));
      hasSession = true;
    } else if (decision.action === 'clear') {
      response = NextResponse.next();
      response.headers.append('set-cookie', core.clearSessionCookie(request));
      hasSession = false;
    } else {
      response = NextResponse.next();
      hasSession = Boolean(current && (await core.sessionFromCookieHeader(request.headers.get('cookie'))));
    }

    if (!hasSession && isProtected(pathname, options.protect)) {
      const returnTo = safeReturnTo(`${pathname}${request.nextUrl.search}`) ?? '/';
      const redirect = NextResponse.redirect(new URL(core.signInPath(returnTo), request.url));
      for (const cookie of response.headers.getSetCookie()) redirect.headers.append('set-cookie', cookie);
      return redirect;
    }
    return response;
  };
}
