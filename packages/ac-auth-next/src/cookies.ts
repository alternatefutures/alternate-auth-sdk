/**
 * Cookie plumbing for plain `Request`/`Response` handlers. The proxy uses
 * `NextResponse.cookies`; everything else goes through here so the package
 * works with any handler that speaks the Fetch API.
 */

export interface CookieAttributes {
  path?: string;
  domain?: string;
  maxAge?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
}

export function serializeCookie(name: string, value: string, attributes: CookieAttributes = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${attributes.path ?? '/'}`);
  if (attributes.domain) parts.push(`Domain=${attributes.domain}`);
  if (attributes.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(attributes.maxAge))}`);
  if (attributes.httpOnly !== false) parts.push('HttpOnly');
  if (attributes.secure) parts.push('Secure');
  parts.push(`SameSite=${capitalize(attributes.sameSite ?? 'lax')}`);
  return parts.join('; ');
}

export function expireCookie(name: string, attributes: Pick<CookieAttributes, 'path' | 'domain' | 'secure' | 'sameSite'> = {}): string {
  return serializeCookie(name, '', { ...attributes, maxAge: 0 });
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/** Read one cookie from a `Cookie` request header. */
export function readCookie(header: string | null | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1).trim());
      } catch {
        return part.slice(eq + 1).trim();
      }
    }
  }
  return null;
}

/** Replace (or add) one cookie in a `Cookie` request header value. */
export function withCookie(header: string | null | undefined, name: string, value: string): string {
  const kept = (header ?? '')
    .split(';')
    .map((p) => p.trim())
    .filter((p) => p && p.slice(0, p.indexOf('=')).trim() !== name);
  kept.push(`${name}=${encodeURIComponent(value)}`);
  return kept.join('; ');
}
