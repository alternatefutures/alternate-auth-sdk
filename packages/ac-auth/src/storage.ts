/**
 * Where the client keeps its state. Two stores:
 *
 * - transaction store: the pending sign-in (state, nonce, PKCE verifier,
 *   return path). It must survive the redirect to the issuer and back, so
 *   in a browser it defaults to `sessionStorage`.
 * - session store: the tokens. Defaults to memory (lost on reload; the
 *   next click on the sign-in button comes straight back because consent is
 *   remembered). `session` keeps them per tab, `local` shares them between
 *   tabs; both are readable by any script on the origin, so prefer a
 *   server-side (BFF) session when the app has a server.
 */

export interface AuthStorage {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export type StorageKind = 'memory' | 'session' | 'local';

export function memoryStorage(): AuthStorage {
  const map = new Map<string, string>();
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => {
      map.set(key, value);
    },
    remove: (key) => {
      map.delete(key);
    },
  };
}

function webStorageArea(kind: 'session' | 'local'): Storage | null {
  try {
    const area = kind === 'session' ? globalThis.sessionStorage : globalThis.localStorage;
    if (!area) return null;
    // Some browsers throw on access in private mode or when storage is blocked.
    const probe = '__af_auth_probe__';
    area.setItem(probe, '1');
    area.removeItem(probe);
    return area;
  } catch {
    return null;
  }
}

/** `sessionStorage` or `localStorage` with a memory fallback when the area is unavailable. */
export function webStorage(kind: 'session' | 'local'): AuthStorage {
  const area = webStorageArea(kind);
  if (!area) return memoryStorage();
  return {
    get: (key) => {
      try {
        return area.getItem(key);
      } catch {
        return null;
      }
    },
    set: (key, value) => {
      try {
        area.setItem(key, value);
      } catch {
        /* quota or blocked: the caller treats storage as best effort */
      }
    },
    remove: (key) => {
      try {
        area.removeItem(key);
      } catch {
        /* ignore */
      }
    },
  };
}

export function resolveStorage(kind: StorageKind | AuthStorage | undefined, fallback: StorageKind): AuthStorage {
  const choice = kind ?? fallback;
  if (typeof choice === 'object') return choice;
  if (choice === 'memory') return memoryStorage();
  return webStorage(choice);
}

/**
 * Run `fn` under a cross-tab lock when the Web Locks API exists (so two tabs
 * sharing `localStorage` never refresh the same token twice), else directly.
 */
export async function withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const locks = (globalThis.navigator as { locks?: { request<R>(name: string, callback: () => Promise<R>): Promise<R> } } | undefined)?.locks;
  if (locks && typeof locks.request === 'function') {
    return locks.request(name, fn);
  }
  return fn();
}
