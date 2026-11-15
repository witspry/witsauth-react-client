import type { BffAppScope } from './bff-security.js';
import { computeSha256Base64Url } from './bff-security.js';

interface SettledRefreshEntry {
  readonly value: unknown;
  readonly expiresAtMs: number;
}

interface RefreshGraceStore {
  readonly inFlightRefreshes: Map<string, Promise<unknown>>;
  readonly settledRefreshes: Map<string, SettledRefreshEntry>;
  readonly timers: Map<string, ReturnType<typeof setTimeout>>;
}

const REFRESH_GRACE_GLOBAL_SYMBOL = Symbol.for('witsauth.bff.refreshGrace');
const MAX_SETTLED_REFRESH_ENTRIES = 512;
const DEFAULT_REFRESH_GRACE_TTL_MS = 15_000;

function getRefreshGraceStore(): RefreshGraceStore {
  const holder = globalThis as Record<symbol, RefreshGraceStore | undefined>;
  let existing = holder[REFRESH_GRACE_GLOBAL_SYMBOL];
  if (!existing) {
    existing = {
      inFlightRefreshes: new Map<string, Promise<unknown>>(),
      settledRefreshes: new Map<string, SettledRefreshEntry>(),
      timers: new Map<string, ReturnType<typeof setTimeout>>(),
    };
    holder[REFRESH_GRACE_GLOBAL_SYMBOL] = existing;
  }
  return existing;
}

function clearTimerForKey(store: RefreshGraceStore, key: string): void {
  const existingTimer = store.timers.get(key);
  if (existingTimer !== undefined) {
    globalThis.clearTimeout(existingTimer);
    store.timers.delete(key);
  }
}

function pruneSettledRefreshes(store: RefreshGraceStore, nowMs: number): void {
  for (const [k, entry] of store.settledRefreshes.entries()) {
    if (entry.expiresAtMs <= nowMs) {
      store.settledRefreshes.delete(k);
      clearTimerForKey(store, k);
    }
  }
  while (store.settledRefreshes.size >= MAX_SETTLED_REFRESH_ENTRIES) {
    const oldestKey = store.settledRefreshes.keys().next().value;
    if (oldestKey === undefined) {
      break;
    }
    store.settledRefreshes.delete(oldestKey);
    clearTimerForKey(store, oldestKey);
  }
}

export function clearRefreshGraceCacheForTesting(): void {
  const store = getRefreshGraceStore();
  for (const timer of store.timers.values()) {
    globalThis.clearTimeout(timer);
  }
  store.timers.clear();
  store.inFlightRefreshes.clear();
  store.settledRefreshes.clear();
}

export function getRefreshGraceCacheStatsForTesting(): {
  readonly inFlightCount: number;
  readonly settledCount: number;
  readonly timerCount: number;
} {
  const store = getRefreshGraceStore();
  return {
    inFlightCount: store.inFlightRefreshes.size,
    settledCount: store.settledRefreshes.size,
    timerCount: store.timers.size,
  };
}

/**
 * Single-flight OIDC refresh deduplicator backed by a process-wide
 * `globalThis[Symbol.for('witsauth.bff.refreshGrace')]` registry with a 15-second
 * post-settlement grace window. Upfront expiry pruning + `.unref()` timers ensure
 * settled token pairs are never retained past TTL.
 */
export async function singleFlightRefreshOidcTokens<TResult>(
  refreshToken: string,
  refreshFn: () => Promise<TResult>,
  options?: {
    readonly appScope?: BffAppScope | undefined;
    readonly graceTtlMs?: number | undefined;
    readonly nowMs?: number | undefined;
  },
): Promise<TResult> {
  const store = getRefreshGraceStore();
  const scope = options?.appScope ?? 'default';
  const key = await computeSha256Base64Url(`${scope}:${refreshToken}`);
  const nowMs = options?.nowMs ?? Date.now();

  pruneSettledRefreshes(store, nowMs);

  const cached = store.settledRefreshes.get(key);
  if (cached && cached.expiresAtMs > nowMs) {
    return cached.value as TResult;
  }

  const existing = store.inFlightRefreshes.get(key) as Promise<TResult> | undefined;
  if (existing) {
    return existing;
  }

  const graceTtlMs = Math.max(0, options?.graceTtlMs ?? DEFAULT_REFRESH_GRACE_TTL_MS);
  const promise = (async () => {
    try {
      const result = await refreshFn();
      if (graceTtlMs > 0) {
        const settleNow = options?.nowMs ?? Date.now();
        clearTimerForKey(store, key);
        pruneSettledRefreshes(store, settleNow);
        store.settledRefreshes.set(key, {
          value: result,
          expiresAtMs: settleNow + graceTtlMs,
        });
        const timer = globalThis.setTimeout(() => {
          store.settledRefreshes.delete(key);
          store.timers.delete(key);
        }, graceTtlMs);
        (timer as { unref?: () => void }).unref?.();
        store.timers.set(key, timer);
      }
      return result;
    } finally {
      store.inFlightRefreshes.delete(key);
    }
  })();

  store.inFlightRefreshes.set(key, promise);
  return promise;
}

export interface UpstreamErrorInfo {
  readonly statusCode: number | undefined;
  readonly errorCode: string | undefined;
  readonly message: string | undefined;
  readonly isTransientOutage: boolean;
}

/**
 * Extracts HTTP/network failure metadata from arbitrary SDK/transport/Fetch errors.
 */
export function extractUpstreamErrorInfo(error: unknown): UpstreamErrorInfo {
  const errObj =
    error !== null && typeof error === 'object' ? (error as Record<string, unknown>) : undefined;
  const rawStatusCode = errObj?.['statusCode'];
  const rawStatus = errObj?.['status'];
  const statusCode =
    typeof rawStatusCode === 'number' && Number.isFinite(rawStatusCode)
      ? rawStatusCode
      : typeof rawStatus === 'number' && Number.isFinite(rawStatus)
        ? rawStatus
        : undefined;

  const rawErrorCode = errObj?.['errorCode'] ?? errObj?.['code'];
  const errorCode = typeof rawErrorCode === 'string' && rawErrorCode.length > 0 ? rawErrorCode : undefined;

  const rawMessage = errObj?.['message'];
  const message =
    typeof rawMessage === 'string' && rawMessage.length > 0
      ? rawMessage
      : error instanceof Error
        ? error.message
        : undefined;

  const errName =
    error instanceof Error
      ? error.name
      : typeof errObj?.['name'] === 'string'
        ? errObj['name']
        : '';

  const isTransientOutage =
    statusCode === 0 ||
    (typeof statusCode === 'number' && statusCode >= 500) ||
    error instanceof TypeError ||
    errName === 'AbortError' ||
    errName === 'TimeoutError';

  return {
    statusCode,
    errorCode,
    message,
    isTransientOutage,
  };
}

/**
 * Returns `true` only when a refresh failure proves the refresh token is invalid/revoked (`400`/`401`/`403`).
 * Transient `5xx` or network errors return `false` so active sessions are not wiped during API blips.
 */
export function isTerminalRefreshAuthError(error: unknown): boolean {
  const info = extractUpstreamErrorInfo(error);
  return info.statusCode === 400 || info.statusCode === 401 || info.statusCode === 403;
}

export interface BffCookieSerializeOptions {
  readonly maxAgeSeconds: number;
  readonly secure: boolean;
  readonly httpOnly?: boolean | undefined;
  readonly sameSite?: 'Lax' | 'Strict' | undefined;
  readonly path?: string | undefined;
}

export function serializeBffSetCookie(
  name: string,
  value: string,
  options: BffCookieSerializeOptions,
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${options.path ?? '/'}`,
    `Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`,
    `SameSite=${options.sameSite ?? 'Lax'}`,
  ];
  if (options.httpOnly !== false) {
    parts.push('HttpOnly');
  }
  if (options.secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}

export function applyRefreshedAuthCookies(
  headers: Pick<Headers, 'append'>,
  tokens: {
    readonly accessToken: string;
    readonly refreshToken?: string | undefined;
    readonly expiresInSeconds: number;
    readonly refreshExpiresInSeconds?: number | undefined;
  },
  config: {
    readonly accessCookieName: string;
    readonly refreshCookieName: string;
    readonly secure: boolean;
    readonly defaultRefreshMaxAgeSeconds?: number | undefined;
    readonly cookiePath?: string | undefined;
    readonly sameSite?: 'Lax' | 'Strict' | undefined;
  },
): void {
  const baseCookieOptions = {
    secure: config.secure,
    ...(config.cookiePath !== undefined ? { path: config.cookiePath } : {}),
    ...(config.sameSite !== undefined ? { sameSite: config.sameSite } : {}),
  };

  headers.append(
    'set-cookie',
    serializeBffSetCookie(config.accessCookieName, tokens.accessToken, {
      ...baseCookieOptions,
      maxAgeSeconds: Math.max(60, tokens.expiresInSeconds),
    }),
  );
  if (tokens.refreshToken) {
    headers.append(
      'set-cookie',
      serializeBffSetCookie(config.refreshCookieName, tokens.refreshToken, {
        ...baseCookieOptions,
        maxAgeSeconds: Math.max(
          60,
          tokens.refreshExpiresInSeconds ?? config.defaultRefreshMaxAgeSeconds ?? 30 * 24 * 60 * 60,
        ),
      }),
    );
  }
}

function escapeHtmlText(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function buildRefreshOutageHtmlResponse(retryHref: string): Response {
  const safeHref = escapeHtmlText(retryHref);
  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Session Temporarily Unavailable</title></head>
<body style="font-family:system-ui,sans-serif;max-width:520px;margin:48px auto;padding:24px;color:#0f172a;">
  <h1 style="font-size:1.25rem;margin-bottom:8px;">Authentication service temporarily unavailable</h1>
  <p style="line-height:1.5;color:#475569;">We could not reach the session service right now. Your existing session credentials were preserved.</p>
  <p style="margin-top:20px;"><a href="${safeHref}" style="display:inline-block;padding:10px 16px;background:#0f172a;color:#fff;text-decoration:none;border-radius:6px;">Retry session check</a></p>
</body>
</html>`;
  return new Response(html, {
    status: 503,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'private, no-store',
    },
  });
}
