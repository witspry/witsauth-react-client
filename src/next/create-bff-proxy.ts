import {
  assertSameOriginMutation,
  generateSecureTokenBase64Url,
  getRequestUrlParts,
  readRequestCookie,
  signGuestSessionId,
  verifySignedGuestSessionId,
  type CookieReadableRequest,
} from './bff-security.js';
import {
  applyRefreshedAuthCookies,
  isTerminalRefreshAuthError,
  serializeBffSetCookie,
  singleFlightRefreshOidcTokens,
} from './refresh-grace.js';

export interface BffIncomingRequest extends CookieReadableRequest {
  readonly method: string;
  readonly body?: ReadableStream<Uint8Array> | null | undefined;
  readonly arrayBuffer: () => Promise<ArrayBuffer>;
}

export interface BffRouteParamsContext {
  readonly params: Promise<{ readonly path: readonly string[] }>;
}

export interface RefreshedBffSessionTokens {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
  readonly refreshToken?: string | undefined;
  readonly refreshExpiresInSeconds?: number | undefined;
}

export interface CreateBffProxyConfig {
  readonly appLabel: string;
  readonly serviceName?: string | undefined;
  readonly getApiOrigin: () => string;
  readonly getPublicOrigin: (requestOrigin: string) => string;
  readonly isSecureCookie: () => boolean;
  readonly isDevelopment?: (() => boolean) | undefined;
  readonly getCookieSecret?: (() => string) | undefined;
  readonly trustedClientIpHeader?: string | (() => string | undefined) | undefined;
  readonly accessCookieName: string;
  readonly refreshCookieName: string;
  readonly impersonationCookieName?: string | undefined;
  readonly guestSessionCookieName?: string | undefined;
  readonly defaultRefreshMaxAgeSeconds?: number | undefined;
  readonly allowedFirstSegments: ReadonlySet<string>;
  readonly extraForwardedRequestHeaders?: readonly string[] | undefined;
  readonly maxBodyBytes?: number | undefined;
  readonly maxResponseBytes?: number | undefined;
  readonly upstreamTimeoutMs?: number | undefined;
  readonly guardRoute?: (
    pathInfo: {
      readonly joined: string;
      readonly firstSegment: string;
      readonly method: string;
    },
    request: BffIncomingRequest,
  ) => Response | null | Promise<Response | null>;
  readonly refreshSession?:
    | ((refreshToken: string) => Promise<RefreshedBffSessionTokens>)
    | undefined;
  readonly fetchImpl?: typeof globalThis.fetch | undefined;
}

const DEFAULT_FORWARDED_REQUEST_HEADERS = [
  'accept',
  'content-type',
  'idempotency-key',
  'x-correlation-id',
] as const;

const FORWARDED_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'cache-control',
  'x-correlation-id',
  'retry-after',
] as const;

class StreamByteLimitExceededError extends Error {
  public constructor(public readonly maxBytes: number) {
    super(`Stream exceeded maximum allowed ${maxBytes} bytes.`);
    this.name = 'StreamByteLimitExceededError';
  }
}

async function readStreamWithByteLimit(
  stream: ReadableStream<Uint8Array> | null | undefined,
  fallbackArrayBuffer: () => Promise<ArrayBuffer>,
  maxBytes: number,
): Promise<Uint8Array> {
  if (stream && typeof stream.getReader === 'function') {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value && value.byteLength > 0) {
          totalBytes += value.byteLength;
          if (totalBytes > maxBytes) {
            try {
              await reader.cancel('BYTE_LIMIT_EXCEEDED');
            } catch {
              // Ignore reader cancellation errors
            }
            throw new StreamByteLimitExceededError(maxBytes);
          }
          chunks.push(value);
        }
      }
    } finally {
      reader.releaseLock();
    }
    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return merged;
  }

  const buf = await fallbackArrayBuffer();
  if (buf.byteLength > maxBytes) {
    throw new StreamByteLimitExceededError(maxBytes);
  }
  return new Uint8Array(buf);
}

function jsonErrorResponse(
  status: number,
  code: string,
  message: string,
  setCookies: readonly string[] = [],
): Response {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'private, no-store',
  });
  for (const cookie of setCookies) {
    headers.append('set-cookie', cookie);
  }
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers,
  });
}

function validateAndNormalizePathSegments(
  rawPathname: string,
  segments: readonly string[],
):
  | { readonly ok: true; readonly joined: string; readonly firstSegment: string }
  | { readonly ok: false } {
  if (
    !Array.isArray(segments) ||
    segments.length === 0 ||
    rawPathname.includes('\\') ||
    rawPathname.includes('//') ||
    /%(?:2e|2f|5c|00)/i.test(rawPathname)
  ) {
    return { ok: false };
  }

  const encodedSegments: string[] = [];
  for (const seg of segments) {
    if (
      typeof seg !== 'string' ||
      seg.length === 0 ||
      seg.length > 256 ||
      seg === '.' ||
      seg === '..' ||
      /[/\\%\x00-\x1f\x7f]/.test(seg)
    ) {
      return { ok: false };
    }
    encodedSegments.push(encodeURIComponent(seg));
  }

  return {
    ok: true,
    joined: encodedSegments.join('/'),
    firstSegment: segments[0] ?? '',
  };
}

/**
 * Shared hardened BFF `/api/v1/[...path]` proxy factory.
 * Enforces segment traversal rejection, route-prefix allowlists, custom route guards,
 * CSRF Origin / Fetch Metadata checks, single-flight OIDC token refresh with 15s grace cache,
 * HMAC-signed guest session cookies, untrusted `X-Forwarded-For` stripping,
 * streaming 1 MiB request / 15 MiB response caps, upstream stream cancellation on fast-path
 * oversized `Content-Length`, and `Cache-Control: private, no-store`.
 */
export function createBffProxy(
  config: CreateBffProxyConfig,
): (request: BffIncomingRequest, context: BffRouteParamsContext) => Promise<Response> {
  const maxBodyBytes = config.maxBodyBytes ?? 1_048_576;
  const maxResponseBytes = config.maxResponseBytes ?? 15 * 1024 * 1024;
  const timeoutMs = config.upstreamTimeoutMs ?? 15_000;
  const appScope = config.appLabel.toLowerCase();
  const serviceLabel = config.serviceName ?? `${config.appLabel} API`;
  const defaultRefreshMaxAgeSeconds = config.defaultRefreshMaxAgeSeconds ?? 30 * 24 * 60 * 60;
  const forwardedReqHeaders = [
    ...DEFAULT_FORWARDED_REQUEST_HEADERS,
    ...(config.extraForwardedRequestHeaders ?? []),
  ];

  return async function handleBffProxyRequest(
    request: BffIncomingRequest,
    context: BffRouteParamsContext,
  ): Promise<Response> {
    const { path } = await context.params;
    const urlParts = getRequestUrlParts(request);
    const pathCheck = validateAndNormalizePathSegments(urlParts.pathname, path);
    if (!pathCheck.ok) {
      return jsonErrorResponse(
        400,
        'INVALID_PROXY_PATH',
        'Invalid or unsafe API path segment rejected by BFF proxy.',
      );
    }

    if (!config.allowedFirstSegments.has(pathCheck.firstSegment)) {
      return jsonErrorResponse(
        403,
        'FORBIDDEN_PROXY_ROUTE',
        `Route prefix '/api/v1/${pathCheck.firstSegment}' is not permitted through the ${config.appLabel} BFF proxy.`,
      );
    }

    if (config.guardRoute) {
      const guardResult = await config.guardRoute(
        {
          joined: pathCheck.joined,
          firstSegment: pathCheck.firstSegment,
          method: request.method.toUpperCase(),
        },
        request,
      );
      if (guardResult) {
        return guardResult;
      }
    }

    let publicOrigin: string;
    let apiOrigin: string;
    let secureCookie: boolean;
    let cookieSecret: string | undefined;
    let trustedIpHeader: string | undefined;
    try {
      publicOrigin = config.getPublicOrigin(urlParts.origin);
      apiOrigin = config.getApiOrigin();
      secureCookie = config.isSecureCookie();
      cookieSecret = config.getCookieSecret ? config.getCookieSecret() : undefined;
      const rawTrustedIpHeader =
        typeof config.trustedClientIpHeader === 'function'
          ? config.trustedClientIpHeader()
          : config.trustedClientIpHeader;
      trustedIpHeader = rawTrustedIpHeader?.trim() || undefined;
    } catch {
      return jsonErrorResponse(
        500,
        'BFF_CONFIG_ERROR',
        'BFF proxy environment configuration is incomplete or invalid.',
      );
    }

    const earlyOriginCheck = assertSameOriginMutation(request, publicOrigin, { hasBody: false });
    if (!earlyOriginCheck.ok) {
      return jsonErrorResponse(
        earlyOriginCheck.status,
        earlyOriginCheck.code,
        earlyOriginCheck.message,
      );
    }

    const methodUpper = request.method.toUpperCase();
    const mayHaveBody = methodUpper !== 'GET' && methodUpper !== 'HEAD';
    let bodyBytes: Uint8Array | undefined;

    if (mayHaveBody) {
      const declaredLen = Number(request.headers.get('content-length') ?? '0');
      if (Number.isFinite(declaredLen) && declaredLen > maxBodyBytes) {
        return jsonErrorResponse(
          413,
          'PAYLOAD_TOO_LARGE',
          `Request payload exceeds the maximum allowed ${maxBodyBytes} bytes.`,
        );
      }
      try {
        bodyBytes = await readStreamWithByteLimit(
          request.body,
          () => request.arrayBuffer(),
          maxBodyBytes,
        );
      } catch (err) {
        if (err instanceof StreamByteLimitExceededError) {
          return jsonErrorResponse(
            413,
            'PAYLOAD_TOO_LARGE',
            `Request payload exceeds the maximum allowed ${maxBodyBytes} bytes.`,
          );
        }
        throw err;
      }
      if (bodyBytes.byteLength > 0) {
        const ctCheck = assertSameOriginMutation(request, publicOrigin, {
          hasBody: true,
          requireJsonContentType: true,
        });
        if (!ctCheck.ok) {
          return jsonErrorResponse(ctCheck.status, ctCheck.code, ctCheck.message);
        }
      }
    }

    const pendingSetCookies: string[] = [];

    const headers = new Headers();
    for (const headerName of forwardedReqHeaders) {
      const value = request.headers.get(headerName);
      if (value) {
        headers.set(headerName, value);
      }
    }

    // Never trust raw client-supplied X-Forwarded-For / X-Real-IP headers.
    if (trustedIpHeader) {
      const trustedRaw = request.headers.get(trustedIpHeader)?.trim();
      const firstIp = trustedRaw?.split(',')[0]?.trim();
      if (firstIp) {
        headers.set('x-forwarded-for', firstIp);
      }
    }

    const userAgent = request.headers.get('user-agent')?.trim();
    if (userAgent) {
      headers.set('user-agent', userAgent);
    }

    let hasGuestSession = false;
    if (config.guestSessionCookieName) {
      hasGuestSession = true;
      const existingCookie = readRequestCookie(request, config.guestSessionCookieName);
      const verifiedGuestSid =
        cookieSecret && existingCookie
          ? await verifySignedGuestSessionId(existingCookie, cookieSecret)
          : null;

      if (verifiedGuestSid) {
        headers.set('x-guest-session-id', verifiedGuestSid);
      } else {
        const freshGuestSid = `se_guest_${generateSecureTokenBase64Url(18)}`;
        const cookieValueToSet = cookieSecret
          ? await signGuestSessionId(freshGuestSid, cookieSecret)
          : freshGuestSid;
        pendingSetCookies.push(
          serializeBffSetCookie(config.guestSessionCookieName, cookieValueToSet, {
            maxAgeSeconds: 30 * 24 * 60 * 60,
            secure: secureCookie,
          }),
        );
        headers.set('x-guest-session-id', freshGuestSid);
      }
    }

    const impToken = config.impersonationCookieName
      ? readRequestCookie(request, config.impersonationCookieName)
      : undefined;
    let accessToken = readRequestCookie(request, config.accessCookieName);
    const refreshToken = readRequestCookie(request, config.refreshCookieName);
    let refreshedInThisRequest = false;

    const queueRotatedCookies = (refreshed: RefreshedBffSessionTokens): void => {
      applyRefreshedAuthCookies(
        {
          append: (_name, value) => {
            pendingSetCookies.push(value);
          },
        },
        refreshed,
        {
          accessCookieName: config.accessCookieName,
          refreshCookieName: config.refreshCookieName,
          secure: secureCookie,
          defaultRefreshMaxAgeSeconds,
        },
      );
    };

    const queueClearSessionCookies = (): void => {
      pendingSetCookies.push(
        serializeBffSetCookie(config.accessCookieName, '', {
          maxAgeSeconds: 0,
          secure: secureCookie,
        }),
      );
      pendingSetCookies.push(
        serializeBffSetCookie(config.refreshCookieName, '', {
          maxAgeSeconds: 0,
          secure: secureCookie,
        }),
      );
    };

    if (!impToken && !accessToken && refreshToken && config.refreshSession) {
      refreshedInThisRequest = true;
      const refreshFn = config.refreshSession;
      try {
        const refreshed = await singleFlightRefreshOidcTokens(
          refreshToken,
          () => refreshFn(refreshToken),
          { appScope },
        );
        accessToken = refreshed.accessToken;
        queueRotatedCookies(refreshed);
      } catch (refreshErr) {
        if (isTerminalRefreshAuthError(refreshErr)) {
          queueClearSessionCookies();
        }
      }
    }

    const effectiveBearer = impToken ?? accessToken;
    if (effectiveBearer) {
      headers.set('authorization', `Bearer ${effectiveBearer}`);
    }

    const upstreamUrl = `${apiOrigin}/api/v1/${pathCheck.joined}${urlParts.search}`;
    const fetchFn = config.fetchImpl ?? globalThis.fetch.bind(globalThis);

    const runFetchOnce = async (currentHeaders: Headers): Promise<Response> => {
      const requestBodyCopy =
        bodyBytes && bodyBytes.byteLength > 0 ? new Uint8Array(bodyBytes) : undefined;
      return fetchFn(upstreamUrl, {
        method: methodUpper,
        headers: currentHeaders,
        ...(requestBodyCopy ? { body: requestBodyCopy } : {}),
        cache: 'no-store',
        signal: AbortSignal.timeout(timeoutMs),
      });
    };

    try {
      let upstream = await runFetchOnce(headers);

      if (
        upstream.status === 401 &&
        !impToken &&
        accessToken &&
        refreshToken &&
        !refreshedInThisRequest &&
        config.refreshSession
      ) {
        refreshedInThisRequest = true;
        const refreshFn = config.refreshSession;
        let refreshedTokens: RefreshedBffSessionTokens | undefined;
        try {
          refreshedTokens = await singleFlightRefreshOidcTokens(
            refreshToken,
            () => refreshFn(refreshToken),
            { appScope },
          );
        } catch (refreshErr) {
          if (isTerminalRefreshAuthError(refreshErr)) {
            queueClearSessionCookies();
          }
        }
        // Execute post-refresh retry OUTSIDE the refresh catch block so retry timeouts
        // surface cleanly as 504 UPSTREAM_API_TIMEOUT rather than returning stale 401.
        if (refreshedTokens) {
          accessToken = refreshedTokens.accessToken;
          queueRotatedCookies(refreshedTokens);
          const retryHeaders = new Headers(headers);
          retryHeaders.set('authorization', `Bearer ${refreshedTokens.accessToken}`);
          await upstream.body?.cancel().catch(() => undefined);
          upstream = await runFetchOnce(retryHeaders);
        }
      }

      const responseHeaders = new Headers();
      for (const headerName of FORWARDED_RESPONSE_HEADERS) {
        const val = upstream.headers.get(headerName);
        if (val) {
          responseHeaders.set(headerName, val);
        }
      }

      const hadAuthContext = Boolean(impToken || accessToken || refreshToken || hasGuestSession);
      if (hadAuthContext || pendingSetCookies.length > 0) {
        responseHeaders.set('cache-control', 'private, no-store');
        responseHeaders.set('vary', 'Cookie, Origin, Sec-Fetch-Site');
      }

      for (const cookie of pendingSetCookies) {
        responseHeaders.append('set-cookie', cookie);
      }

      if (upstream.status === 204 || upstream.status === 205 || upstream.status === 304) {
        await upstream.body?.cancel().catch(() => undefined);
        return new Response(null, { status: upstream.status, headers: responseHeaders });
      }

      const declaredRespLen = Number(upstream.headers.get('content-length') ?? '0');
      if (Number.isFinite(declaredRespLen) && declaredRespLen > maxResponseBytes) {
        // R6-L3.5: Cancel upstream socket/stream immediately before returning 502 fast-path.
        await upstream.body?.cancel().catch(() => undefined);
        return jsonErrorResponse(
          502,
          'UPSTREAM_RESPONSE_TOO_LARGE',
          `Upstream API response exceeded the maximum allowed ${maxResponseBytes} bytes.`,
          pendingSetCookies,
        );
      }

      const payloadBytes = await readStreamWithByteLimit(
        upstream.body,
        () => upstream.arrayBuffer(),
        maxResponseBytes,
      );
      const bodyView = new Uint8Array(payloadBytes.byteLength);
      bodyView.set(payloadBytes);
      return new Response(bodyView, {
        status: upstream.status,
        headers: responseHeaders,
      });
    } catch (err) {
      if (err instanceof StreamByteLimitExceededError) {
        return jsonErrorResponse(
          502,
          'UPSTREAM_RESPONSE_TOO_LARGE',
          `Upstream API response exceeded the maximum allowed ${maxResponseBytes} bytes.`,
          pendingSetCookies,
        );
      }
      const errName = err instanceof Error ? err.name : '';
      if (errName === 'TimeoutError' || errName === 'AbortError') {
        return jsonErrorResponse(
          504,
          'UPSTREAM_API_TIMEOUT',
          `${serviceLabel} timed out after ${Math.round(timeoutMs / 1000)}s.`,
          pendingSetCookies,
        );
      }
      return jsonErrorResponse(
        502,
        'UPSTREAM_API_UNREACHABLE',
        `${serviceLabel} is temporarily unreachable. Please retry shortly.`,
        pendingSetCookies,
      );
    }
  };
}

export const createWitsAuthBffApiProxy = createBffProxy;
