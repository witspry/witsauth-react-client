import {
  getRequestUrlParts,
  readRequestCookie,
  sanitizeRelativeReturnTo,
  type BffAppScope,
  type CookieReadableRequest,
} from './bff-security.js';
import {
  applyRefreshedAuthCookies,
  isTerminalRefreshAuthError,
  serializeBffSetCookie,
  singleFlightRefreshOidcTokens,
} from './refresh-grace.js';

export interface NextProxyRefreshedTokens {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
  readonly refreshToken?: string | undefined;
  readonly refreshExpiresInSeconds?: number | undefined;
}

export interface WitsAuthNextProxyConfig<
  TResponse extends { readonly headers: Headers } = Response,
> {
  readonly appScope: BffAppScope;
  readonly loginPath: string;
  readonly defaultReturnTo: string;
  readonly accessCookieName: string;
  readonly refreshCookieName: string;
  readonly impersonationCookieName?: string | undefined;
  readonly isSecureCookie: () => boolean;
  readonly refreshTokens: (
    refreshToken: string,
    request: CookieReadableRequest,
  ) => Promise<NextProxyRefreshedTokens>;
  readonly validateRefreshedSession?: (
    tokens: NextProxyRefreshedTokens,
    request: CookieReadableRequest,
  ) => Promise<boolean>;
  readonly next: (forwardedHeaders?: Headers) => TResponse;
  readonly redirect: (url: URL, status: 302 | 303 | 307) => TResponse;
  readonly defaultRefreshMaxAgeSeconds?: number | undefined;
  readonly cookiePath?: string | undefined;
  readonly sameSite?: 'Lax' | 'Strict' | undefined;
  readonly publicPathPrefixes?: readonly string[] | undefined;
}

const STATIC_PUBLIC_ASSET_RE =
  /\.(?:ico|svg|png|jpg|jpeg|gif|webp|avif|txt|xml|webmanifest|woff2?)$/i;

function injectCookieHeader(
  existingCookieHeader: string | null,
  name: string,
  value: string,
): string {
  const filtered = (existingCookieHeader ?? '')
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0 && !part.startsWith(`${name}=`));
  filtered.push(`${name}=${encodeURIComponent(value)}`);
  return filtered.join('; ');
}

function isSafeInlineNavigationRequest(request: CookieReadableRequest): boolean {
  const secFetchSite = request.headers.get('sec-fetch-site')?.trim().toLowerCase();
  const secFetchMode = request.headers.get('sec-fetch-mode')?.trim().toLowerCase();
  const secFetchDest = request.headers.get('sec-fetch-dest')?.trim().toLowerCase();
  return (
    (secFetchSite === 'same-origin' || secFetchSite === 'none') &&
    (!secFetchMode || secFetchMode === 'navigate') &&
    (!secFetchDest || secFetchDest === 'document')
  );
}

/**
 * Middleware / Next.js 16 `proxy.ts` factory guarding SSR routes with fail-closed auth checks
 * and inline single-use OIDC token rotation gated on safe direct Fetch Metadata (`same-origin` / `none`).
 */
export function createWitsAuthNextProxy<TResponse extends { readonly headers: Headers }>(
  config: WitsAuthNextProxyConfig<TResponse>,
): (request: CookieReadableRequest) => Promise<TResponse> {
  const normalizedLoginPath = config.loginPath.replace(/\/+$/, '') || '/login';
  const defaultRefreshMaxAgeSeconds = config.defaultRefreshMaxAgeSeconds ?? 12 * 60 * 60;

  return async function handleWitsAuthProxy(request: CookieReadableRequest): Promise<TResponse> {
    const urlParts = getRequestUrlParts(request);
    const { pathname, search } = urlParts;

    if (
      pathname === normalizedLoginPath ||
      pathname.startsWith(`${normalizedLoginPath}/`) ||
      pathname.startsWith('/api/') ||
      pathname.startsWith('/_next/') ||
      pathname === '/favicon.ico' ||
      pathname === '/robots.txt' ||
      pathname === '/sitemap.xml' ||
      STATIC_PUBLIC_ASSET_RE.test(pathname) ||
      config.publicPathPrefixes?.some((prefix) => pathname.startsWith(prefix))
    ) {
      return config.next();
    }

    const impToken = config.impersonationCookieName
      ? readRequestCookie(request, config.impersonationCookieName)
      : undefined;
    const accessToken = readRequestCookie(request, config.accessCookieName);
    const refreshToken = readRequestCookie(request, config.refreshCookieName);

    const buildLoginRedirect = (authError?: string): TResponse => {
      const loginUrl = new URL(normalizedLoginPath, request.url);
      const returnTo = sanitizeRelativeReturnTo(`${pathname}${search}`, config.defaultReturnTo);
      loginUrl.searchParams.set('returnTo', returnTo);
      if (authError) {
        loginUrl.searchParams.set('authError', authError);
      }
      return config.redirect(loginUrl, 307);
    };

    if (!impToken && !accessToken && !refreshToken) {
      return buildLoginRedirect();
    }

    if (!impToken && !accessToken && refreshToken) {
      // R6-M3: Never rotate a single-use refresh token inline on cross-site, same-site,
      // or prefetch/non-document requests; let the guarded route bounce to /login cleanly.
      if (!isSafeInlineNavigationRequest(request)) {
        return config.next();
      }

      let secureCookie = true;
      try {
        secureCookie = config.isSecureCookie();
      } catch {
        return config.next();
      }

      const appendClearedCookies = (headers: Headers): void => {
        const cookieOpts = {
          maxAgeSeconds: 0,
          secure: secureCookie,
          ...(config.cookiePath !== undefined ? { path: config.cookiePath } : {}),
          ...(config.sameSite !== undefined ? { sameSite: config.sameSite } : {}),
        };
        headers.append('set-cookie', serializeBffSetCookie(config.accessCookieName, '', cookieOpts));
        headers.append(
          'set-cookie',
          serializeBffSetCookie(config.refreshCookieName, '', cookieOpts),
        );
      };

      try {
        const refreshed = await singleFlightRefreshOidcTokens(
          refreshToken,
          () => config.refreshTokens(refreshToken, request),
          { appScope: config.appScope },
        );

        if (config.validateRefreshedSession) {
          const allowed = await config.validateRefreshedSession(refreshed, request);
          if (!allowed) {
            const deniedRes = buildLoginRedirect('forbidden_staff_role');
            appendClearedCookies(deniedRes.headers);
            return deniedRes;
          }
        }

        // Preserve original request headers without mutating request.headers directly.
        const combinedHeaders = new Headers();
        const headerSource = request.headers as unknown as {
          forEach?: (cb: (val: string, key: string) => void) => void;
        };
        if (typeof headerSource.forEach === 'function') {
          headerSource.forEach((val, key) => {
            combinedHeaders.set(key, val);
          });
        }
        let cookieHeader = injectCookieHeader(
          request.headers.get('cookie'),
          config.accessCookieName,
          refreshed.accessToken,
        );
        if (refreshed.refreshToken) {
          cookieHeader = injectCookieHeader(
            cookieHeader,
            config.refreshCookieName,
            refreshed.refreshToken,
          );
        }
        combinedHeaders.set('cookie', cookieHeader);

        const response = config.next(combinedHeaders);
        applyRefreshedAuthCookies(response.headers, refreshed, {
          accessCookieName: config.accessCookieName,
          refreshCookieName: config.refreshCookieName,
          secure: secureCookie,
          defaultRefreshMaxAgeSeconds,
          ...(config.cookiePath !== undefined ? { cookiePath: config.cookiePath } : {}),
          ...(config.sameSite !== undefined ? { sameSite: config.sameSite } : {}),
        });
        return response;
      } catch (err) {
        if (isTerminalRefreshAuthError(err)) {
          const redirectRes = buildLoginRedirect();
          appendClearedCookies(redirectRes.headers);
          return redirectRes;
        }
        // Transient 5xx / network error: preserve cookies and allow protected route recovery UI.
        return config.next();
      }
    }

    return config.next();
  };
}
