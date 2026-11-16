import { decodeJwtPayload } from '../core/pkce.js';
import {
  assertBrowserNavigationFetchMetadata,
  assertSameOriginMutation,
  computeSha256Base64Url,
  constantTimeEqualStrings,
  FETCH_METADATA_VARY_HEADER,
  generateSecureTokenBase64Url,
  getRequestUrlParts,
  readRequestCookie,
  sanitizeRelativeReturnTo,
  signImpersonationHandoffConsume,
  signPkceCookiePayload,
  verifySignedGuestSessionId,
  verifySignedPkceCookiePayload,
  type BffAppScope,
  type CookieReadableRequest,
} from './bff-security.js';
import {
  applyRefreshedAuthCookies,
  buildRefreshOutageHtmlResponse,
  extractUpstreamErrorInfo,
  isTerminalRefreshAuthError,
  serializeBffSetCookie,
  singleFlightRefreshOidcTokens,
} from './refresh-grace.js';

export interface BffRouteActionContext {
  readonly params: Promise<{ readonly action: readonly string[] }>;
}

export interface WitsAuthNextCookieConfig {
  readonly accessCookieName: string;
  readonly refreshCookieName: string;
  readonly pkceCookieName: string;
  readonly impersonationCookieName?: string | undefined;
  readonly guestSessionCookieName?: string | undefined;
  readonly cookiePath?: string | undefined;
  readonly sameSite?: 'Lax' | 'Strict' | undefined;
}

export interface ExchangedBffTokens {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
  readonly refreshToken?: string | undefined;
  readonly refreshExpiresInSeconds?: number | undefined;
  readonly idToken?: string | undefined;
  readonly user?: Record<string, unknown> | undefined;
}

export interface RefreshedBffSessionOutput {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
  readonly refreshToken?: string | undefined;
  readonly refreshExpiresInSeconds?: number | undefined;
}

export type FetchBffSessionHookResult =
  | { readonly ok: true; readonly data: Record<string, unknown> }
  | {
      readonly ok: false;
      readonly errorCode?: string | undefined;
      readonly errorMessage?: string | undefined;
    };

export type ValidateEstablishedSessionResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly errorCode: string;
      readonly errorMessage?: string | undefined;
    };

export interface ConsumeImpersonationHandoffResult {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
  readonly sessionId: string;
  readonly targetUserId: string;
  readonly ticketRef: string;
  readonly expiresAtEpochSec: number;
}

export interface CustomPostActionConfig {
  readonly hasBody?: boolean | undefined;
  readonly requireJsonContentType?: boolean | undefined;
  readonly handler: (
    request: CookieReadableRequest & {
      readonly method: string;
      readonly json: () => Promise<unknown>;
    },
    ctx: {
      readonly publicOrigin: string;
      readonly secureCookie: boolean;
    },
  ) => Promise<Response>;
}

export interface WitsAuthNextHandlerConfig {
  readonly appScope: BffAppScope;
  readonly cookies: WitsAuthNextCookieConfig;
  readonly getPublicOrigin: (requestOrigin: string) => string;
  readonly getCookieSecret: () => string;
  readonly getClientId: () => string;
  readonly getAuthorizeUrl: () => string;
  readonly isSecureCookie: () => boolean;
  readonly getClientSecret?: (() => string | undefined) | undefined;
  readonly getTokenEndpoint?: (() => string) | undefined;
  readonly getRevokeEndpoint?: (() => string) | undefined;
  readonly getUserInfoEndpoint?: (() => string) | undefined;
  readonly fetchImpl?: typeof globalThis.fetch | undefined;
  readonly callbackPath?: string | undefined;
  readonly loginPagePath?: string | undefined;
  readonly defaultReturnTo?: string | undefined;
  readonly callbackErrorRedirectPath?: string | undefined;
  readonly callbackErrorOnExchangeFailure?: 'errorRedirectPath' | 'returnTo' | undefined;
  readonly scope?: string | undefined;
  readonly pkceTtlSeconds?: number | undefined;
  readonly defaultRefreshMaxAgeSeconds?: number | undefined;
  readonly authorizeStaticParams?: Readonly<Record<string, string>> | undefined;
  readonly allowLoginHint?: boolean | undefined;
  readonly clearSiteDataHeader?: string | undefined;
  readonly enableRefreshSessionGet?: boolean | undefined;
  readonly enableClearSessionGet?: boolean | undefined;
  readonly enablePostRefresh?: boolean | undefined;
  readonly enablePostClearStaleSession?: boolean | undefined;
  readonly enableImpersonation?: boolean | undefined;
  readonly impersonationDefaultReturnTo?: string | undefined;
  readonly getImpersonationHmacSecret?: (() => string) | undefined;
  readonly allowedClearSessionErrors?: ReadonlySet<string> | undefined;
  readonly unauthenticatedSessionData?: Record<string, unknown> | undefined;
  readonly exchangeCode?: (input: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
    readonly expectedNonce: string;
    readonly guestSessionId?: string | undefined;
    readonly request: CookieReadableRequest;
  }) => Promise<ExchangedBffTokens>;
  readonly refreshTokens?: (input: {
    readonly refreshToken: string;
    readonly request: CookieReadableRequest;
  }) => Promise<RefreshedBffSessionOutput>;
  readonly revokeSession?: (input: {
    readonly accessToken?: string | undefined;
    readonly refreshToken?: string | undefined;
    readonly request: CookieReadableRequest;
  }) => Promise<{ readonly upstreamRevoked: boolean; readonly locallyRevoked: boolean }>;
  readonly fetchSession?: (input: {
    readonly accessToken: string;
    readonly isImpersonation: boolean;
    readonly request: CookieReadableRequest;
  }) => Promise<FetchBffSessionHookResult>;
  readonly validateEstablishedSession?: (input: {
    readonly accessToken: string;
    readonly exchanged?: ExchangedBffTokens | undefined;
    readonly request: CookieReadableRequest;
  }) => Promise<ValidateEstablishedSessionResult>;
  readonly decorateCallbackSuccessUrl?: (
    targetUrl: URL,
    exchanged: ExchangedBffTokens,
  ) => void;
  readonly consumeImpersonationHandoff?: (input: {
    readonly handoffCode: string;
    readonly origin: string;
    readonly bffHandoffSignature: string;
    readonly request: CookieReadableRequest;
  }) => Promise<ConsumeImpersonationHandoffResult>;
  readonly customPostActions?: Readonly<Record<string, CustomPostActionConfig>> | undefined;
}

const DEFAULT_CLEAR_SESSION_ERRORS = new Set([
  'forbidden_staff_role',
  'two_factor_required',
  'invalid_oidc_state',
  'oidc_exchange_failed',
]);

class UpstreamStatusError extends Error {
  public constructor(
    public readonly statusCode: number,
    public readonly errorCode: string,
    message: string,
  ) {
    super(message);
    this.name = 'UpstreamStatusError';
  }
}

function jsonResponse(
  status: number,
  body: unknown,
  extraHeaders?: Readonly<Record<string, string>>,
  setCookies: readonly string[] = [],
): Response {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'private, no-store',
  });
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) {
      headers.set(k, v);
    }
  }
  for (const cookie of setCookies) {
    headers.append('set-cookie', cookie);
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function jsonErrorResponse(
  status: number,
  code: string,
  message: string,
  extraHeaders?: Readonly<Record<string, string>>,
  setCookies: readonly string[] = [],
): Response {
  return jsonResponse(status, { error: { code, message } }, extraHeaders, setCookies);
}

function redirectResponse(
  location: string,
  status: 302 | 303 | 307,
  setCookies: readonly string[] = [],
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  const headers = new Headers({
    location,
    'cache-control': 'private, no-store',
  });
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) {
      headers.set(k, v);
    }
  }
  for (const cookie of setCookies) {
    headers.append('set-cookie', cookie);
  }
  return new Response(null, { status, headers });
}

function bffConfigErrorResponse(): Response {
  return jsonErrorResponse(
    500,
    'BFF_CONFIG_ERROR',
    'BFF session configuration is incomplete or invalid.',
  );
}

export function createWitsAuthNextHandler(config: WitsAuthNextHandlerConfig): {
  readonly GET: (
    request: CookieReadableRequest & { readonly method: string },
    context: BffRouteActionContext,
  ) => Promise<Response>;
  readonly POST: (
    request: CookieReadableRequest & {
      readonly method: string;
      readonly json: () => Promise<unknown>;
    },
    context: BffRouteActionContext,
  ) => Promise<Response>;
} {
  const callbackPath = config.callbackPath ?? '/api/auth/callback';
  const loginPagePath = config.loginPagePath ?? '/login';
  const defaultReturnTo = sanitizeRelativeReturnTo(config.defaultReturnTo, '/');
  const callbackErrorRedirectPath = config.callbackErrorRedirectPath ?? loginPagePath;
  const scope = config.scope ?? 'openid profile email offline_access';
  const pkceTtlSeconds = config.pkceTtlSeconds ?? 600;
  const defaultRefreshMaxAgeSeconds = config.defaultRefreshMaxAgeSeconds ?? 30 * 24 * 60 * 60;
  const allowedClearSessionErrors = config.allowedClearSessionErrors ?? DEFAULT_CLEAR_SESSION_ERRORS;
  const clearSiteDataHeader = config.clearSiteDataHeader ?? '"cookies", "storage", "cache"';
  const unauthenticatedData = config.unauthenticatedSessionData ?? {
    isAuthenticated: false,
    user: null,
  };

  const getFetch = () => config.fetchImpl ?? globalThis.fetch.bind(globalThis);

  const deleteCookieString = (
    name: string,
    secure: boolean,
  ): string =>
    serializeBffSetCookie(name, '', {
      maxAgeSeconds: 0,
      secure,
      ...(config.cookies.cookiePath !== undefined ? { path: config.cookies.cookiePath } : {}),
      ...(config.cookies.sameSite !== undefined ? { sameSite: config.cookies.sameSite } : {}),
    });

  const clearSessionCookieHeaders = (
    secure: boolean,
    opts?: { readonly includePkce?: boolean; readonly includeImpersonation?: boolean; readonly includeGuest?: boolean },
  ): string[] => {
    const out = [
      deleteCookieString(config.cookies.accessCookieName, secure),
      deleteCookieString(config.cookies.refreshCookieName, secure),
    ];
    if (opts?.includePkce) {
      out.push(deleteCookieString(config.cookies.pkceCookieName, secure));
    }
    if (opts?.includeImpersonation && config.cookies.impersonationCookieName) {
      out.push(deleteCookieString(config.cookies.impersonationCookieName, secure));
    }
    if (opts?.includeGuest && config.cookies.guestSessionCookieName) {
      out.push(deleteCookieString(config.cookies.guestSessionCookieName, secure));
    }
    return out;
  };

  const runExchangeCode = async (input: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
    readonly expectedNonce: string;
    readonly guestSessionId?: string | undefined;
    readonly request: CookieReadableRequest;
  }): Promise<ExchangedBffTokens> => {
    if (config.exchangeCode) {
      return config.exchangeCode(input);
    }
    const tokenEndpoint = config.getTokenEndpoint?.();
    if (!tokenEndpoint) {
      throw new Error('BFF OAuth tokenEndpoint or exchangeCode hook must be configured.');
    }
    const clientId = config.getClientId();
    const clientSecret = config.getClientSecret?.();
    const bodyParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirectUri,
      code_verifier: input.codeVerifier,
      ...(clientSecret ? {} : { client_id: clientId }),
    });
    const reqHeaders = new Headers({
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    });
    if (clientSecret) {
      reqHeaders.set('authorization', `Basic ${globalThis.btoa(`${clientId}:${clientSecret}`)}`);
    }
    const resp = await getFetch()(tokenEndpoint, {
      method: 'POST',
      headers: reqHeaders,
      body: bodyParams.toString(),
      cache: 'no-store',
    });
    if (!resp.ok) {
      throw new UpstreamStatusError(
        resp.status,
        'OIDC_EXCHANGE_FAILED',
        `Token endpoint failed with status ${resp.status}.`,
      );
    }
    const json = (await resp.json()) as Record<string, unknown>;
    const accessToken = json['access_token'];
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      throw new UpstreamStatusError(502, 'INVALID_TOKEN_RESPONSE', 'Missing access_token.');
    }
    const idToken = typeof json['id_token'] === 'string' ? json['id_token'] : undefined;
    if (input.expectedNonce && idToken) {
      const claims = decodeJwtPayload<Record<string, unknown>>(idToken);
      const claimNonce = claims?.['nonce'];
      if (
        typeof claimNonce !== 'string' ||
        !constantTimeEqualStrings(claimNonce, input.expectedNonce)
      ) {
        throw new UpstreamStatusError(401, 'INVALID_OIDC_NONCE', 'OIDC ID token nonce mismatch.');
      }
    }
    const expiresInSeconds =
      typeof json['expires_in'] === 'number' && Number.isFinite(json['expires_in'])
        ? json['expires_in']
        : 3600;
    const refreshToken =
      typeof json['refresh_token'] === 'string' && json['refresh_token'].length > 0
        ? json['refresh_token']
        : undefined;
    const refreshExpiresInSeconds =
      typeof json['refresh_expires_in'] === 'number' && Number.isFinite(json['refresh_expires_in'])
        ? json['refresh_expires_in']
        : undefined;
    const userClaims = decodeJwtPayload<Record<string, unknown>>(idToken ?? accessToken) ?? undefined;
    return {
      accessToken,
      expiresInSeconds,
      ...(refreshToken ? { refreshToken } : {}),
      ...(refreshExpiresInSeconds !== undefined ? { refreshExpiresInSeconds } : {}),
      ...(idToken ? { idToken } : {}),
      ...(userClaims ? { user: userClaims } : {}),
    };
  };

  const runRefreshTokens = async (input: {
    readonly refreshToken: string;
    readonly request: CookieReadableRequest;
  }): Promise<RefreshedBffSessionOutput> => {
    if (config.refreshTokens) {
      return config.refreshTokens(input);
    }
    const tokenEndpoint = config.getTokenEndpoint?.();
    if (!tokenEndpoint) {
      throw new Error('BFF OAuth tokenEndpoint or refreshTokens hook must be configured.');
    }
    const clientId = config.getClientId();
    const clientSecret = config.getClientSecret?.();
    const bodyParams = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: input.refreshToken,
      ...(clientSecret ? {} : { client_id: clientId }),
    });
    const reqHeaders = new Headers({
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    });
    if (clientSecret) {
      reqHeaders.set('authorization', `Basic ${globalThis.btoa(`${clientId}:${clientSecret}`)}`);
    }
    const resp = await getFetch()(tokenEndpoint, {
      method: 'POST',
      headers: reqHeaders,
      body: bodyParams.toString(),
      cache: 'no-store',
    });
    if (!resp.ok) {
      throw new UpstreamStatusError(
        resp.status,
        'REFRESH_FAILED',
        `Refresh token request failed with status ${resp.status}.`,
      );
    }
    const json = (await resp.json()) as Record<string, unknown>;
    const accessToken = json['access_token'];
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      throw new UpstreamStatusError(502, 'INVALID_TOKEN_RESPONSE', 'Missing access_token.');
    }
    const expiresInSeconds =
      typeof json['expires_in'] === 'number' && Number.isFinite(json['expires_in'])
        ? json['expires_in']
        : 3600;
    const rotatedRefresh =
      typeof json['refresh_token'] === 'string' && json['refresh_token'].length > 0
        ? json['refresh_token']
        : undefined;
    const refreshExpiresInSeconds =
      typeof json['refresh_expires_in'] === 'number' && Number.isFinite(json['refresh_expires_in'])
        ? json['refresh_expires_in']
        : undefined;
    return {
      accessToken,
      expiresInSeconds,
      ...(rotatedRefresh ? { refreshToken: rotatedRefresh } : {}),
      ...(refreshExpiresInSeconds !== undefined ? { refreshExpiresInSeconds } : {}),
    };
  };

  const runRevokeSession = async (input: {
    readonly accessToken?: string | undefined;
    readonly refreshToken?: string | undefined;
    readonly request: CookieReadableRequest;
  }): Promise<{ readonly upstreamRevoked: boolean; readonly locallyRevoked: boolean }> => {
    if (config.revokeSession) {
      return config.revokeSession(input);
    }
    const revokeEndpoint = config.getRevokeEndpoint?.();
    if (!revokeEndpoint) {
      return { upstreamRevoked: true, locallyRevoked: true };
    }
    const clientId = config.getClientId();
    const clientSecret = config.getClientSecret?.();
    const items = [
      ...(input.refreshToken
        ? [{ token: input.refreshToken, token_type_hint: 'refresh_token' }]
        : []),
      ...(input.accessToken
        ? [{ token: input.accessToken, token_type_hint: 'access_token' }]
        : []),
    ];
    let allOk = true;
    for (const item of items) {
      try {
        const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
        const params = new URLSearchParams({
          token: item.token,
          token_type_hint: item.token_type_hint,
          ...(clientSecret ? {} : { client_id: clientId }),
        });
        if (clientSecret) {
          headers.set('authorization', `Basic ${globalThis.btoa(`${clientId}:${clientSecret}`)}`);
        }
        const resp = await getFetch()(revokeEndpoint, {
          method: 'POST',
          headers,
          body: params.toString(),
          cache: 'no-store',
        });
        if (!resp.ok) {
          allOk = false;
        }
      } catch {
        allOk = false;
      }
    }
    return { upstreamRevoked: allOk, locallyRevoked: true };
  };

  const runFetchSession = async (input: {
    readonly accessToken: string;
    readonly isImpersonation: boolean;
    readonly request: CookieReadableRequest;
  }): Promise<FetchBffSessionHookResult> => {
    if (config.fetchSession) {
      return config.fetchSession(input);
    }
    const userInfoEndpoint = config.getUserInfoEndpoint?.();
    if (!userInfoEndpoint) {
      const claims = decodeJwtPayload<Record<string, unknown>>(input.accessToken);
      if (!claims) {
        return { ok: false, errorCode: 'UNAUTHENTICATED', errorMessage: 'Invalid access token.' };
      }
      return {
        ok: true,
        data: {
          isAuthenticated: true,
          user: claims,
        },
      };
    }
    const resp = await getFetch()(userInfoEndpoint, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${input.accessToken}`,
        accept: 'application/json',
      },
      cache: 'no-store',
    });
    if (!resp.ok) {
      throw new UpstreamStatusError(
        resp.status,
        resp.status === 401 ? 'UNAUTHENTICATED' : 'USERINFO_ERROR',
        `UserInfo request failed with status ${resp.status}.`,
      );
    }
    const user = (await resp.json()) as Record<string, unknown>;
    return {
      ok: true,
      data: {
        isAuthenticated: true,
        user,
      },
    };
  };

  const validateEstablished = async (input: {
    readonly accessToken: string;
    readonly exchanged?: ExchangedBffTokens | undefined;
    readonly request: CookieReadableRequest;
  }): Promise<ValidateEstablishedSessionResult> => {
    if (config.validateEstablishedSession) {
      return config.validateEstablishedSession(input);
    }
    if (config.fetchSession) {
      const me = await config.fetchSession({
        accessToken: input.accessToken,
        isImpersonation: false,
        request: input.request,
      });
      if (!me.ok) {
        return {
          ok: false,
          errorCode: me.errorCode ?? 'FORBIDDEN_STAFF_ROLE',
          ...(me.errorMessage ? { errorMessage: me.errorMessage } : {}),
        };
      }
    }
    return { ok: true };
  };

  const applyRotatedCookiesToArray = (
    tokens: {
      readonly accessToken: string;
      readonly refreshToken?: string | undefined;
      readonly expiresInSeconds: number;
      readonly refreshExpiresInSeconds?: number | undefined;
    },
    secure: boolean,
  ): string[] => {
    const out: string[] = [];
    applyRefreshedAuthCookies(
      {
        append: (_name, value) => {
          out.push(value);
        },
      },
      tokens,
      {
        accessCookieName: config.cookies.accessCookieName,
        refreshCookieName: config.cookies.refreshCookieName,
        secure,
        defaultRefreshMaxAgeSeconds,
        ...(config.cookies.cookiePath !== undefined ? { cookiePath: config.cookies.cookiePath } : {}),
        ...(config.cookies.sameSite !== undefined ? { sameSite: config.cookies.sameSite } : {}),
      },
    );
    return out;
  };

  async function handleLoginRedirect(request: CookieReadableRequest): Promise<Response> {
    const urlParts = getRequestUrlParts(request);
    let cookieSecret: string;
    let publicOrigin: string;
    let clientId: string;
    let authorizeBaseUrl: string;
    let secureCookie: boolean;
    try {
      cookieSecret = config.getCookieSecret();
      publicOrigin = config.getPublicOrigin(urlParts.origin);
      clientId = config.getClientId();
      authorizeBaseUrl = config.getAuthorizeUrl();
      secureCookie = config.isSecureCookie();
    } catch {
      return bffConfigErrorResponse();
    }

    const returnTo = sanitizeRelativeReturnTo(
      urlParts.searchParams.get('returnTo'),
      defaultReturnTo,
    );
    const loginHint =
      config.allowLoginHint !== false
        ? (
            urlParts.searchParams.get('loginHint') ?? urlParts.searchParams.get('login_hint')
          )?.trim()
        : undefined;

    const codeVerifier = generateSecureTokenBase64Url(32);
    const codeChallenge = await computeSha256Base64Url(codeVerifier);
    const state = generateSecureTokenBase64Url(24);
    const nonce = generateSecureTokenBase64Url(24);

    const authorizeUrl = new URL(authorizeBaseUrl);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('client_id', clientId);
    authorizeUrl.searchParams.set('redirect_uri', `${publicOrigin}${callbackPath}`);
    authorizeUrl.searchParams.set('scope', scope);
    authorizeUrl.searchParams.set('state', state);
    authorizeUrl.searchParams.set('nonce', nonce);
    authorizeUrl.searchParams.set('code_challenge', codeChallenge);
    authorizeUrl.searchParams.set('code_challenge_method', 'S256');
    if (config.authorizeStaticParams) {
      for (const [k, v] of Object.entries(config.authorizeStaticParams)) {
        authorizeUrl.searchParams.set(k, v);
      }
    }
    if (loginHint) {
      authorizeUrl.searchParams.set('login_hint', loginHint);
    }

    const signedPkce = await signPkceCookiePayload(
      {
        codeVerifier,
        state,
        nonce,
        returnTo,
        app: config.appScope,
        ttlSeconds: pkceTtlSeconds,
      },
      cookieSecret,
    );

    const pkceCookie = serializeBffSetCookie(config.cookies.pkceCookieName, signedPkce, {
      maxAgeSeconds: pkceTtlSeconds,
      secure: secureCookie,
      ...(config.cookies.cookiePath !== undefined ? { path: config.cookies.cookiePath } : {}),
      ...(config.cookies.sameSite !== undefined ? { sameSite: config.cookies.sameSite } : {}),
    });

    return redirectResponse(authorizeUrl.toString(), 302, [pkceCookie]);
  }

  async function handleOidcCallback(request: CookieReadableRequest): Promise<Response> {
    const urlParts = getRequestUrlParts(request);
    let cookieSecret: string;
    let publicOrigin: string;
    let secureCookie: boolean;
    try {
      cookieSecret = config.getCookieSecret();
      publicOrigin = config.getPublicOrigin(urlParts.origin);
      secureCookie = config.isSecureCookie();
    } catch {
      return bffConfigErrorResponse();
    }

    const code = urlParts.searchParams.get('code')?.trim();
    const state = urlParts.searchParams.get('state')?.trim();
    const rawPkceCookie = readRequestCookie(request, config.cookies.pkceCookieName);
    const pkce = await verifySignedPkceCookiePayload(rawPkceCookie, cookieSecret, config.appScope);
    const sanitizedReturnTo = pkce
      ? sanitizeRelativeReturnTo(pkce.returnTo, defaultReturnTo)
      : defaultReturnTo;

    if (!code || !state || !pkce || !constantTimeEqualStrings(state, pkce.state)) {
      const errorUrl = new URL(callbackErrorRedirectPath, publicOrigin);
      errorUrl.searchParams.set('authError', 'invalid_oidc_state');
      return redirectResponse(errorUrl.toString(), 302, [
        deleteCookieString(config.cookies.pkceCookieName, secureCookie),
      ]);
    }

    try {
      let guestSessionId: string | undefined;
      if (config.cookies.guestSessionCookieName) {
        const rawGuestCookie = readRequestCookie(request, config.cookies.guestSessionCookieName);
        guestSessionId =
          (await verifySignedGuestSessionId(rawGuestCookie, cookieSecret)) ?? undefined;
      }

      const exchanged = await runExchangeCode({
        code,
        codeVerifier: pkce.codeVerifier,
        redirectUri: `${publicOrigin}${callbackPath}`,
        expectedNonce: pkce.nonce,
        ...(guestSessionId ? { guestSessionId } : {}),
        request,
      });

      const validation = await validateEstablished({
        accessToken: exchanged.accessToken,
        exchanged,
        request,
      });
      if (!validation.ok) {
        let upstreamRevoked = true;
        try {
          const outcome = await runRevokeSession({
            accessToken: exchanged.accessToken,
            refreshToken: exchanged.refreshToken,
            request,
          });
          upstreamRevoked = outcome.upstreamRevoked;
        } catch {
          upstreamRevoked = false;
        }
        const forbiddenUrl = new URL(loginPagePath, publicOrigin);
        forbiddenUrl.searchParams.set('authError', validation.errorCode);
        if (!upstreamRevoked) {
          forbiddenUrl.searchParams.set('authWarning', 'upstream_revoke_failed');
        }
        return redirectResponse(
          forbiddenUrl.toString(),
          302,
          clearSessionCookieHeaders(secureCookie, { includePkce: true }),
        );
      }

      const targetUrl = new URL(sanitizedReturnTo, publicOrigin);
      config.decorateCallbackSuccessUrl?.(targetUrl, exchanged);

      const cookiesToSet: string[] = [
        deleteCookieString(config.cookies.pkceCookieName, secureCookie),
        ...(config.cookies.impersonationCookieName
          ? [deleteCookieString(config.cookies.impersonationCookieName, secureCookie)]
          : []),
        ...applyRotatedCookiesToArray(exchanged, secureCookie),
      ];

      return redirectResponse(targetUrl.toString(), 302, cookiesToSet);
    } catch {
      const failureBase =
        config.callbackErrorOnExchangeFailure === 'returnTo'
          ? sanitizedReturnTo
          : callbackErrorRedirectPath;
      const failUrl = new URL(failureBase, publicOrigin);
      failUrl.searchParams.set('authError', 'oidc_exchange_failed');
      return redirectResponse(failUrl.toString(), 302, [
        deleteCookieString(config.cookies.pkceCookieName, secureCookie),
      ]);
    }
  }

  async function handleSessionRead(request: CookieReadableRequest): Promise<Response> {
    let secureCookie: boolean;
    try {
      secureCookie = config.isSecureCookie();
    } catch {
      return bffConfigErrorResponse();
    }

    const impToken = config.cookies.impersonationCookieName
      ? readRequestCookie(request, config.cookies.impersonationCookieName)
      : undefined;
    const accessToken = readRequestCookie(request, config.cookies.accessCookieName);
    const refreshToken = readRequestCookie(request, config.cookies.refreshCookieName);
    const activeToken = impToken ?? accessToken;

    if (!activeToken && !refreshToken) {
      return jsonResponse(200, { data: unauthenticatedData });
    }

    if (activeToken) {
      try {
        const me = await runFetchSession({
          accessToken: activeToken,
          isImpersonation: Boolean(impToken),
          request,
        });
        if (!me.ok) {
          try {
            await runRevokeSession(
              impToken
                ? { accessToken: activeToken, request }
                : {
                    accessToken: activeToken,
                    ...(refreshToken ? { refreshToken } : {}),
                    request,
                  },
            );
          } catch {
            // Best-effort upstream revocation when active session is rejected.
          }
          const cookiesToClear = impToken && config.cookies.impersonationCookieName
            ? [deleteCookieString(config.cookies.impersonationCookieName, secureCookie)]
            : clearSessionCookieHeaders(secureCookie);
          return jsonResponse(200, { data: unauthenticatedData }, undefined, cookiesToClear);
        }
        return jsonResponse(200, { data: me.data });
      } catch (err) {
        const errInfo = extractUpstreamErrorInfo(err);
        if (impToken) {
          const clearCookies =
            errInfo.statusCode === 401 && config.cookies.impersonationCookieName
              ? [deleteCookieString(config.cookies.impersonationCookieName, secureCookie)]
              : [];
          return jsonResponse(200, { data: unauthenticatedData }, undefined, clearCookies);
        }
        if (!(errInfo.statusCode === 401 && refreshToken)) {
          return jsonResponse(200, { data: unauthenticatedData });
        }
      }
    }

    if (refreshToken && !impToken) {
      let rotatedCookies: readonly string[] = [];
      try {
        const refreshed = await singleFlightRefreshOidcTokens(
          refreshToken,
          () => runRefreshTokens({ refreshToken, request }),
          { appScope: config.appScope },
        );
        rotatedCookies = applyRotatedCookiesToArray(refreshed, secureCookie);
        const me = await runFetchSession({
          accessToken: refreshed.accessToken,
          isImpersonation: false,
          request,
        });
        if (!me.ok) {
          try {
            await runRevokeSession({
              accessToken: refreshed.accessToken,
              refreshToken: refreshed.refreshToken ?? refreshToken,
              request,
            });
          } catch {
            // Best-effort upstream revocation when refreshed session is rejected.
          }
          return jsonResponse(
            200,
            { data: unauthenticatedData },
            undefined,
            clearSessionCookieHeaders(secureCookie),
          );
        }
        return jsonResponse(
          200,
          { data: me.data },
          undefined,
          rotatedCookies,
        );
      } catch (refreshErr) {
        const setCookies = isTerminalRefreshAuthError(refreshErr)
          ? clearSessionCookieHeaders(secureCookie)
          : rotatedCookies;
        return jsonResponse(200, { data: unauthenticatedData }, undefined, setCookies);
      }
    }

    return jsonResponse(200, { data: unauthenticatedData });
  }

  async function handleRefreshSessionGet(request: CookieReadableRequest): Promise<Response> {
    const fetchMeta = assertBrowserNavigationFetchMetadata(request, {
      allowCrossSiteDocumentNavigation: true,
    });
    if (!fetchMeta.ok) {
      return jsonErrorResponse(fetchMeta.status, fetchMeta.code, fetchMeta.message, {
        vary: FETCH_METADATA_VARY_HEADER,
      });
    }

    const urlParts = getRequestUrlParts(request);
    let publicOrigin: string;
    let secureCookie: boolean;
    try {
      publicOrigin = config.getPublicOrigin(urlParts.origin);
      secureCookie = config.isSecureCookie();
    } catch {
      return bffConfigErrorResponse();
    }

    const returnTo = sanitizeRelativeReturnTo(
      urlParts.searchParams.get('returnTo'),
      defaultReturnTo,
    );

    // R6-M3: Only perform inline GET refresh on explicit same-origin or direct navigation requests.
    // Cross-site, same-site subdomain, and missing Sec-Fetch-Site requests bounce through /login?refresh=1.
    const secFetchSite = request.headers.get('sec-fetch-site')?.trim().toLowerCase();
    if (secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
      const bounceUrl = new URL(loginPagePath, publicOrigin);
      bounceUrl.searchParams.set('refresh', '1');
      bounceUrl.searchParams.set('returnTo', returnTo);
      return redirectResponse(bounceUrl.toString(), 303, [], {
        vary: FETCH_METADATA_VARY_HEADER,
      });
    }

    const redirectToLoginAndClear = (authError?: string, authWarning?: string): Response => {
      const loginUrl = new URL(loginPagePath, publicOrigin);
      loginUrl.searchParams.set('returnTo', returnTo);
      if (authError) {
        loginUrl.searchParams.set('authError', authError);
      }
      if (authWarning) {
        loginUrl.searchParams.set('authWarning', authWarning);
      }
      return redirectResponse(
        loginUrl.toString(),
        302,
        clearSessionCookieHeaders(secureCookie, { includePkce: true }),
        { vary: FETCH_METADATA_VARY_HEADER },
      );
    };

    const refreshToken = readRequestCookie(request, config.cookies.refreshCookieName);
    if (!refreshToken) {
      return redirectToLoginAndClear();
    }

    let rotatedCookies: readonly string[] = [];
    try {
      const refreshed = await singleFlightRefreshOidcTokens(
        refreshToken,
        () => runRefreshTokens({ refreshToken, request }),
        { appScope: config.appScope },
      );
      rotatedCookies = applyRotatedCookiesToArray(refreshed, secureCookie);
      const validation = await validateEstablished({
        accessToken: refreshed.accessToken,
        request,
      });
      if (!validation.ok) {
        let upstreamRevoked = true;
        try {
          const outcome = await runRevokeSession({
            accessToken: refreshed.accessToken,
            refreshToken: refreshed.refreshToken ?? refreshToken,
            request,
          });
          upstreamRevoked = outcome.upstreamRevoked;
        } catch {
          upstreamRevoked = false;
        }
        return redirectToLoginAndClear(
          validation.errorCode,
          !upstreamRevoked ? 'upstream_revoke_failed' : undefined,
        );
      }
      return redirectResponse(
        new URL(returnTo, publicOrigin).toString(),
        302,
        rotatedCookies,
        { vary: FETCH_METADATA_VARY_HEADER },
      );
    } catch (err) {
      if (isTerminalRefreshAuthError(err)) {
        return redirectToLoginAndClear();
      }
      const outageRes = buildRefreshOutageHtmlResponse(returnTo);
      outageRes.headers.set('vary', FETCH_METADATA_VARY_HEADER);
      for (const cookie of rotatedCookies) {
        outageRes.headers.append('set-cookie', cookie);
      }
      return outageRes;
    }
  }

  function handleClearSessionGet(request: CookieReadableRequest): Response {
    const fetchMeta = assertBrowserNavigationFetchMetadata(request, {
      allowCrossSiteDocumentNavigation: true,
    });
    if (!fetchMeta.ok) {
      return jsonErrorResponse(fetchMeta.status, fetchMeta.code, fetchMeta.message, {
        vary: FETCH_METADATA_VARY_HEADER,
      });
    }

    const urlParts = getRequestUrlParts(request);
    let publicOrigin: string;
    try {
      publicOrigin = config.getPublicOrigin(urlParts.origin);
    } catch {
      return bffConfigErrorResponse();
    }

    const returnTo = sanitizeRelativeReturnTo(
      urlParts.searchParams.get('returnTo'),
      defaultReturnTo,
    );
    const rawAuthError = (
      urlParts.searchParams.get('authError') ?? urlParts.searchParams.get('reason')
    )?.trim();
    const loginUrl = new URL(loginPagePath, publicOrigin);
    loginUrl.searchParams.set('clearSession', '1');
    loginUrl.searchParams.set('returnTo', returnTo);
    if (rawAuthError && allowedClearSessionErrors.has(rawAuthError)) {
      loginUrl.searchParams.set('authError', rawAuthError);
    }
    return redirectResponse(loginUrl.toString(), 302, [], {
      vary: FETCH_METADATA_VARY_HEADER,
    });
  }

  async function handlePostRefresh(
    request: CookieReadableRequest,
    secureCookie: boolean,
  ): Promise<Response> {
    const refreshToken = readRequestCookie(request, config.cookies.refreshCookieName);
    if (!refreshToken) {
      return jsonErrorResponse(401, 'UNAUTHENTICATED', 'Missing refresh session.');
    }
    let rotatedCookies: readonly string[] = [];
    try {
      const refreshed = await singleFlightRefreshOidcTokens(
        refreshToken,
        () => runRefreshTokens({ refreshToken, request }),
        { appScope: config.appScope },
      );
      rotatedCookies = applyRotatedCookiesToArray(refreshed, secureCookie);
      const me = await runFetchSession({
        accessToken: refreshed.accessToken,
        isImpersonation: false,
        request,
      });
      if (!me.ok) {
        try {
          await runRevokeSession({
            accessToken: refreshed.accessToken,
            refreshToken: refreshed.refreshToken ?? refreshToken,
            request,
          });
        } catch {
          // Best effort revocation on denied role
        }
        return jsonErrorResponse(
          403,
          me.errorCode ?? 'FORBIDDEN_STAFF_ROLE',
          me.errorMessage ?? 'Required session authorization could not be verified.',
          undefined,
          clearSessionCookieHeaders(secureCookie),
        );
      }
      return jsonResponse(
        200,
        {
          data: {
            refreshed: true,
            ...(me.data['user'] !== undefined ? { user: me.data['user'] } : {}),
            ...(me.data['profile'] !== undefined ? { profile: me.data['profile'] } : {}),
          },
        },
        undefined,
        rotatedCookies,
      );
    } catch (err) {
      if (isTerminalRefreshAuthError(err)) {
        return jsonErrorResponse(
          401,
          'REFRESH_SESSION_EXPIRED',
          'Session expired. Please sign in again.',
          undefined,
          clearSessionCookieHeaders(secureCookie),
        );
      }
      return jsonErrorResponse(
        503,
        'AUTH_REFRESH_UNAVAILABLE',
        'Authentication service is temporarily unavailable.',
        undefined,
        rotatedCookies,
      );
    }
  }

  async function handlePostClearStaleSession(
    request: CookieReadableRequest,
    secureCookie: boolean,
  ): Promise<Response> {
    const impToken = config.cookies.impersonationCookieName
      ? readRequestCookie(request, config.cookies.impersonationCookieName)
      : undefined;
    const accessToken = readRequestCookie(request, config.cookies.accessCookieName);
    const refreshToken = readRequestCookie(request, config.cookies.refreshCookieName);

    if (!impToken && !accessToken && !refreshToken) {
      return jsonResponse(200, { data: { cleared: false, activeSession: false } });
    }

    const activeToken = impToken ?? accessToken;
    let revokedTokensAccess: string | undefined = accessToken;
    let revokedTokensRefresh: string | undefined = refreshToken;

    const tryKeepSessionViaRefresh = async (
      currentRefreshToken: string,
    ): Promise<Response | null> => {
      let rotatedCookies: readonly string[] = [];
      try {
        const refreshed = await singleFlightRefreshOidcTokens(
          currentRefreshToken,
          () => runRefreshTokens({ refreshToken: currentRefreshToken, request }),
          { appScope: config.appScope },
        );
        rotatedCookies = applyRotatedCookiesToArray(refreshed, secureCookie);
        revokedTokensAccess = refreshed.accessToken;
        revokedTokensRefresh = refreshed.refreshToken ?? currentRefreshToken;
        const me = await runFetchSession({
          accessToken: refreshed.accessToken,
          isImpersonation: false,
          request,
        });
        if (me.ok) {
          return jsonResponse(
            200,
            { data: { cleared: false, activeSession: true } },
            undefined,
            rotatedCookies,
          );
        }
        return null;
      } catch (refreshErr) {
        if (!isTerminalRefreshAuthError(refreshErr)) {
          return jsonErrorResponse(
            503,
            'AUTH_SESSION_CHECK_UNAVAILABLE',
            'Authentication service is temporarily unavailable.',
            undefined,
            rotatedCookies,
          );
        }
        return null;
      }
    };

    if (activeToken) {
      try {
        const me = await runFetchSession({
          accessToken: activeToken,
          isImpersonation: Boolean(impToken),
          request,
        });
        if (me.ok) {
          // R6-H1: Preserve live valid sessions without revoking or deleting cookies.
          return jsonResponse(200, { data: { cleared: false, activeSession: true } });
        }
      } catch (err) {
        const errInfo = extractUpstreamErrorInfo(err);
        if (errInfo.isTransientOutage) {
          return jsonErrorResponse(
            503,
            'AUTH_SESSION_CHECK_UNAVAILABLE',
            'Authentication service is temporarily unavailable.',
          );
        }
        if (errInfo.statusCode === 401 && refreshToken && !impToken) {
          const refreshedOutcome = await tryKeepSessionViaRefresh(refreshToken);
          if (refreshedOutcome) {
            return refreshedOutcome;
          }
        }
      }
    } else if (refreshToken && !impToken) {
      const refreshedOutcome = await tryKeepSessionViaRefresh(refreshToken);
      if (refreshedOutcome) {
        return refreshedOutcome;
      }
    }

    let upstreamRevoked = true;
    let locallyRevoked = true;
    if (revokedTokensAccess || revokedTokensRefresh) {
      try {
        const outcome = await runRevokeSession({
          accessToken: revokedTokensAccess,
          refreshToken: revokedTokensRefresh,
          request,
        });
        upstreamRevoked = outcome.upstreamRevoked;
        locallyRevoked = outcome.locallyRevoked;
      } catch {
        upstreamRevoked = false;
        locallyRevoked = false;
      }
    }
    if (impToken && impToken !== revokedTokensAccess) {
      try {
        const outcome = await runRevokeSession({
          accessToken: impToken,
          request,
        });
        upstreamRevoked = upstreamRevoked && outcome.upstreamRevoked;
        locallyRevoked = locallyRevoked && outcome.locallyRevoked;
      } catch {
        upstreamRevoked = false;
        locallyRevoked = false;
      }
    }

    return jsonResponse(
      200,
      {
        data: {
          cleared: true,
          activeSession: false,
          upstreamRevoked,
          locallyRevoked,
        },
      },
      undefined,
      clearSessionCookieHeaders(secureCookie, {
        includePkce: true,
        includeImpersonation: true,
      }),
    );
  }

  async function handlePostLogout(
    request: CookieReadableRequest,
    secureCookie: boolean,
  ): Promise<Response> {
    const accessToken = readRequestCookie(request, config.cookies.accessCookieName);
    const refreshToken = readRequestCookie(request, config.cookies.refreshCookieName);
    const impToken = config.cookies.impersonationCookieName
      ? readRequestCookie(request, config.cookies.impersonationCookieName)
      : undefined;

    let upstreamRevoked = true;
    let locallyRevoked = true;

    if (accessToken || refreshToken) {
      try {
        const outcome = await runRevokeSession({
          accessToken,
          refreshToken,
          request,
        });
        upstreamRevoked = outcome.upstreamRevoked;
        locallyRevoked = outcome.locallyRevoked;
      } catch {
        upstreamRevoked = false;
        locallyRevoked = false;
      }
    }

    if (impToken && impToken !== accessToken) {
      try {
        const outcome = await runRevokeSession({
          accessToken: impToken,
          request,
        });
        upstreamRevoked = upstreamRevoked && outcome.upstreamRevoked;
        locallyRevoked = locallyRevoked && outcome.locallyRevoked;
      } catch {
        upstreamRevoked = false;
        locallyRevoked = false;
      }
    }

    return jsonResponse(
      200,
      { data: { loggedOut: true, upstreamRevoked, locallyRevoked } },
      { 'clear-site-data': clearSiteDataHeader },
      clearSessionCookieHeaders(secureCookie, {
        includePkce: true,
        includeImpersonation: true,
        includeGuest: true,
      }),
    );
  }

  async function handlePostImpersonateConsume(
    request: CookieReadableRequest & { readonly json: () => Promise<unknown> },
    publicOrigin: string,
    secureCookie: boolean,
  ): Promise<Response> {
    let rawBody: Record<string, unknown>;
    try {
      const parsed = await request.json();
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return jsonErrorResponse(400, 'INVALID_JSON', 'Valid JSON payload is required.');
      }
      rawBody = parsed as Record<string, unknown>;
    } catch {
      return jsonErrorResponse(400, 'INVALID_JSON', 'Valid JSON payload is required.');
    }

    const code = typeof rawBody['code'] === 'string' ? rawBody['code'].trim() : '';
    const impDefaultReturnTo = sanitizeRelativeReturnTo(
      config.impersonationDefaultReturnTo ?? defaultReturnTo,
      defaultReturnTo,
    );
    const returnTo = sanitizeRelativeReturnTo(
      typeof rawBody['returnTo'] === 'string' ? rawBody['returnTo'] : undefined,
      impDefaultReturnTo,
    );

    if (!code || code.length < 20) {
      return jsonErrorResponse(
        400,
        'MISSING_HANDOFF_CODE',
        'A valid single-use support handoff code is required.',
      );
    }

    let hmacSecret: string;
    try {
      const secretGetter = config.getImpersonationHmacSecret ?? config.getCookieSecret;
      hmacSecret = secretGetter();
    } catch {
      return jsonErrorResponse(
        500,
        'BFF_CONFIG_ERROR',
        'BFF impersonation configuration is incomplete or invalid.',
      );
    }

    if (!config.consumeImpersonationHandoff || !config.cookies.impersonationCookieName) {
      return jsonErrorResponse(
        500,
        'BFF_CONFIG_ERROR',
        'BFF impersonation handoff consumer is not configured.',
      );
    }

    try {
      const bffHandoffSignature = await signImpersonationHandoffConsume(
        code,
        publicOrigin,
        hmacSecret,
      );
      const consumed = await config.consumeImpersonationHandoff({
        handoffCode: code,
        origin: publicOrigin,
        bffHandoffSignature,
        request,
      });
      const impCookie = serializeBffSetCookie(
        config.cookies.impersonationCookieName,
        consumed.accessToken,
        {
          maxAgeSeconds: Math.min(900, Math.max(60, consumed.expiresInSeconds)),
          secure: secureCookie,
          ...(config.cookies.cookiePath !== undefined ? { path: config.cookies.cookiePath } : {}),
          ...(config.cookies.sameSite !== undefined ? { sameSite: config.cookies.sameSite } : {}),
        },
      );
      return jsonResponse(
        200,
        {
          data: {
            redirectTo: returnTo,
            sessionId: consumed.sessionId,
            targetUserId: consumed.targetUserId,
            ticketRef: consumed.ticketRef,
            expiresAtEpochSec: consumed.expiresAtEpochSec,
          },
        },
        undefined,
        [impCookie],
      );
    } catch (error) {
      const errInfo = extractUpstreamErrorInfo(error);
      if (errInfo.statusCode === 403) {
        return jsonErrorResponse(
          403,
          errInfo.errorCode ?? 'FORBIDDEN',
          errInfo.message ?? 'Impersonation handoff request was rejected.',
        );
      }
      if (errInfo.statusCode === 429) {
        return jsonErrorResponse(
          429,
          errInfo.errorCode ?? 'RATE_LIMITED',
          errInfo.message ?? 'Too many impersonation attempts. Please wait and retry.',
        );
      }
      // R6-M6: Network timeouts, AbortError, TypeError, and 5xx map to 502 instead of 401.
      if (errInfo.isTransientOutage) {
        return jsonErrorResponse(
          502,
          'UPSTREAM_AUTH_UNAVAILABLE',
          'Authentication service is temporarily unavailable. Please try again.',
        );
      }
      return jsonErrorResponse(
        401,
        'INVALID_HANDOFF_CODE',
        'This single-use support handoff code is invalid, expired (60s TTL), or has already been used.',
      );
    }
  }

  async function handlePostImpersonateExit(
    request: CookieReadableRequest,
    secureCookie: boolean,
  ): Promise<Response> {
    if (!config.cookies.impersonationCookieName) {
      return jsonErrorResponse(
        500,
        'BFF_CONFIG_ERROR',
        'Impersonation cookie is not configured.',
      );
    }
    const impToken = readRequestCookie(request, config.cookies.impersonationCookieName);
    let upstreamExited = true;
    if (impToken) {
      try {
        const out = await runRevokeSession({
          accessToken: impToken,
          request,
        });
        upstreamExited = out.upstreamRevoked;
      } catch {
        upstreamExited = false;
      }
    }
    return jsonResponse(
      200,
      { data: { exitedImpersonation: true, upstreamExited } },
      undefined,
      [deleteCookieString(config.cookies.impersonationCookieName, secureCookie)],
    );
  }

  return {
    async GET(request, context) {
      const { action } = await context.params;
      const routeKey = action.join('/');

      if (routeKey === 'login') {
        return handleLoginRedirect(request);
      }
      if (routeKey === 'callback') {
        return handleOidcCallback(request);
      }
      if (routeKey === 'session') {
        return handleSessionRead(request);
      }
      if (routeKey === 'refresh-session' && config.enableRefreshSessionGet) {
        return handleRefreshSessionGet(request);
      }
      if (routeKey === 'clear-session' && config.enableClearSessionGet) {
        return handleClearSessionGet(request);
      }
      if (routeKey === 'impersonate/consume' && config.enableImpersonation) {
        return jsonErrorResponse(
          405,
          'METHOD_NOT_ALLOWED',
          'Impersonation handoff consumption requires HTTP POST.',
          { allow: 'POST' },
        );
      }
      return jsonErrorResponse(404, 'NOT_FOUND', `Unknown auth route: ${routeKey}`);
    },

    async POST(request, context) {
      const { action } = await context.params;
      const routeKey = action.join('/');
      const urlParts = getRequestUrlParts(request);

      let publicOrigin: string;
      let secureCookie: boolean;
      try {
        publicOrigin = config.getPublicOrigin(urlParts.origin);
        secureCookie = config.isSecureCookie();
      } catch {
        return bffConfigErrorResponse();
      }

      const customAction = config.customPostActions?.[routeKey];
      if (customAction) {
        const csrf = assertSameOriginMutation(request, publicOrigin, {
          hasBody: customAction.hasBody,
          requireJsonContentType: customAction.requireJsonContentType,
        });
        if (!csrf.ok) {
          return jsonErrorResponse(csrf.status, csrf.code, csrf.message);
        }
        try {
          return await customAction.handler(request, { publicOrigin, secureCookie });
        } catch (err) {
          const info = extractUpstreamErrorInfo(err);
          const safeStatus =
            typeof info.statusCode === 'number' &&
            info.statusCode >= 400 &&
            info.statusCode <= 599
              ? info.statusCode
              : 502;
          return jsonErrorResponse(
            safeStatus,
            info.errorCode ?? 'CUSTOM_AUTH_ACTION_FAILED',
            info.message ?? 'Authentication action failed.',
          );
        }
      }

      const isConsume = config.enableImpersonation === true && routeKey === 'impersonate/consume';
      const csrf = assertSameOriginMutation(request, publicOrigin, {
        hasBody: isConsume,
        requireJsonContentType: isConsume,
      });
      if (!csrf.ok) {
        return jsonErrorResponse(csrf.status, csrf.code, csrf.message);
      }

      if (isConsume) {
        return handlePostImpersonateConsume(request, publicOrigin, secureCookie);
      }
      if (config.enableImpersonation && routeKey === 'impersonate/exit') {
        return handlePostImpersonateExit(request, secureCookie);
      }
      if (config.enablePostRefresh !== false && routeKey === 'refresh') {
        return handlePostRefresh(request, secureCookie);
      }
      if (config.enablePostClearStaleSession !== false && routeKey === 'clear-stale-session') {
        return handlePostClearStaleSession(request, secureCookie);
      }
      if (routeKey === 'logout') {
        return handlePostLogout(request, secureCookie);
      }
      return jsonErrorResponse(404, 'NOT_FOUND', `Unknown auth action: ${routeKey}`);
    },
  };
}
