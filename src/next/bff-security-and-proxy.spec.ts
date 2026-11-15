// @vitest-environment node
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  assertBrowserNavigationFetchMetadata,
  assertSameOriginMutation,
  clearRefreshGraceCacheForTesting,
  createBffProxy,
  createWitsAuthBffApiProxy,
  createWitsAuthNextHandler,
  createWitsAuthNextProxy,
  signGuestSessionId,
  signPkceCookiePayload,
  verifySignedGuestSessionId,
  verifySignedPkceCookiePayload,
} from './index.js';

const SECRET = 'super_secret_hmac_key_at_least_32_bytes_long!';
const PUBLIC_ORIGIN = 'https://admin.satvikease.example';

function makeRequest(
  url: string,
  options?: {
    readonly method?: string;
    readonly headers?: Readonly<Record<string, string>>;
    readonly cookies?: Readonly<Record<string, string>>;
    readonly body?: BodyInit | null;
  },
) {
  const headers = new Headers(options?.headers);
  if (options?.cookies && !headers.has('cookie')) {
    const cookieStr = Object.entries(options.cookies)
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('; ');
    if (cookieStr) {
      headers.set('cookie', cookieStr);
    }
  }
  const req = new Request(url, {
    method: options?.method ?? 'GET',
    headers,
    ...(options?.body !== undefined ? { body: options.body } : {}),
  });
  return req;
}

describe('@witsauth/react-client/next BFF kernel, handlers & proxies', () => {
  beforeEach(() => {
    clearRefreshGraceCacheForTesting();
    vi.restoreAllMocks();
  });

  it('signs and verifies PKCE cookies bound to exp and app scope, plus guest SIDs', async () => {
    const nowMs = 1_700_000_000_000;
    const token = await signPkceCookiePayload(
      {
        state: 'st_1',
        codeVerifier: 'cv_1',
        nonce: 'nc_1',
        returnTo: '/orders',
        app: 'storefront',
        ttlSeconds: 300,
        nowMs,
      },
      SECRET,
    );

    const verified = await verifySignedPkceCookiePayload(token, SECRET, 'storefront', nowMs + 60_000);
    expect(verified?.state).toBe('st_1');
    expect(verified?.returnTo).toBe('/orders');

    // Tampered payload rejected
    const tampered = `x${token.slice(1)}`;
    expect(await verifySignedPkceCookiePayload(tampered, SECRET, 'storefront', nowMs)).toBeNull();
    // Expired token rejected
    expect(
      await verifySignedPkceCookiePayload(token, SECRET, 'storefront', nowMs + 400_000),
    ).toBeNull();
    // Wrong app scope rejected
    expect(await verifySignedPkceCookiePayload(token, SECRET, 'admin', nowMs)).toBeNull();

    const guestCookie = await signGuestSessionId('se_guest_abcdefgh12345678', SECRET);
    expect(await verifySignedGuestSessionId(guestCookie, SECRET)).toBe('se_guest_abcdefgh12345678');
    expect(await verifySignedGuestSessionId(`${guestCookie}tamper`, SECRET)).toBeNull();
  });

  it('rejects cross-site Fetch Metadata when Sec-Fetch-Mode or Sec-Fetch-Dest is omitted (R6-M3)', () => {
    const missingMode = makeRequest(`${PUBLIC_ORIGIN}/api/auth/refresh-session`, {
      headers: {
        'sec-fetch-site': 'cross-site',
        'sec-fetch-dest': 'document',
      },
    });
    expect(
      assertBrowserNavigationFetchMetadata(missingMode, {
        allowCrossSiteDocumentNavigation: true,
      }).ok,
    ).toBe(false);

    const missingDest = makeRequest(`${PUBLIC_ORIGIN}/api/auth/refresh-session`, {
      headers: {
        'sec-fetch-site': 'cross-site',
        'sec-fetch-mode': 'navigate',
      },
    });
    expect(
      assertBrowserNavigationFetchMetadata(missingDest, {
        allowCrossSiteDocumentNavigation: true,
      }).ok,
    ).toBe(false);

    const validCrossSiteDoc = makeRequest(`${PUBLIC_ORIGIN}/api/auth/refresh-session`, {
      headers: {
        'sec-fetch-site': 'cross-site',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
      },
    });
    expect(
      assertBrowserNavigationFetchMetadata(validCrossSiteDoc, {
        allowCrossSiteDocumentNavigation: true,
      }).ok,
    ).toBe(true);
  });

  it('enforces Origin / Sec-Fetch-Site and JSON Content-Type on mutations', () => {
    const crossOriginPost = makeRequest(`${PUBLIC_ORIGIN}/api/auth/logout`, {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
    });
    expect(assertSameOriginMutation(crossOriginPost, PUBLIC_ORIGIN)).toMatchObject({
      ok: false,
      status: 403,
      code: 'CSRF_ORIGIN_REJECTED',
    });

    const badContentTypePost = makeRequest(`${PUBLIC_ORIGIN}/api/auth/impersonate/consume`, {
      method: 'POST',
      headers: { origin: PUBLIC_ORIGIN, 'content-type': 'text/plain' },
    });
    expect(
      assertSameOriginMutation(badContentTypePost, PUBLIC_ORIGIN, { hasBody: true }),
    ).toMatchObject({
      ok: false,
      status: 415,
      code: 'UNSUPPORTED_MEDIA_TYPE',
    });
  });

  it('handles login, callback, side-effect-free clear-session, live-session-safe clear-stale-session (R6-H1), and R6-M3 refresh-session bounce', async () => {
    const revokeSpy = vi.fn(async () => ({ upstreamRevoked: true, locallyRevoked: true }));
    const refreshSpy = vi.fn(async () => ({
      accessToken: 'rotated_access',
      refreshToken: 'rotated_refresh',
      expiresInSeconds: 900,
    }));

    const handler = createWitsAuthNextHandler({
      appScope: 'admin',
      cookies: {
        accessCookieName: 'adm_acc',
        refreshCookieName: 'adm_ref',
        pkceCookieName: 'adm_pkce',
      },
      getPublicOrigin: () => PUBLIC_ORIGIN,
      getCookieSecret: () => SECRET,
      getClientId: () => 'satvikease-admin',
      getAuthorizeUrl: () => 'https://auth.example/oauth/authorize',
      isSecureCookie: () => true,
      enableRefreshSessionGet: true,
      enableClearSessionGet: true,
      exchangeCode: async () => ({
        accessToken: 'acc_new',
        refreshToken: 'ref_new',
        expiresInSeconds: 900,
      }),
      refreshTokens: refreshSpy,
      revokeSession: revokeSpy,
      fetchSession: async ({ accessToken }) => {
        if (accessToken === 'valid_2fa_access') {
          return { ok: true, data: { isAuthenticated: true, user: { userId: 'u_admin' } } };
        }
        return { ok: false, errorCode: 'FORBIDDEN_STAFF_ROLE' };
      },
    });

    // 1. GET /clear-session is side-effect-free
    const clearGetRes = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/clear-session?returnTo=%2Faudit&authError=two_factor_required`, {
        headers: {
          'sec-fetch-site': 'cross-site',
          'sec-fetch-mode': 'navigate',
          'sec-fetch-dest': 'document',
        },
        cookies: { adm_acc: 'valid_2fa_access' },
      }),
      { params: Promise.resolve({ action: ['clear-session'] }) },
    );
    expect(clearGetRes.status).toBe(302);
    expect(clearGetRes.headers.getSetCookie()).toEqual([]);
    expect(clearGetRes.headers.get('location')).toBe(
      `${PUBLIC_ORIGIN}/login?clearSession=1&returnTo=%2Faudit&authError=two_factor_required`,
    );

    // 2. POST /clear-stale-session preserves valid 2FA session (R6-H1)
    const liveClearRes = await handler.POST(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/clear-stale-session`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN },
        cookies: { adm_acc: 'valid_2fa_access', adm_ref: 'ref_1' },
      }),
      { params: Promise.resolve({ action: ['clear-stale-session'] }) },
    );
    expect(liveClearRes.status).toBe(200);
    expect(await liveClearRes.json()).toEqual({ data: { cleared: false, activeSession: true } });
    expect(revokeSpy).not.toHaveBeenCalled();
    expect(liveClearRes.headers.getSetCookie()).toEqual([]);

    // 3. POST /clear-stale-session revokes & wipes genuinely invalid/403 session
    const staleClearRes = await handler.POST(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/clear-stale-session`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN },
        cookies: { adm_acc: 'revoked_acc', adm_ref: 'stale_ref' },
      }),
      { params: Promise.resolve({ action: ['clear-stale-session'] }) },
    );
    expect(staleClearRes.status).toBe(200);
    expect(await staleClearRes.json()).toEqual({
      data: {
        cleared: true,
        activeSession: false,
        upstreamRevoked: true,
        locallyRevoked: true,
      },
    });
    expect(revokeSpy).toHaveBeenCalledTimes(1);
    expect(staleClearRes.headers.getSetCookie().some((c) => c.startsWith('adm_acc=;'))).toBe(true);

    // 4. GET /refresh-session bounces same-site / cross-site / missing Sec-Fetch-Site via 303 without rotating
    for (const headers of [
      { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
      { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
      {},
    ]) {
      const bounceRes = await handler.GET(
        makeRequest(`${PUBLIC_ORIGIN}/api/auth/refresh-session?returnTo=%2Forders`, {
          headers,
          cookies: { adm_ref: 'ref_should_not_rotate' },
        }),
        { params: Promise.resolve({ action: ['refresh-session'] }) },
      );
      expect(bounceRes.status).toBe(303);
      expect(bounceRes.headers.get('location')).toBe(
        `${PUBLIC_ORIGIN}/login?refresh=1&returnTo=%2Forders`,
      );
    }
    expect(refreshSpy).not.toHaveBeenCalled();
  });

  it('runs GET /login -> GET /callback full PKCE round-trip, forbidden role revocation, GET /session refresh, GET /impersonate/consume 405, and POST /logout', async () => {
    const revokeSpy = vi.fn(async () => ({ upstreamRevoked: true, locallyRevoked: true }));
    let allowLogin = true;

    const handler = createWitsAuthNextHandler({
      appScope: 'admin',
      cookies: {
        accessCookieName: 'adm_acc',
        refreshCookieName: 'adm_ref',
        pkceCookieName: 'adm_pkce',
        impersonationCookieName: 'adm_imp',
      },
      getPublicOrigin: () => PUBLIC_ORIGIN,
      getCookieSecret: () => SECRET,
      getClientId: () => 'satvikease-admin',
      getAuthorizeUrl: () => 'https://auth.example/oauth/authorize',
      isSecureCookie: () => true,
      enableImpersonation: true,
      exchangeCode: async () => ({
        accessToken: 'exchanged_access',
        refreshToken: 'exchanged_refresh',
        expiresInSeconds: 600,
      }),
      refreshTokens: async () => ({
        accessToken: 'refreshed_access',
        refreshToken: 'refreshed_refresh',
        expiresInSeconds: 600,
      }),
      revokeSession: revokeSpy,
      validateEstablishedSession: async () =>
        allowLogin ? { ok: true } : { ok: false, errorCode: 'two_factor_required' },
      fetchSession: async ({ accessToken }) => ({
        ok: true,
        data: { isAuthenticated: true, user: { token: accessToken } },
      }),
    });

    // 1. GET /login mints signed PKCE cookie and redirects to IdP
    const loginRes = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/login?returnTo=%2Fusers&loginHint=staff%40test.com`),
      { params: Promise.resolve({ action: ['login'] }) },
    );
    expect(loginRes.status).toBe(302);
    const authorizeLoc = new URL(loginRes.headers.get('location') ?? '');
    const state = authorizeLoc.searchParams.get('state') ?? '';
    expect(authorizeLoc.searchParams.get('login_hint')).toBe('staff@test.com');
    const pkceSetCookie = loginRes.headers.getSetCookie().find((c) => c.startsWith('adm_pkce='));
    const pkceVal = decodeURIComponent((pkceSetCookie ?? '').split(';')[0]?.split('=')[1] ?? '');

    // 2. GET /callback rejects invalid 2FA/staff role and revokes upstream tokens
    allowLogin = false;
    const deniedCb = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/callback?code=auth_code_1&state=${encodeURIComponent(state)}`, {
        cookies: { adm_pkce: pkceVal },
      }),
      { params: Promise.resolve({ action: ['callback'] }) },
    );
    expect(deniedCb.status).toBe(302);
    expect(deniedCb.headers.get('location')).toBe(
      `${PUBLIC_ORIGIN}/login?authError=two_factor_required`,
    );
    expect(revokeSpy).toHaveBeenCalledTimes(1);

    // 3. GET /callback succeeds for valid 2FA staff and sets httpOnly cookies
    allowLogin = true;
    const okCb = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/callback?code=auth_code_2&state=${encodeURIComponent(state)}`, {
        cookies: { adm_pkce: pkceVal },
      }),
      { params: Promise.resolve({ action: ['callback'] }) },
    );
    expect(okCb.status).toBe(302);
    expect(okCb.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/users`);
    expect(okCb.headers.getSetCookie().some((c) => c.includes('adm_acc=exchanged_access'))).toBe(true);

    // 4. GET /impersonate/consume returns 405 Allow: POST
    const method405 = await handler.GET(makeRequest(`${PUBLIC_ORIGIN}/api/auth/impersonate/consume`), {
      params: Promise.resolve({ action: ['impersonate', 'consume'] }),
    });
    expect(method405.status).toBe(405);
    expect(method405.headers.get('allow')).toBe('POST');

    // 5. POST /logout revokes both normal + impersonation tokens and emits Clear-Site-Data
    const logoutRes = await handler.POST(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/logout`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN },
        cookies: { adm_acc: 'a1', adm_ref: 'r1', adm_imp: 'imp1' },
      }),
      { params: Promise.resolve({ action: ['logout'] }) },
    );
    expect(logoutRes.status).toBe(200);
    expect(logoutRes.headers.get('clear-site-data')).toBe('"cookies", "storage", "cache"');
    expect(revokeSpy).toHaveBeenCalledTimes(3);
  });

  it('returns 500 BFF_CONFIG_ERROR when config fails (R6-L2) and maps POST /impersonate/consume outages to 502 (R6-M6)', async () => {
    const brokenHandler = createWitsAuthNextHandler({
      appScope: 'admin',
      cookies: {
        accessCookieName: 'adm_acc',
        refreshCookieName: 'adm_ref',
        pkceCookieName: 'adm_pkce',
      },
      getPublicOrigin: () => PUBLIC_ORIGIN,
      getCookieSecret: () => {
        throw new Error('BFF_COOKIE_SECRET missing');
      },
      getClientId: () => 'cid',
      getAuthorizeUrl: () => 'https://auth.example/authorize',
      isSecureCookie: () => true,
    });

    const cfgErrRes = await brokenHandler.GET(makeRequest(`${PUBLIC_ORIGIN}/api/auth/login`), {
      params: Promise.resolve({ action: ['login'] }),
    });
    expect(cfgErrRes.status).toBe(500);
    expect(await cfgErrRes.json()).toMatchObject({ error: { code: 'BFF_CONFIG_ERROR' } });

    let mode: 'network0' | 'typeerror' | 'timeout' | 'badcode' = 'network0';
    const impHandler = createWitsAuthNextHandler({
      appScope: 'storefront',
      cookies: {
        accessCookieName: 'sf_acc',
        refreshCookieName: 'sf_ref',
        pkceCookieName: 'sf_pkce',
        impersonationCookieName: 'sf_imp',
      },
      getPublicOrigin: () => PUBLIC_ORIGIN,
      getCookieSecret: () => SECRET,
      getClientId: () => 'sf',
      getAuthorizeUrl: () => 'https://auth.example/authorize',
      isSecureCookie: () => true,
      enableImpersonation: true,
      consumeImpersonationHandoff: async () => {
        if (mode === 'network0') {
          throw Object.assign(new Error('network'), { statusCode: 0 });
        }
        if (mode === 'typeerror') {
          throw new TypeError('fetch failed');
        }
        if (mode === 'timeout') {
          const e = new Error('timed out');
          e.name = 'TimeoutError';
          throw e;
        }
        throw Object.assign(new Error('expired'), { statusCode: 401 });
      },
    });

    for (const currentMode of ['network0', 'typeerror', 'timeout'] as const) {
      mode = currentMode;
      const outageRes = await impHandler.POST(
        makeRequest(`${PUBLIC_ORIGIN}/api/auth/impersonate/consume`, {
          method: 'POST',
          headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
          body: JSON.stringify({ code: 'valid_length_handoff_code_123456' }),
        }),
        { params: Promise.resolve({ action: ['impersonate', 'consume'] }) },
      );
      expect(outageRes.status).toBe(502);
      expect(await outageRes.json()).toMatchObject({ error: { code: 'UPSTREAM_AUTH_UNAVAILABLE' } });
    }

    mode = 'badcode';
    const invalidRes = await impHandler.POST(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/impersonate/consume`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ code: 'valid_length_handoff_code_123456' }),
      }),
      { params: Promise.resolve({ action: ['impersonate', 'consume'] }) },
    );
    expect(invalidRes.status).toBe(401);
  });

  it('guards createWitsAuthNextProxy inline refresh strictly to same-origin/none navigation (R6-M3)', async () => {
    const refreshMock = vi.fn(async () => ({
      accessToken: 'new_access_tok',
      refreshToken: 'new_refresh_tok',
      expiresInSeconds: 900,
    }));

    const proxy = createWitsAuthNextProxy({
      appScope: 'admin',
      loginPath: '/login',
      defaultReturnTo: '/dashboard',
      accessCookieName: 'adm_acc',
      refreshCookieName: 'adm_ref',
      isSecureCookie: () => true,
      refreshTokens: refreshMock,
      next: (headers) => {
        const res = new Response('ok', { status: 200 });
        if (headers) {
          res.headers.set('x-forwarded-cookie', headers.get('cookie') ?? '');
        }
        return res;
      },
      redirect: (url, status) => new Response(null, { status, headers: { location: url.toString() } }),
    });

    // Cross-site request with missing access cookie must NOT rotate refresh token
    const crossSiteRes = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/dashboard`, {
        headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
        cookies: { adm_ref: 'ref_only' },
      }),
    );
    expect(crossSiteRes.status).toBe(200);
    expect(refreshMock).not.toHaveBeenCalled();

    // Same-origin document navigation DOES rotate once cleanly
    const sameOriginRes = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/dashboard`, {
        headers: { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
        cookies: { adm_ref: 'ref_only' },
      }),
    );
    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(sameOriginRes.headers.get('x-forwarded-cookie')).toContain('adm_acc=new_access_tok');
    expect(sameOriginRes.headers.getSetCookie().some((c) => c.includes('adm_ref=new_refresh_tok'))).toBe(
      true,
    );
  });

  it('enforces BFF API proxy path checks, guardRoute, 401 refresh retry, and R6-L3.5 upstream.body.cancel on oversized content-length', async () => {
    expect(createWitsAuthBffApiProxy).toBe(createBffProxy);

    const cancelSpy = vi.fn(async () => undefined);
    let callCount = 0;

    const proxy = createBffProxy({
      appLabel: 'Storefront',
      getApiOrigin: () => 'https://api.internal.example',
      getPublicOrigin: () => PUBLIC_ORIGIN,
      isSecureCookie: () => true,
      getCookieSecret: () => SECRET,
      accessCookieName: 'sf_acc',
      refreshCookieName: 'sf_ref',
      allowedFirstSegments: new Set(['bookings', 'oversized']),
      guardRoute: ({ joined }) =>
        joined.endsWith('confirm-payment')
          ? new Response(JSON.stringify({ error: { code: 'MOCK_PAYMENT_DISABLED' } }), {
              status: 403,
            })
          : null,
      refreshSession: async () => ({
        accessToken: 'fresh_acc',
        refreshToken: 'fresh_ref',
        expiresInSeconds: 600,
      }),
      fetchImpl: async (input) => {
        callCount += 1;
        const url = String(input);
        if (url.includes('/oversized/')) {
          const fakeStream = {
            getReader: () => {
              throw new Error('should not read body past content-length fast-path');
            },
            cancel: cancelSpy,
          } as unknown as ReadableStream<Uint8Array>;
          return {
            status: 200,
            headers: new Headers({ 'content-length': String(20 * 1024 * 1024) }),
            body: fakeStream,
            arrayBuffer: async () => new ArrayBuffer(0),
          } as unknown as Response;
        }
        if (callCount === 1) {
          return new Response(JSON.stringify({ error: 'expired' }), { status: 401 });
        }
        return new Response(JSON.stringify({ data: { ok: true } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    // Traversal blocked
    const badPath = await proxy(makeRequest(`${PUBLIC_ORIGIN}/api/v1/%2e%2e/secret`), {
      params: Promise.resolve({ path: ['..', 'secret'] }),
    });
    expect(badPath.status).toBe(400);

    // Custom guardRoute enforced
    const blockedGuard = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/api/v1/bookings/b1/confirm-payment`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN },
      }),
      { params: Promise.resolve({ path: ['bookings', 'b1', 'confirm-payment'] }) },
    );
    expect(blockedGuard.status).toBe(403);

    // 401 auto-refresh + retry works cleanly
    const retryOk = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/api/v1/bookings/b1`, {
        cookies: { sf_acc: 'stale_acc', sf_ref: 'good_ref' },
      }),
      { params: Promise.resolve({ path: ['bookings', 'b1'] }) },
    );
    expect(retryOk.status).toBe(200);
    expect(await retryOk.json()).toEqual({ data: { ok: true } });

    // Oversized Content-Length cancels upstream body before returning 502 (R6-L3.5)
    const oversizedRes = await proxy(makeRequest(`${PUBLIC_ORIGIN}/api/v1/oversized/export`), {
      params: Promise.resolve({ path: ['oversized', 'export'] }),
    });
    expect(oversizedRes.status).toBe(502);
    expect(await oversizedRes.json()).toMatchObject({
      error: { code: 'UPSTREAM_RESPONSE_TOO_LARGE' },
    });
    expect(cancelSpy).toHaveBeenCalledTimes(1);
  });

  it('sets private no-store + Vary on returning signed guest sessions (R7-M4) and evaluates lazy trustedClientIpHeader per request (R7-L2)', async () => {
    let dynamicIpHeader: string | undefined = 'x-real-ip';
    let shouldThrowIpHeader = false;
    const forwardedIpValues: Array<string | null> = [];

    const proxy = createBffProxy({
      appLabel: 'Storefront',
      getApiOrigin: () => 'https://api.internal.example',
      getPublicOrigin: () => PUBLIC_ORIGIN,
      isSecureCookie: () => true,
      getCookieSecret: () => SECRET,
      trustedClientIpHeader: () => {
        if (shouldThrowIpHeader) {
          throw new Error('Missing IP header config');
        }
        return dynamicIpHeader;
      },
      accessCookieName: 'sf_acc',
      refreshCookieName: 'sf_ref',
      guestSessionCookieName: 'se_guest_sid',
      allowedFirstSegments: new Set(['bookings']),
      fetchImpl: async (_input, init) => {
        const hdrs = new Headers(init?.headers);
        forwardedIpValues.push(hdrs.get('x-forwarded-for'));
        return new Response(JSON.stringify({ data: { guestOk: true } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    const signedGuestCookie = await signGuestSessionId('se_guest_abcdefgh12345678', SECRET);

    const returningGuestRes = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/api/v1/bookings/hold`, {
        cookies: { se_guest_sid: signedGuestCookie },
        headers: {
          'x-real-ip': '203.0.113.10',
          'cf-connecting-ip': '198.51.100.25',
        },
      }),
      { params: Promise.resolve({ path: ['bookings', 'hold'] }) },
    );
    expect(returningGuestRes.status).toBe(200);
    expect(returningGuestRes.headers.getSetCookie()).toHaveLength(0);
    expect(returningGuestRes.headers.get('cache-control')).toBe('private, no-store');
    expect(returningGuestRes.headers.get('vary')).toBe('Cookie, Origin, Sec-Fetch-Site');
    expect(forwardedIpValues[0]).toBe('203.0.113.10');

    // Lazy header change applies on subsequent request without recreating proxy
    dynamicIpHeader = 'cf-connecting-ip';
    const rotatedHeaderRes = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/api/v1/bookings/hold`, {
        cookies: { se_guest_sid: signedGuestCookie },
        headers: {
          'x-real-ip': '203.0.113.10',
          'cf-connecting-ip': '198.51.100.25',
        },
      }),
      { params: Promise.resolve({ path: ['bookings', 'hold'] }) },
    );
    expect(rotatedHeaderRes.status).toBe(200);
    expect(forwardedIpValues[1]).toBe('198.51.100.25');

    // Throwing lazy getter fails closed with 500 BFF_CONFIG_ERROR
    shouldThrowIpHeader = true;
    const configErrRes = await proxy(makeRequest(`${PUBLIC_ORIGIN}/api/v1/bookings/hold`), {
      params: Promise.resolve({ path: ['bookings', 'hold'] }),
    });
    expect(configErrRes.status).toBe(500);
    expect(await configErrRes.json()).toMatchObject({
      error: { code: 'BFF_CONFIG_ERROR' },
    });
  });

  it('revokes upstream tokens on rejected GET /session & unrotated refresh (R7-M5) and guards customPostActions statusCode=0 -> 502 (R7-L2)', async () => {
    const revokeCalls: Array<{
      readonly accessToken?: string | undefined;
      readonly refreshToken?: string | undefined;
    }> = [];

    const handler = createWitsAuthNextHandler({
      appScope: 'admin',
      cookies: {
        accessCookieName: 'adm_acc',
        refreshCookieName: 'adm_ref',
        pkceCookieName: 'adm_pkce',
      },
      getPublicOrigin: () => PUBLIC_ORIGIN,
      getCookieSecret: () => SECRET,
      getClientId: () => 'satvikease-admin',
      getAuthorizeUrl: () => 'https://auth.example/oauth/authorize',
      isSecureCookie: () => true,
      enableRefreshSessionGet: true,
      refreshTokens: async () => ({
        accessToken: 'new_acc_unrotated',
        expiresInSeconds: 600,
      }),
      validateEstablishedSession: async () => ({
        ok: false,
        errorCode: 'two_factor_required',
      }),
      fetchSession: async () => ({
        ok: false,
        errorCode: 'TWO_FACTOR_REQUIRED',
        errorMessage: '2FA required.',
      }),
      revokeSession: async ({ accessToken, refreshToken }) => {
        revokeCalls.push({ accessToken, refreshToken });
        return { upstreamRevoked: true, locallyRevoked: true };
      },
      customPostActions: {
        'dev-switch': {
          hasBody: true,
          requireJsonContentType: true,
          handler: async () => {
            throw Object.assign(new Error('Upstream reset'), {
              statusCode: 0,
              errorCode: 'UPSTREAM_DOWN',
            });
          },
        },
      },
    });

    // 1. Active token rejected by fetchSession triggers best-effort revokeSession before clearing cookies
    const activeRejected = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/session`, {
        cookies: { adm_acc: 'bad_acc', adm_ref: 'cur_ref_1' },
      }),
      { params: Promise.resolve({ action: ['session'] }) },
    );
    expect(activeRejected.status).toBe(200);
    expect(await activeRejected.json()).toEqual({ data: { isAuthenticated: false, user: null } });
    expect(revokeCalls[0]).toEqual({ accessToken: 'bad_acc', refreshToken: 'cur_ref_1' });

    // 2. Inline refresh on GET /session rejected by fetchSession falls back to incoming refreshToken
    const inlineRejected = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/session`, {
        cookies: { adm_ref: 'cur_ref_2' },
      }),
      { params: Promise.resolve({ action: ['session'] }) },
    );
    expect(inlineRejected.status).toBe(200);
    expect(revokeCalls[1]).toEqual({
      accessToken: 'new_acc_unrotated',
      refreshToken: 'cur_ref_2',
    });

    // 3. GET /refresh-session rejected falls back to incoming refreshToken when refreshed.refreshToken omitted
    const refreshGetRejected = await handler.GET(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/refresh-session?returnTo=%2Fusers`, {
        headers: {
          'sec-fetch-site': 'same-origin',
          'sec-fetch-mode': 'navigate',
          'sec-fetch-dest': 'document',
        },
        cookies: { adm_ref: 'cur_ref_3' },
      }),
      { params: Promise.resolve({ action: ['refresh-session'] }) },
    );
    expect(refreshGetRejected.status).toBe(302);
    expect(revokeCalls[2]).toEqual({
      accessToken: 'new_acc_unrotated',
      refreshToken: 'cur_ref_3',
    });

    // 4. POST /refresh rejected falls back to incoming refreshToken when refreshed.refreshToken omitted
    const postRefreshRejected = await handler.POST(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/refresh`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN },
        cookies: { adm_ref: 'cur_ref_4' },
      }),
      { params: Promise.resolve({ action: ['refresh'] }) },
    );
    expect(postRefreshRejected.status).toBe(403);
    expect(revokeCalls[3]).toEqual({
      accessToken: 'new_acc_unrotated',
      refreshToken: 'cur_ref_4',
    });

    // 5. customPostActions throwing statusCode=0 maps cleanly to HTTP 502 instead of RangeError
    const customErrRes = await handler.POST(
      makeRequest(`${PUBLIC_ORIGIN}/api/auth/dev-switch`, {
        method: 'POST',
        headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'ops_admin' }),
      }),
      { params: Promise.resolve({ action: ['dev-switch'] }) },
    );
    expect(customErrRes.status).toBe(502);
    expect(await customErrRes.json()).toEqual({
      error: { code: 'UPSTREAM_DOWN', message: 'Upstream reset' },
    });
  });

  it('preserves ValidateEstablishedSessionResult errorCode and invokes revokeSession in createWitsAuthNextProxy (R7-M5)', async () => {
    const revokeSpy = vi.fn(async () => ({ upstreamRevoked: true, locallyRevoked: true }));
    let returnBooleanFalse = false;

    const proxy = createWitsAuthNextProxy({
      appScope: 'admin',
      loginPath: '/login',
      defaultReturnTo: '/dashboard',
      accessCookieName: 'adm_acc',
      refreshCookieName: 'adm_ref',
      isSecureCookie: () => true,
      refreshTokens: async () => ({
        accessToken: 'proxy_acc_1',
        expiresInSeconds: 600,
      }),
      validateRefreshedSession: async (_tokens, _req, meta) => {
        expect(meta.incomingRefreshToken).toBe(returnBooleanFalse ? 'proxy_ref_2' : 'proxy_ref_1');
        if (returnBooleanFalse) {
          return false;
        }
        return { ok: false, errorCode: 'two_factor_required' };
      },
      revokeSession: revokeSpy,
      next: (forwardedHeaders) =>
        new Response('next', {
          status: 200,
          headers: forwardedHeaders
            ? { 'x-forwarded-cookie': forwardedHeaders.get('cookie') ?? '' }
            : {},
        }),
      redirect: (url, status) =>
        new Response(null, { status, headers: { location: url.toString() } }),
    });

    const mfaRes = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/dashboard`, {
        headers: {
          'sec-fetch-site': 'same-origin',
          'sec-fetch-mode': 'navigate',
          'sec-fetch-dest': 'document',
        },
        cookies: { adm_ref: 'proxy_ref_1' },
      }),
    );
    expect(mfaRes.status).toBe(307);
    expect(mfaRes.headers.get('location')).toBe(
      `${PUBLIC_ORIGIN}/login?returnTo=%2Fdashboard&authError=two_factor_required`,
    );
    expect(revokeSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        accessToken: 'proxy_acc_1',
        refreshToken: 'proxy_ref_1',
      }),
    );
    expect(
      mfaRes.headers.getSetCookie().some((c) => c.startsWith('adm_acc=;') && c.includes('Max-Age=0')),
    ).toBe(true);
    expect(
      mfaRes.headers.getSetCookie().some((c) => c.startsWith('adm_ref=;') && c.includes('Max-Age=0')),
    ).toBe(true);

    returnBooleanFalse = true;
    const roleRes = await proxy(
      makeRequest(`${PUBLIC_ORIGIN}/dashboard`, {
        headers: {
          'sec-fetch-site': 'same-origin',
          'sec-fetch-mode': 'navigate',
          'sec-fetch-dest': 'document',
        },
        cookies: { adm_ref: 'proxy_ref_2' },
      }),
    );
    expect(roleRes.status).toBe(307);
    expect(roleRes.headers.get('location')).toBe(
      `${PUBLIC_ORIGIN}/login?returnTo=%2Fdashboard&authError=forbidden_staff_role`,
    );
  });
});
