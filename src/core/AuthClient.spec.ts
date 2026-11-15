import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthClient } from './AuthClient.js';
import { OAuthCallbackError, STORAGE_KEYS, type OAuth2Config } from '../models/types.js';

function encodeBase64Url(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj);
  return btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeJwt(payload: Record<string, unknown>): string {
  return `${encodeBase64Url({ alg: 'RS256', typ: 'JWT' })}.${encodeBase64Url(payload)}.sig`;
}

describe('AuthClient (@witsauth/react-client)', () => {
  let config: OAuth2Config;

  beforeEach(() => {
    config = {
      clientId: 'web-client-123',
      authorizationEndpoint: 'https://auth.witspry.com/auth/authorize',
      tokenEndpoint: 'https://auth.witspry.com/oauth/token',
      revokeEndpoint: 'https://auth.witspry.com/oauth/revoke',
      redirectUri: 'https://app.example.com/callback',
      scope: 'openid profile email offline_access',
    };
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  it('persists id_token on exchangeCodeForTokens and exposes getIdToken() and getUserProfile()', async () => {
    const client = new AuthClient(config);
    window.localStorage.setItem(STORAGE_KEYS.STATE, 'state-xyz');
    window.localStorage.setItem(STORAGE_KEYS.CODE_VERIFIER, 'verifier-xyz');

    const profilePayload = {
      sub: 'usr_web_1',
      email: 'alice@example.com',
      name: 'Alice Smith',
      roles: ['admin'],
    };
    const idToken = makeJwt(profilePayload);

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'access-abc',
          refresh_token: 'refresh-def',
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 3600,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    await client.exchangeCodeForTokens('auth-code-1', 'state-xyz');

    expect(client.getIdToken()).toBe(idToken);
    expect(client.getUserProfile()).toEqual(profilePayload);
  });

  it('verifies id_token nonce against stored nonce and rejects mismatches or missing nonce claims', async () => {
    const client = new AuthClient(config);

    // Matching nonce succeeds
    window.localStorage.setItem(STORAGE_KEYS.STATE, 'state-ok');
    window.localStorage.setItem(STORAGE_KEYS.CODE_VERIFIER, 'verifier-ok');
    window.localStorage.setItem(STORAGE_KEYS.NONCE, 'nonce-expected-123');
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: makeJwt({ sub: 'u1' }),
          id_token: makeJwt({ sub: 'u1', nonce: 'nonce-expected-123' }),
          expires_in: 3600,
        }),
        { status: 200 },
      ),
    );
    await expect(client.exchangeCodeForTokens('code-ok', 'state-ok')).resolves.toBeDefined();

    // Mismatched nonce fails
    window.localStorage.setItem(STORAGE_KEYS.STATE, 'state-bad');
    window.localStorage.setItem(STORAGE_KEYS.CODE_VERIFIER, 'verifier-bad');
    window.localStorage.setItem(STORAGE_KEYS.NONCE, 'nonce-expected-123');
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: makeJwt({ sub: 'u1' }),
          id_token: makeJwt({ sub: 'u1', nonce: 'wrong-nonce' }),
          expires_in: 3600,
        }),
        { status: 200 },
      ),
    );
    await expect(client.exchangeCodeForTokens('code-bad', 'state-bad')).rejects.toThrow(
      'Invalid OIDC nonce parameter.',
    );

    // Missing nonce claim in id_token fails when storedNonce is present
    window.localStorage.setItem(STORAGE_KEYS.STATE, 'state-missing');
    window.localStorage.setItem(STORAGE_KEYS.CODE_VERIFIER, 'verifier-missing');
    window.localStorage.setItem(STORAGE_KEYS.NONCE, 'nonce-expected-123');
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: makeJwt({ sub: 'u1' }),
          id_token: makeJwt({ sub: 'u1' }),
          expires_in: 3600,
        }),
        { status: 200 },
      ),
    );
    await expect(client.exchangeCodeForTokens('code-missing', 'state-missing')).rejects.toThrow(
      'Invalid OIDC nonce parameter.',
    );
  });

  it('prefers access_token act claim over id_token for getImpersonationActor() and isImpersonatedSession()', () => {
    const client = new AuthClient(config);
    const idTokenWithoutAct = makeJwt({ sub: 'customer_1', name: 'Customer' });
    const accessTokenWithAct = makeJwt({
      sub: 'customer_1',
      act: { sub: 'support_agent_42', ticket_ref: 'SUP-991' },
    });

    window.localStorage.setItem(STORAGE_KEYS.ID_TOKEN, idTokenWithoutAct);
    window.localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, accessTokenWithAct);

    expect(client.isImpersonatedSession()).toBe(true);
    expect(client.getImpersonationActor()).toEqual({
      sub: 'support_agent_42',
      ticket_ref: 'SUP-991',
    });
  });

  it('clears stale refresh_token on non-refreshable token exchange and skips refresh in getToken()', async () => {
    const client = new AuthClient(config);
    window.localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, 'stale-refresh');
    window.localStorage.setItem(STORAGE_KEYS.STATE, 'state-imp');
    window.localStorage.setItem(STORAGE_KEYS.CODE_VERIFIER, 'verifier-imp');

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: makeJwt({ sub: 'customer_1', act: { sub: 'agent_1' } }),
          expires_in: -60, // expired immediately for test
        }),
        { status: 200 },
      ),
    );

    await client.exchangeCodeForTokens('code-imp', 'state-imp');
    expect(client.getRefreshToken()).toBeNull();
    expect(await client.getToken()).toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('stores sanitized returnTo, loginHint, and extraParams during startAuthorization()', async () => {
    const originalLocation = window.location;
    let assignedHref = '';
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...originalLocation,
        get href() {
          return assignedHref;
        },
        set href(val: string) {
          assignedHref = val;
        },
      },
    });

    try {
      const client = new AuthClient(config);
      await client.startAuthorization({
        returnTo: '/orders/ord_123?tab=receipt',
        loginHint: 'alice@example.com',
        extraParams: { portal: 'customer', client_id: 'should-not-override' },
      });

      const parsed = new URL(assignedHref);
      expect(parsed.searchParams.get('client_id')).toBe('web-client-123');
      expect(parsed.searchParams.get('login_hint')).toBe('alice@example.com');
      expect(parsed.searchParams.get('portal')).toBe('customer');
      expect(client.consumeStoredReturnTo('/')).toBe('/orders/ord_123?tab=receipt');
      // Consumed once
      expect(client.consumeStoredReturnTo('/fallback')).toBe('/fallback');
    } finally {
      Object.defineProperty(window, 'location', {
        configurable: true,
        value: originalLocation,
      });
    }
  });

  it('invokes onCallbackError via reportCallbackError', () => {
    const onCallbackError = vi.fn();
    const client = new AuthClient({ ...config, onCallbackError });
    const err = new OAuthCallbackError('access_denied', 'User cancelled login');
    client.reportCallbackError(err);
    expect(onCallbackError).toHaveBeenCalledWith(err);
  });

  it('exposes getToken() which returns active access token or refreshes when expired', async () => {
    const client = new AuthClient(config);
    window.localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, 'expired-access');
    window.localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, 'valid-refresh');
    window.localStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, String(Date.now() - 1000));

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'refreshed-access-token',
          refresh_token: 'rotated-refresh',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
        { status: 200 },
      ),
    );

    const token = await client.getToken();
    expect(token).toBe('refreshed-access-token');
    expect(client.getAccessToken()).toBe('refreshed-access-token');
  });

  it('operates safely in SSR environments where window is undefined', async () => {
    const originalWindow = (globalThis as { window?: unknown }).window;
    try {
      delete (globalThis as { window?: unknown }).window;
      const client = new AuthClient(config);
      expect(client.isAuthenticated()).toBe(false);
      expect(client.getAccessToken()).toBeNull();
      expect(client.getIdToken()).toBeNull();
      expect(client.getUserProfile()).toBeNull();
      expect(client.getImpersonationActor()).toBeNull();
      expect(client.isImpersonatedSession()).toBe(false);
      expect(await client.getToken()).toBeNull();
    } finally {
      if (originalWindow !== undefined) {
        (globalThis as { window?: unknown }).window = originalWindow;
      }
    }
  });
});
