import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthClient } from './AuthClient';
import { OAuth2Config, STORAGE_KEYS } from '../models/types';

function encodeBase64Url(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj);
  return btoa(json)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
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
      scope: 'openid profile email offline_access'
    };
    vi.restoreAllMocks();
  });

  it('persists id_token on exchangeCodeForTokens and exposes getIdToken() and getUserProfile()', async () => {
    const client = new AuthClient(config);
    (client as any).storage.setItem(STORAGE_KEYS.STATE, 'state-xyz');
    (client as any).storage.setItem(STORAGE_KEYS.CODE_VERIFIER, 'verifier-xyz');

    const profilePayload = {
      sub: 'usr_web_1',
      email: 'alice@example.com',
      name: 'Alice Smith',
      roles: ['admin']
    };
    const idToken = `${encodeBase64Url({ alg: 'RS256', typ: 'JWT' })}.${encodeBase64Url(profilePayload)}.sig`;

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'access-abc',
          refresh_token: 'refresh-def',
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 3600
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    await client.exchangeCodeForTokens('auth-code-1', 'state-xyz');

    expect(client.getIdToken()).toBe(idToken);
    expect(client.getUserProfile()).toEqual(profilePayload);
  });

  it('exposes getToken() which returns active access token or refreshes when expired', async () => {
    const client = new AuthClient(config);
    (client as any).storage.setItem(STORAGE_KEYS.ACCESS_TOKEN, 'expired-access');
    (client as any).storage.setItem(STORAGE_KEYS.REFRESH_TOKEN, 'valid-refresh');
    (client as any).storage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, String(Date.now() - 1000));

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'refreshed-access-token',
          refresh_token: 'rotated-refresh',
          token_type: 'Bearer',
          expires_in: 3600
        }),
        { status: 200 }
      )
    );

    const token = await client.getToken();
    expect(token).toBe('refreshed-access-token');
    expect(client.getAccessToken()).toBe('refreshed-access-token');
  });

  it('operates safely in SSR environments where window is undefined', async () => {
    const originalWindow = (globalThis as any).window;
    try {
      delete (globalThis as any).window;
      const client = new AuthClient(config);
      expect(client.isAuthenticated()).toBe(false);
      expect(client.getAccessToken()).toBeNull();
      expect(client.getIdToken()).toBeNull();
      expect(client.getUserProfile()).toBeNull();
      expect(await client.getToken()).toBeNull();
    } finally {
      if (originalWindow !== undefined) {
        (globalThis as any).window = originalWindow;
      }
    }
  });
});
