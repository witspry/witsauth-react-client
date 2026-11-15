import {
  STORAGE_KEYS,
  type AuthorizeOptions,
  type ImpersonationActor,
  type OAuth2Config,
  type OAuthCallbackError,
  type TokenInfo,
  type UserInfo,
} from '../models/types.js';
import {
  createCodeChallenge,
  decodeJwtPayload,
  generateCodeVerifier,
  generateState,
} from './pkce.js';
import { TokenStorage } from './storage.js';
import { constantTimeEqualStrings, sanitizeRelativeReturnTo } from './url-security.js';

const RESERVED_AUTHORIZE_PARAMS = new Set([
  'client_id',
  'redirect_uri',
  'response_type',
  'code_challenge',
  'code_challenge_method',
  'state',
  'nonce',
]);

function extractValidActorClaim(claims: UserInfo | null): ImpersonationActor | null {
  const act = claims?.act;
  if (!act || typeof act !== 'object' || typeof act.sub !== 'string') {
    return null;
  }
  const sub = act.sub.trim();
  if (sub.length === 0) {
    return null;
  }
  return { ...act, sub };
}

export class AuthClient {
  private config: OAuth2Config;
  private storage: TokenStorage;
  private refreshPromise: Promise<TokenInfo> | null = null;

  constructor(config: OAuth2Config, storage?: TokenStorage) {
    this.config = config;
    this.storage = storage || new TokenStorage(config.storage, config.customStorage);
  }

  log(level: 'error' | 'warn' | 'info' | 'debug', ...args: unknown[]): void {
    const levels = { none: 0, error: 1, warn: 2, info: 3, debug: 4 };
    const currentLevel = levels[this.config.logLevel || 'warn'] || 0;
    const msgLevel = levels[level] || 0;

    if (msgLevel > 0 && currentLevel >= msgLevel) {
      console[level](...args);
    }
  }

  getDefaultRedirectRoute(): string {
    return sanitizeRelativeReturnTo(this.config.redirectRoute, '/');
  }

  reportCallbackError(error: OAuthCallbackError): void {
    this.log('error', 'OAuth callback error:', error.code, error.description ?? '');
    this.config.onCallbackError?.(error);
  }

  consumeStoredReturnTo(fallback?: string): string {
    const defaultFallback = sanitizeRelativeReturnTo(fallback ?? this.config.redirectRoute, '/');
    const stored = this.storage.getItem(STORAGE_KEYS.RETURN_TO);
    this.storage.removeItem(STORAGE_KEYS.RETURN_TO);
    return sanitizeRelativeReturnTo(stored, defaultFallback);
  }

  async startAuthorization(options?: AuthorizeOptions): Promise<void> {
    const verifier = generateCodeVerifier();
    const challenge = await createCodeChallenge(verifier);
    const state = generateState();
    const nonce = this.config.nonce || generateState();

    this.storage.setItem(STORAGE_KEYS.CODE_VERIFIER, verifier);
    this.storage.setItem(STORAGE_KEYS.STATE, state);
    this.storage.setItem(STORAGE_KEYS.NONCE, nonce);

    if (options?.returnTo !== undefined) {
      this.storage.setItem(
        STORAGE_KEYS.RETURN_TO,
        sanitizeRelativeReturnTo(options.returnTo, this.getDefaultRedirectRoute()),
      );
    } else {
      this.storage.removeItem(STORAGE_KEYS.RETURN_TO);
    }

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: this.config.responseType || 'code',
      code_challenge_method: this.config.codeChallengeMethod || 'S256',
      code_challenge: challenge,
      state,
      nonce,
    });

    if (this.config.theme) {
      const themeVal =
        typeof this.config.theme === 'function' ? this.config.theme() : this.config.theme;
      if (themeVal) {
        params.append('theme', themeVal);
      }
    }

    const effectiveScope = options?.scope ?? this.config.scope;
    const effectiveAudience = options?.audience ?? this.config.audience;

    if (effectiveScope) params.append('scope', effectiveScope);
    if (effectiveAudience) params.append('audience', effectiveAudience);
    if (options?.prompt) params.append('prompt', options.prompt);
    const loginHint = options?.loginHint?.trim();
    if (loginHint) params.append('login_hint', loginHint);

    if (options?.extraParams) {
      for (const [key, value] of Object.entries(options.extraParams)) {
        if (!RESERVED_AUTHORIZE_PARAMS.has(key) && value.length > 0) {
          params.set(key, value);
        }
      }
    }

    const authUrl = `${this.config.authorizationEndpoint}?${params.toString()}`;

    if (typeof window === 'undefined' || !window.location) {
      throw new Error('startAuthorization requires a browser environment to redirect the user.');
    }

    window.location.href = authUrl;
  }

  async exchangeCodeForTokens(code: string, state: string): Promise<TokenInfo> {
    const storedState = this.storage.getItem(STORAGE_KEYS.STATE);
    const verifier = this.storage.getItem(STORAGE_KEYS.CODE_VERIFIER);
    const storedNonce = this.storage.getItem(STORAGE_KEYS.NONCE);

    if (!storedState || !constantTimeEqualStrings(state, storedState)) {
      throw new Error('Invalid state parameter. Possible CSRF attack.');
    }
    if (!verifier) {
      throw new Error('Code verifier missing from storage.');
    }

    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      code,
      code_verifier: verifier,
    });

    const response = await fetch(this.config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    const data = (await response.json()) as Record<string, unknown>;
    const accessToken = data['access_token'];
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      throw new Error('Token endpoint did not return a valid access_token.');
    }

    const idToken =
      typeof data['id_token'] === 'string' && data['id_token'].length > 0
        ? data['id_token']
        : undefined;

    if (storedNonce && idToken) {
      const claims = decodeJwtPayload<Record<string, unknown>>(idToken);
      const claimNonce = claims?.['nonce'];
      if (typeof claimNonce !== 'string' || !constantTimeEqualStrings(claimNonce, storedNonce)) {
        this.storage.clearTemporary();
        throw new Error('Invalid OIDC nonce parameter.');
      }
    }

    const expiresInSec =
      typeof data['expires_in'] === 'number' && Number.isFinite(data['expires_in'])
        ? data['expires_in']
        : 3600;
    const refreshToken =
      typeof data['refresh_token'] === 'string' && data['refresh_token'].length > 0
        ? data['refresh_token']
        : undefined;
    const scope = typeof data['scope'] === 'string' ? data['scope'] : undefined;

    const tokenInfo: TokenInfo = {
      accessToken,
      tokenType: typeof data['token_type'] === 'string' ? data['token_type'] : 'Bearer',
      expiresAt: Date.now() + expiresInSec * 1000,
      ...(refreshToken ? { refreshToken } : {}),
      ...(scope ? { scope } : {}),
      ...(idToken ? { idToken } : {}),
    };

    this.saveTokenInfo(tokenInfo);
    this.storage.clearTemporary();

    return tokenInfo;
  }

  async refreshAccessToken(): Promise<TokenInfo> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      const refreshToken = this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const formData = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        refresh_token: refreshToken,
      });

      let response: Response;
      try {
        response = await fetch(this.config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString(),
        });
      } catch (networkError) {
        this.log('error', 'Token refresh network request failed:', networkError);
        throw networkError;
      }

      if (!response.ok) {
        let errorData: Record<string, unknown> = {};
        try {
          errorData = (await response.json()) as Record<string, unknown>;
        } catch {
          try {
            errorData = { error: await response.text() };
          } catch {
            errorData = {};
          }
        }

        this.log('error', 'Token refresh failed with status:', response.status, errorData);

        // Only wipe tokens on client authentication errors (400 Bad Request or 401 Unauthorized)
        // Keep tokens on 5xx server errors or transient network failures
        if (response.status === 400 || response.status === 401) {
          this.storage.clearTokens();
        }

        const errorMsg =
          (typeof errorData['error_description'] === 'string'
            ? errorData['error_description']
            : undefined) ||
          (typeof errorData['error'] === 'string' ? errorData['error'] : undefined) ||
          response.statusText ||
          'Failed to refresh token';
        throw new Error(`Failed to refresh token (${response.status}): ${errorMsg}`);
      }

      const data = (await response.json()) as Record<string, unknown>;
      const accessToken = data['access_token'];
      if (typeof accessToken !== 'string' || accessToken.length === 0) {
        throw new Error('Refresh endpoint did not return a valid access_token.');
      }

      const expiresInSec =
        typeof data['expires_in'] === 'number' && Number.isFinite(data['expires_in'])
          ? data['expires_in']
          : 3600;
      const rotatedRefreshToken =
        typeof data['refresh_token'] === 'string' && data['refresh_token'].length > 0
          ? data['refresh_token']
          : refreshToken;
      const scope = typeof data['scope'] === 'string' ? data['scope'] : undefined;
      const idToken =
        typeof data['id_token'] === 'string' && data['id_token'].length > 0
          ? data['id_token']
          : undefined;

      const tokenInfo: TokenInfo = {
        accessToken,
        refreshToken: rotatedRefreshToken,
        tokenType: typeof data['token_type'] === 'string' ? data['token_type'] : 'Bearer',
        expiresAt: Date.now() + expiresInSec * 1000,
        ...(scope ? { scope } : {}),
        ...(idToken ? { idToken } : {}),
      };

      this.saveTokenInfo(tokenInfo);
      return tokenInfo;
    })().finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  private saveTokenInfo(info: TokenInfo): void {
    this.storage.setItem(STORAGE_KEYS.ACCESS_TOKEN, info.accessToken);
    this.storage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, info.expiresAt.toString());
    this.storage.setItem(STORAGE_KEYS.TOKEN_TYPE, info.tokenType);
    if (typeof info.refreshToken === 'string' && info.refreshToken.length > 0) {
      this.storage.setItem(STORAGE_KEYS.REFRESH_TOKEN, info.refreshToken);
    } else {
      this.storage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    }
    if (info.scope) {
      this.storage.setItem(STORAGE_KEYS.SCOPE, info.scope);
    }
    if (info.idToken) {
      this.storage.setItem(STORAGE_KEYS.ID_TOKEN, info.idToken);
    }
  }

  getAccessToken(): string | null {
    return this.storage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
  }

  getIdToken(): string | null {
    return this.storage.getItem(STORAGE_KEYS.ID_TOKEN);
  }

  getRefreshToken(): string | null {
    return this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
  }

  getUserProfile<T extends UserInfo = UserInfo>(): T | null {
    const token = this.getIdToken() || this.getAccessToken();
    return decodeJwtPayload<T>(token);
  }

  getImpersonationActor(): ImpersonationActor | null {
    const fromAccess = extractValidActorClaim(decodeJwtPayload<UserInfo>(this.getAccessToken()));
    if (fromAccess) {
      return fromAccess;
    }
    return extractValidActorClaim(decodeJwtPayload<UserInfo>(this.getIdToken()));
  }

  isImpersonatedSession(): boolean {
    return this.getImpersonationActor() !== null;
  }

  async getToken(): Promise<string | null> {
    if (this.isAuthenticated()) {
      return this.getAccessToken();
    }
    if (!this.getRefreshToken()) {
      return null;
    }
    try {
      const info = await this.refreshAccessToken();
      return info.accessToken;
    } catch {
      return null;
    }
  }

  getExpiresAt(): number | null {
    const expiresAt = this.storage.getItem(STORAGE_KEYS.TOKEN_EXPIRES_AT);
    if (!expiresAt) return null;
    const parsed = Number(expiresAt);
    return Number.isFinite(parsed) ? parsed : null;
  }

  isAuthenticated(): boolean {
    const expiresAt = this.getExpiresAt();
    if (expiresAt === null) return false;

    // Add small buffer (30s) to consider it expired early
    const isValid = Date.now() < expiresAt - 30000;
    return isValid && !!this.getAccessToken();
  }

  async navigateToAccountManagement(): Promise<void> {
    const refreshToken = this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
    if (!refreshToken) {
      throw new Error('No refresh token available to access account management.');
    }

    if (typeof window === 'undefined' || typeof document === 'undefined' || !document) {
      throw new Error('navigateToAccountManagement requires a browser environment.');
    }

    const form = document.createElement('form');
    form.method = 'POST';

    // Derive the account session endpoint from the authorizationEndpoint
    const authEndpointBase = this.config.authorizationEndpoint.replace(/\/authorize\/?$/, '');
    form.action = `${authEndpointBase}/account/session`;

    const addInput = (name: string, value: string) => {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = value;
      form.appendChild(input);
    };

    try {
      const csrfResponse = await fetch(`${authEndpointBase}/csrf-token`, { credentials: 'include' });
      const data = (await csrfResponse.json()) as { csrfToken?: unknown };
      if (typeof data.csrfToken === 'string' && data.csrfToken.length > 0) {
        addInput('_csrf', data.csrfToken);
      }
    } catch (err) {
      this.log('warn', 'Failed to fetch CSRF token for Account Management navigation', err);
    }

    addInput('refreshToken', refreshToken);
    addInput('clientId', this.config.clientId);
    addInput('redirectUri', this.config.redirectUri);

    document.body.appendChild(form);
    form.submit();
  }

  async logout(): Promise<void> {
    const accessToken = this.getAccessToken();
    const refreshToken = this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);

    this.storage.clearTokens();
    this.storage.clearTemporary();

    if (this.config.revokeEndpoint) {
      const tokensToRevoke = [
        ...(refreshToken ? [{ token: refreshToken, token_type_hint: 'refresh_token' }] : []),
        ...(accessToken ? [{ token: accessToken, token_type_hint: 'access_token' }] : []),
      ];
      for (const item of tokensToRevoke) {
        try {
          await fetch(this.config.revokeEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              token: item.token,
              token_type_hint: item.token_type_hint,
              client_id: this.config.clientId,
            }).toString(),
          });
        } catch (err) {
          this.log('error', 'Failed to revoke token during logout', err);
        }
      }
    }
  }
}
