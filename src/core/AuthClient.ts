import { OAuth2Config, STORAGE_KEYS, TokenInfo } from '../models/types';
import { generateCodeVerifier, generateState, createCodeChallenge } from './pkce';
import { TokenStorage } from './storage';

export class AuthClient {
  private config: OAuth2Config;
  private storage: TokenStorage;

  constructor(config: OAuth2Config, storage?: TokenStorage) {
    this.config = config;
    this.storage = storage || new TokenStorage(config.storage, config.customStorage);
  }

  log(level: 'error' | 'warn' | 'info' | 'debug', ...args: any[]): void {
    const levels = { none: 0, error: 1, warn: 2, info: 3, debug: 4 };
    const currentLevel = levels[this.config.logLevel || 'warn'] || 0;
    const msgLevel = levels[level] || 0;
    
    if (msgLevel > 0 && currentLevel >= msgLevel) {
      console[level](...args);
    }
  }

  async startAuthorization(): Promise<void> {
    const verifier = generateCodeVerifier();
    const challenge = await createCodeChallenge(verifier);
    const state = generateState();
    
    // Nonce is often generated similarly to state
    const nonce = this.config.nonce || generateState();

    this.storage.setItem(STORAGE_KEYS.CODE_VERIFIER, verifier);
    this.storage.setItem(STORAGE_KEYS.STATE, state);
    this.storage.setItem(STORAGE_KEYS.NONCE, nonce);

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: this.config.responseType || 'code',
      code_challenge_method: this.config.codeChallengeMethod || 'S256',
      code_challenge: challenge,
      state,
      nonce
    });

    if (this.config.scope) params.append('scope', this.config.scope);
    if (this.config.audience) params.append('audience', this.config.audience);

    const authUrl = `${this.config.authorizationEndpoint}?${params.toString()}`;
    
    if (typeof window === 'undefined' || !window.location) {
      throw new Error('startAuthorization requires a browser environment to redirect the user.');
    }

    window.location.href = authUrl;
  }

  async exchangeCodeForTokens(code: string, state: string): Promise<TokenInfo> {
    const storedState = this.storage.getItem(STORAGE_KEYS.STATE);
    const verifier = this.storage.getItem(STORAGE_KEYS.CODE_VERIFIER);

    if (state !== storedState) {
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
      code_verifier: verifier
    });

    const response = await fetch(this.config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    const data = await response.json();
    
    const tokenInfo: TokenInfo = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      tokenType: data.token_type || 'Bearer',
      expiresAt: Date.now() + (data.expires_in * 1000),
      scope: data.scope,
      idToken: data.id_token
    };

    this.saveTokenInfo(tokenInfo);
    this.storage.clearTemporary();

    return tokenInfo;
  }

  async refreshAccessToken(): Promise<TokenInfo> {
    const refreshToken = this.storage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const formData = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      refresh_token: refreshToken
    });

    const response = await fetch(this.config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });

    if (!response.ok) {
      this.storage.clearTokens();
      throw new Error('Failed to refresh token');
    }

    const data = await response.json();

    const tokenInfo: TokenInfo = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken, // fallback if provider doesn't rotate refresh tokens
      tokenType: data.token_type || 'Bearer',
      expiresAt: Date.now() + (data.expires_in * 1000),
      scope: data.scope,
      idToken: data.id_token
    };

    this.saveTokenInfo(tokenInfo);
    return tokenInfo;
  }

  private saveTokenInfo(info: TokenInfo): void {
    this.storage.setItem(STORAGE_KEYS.ACCESS_TOKEN, info.accessToken);
    this.storage.setItem(STORAGE_KEYS.TOKEN_EXPIRES_AT, info.expiresAt.toString());
    this.storage.setItem(STORAGE_KEYS.TOKEN_TYPE, info.tokenType);
    if (info.refreshToken) {
      this.storage.setItem(STORAGE_KEYS.REFRESH_TOKEN, info.refreshToken);
    }
    if (info.scope) {
      this.storage.setItem(STORAGE_KEYS.SCOPE, info.scope);
    }
  }

  getAccessToken(): string | null {
    return this.storage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
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
    
    // Add small buffer (e.g. 30s) to consider it expired early
    const isValid = Date.now() < (expiresAt - 30000);
    return isValid && !!this.getAccessToken();
  }

  async logout(): Promise<void> {
    const token = this.getAccessToken();
    
    this.storage.clearTokens();
    this.storage.clearTemporary();
    
    if (this.config.revokeEndpoint && token) {
      try {
        await fetch(this.config.revokeEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token }).toString()
        });
      } catch (err) {
        this.log('error', 'Failed to revoke token during logout', err);
      }
    }
  }
}
