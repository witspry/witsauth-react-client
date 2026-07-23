import { STORAGE_KEYS } from '../models/types';

export class TokenStorage {
  private getStorage(): Storage {
    // Only use localStorage if running in browser
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
    // Fallback in-memory storage for non-browser environments
    return {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
      length: 0,
      key: () => null,
    };
  }

  setItem(key: string, value: string): void {
    this.getStorage().setItem(key, value);
  }

  getItem(key: string): string | null {
    return this.getStorage().getItem(key);
  }

  removeItem(key: string): void {
    this.getStorage().removeItem(key);
  }

  clearTokens(): void {
    const storage = this.getStorage();
    storage.removeItem(STORAGE_KEYS.ACCESS_TOKEN);
    storage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
    storage.removeItem(STORAGE_KEYS.TOKEN_EXPIRES_AT);
    storage.removeItem(STORAGE_KEYS.TOKEN_TYPE);
    storage.removeItem(STORAGE_KEYS.SCOPE);
  }

  clearTemporary(): void {
    const storage = this.getStorage();
    storage.removeItem(STORAGE_KEYS.CODE_VERIFIER);
    storage.removeItem(STORAGE_KEYS.STATE);
    storage.removeItem(STORAGE_KEYS.NONCE);
  }
}
