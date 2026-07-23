import { STORAGE_KEYS } from '../models/types';

export class TokenStorage {
  private memoryStorage = new Map<string, string>();

  private getStorage(): Storage {
    // Only use localStorage if running in browser
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
    
    const store = this.memoryStorage;
    // Fallback in-memory storage for non-browser environments
    return {
      getItem: (key: string) => store.has(key) ? store.get(key) as string : null,
      setItem: (key: string, value: string) => { store.set(key, value); },
      removeItem: (key: string) => { store.delete(key); },
      clear: () => { store.clear(); },
      get length() { return store.size; },
      key: (index: number) => Array.from(store.keys())[index] || null,
    } as Storage;
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
