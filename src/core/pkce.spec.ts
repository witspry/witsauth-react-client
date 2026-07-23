import { describe, it, expect, beforeEach } from 'vitest';
import { generateCodeVerifier, generateState, createCodeChallenge } from './pkce';

describe('PKCE Utilities', () => {
  beforeEach(() => {
    // Mock crypto for node environment if needed
    if (!globalThis.crypto) {
      globalThis.crypto = {
        getRandomValues: (arr: any) => {
          for (let i = 0; i < arr.length; i++) {
            arr[i] = Math.floor(Math.random() * 256);
          }
          return arr;
        },
        subtle: {
          digest: async (_algo: string, data: Uint8Array) => {
            // Mock SHA-256 digest just returning the data back for testing
            return data.buffer;
          }
        }
      } as any;
    }
  });

  it('generateCodeVerifier should return a 6 digit string', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toHaveLength(6);
    expect(verifier).toMatch(/^[0-9]{6}$/);
  });

  it('generateState should return a base64url string', () => {
    const state = generateState();
    expect(state).toBeTruthy();
    expect(typeof state).toBe('string');
    // base64url characters only
    expect(state).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('createCodeChallenge should return a valid base64url encoded string', async () => {
    const challenge = await createCodeChallenge('123456');
    expect(challenge).toBeTruthy();
    expect(typeof challenge).toBe('string');
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
});
