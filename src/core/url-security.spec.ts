import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  constantTimeEqualStrings,
  isSameTupleOrigin,
  sanitizeRelativeReturnTo,
} from './url-security.js';

describe('url-security', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('sanitizeRelativeReturnTo', () => {
    it('accepts valid relative paths with query strings and fragments', () => {
      expect(sanitizeRelativeReturnTo('/my-bookings?status=confirmed#top', '/')).toBe(
        '/my-bookings?status=confirmed#top',
      );
      expect(sanitizeRelativeReturnTo('  /dashboard/audit?page=2  ', '/dashboard')).toBe(
        '/dashboard/audit?page=2',
      );
    });

    it('rejects open-redirect bypass vectors and control characters', () => {
      const vectors = [
        null,
        undefined,
        '',
        '   ',
        '//evil.com',
        '///evil.com',
        '/\\evil.com',
        '\\evil.com',
        '/%2f/evil.com',
        '/%2F%2Fevil.com',
        '/.//evil.com',
        '/foo/..//evil.com',
        '/foo/%2e%2e//evil.com',
        'javascript:alert(1)',
        'https://evil.com/phish',
        'http://localhost:3000/test',
        'data:text/html,<script>alert(1)</script>',
        '/ok\r\nSet-Cookie: a=b',
        '/ok\tpath',
        `/${'a'.repeat(2050)}`,
      ];

      for (const vector of vectors) {
        expect(sanitizeRelativeReturnTo(vector, '/fallback')).toBe('/fallback');
      }
    });
  });

  describe('isSameTupleOrigin', () => {
    it('enforces exact tuple-origin equality and rejects opaque null origins', () => {
      expect(isSameTupleOrigin('https://app.example.com', 'https://app.example.com:443/cb')).toBe(
        true,
      );
      expect(isSameTupleOrigin('http://app.example.com', 'https://app.example.com')).toBe(false);
      expect(isSameTupleOrigin('https://sub.example.com', 'https://app.example.com')).toBe(false);
      expect(isSameTupleOrigin('https://app.example.com:8443', 'https://app.example.com')).toBe(
        false,
      );
      expect(isSameTupleOrigin('null', 'https://app.example.com')).toBe(false);
      expect(isSameTupleOrigin('null', 'null')).toBe(false);
      expect(isSameTupleOrigin('', 'https://app.example.com')).toBe(false);
      expect(isSameTupleOrigin('not-a-url', 'https://app.example.com')).toBe(false);
    });

    it('uses standardized Origin API when available in globalThis', () => {
      const fromMock = vi.fn((input: unknown) => ({
        isSameOrigin: (other: unknown) =>
          String(input).startsWith('https://trusted.test') &&
          String((other as { raw: string }).raw).startsWith('https://trusted.test'),
        raw: String(input),
      }));
      vi.stubGlobal('Origin', { from: fromMock });

      expect(isSameTupleOrigin('https://trusted.test/a', 'https://trusted.test/b')).toBe(true);
      expect(fromMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('constantTimeEqualStrings', () => {
    it('compares equal and different UTF-8 strings accurately', () => {
      expect(constantTimeEqualStrings('abc-123-✓', 'abc-123-✓')).toBe(true);
      expect(constantTimeEqualStrings('abc-123', 'abc-124')).toBe(false);
      expect(constantTimeEqualStrings('short', 'longer-string')).toBe(false);
      expect(constantTimeEqualStrings('', '')).toBe(true);
    });
  });
});
