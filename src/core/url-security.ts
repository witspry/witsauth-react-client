const SENTINEL_INTERNAL_ORIGIN = 'https://witsauth.internal';

interface GlobalOriginApi {
  readonly Origin?: {
    from(input: unknown): {
      isSameOrigin(other: unknown): boolean;
    };
  };
}

/**
 * Constant-time UTF-8 string equality helper for state, nonce, and token comparisons.
 */
export function constantTimeEqualStrings(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const maxLen = Math.max(leftBytes.length, rightBytes.length);
  let diff = leftBytes.length ^ rightBytes.length;
  for (let i = 0; i < maxLen; i += 1) {
    diff |= (leftBytes[i] ?? 0) ^ (rightBytes[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Hardened relative redirect target sanitizer.
 * Rejects ASCII control characters (`[\x00-\x20\x7f]`), percent-encoded control/slash tricks,
 * backslashes, scheme prefixes, and protocol-relative `//` targets, then verifies same-origin
 * resolution via the WHATWG `URL` parser.
 */
export function sanitizeRelativeReturnTo(raw: string | null | undefined, fallback = '/'): string {
  if (!raw || typeof raw !== 'string') {
    return fallback;
  }
  const trimmed = raw.trim();
  if (
    trimmed.length === 0 ||
    trimmed.length > 2048 ||
    /[\x00-\x20\x7f\\]/.test(trimmed) ||
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//') ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)
  ) {
    return fallback;
  }

  try {
    const decoded = decodeURIComponent(trimmed);
    if (
      /[\x00-\x1f\x7f\\]/.test(decoded) ||
      !decoded.startsWith('/') ||
      decoded.startsWith('//') ||
      decoded.includes('://')
    ) {
      return fallback;
    }
  } catch {
    return fallback;
  }

  try {
    const parsed = new URL(trimmed, SENTINEL_INTERNAL_ORIGIN);
    if (
      parsed.origin !== SENTINEL_INTERNAL_ORIGIN ||
      !parsed.pathname.startsWith('/') ||
      parsed.pathname.startsWith('//') ||
      parsed.pathname.includes('\\')
    ) {
      return fallback;
    }
    const decodedPathname = decodeURIComponent(parsed.pathname);
    if (decodedPathname.startsWith('//') || decodedPathname.includes('\\')) {
      return fallback;
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return fallback;
  }
}

/**
 * Validates exact tuple-origin equality (`scheme` + `host` + `port`), rejecting opaque `"null"` origins.
 * Uses the standardized `Origin` API when present (`'Origin' in globalThis`) and falls back to WHATWG `new URL()`.
 */
export function isSameTupleOrigin(
  candidateOriginOrUrl: string | null | undefined,
  trustedOriginOrUrl: string,
): boolean {
  if (!candidateOriginOrUrl || !trustedOriginOrUrl) {
    return false;
  }
  try {
    const globalOrigin = (globalThis as GlobalOriginApi).Origin;
    if (globalOrigin && typeof globalOrigin.from === 'function') {
      return globalOrigin
        .from(candidateOriginOrUrl)
        .isSameOrigin(globalOrigin.from(trustedOriginOrUrl));
    }
    const candidate = new URL(candidateOriginOrUrl);
    const trusted = new URL(trustedOriginOrUrl);
    return (
      candidate.origin !== 'null' &&
      trusted.origin !== 'null' &&
      candidate.origin === trusted.origin
    );
  } catch {
    return false;
  }
}
