import {
  constantTimeEqualStrings,
  isSameTupleOrigin,
  sanitizeRelativeReturnTo,
} from '../core/url-security.js';

export { constantTimeEqualStrings, isSameTupleOrigin, sanitizeRelativeReturnTo };

const MUTATING_HTTP_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const VALID_RAW_GUEST_SID_RE = /^se_guest_[A-Za-z0-9_-]{16,110}$/;

export type BffAppScope = string;

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(encoded: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    return null;
  }
  try {
    const padded = encoded
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(encoded.length / 4) * 4, '=');
    const binary = globalThis.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

export function generateSecureTokenBase64Url(byteLength = 24): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export async function computeSha256Base64Url(input: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return toBase64Url(new Uint8Array(digest));
}

export interface CsrfValidationSuccess {
  readonly ok: true;
}

export interface CsrfValidationFailure {
  readonly ok: false;
  readonly status: 403 | 415;
  readonly code: 'CSRF_ORIGIN_REJECTED' | 'UNSUPPORTED_MEDIA_TYPE';
  readonly message: string;
}

export type CsrfValidationResult = CsrfValidationSuccess | CsrfValidationFailure;

/**
 * Enforces same-origin CSRF protection on cookie-authenticated mutations.
 * Requires matching `Origin` (or `Sec-Fetch-Site: same-origin` when `Origin` is omitted)
 * and `Content-Type: application/json` when a request body is expected.
 */
export function assertSameOriginMutation(
  request: {
    readonly method: string;
    readonly headers: { readonly get: (name: string) => string | null };
  },
  expectedPublicOrigin: string,
  options?: {
    readonly hasBody?: boolean | undefined;
    readonly requireJsonContentType?: boolean | undefined;
  },
): CsrfValidationResult {
  const methodUpper = request.method.toUpperCase();
  if (!MUTATING_HTTP_METHODS.has(methodUpper)) {
    return { ok: true };
  }

  const originHeader = request.headers.get('origin')?.trim();
  if (originHeader && originHeader.length > 0) {
    if (!isSameTupleOrigin(originHeader, expectedPublicOrigin)) {
      return {
        ok: false,
        status: 403,
        code: 'CSRF_ORIGIN_REJECTED',
        message: 'Cross-origin state-changing request was rejected.',
      };
    }
  } else {
    const secFetchSite = request.headers.get('sec-fetch-site')?.trim().toLowerCase();
    if (secFetchSite !== 'same-origin') {
      return {
        ok: false,
        status: 403,
        code: 'CSRF_ORIGIN_REJECTED',
        message:
          'State-changing request requires a verified same-origin Origin or Fetch Metadata header.',
      };
    }
  }

  if (options?.hasBody && options.requireJsonContentType !== false) {
    const contentType = (request.headers.get('content-type') ?? '').trim().toLowerCase();
    if (!contentType.startsWith('application/json')) {
      return {
        ok: false,
        status: 415,
        code: 'UNSUPPORTED_MEDIA_TYPE',
        message: 'Mutating BFF requests with a payload must use Content-Type: application/json.',
      };
    }
  }

  return { ok: true };
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  if (!secret || secret.trim().length < 16) {
    throw new Error('BFF cookie HMAC secret must be at least 16 characters.');
  }
  return globalThis.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

export interface SignedPkceCookiePayload extends Record<string, unknown> {
  readonly state: string;
  readonly codeVerifier: string;
  readonly nonce: string;
  readonly returnTo: string;
  readonly app: BffAppScope;
  readonly exp: number;
}

export async function signBffCookiePayload(
  payload: Record<string, unknown>,
  secret: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const payloadB64 = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const key = await importHmacKey(secret);
  const sig = await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(payloadB64));
  return `${payloadB64}.${toBase64Url(new Uint8Array(sig))}`;
}

export async function verifySignedBffCookiePayload<
  TPayload extends Record<string, unknown> = Record<string, unknown>,
>(
  cookieValue: string | undefined,
  secret: string,
  options?: {
    readonly expectedApp?: BffAppScope | undefined;
    readonly requireExp?: boolean | undefined;
    readonly nowMs?: number | undefined;
  },
): Promise<TPayload | null> {
  if (!cookieValue || typeof cookieValue !== 'string') {
    return null;
  }
  const parts = cookieValue.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) {
    return null;
  }
  const sigBytes = fromBase64Url(sigB64);
  const payloadBytes = fromBase64Url(payloadB64);
  if (!sigBytes || !payloadBytes) {
    return null;
  }

  try {
    const key = await importHmacKey(secret);
    const sigCopy = new Uint8Array(sigBytes.byteLength);
    sigCopy.set(sigBytes);
    const valid = await globalThis.crypto.subtle.verify(
      'HMAC',
      key,
      sigCopy,
      new TextEncoder().encode(payloadB64),
    );
    if (!valid) {
      return null;
    }
    const parsed = JSON.parse(new TextDecoder().decode(payloadBytes)) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const record = parsed as Record<string, unknown>;
    const nowSec = Math.floor((options?.nowMs ?? Date.now()) / 1000);
    if (
      options?.requireExp &&
      (typeof record['exp'] !== 'number' || !Number.isFinite(record['exp']))
    ) {
      return null;
    }
    if (typeof record['exp'] === 'number' && record['exp'] <= nowSec) {
      return null;
    }
    if (options?.expectedApp !== undefined && record['app'] !== options.expectedApp) {
      return null;
    }
    return record as TPayload;
  } catch {
    return null;
  }
}

export async function signPkceCookiePayload(
  input: {
    readonly state: string;
    readonly codeVerifier: string;
    readonly nonce: string;
    readonly returnTo: string;
    readonly app: BffAppScope;
    readonly ttlSeconds?: number | undefined;
    readonly nowMs?: number | undefined;
  },
  secret: string,
): Promise<string> {
  const nowSec = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const ttlSec = Math.max(60, Math.floor(input.ttlSeconds ?? 600));
  const payload: SignedPkceCookiePayload = {
    state: input.state,
    codeVerifier: input.codeVerifier,
    nonce: input.nonce,
    returnTo: input.returnTo,
    app: input.app,
    exp: nowSec + ttlSec,
  };
  return signBffCookiePayload(payload, secret);
}

export async function verifySignedPkceCookiePayload(
  cookieValue: string | undefined,
  secret: string,
  expectedApp: BffAppScope,
  nowMs?: number,
): Promise<SignedPkceCookiePayload | null> {
  const verified = await verifySignedBffCookiePayload<SignedPkceCookiePayload>(
    cookieValue,
    secret,
    {
      expectedApp,
      requireExp: true,
      nowMs,
    },
  );
  if (
    !verified ||
    typeof verified.state !== 'string' ||
    typeof verified.codeVerifier !== 'string' ||
    typeof verified.nonce !== 'string' ||
    typeof verified.returnTo !== 'string'
  ) {
    return null;
  }
  return verified;
}

export async function signGuestSessionId(guestSid: string, secret: string): Promise<string> {
  if (!VALID_RAW_GUEST_SID_RE.test(guestSid)) {
    throw new Error('Invalid guest session ID format.');
  }
  const key = await importHmacKey(secret);
  const sig = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`guest:${guestSid}`),
  );
  return `${guestSid}.${toBase64Url(new Uint8Array(sig))}`;
}

export async function verifySignedGuestSessionId(
  cookieValue: string | undefined,
  secret: string,
): Promise<string | null> {
  if (!cookieValue || typeof cookieValue !== 'string') {
    return null;
  }
  const parts = cookieValue.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [guestSid, sigB64] = parts;
  if (!guestSid || !sigB64 || !VALID_RAW_GUEST_SID_RE.test(guestSid)) {
    return null;
  }
  const sigBytes = fromBase64Url(sigB64);
  if (!sigBytes) {
    return null;
  }
  try {
    const key = await importHmacKey(secret);
    const sigCopy = new Uint8Array(sigBytes.byteLength);
    sigCopy.set(sigBytes);
    const valid = await globalThis.crypto.subtle.verify(
      'HMAC',
      key,
      sigCopy,
      new TextEncoder().encode(`guest:${guestSid}`),
    );
    return valid ? guestSid : null;
  } catch {
    return null;
  }
}

export const FETCH_METADATA_VARY_HEADER = 'Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site';

export type FetchMetadataCheckResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly status: 403;
      readonly code: 'FETCH_METADATA_REJECTED';
      readonly message: string;
    };

/**
 * Enforces browser Fetch Metadata on sensitive cookie-bearing GET endpoints before any auth/session work.
 * When `Sec-Fetch-Site` is `'cross-site'`, requires BOTH `allowCrossSiteDocumentNavigation === true`
 * AND explicit `Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document`.
 */
export function assertBrowserNavigationFetchMetadata(
  request: {
    readonly headers: { readonly get: (name: string) => string | null };
  },
  options?: { readonly allowCrossSiteDocumentNavigation?: boolean | undefined },
): FetchMetadataCheckResult {
  const site = request.headers.get('sec-fetch-site')?.trim().toLowerCase();
  const mode = request.headers.get('sec-fetch-mode')?.trim().toLowerCase();
  const dest = request.headers.get('sec-fetch-dest')?.trim().toLowerCase();
  if (mode && mode !== 'navigate') {
    return {
      ok: false,
      status: 403,
      code: 'FETCH_METADATA_REJECTED',
      message: 'Non-navigation Fetch Metadata mode rejected.',
    };
  }
  if (dest && dest !== 'document') {
    return {
      ok: false,
      status: 403,
      code: 'FETCH_METADATA_REJECTED',
      message: 'Non-document Fetch Metadata destination rejected.',
    };
  }
  if (site === 'cross-site') {
    if (
      options?.allowCrossSiteDocumentNavigation !== true ||
      mode !== 'navigate' ||
      dest !== 'document'
    ) {
      return {
        ok: false,
        status: 403,
        code: 'FETCH_METADATA_REJECTED',
        message: 'Cross-site request rejected by Fetch Metadata policy.',
      };
    }
  }
  return { ok: true };
}

/**
 * Computes an HMAC-SHA256 signature binding impersonation handoff consumption to exact origin
 * and handoff code hash.
 */
export async function signImpersonationHandoffConsume(
  handoffCode: string,
  origin: string,
  secret: string,
): Promise<string> {
  const normalizedOrigin = new URL(origin).origin;
  if (normalizedOrigin === 'null') {
    throw new Error('Impersonation handoff consume origin cannot be opaque "null".');
  }
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(handoffCode),
  );
  const codeHash = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join(
    '',
  );
  const key = await importHmacKey(secret);
  const sig = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`impersonation_handoff_consume:${normalizedOrigin}:${codeHash}`),
  );
  return toBase64Url(new Uint8Array(sig));
}

export interface CookieReadableRequest {
  readonly url: string;
  readonly nextUrl?: {
    readonly pathname: string;
    readonly search: string;
    readonly origin: string;
    readonly searchParams: URLSearchParams;
  } | undefined;
  readonly headers: {
    readonly get: (name: string) => string | null;
  };
  readonly cookies?: {
    readonly get: (name: string) => { readonly value: string } | undefined;
  } | undefined;
}

export function readRequestCookie(
  request: CookieReadableRequest,
  cookieName: string,
): string | undefined {
  const direct = request.cookies?.get(cookieName)?.value;
  if (direct !== undefined) {
    return direct;
  }
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) {
    return undefined;
  }
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx <= 0) {
      continue;
    }
    const name = trimmed.slice(0, eqIdx).trim();
    if (name !== cookieName) {
      continue;
    }
    const rawVal = trimmed.slice(eqIdx + 1).trim();
    try {
      return decodeURIComponent(rawVal);
    } catch {
      return rawVal;
    }
  }
  return undefined;
}

export function getRequestUrlParts(request: CookieReadableRequest): {
  readonly pathname: string;
  readonly search: string;
  readonly origin: string;
  readonly searchParams: URLSearchParams;
} {
  if (request.nextUrl) {
    return request.nextUrl;
  }
  const parsed = new URL(request.url);
  return {
    pathname: parsed.pathname,
    search: parsed.search,
    origin: parsed.origin,
    searchParams: parsed.searchParams,
  };
}
