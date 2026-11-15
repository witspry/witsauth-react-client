import React, { useCallback, useEffect, useRef, useState } from 'react';
import { sanitizeRelativeReturnTo } from '../core/url-security.js';

export interface ImpersonationCallbackRenderState {
  readonly hydrated: boolean;
  readonly handoffCode: string;
  readonly canSubmit: boolean;
  readonly submitting: boolean;
  readonly errorMessage: string | null;
  readonly safeReturnTo: string;
  readonly cancelHref: string;
  readonly activate: () => Promise<void>;
}

export interface ImpersonationCallbackProps {
  readonly bffBasePath?: string | undefined;
  readonly consumeEndpoint?: string | undefined;
  readonly initialReturnTo?: string | undefined;
  readonly defaultReturnTo?: string | undefined;
  readonly cleanUrlPath?: string | undefined;
  readonly minCodeLength?: number | undefined;
  readonly autoSubmit?: boolean | undefined;
  readonly cancelHref?: string | undefined;
  readonly fetchImpl?: typeof globalThis.fetch | undefined;
  readonly onSuccessNavigate?: ((nextPath: string) => void) | undefined;
  readonly children?: ((state: ImpersonationCallbackRenderState) => React.ReactNode) | undefined;
}

function extractCodeFromHash(hash: string): string {
  const cleaned = hash.replace(/^#/, '').trim();
  if (!cleaned) {
    return '';
  }
  const params = new URLSearchParams(cleaned);
  return (params.get('code') ?? '').trim();
}

export function ImpersonationCallback({
  bffBasePath = '/api/auth',
  consumeEndpoint,
  initialReturnTo,
  defaultReturnTo = '/my-bookings',
  cleanUrlPath = '/impersonate/consume',
  minCodeLength = 20,
  autoSubmit = false,
  cancelHref = '/',
  fetchImpl,
  onSuccessNavigate,
  children,
}: ImpersonationCallbackProps): React.JSX.Element {
  const normalizedBase = bffBasePath.trim().replace(/\/+$/, '') || '/api/auth';
  const endpoint = consumeEndpoint ?? `${normalizedBase}/impersonate/consume`;
  const fallbackReturnTo = sanitizeRelativeReturnTo(defaultReturnTo, '/');
  const safeReturnTo = sanitizeRelativeReturnTo(initialReturnTo, fallbackReturnTo);
  const safeCancelHref = sanitizeRelativeReturnTo(cancelHref, '/');

  const capturedCodeRef = useRef<string>('');
  const submitInFlightRef = useRef<boolean>(false);
  const autoSubmittedRef = useRef<boolean>(false);

  const [handoffCode, setHandoffCode] = useState<string>('');
  const [hydrated, setHydrated] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchRef = useRef(fetchImpl);
  fetchRef.current = fetchImpl;
  const navRef = useRef(onSuccessNavigate);
  navRef.current = onSuccessNavigate;

  const activate = useCallback(async (): Promise<void> => {
    const activeCode = handoffCode || capturedCodeRef.current;
    if (!activeCode || activeCode.length < minCodeLength || submitInFlightRef.current) {
      return;
    }
    submitInFlightRef.current = true;
    setSubmitting(true);
    setErrorMessage(null);
    let redirected = false;
    try {
      const customFetch = fetchRef.current;
      const runFetch = customFetch
        ? customFetch(endpoint, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/json',
              Accept: 'application/json',
            },
            body: JSON.stringify({
              code: activeCode,
              returnTo: safeReturnTo,
            }),
          })
        : globalThis.fetch(endpoint, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              'Content-Type': 'application/json',
              Accept: 'application/json',
            },
            body: JSON.stringify({
              code: activeCode,
              returnTo: safeReturnTo,
            }),
          });

      const response = await runFetch;
      const json = (await response.json().catch(() => ({}))) as {
        readonly data?: { readonly redirectTo?: unknown } | undefined;
        readonly error?: { readonly message?: unknown } | undefined;
      };
      if (!response.ok) {
        const msg =
          typeof json.error?.message === 'string' && json.error.message.trim().length > 0
            ? json.error.message
            : 'Support handoff code could not be redeemed. It may have expired or already been consumed.';
        setErrorMessage(msg);
        return;
      }
      const nextRaw = typeof json.data?.redirectTo === 'string' ? json.data.redirectTo : undefined;
      const nextPath = sanitizeRelativeReturnTo(nextRaw, safeReturnTo);
      redirected = true;
      const customNav = navRef.current;
      if (customNav) {
        customNav(nextPath);
      } else if (typeof window !== 'undefined') {
        window.location.assign(nextPath);
      }
    } catch {
      setErrorMessage('Network error while activating support session. Please try again.');
    } finally {
      if (!redirected) {
        submitInFlightRef.current = false;
        setSubmitting(false);
      }
    }
  }, [endpoint, handoffCode, minCodeLength, safeReturnTo]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    const codeFromFragment = extractCodeFromHash(window.location.hash);
    if (codeFromFragment.length > 0) {
      capturedCodeRef.current = codeFromFragment;
    }
    if (window.location.hash.length > 0 || window.location.search.length > 0) {
      const scrubPath = sanitizeRelativeReturnTo(cleanUrlPath, window.location.pathname || '/');
      window.history.replaceState(null, '', scrubPath);
    }
    const resolvedCode = capturedCodeRef.current || codeFromFragment;
    setHandoffCode(resolvedCode);
    if (resolvedCode.length < minCodeLength) {
      setErrorMessage(
        'Missing or invalid single-use support handoff code in URL fragment (#code=...).',
      );
    } else {
      setErrorMessage(null);
    }
    setHydrated(true);
  }, [cleanUrlPath, minCodeLength]);

  useEffect(() => {
    if (
      autoSubmit &&
      hydrated &&
      !autoSubmittedRef.current &&
      (handoffCode.length >= minCodeLength || capturedCodeRef.current.length >= minCodeLength)
    ) {
      autoSubmittedRef.current = true;
      void activate();
    }
  }, [activate, autoSubmit, handoffCode.length, hydrated, minCodeLength]);

  const canSubmit = hydrated && !submitting && handoffCode.length >= minCodeLength;

  if (children) {
    return (
      <>
        {children({
          hydrated,
          handoffCode,
          canSubmit,
          submitting,
          errorMessage,
          safeReturnTo,
          cancelHref: safeCancelHref,
          activate,
        })}
      </>
    );
  }

  return (
    <section
      style={{
        maxWidth: '560px',
        margin: '40px auto',
        padding: '24px',
        border: '1px solid #E2E8F0',
        borderRadius: '12px',
        display: 'grid',
        gap: '16px',
      }}
    >
      <h1 style={{ margin: 0, fontSize: '1.25rem' }}>Confirm Impersonation Session</h1>
      <p style={{ margin: 0, fontSize: '0.92rem', lineHeight: 1.5 }}>
        Activate your time-boxed, audited impersonation session. All actions during this session
        remain recorded under the impersonating actor identity.
      </p>
      {errorMessage ? (
        <div
          role="alert"
          style={{
            padding: '12px 14px',
            borderRadius: '8px',
            backgroundColor: '#FEF2F2',
            border: '1px solid #FECACA',
            color: '#991B1B',
            fontSize: '0.88rem',
          }}
        >
          {errorMessage}
        </div>
      ) : null}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void activate();
        }}
        style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}
      >
        <button type="submit" disabled={!canSubmit}>
          {submitting ? 'Activating Session…' : 'Activate Support Session'}
        </button>
        <a href={safeCancelHref}>Cancel &amp; Return Home</a>
      </form>
    </section>
  );
}
