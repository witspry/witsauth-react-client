import React, { useEffect, useRef } from 'react';
import { OAuthCallbackError } from '../models/types.js';
import { useAuth } from './AuthContext.js';

export interface AuthCallbackProps {
  readonly onSuccess?: (() => void) | undefined;
  readonly onError?: ((error: Error) => void) | undefined;
  readonly loadingComponent?: React.ReactNode | undefined;
}

export const AuthCallback: React.FC<AuthCallbackProps> = ({
  onSuccess,
  onError,
  loadingComponent = <div>Processing authentication...</div>,
}) => {
  const { handleCallback, client } = useAuth();
  const hasProcessed = useRef(false);

  useEffect(() => {
    // Prevent React StrictMode double-redemption of single-use authorization codes.
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const processCallback = async () => {
      if (typeof window === 'undefined' || !window.location) return;
      const searchParams = new URLSearchParams(window.location.search);
      const hashParams = new URLSearchParams(window.location.hash.substring(1));

      const code = searchParams.get('code') || hashParams.get('code');
      const state = searchParams.get('state') || hashParams.get('state');
      const error = searchParams.get('error') || hashParams.get('error');
      const errorDescription =
        searchParams.get('error_description') || hashParams.get('error_description') || undefined;

      if (error) {
        const callbackErr = new OAuthCallbackError(error, errorDescription);
        client?.reportCallbackError(callbackErr);
        onError?.(callbackErr);
        return;
      }

      if (code && state) {
        try {
          await handleCallback(code, state);
          onSuccess?.();
        } catch (err) {
          const normalized = err instanceof Error ? err : new Error(String(err));
          onError?.(normalized);
        }
      } else if (!code) {
        const target = client ? client.consumeStoredReturnTo(client.getDefaultRedirectRoute()) : '/';
        window.location.assign(target);
      }
    };

    void processCallback();
  }, [handleCallback, client, onSuccess, onError]);

  return <>{loadingComponent}</>;
};
