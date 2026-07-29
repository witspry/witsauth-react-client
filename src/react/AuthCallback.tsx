import React, { useEffect, useRef } from 'react';
import { useAuth } from './AuthContext';

interface AuthCallbackProps {
  onSuccess?: () => void;
  onError?: (error: Error) => void;
  loadingComponent?: React.ReactNode;
}

export const AuthCallback: React.FC<AuthCallbackProps> = ({ 
  onSuccess, 
  onError, 
  loadingComponent = <div>Processing authentication...</div> 
}) => {
  const { handleCallback, client } = useAuth();
  const hasProcessed = useRef(false);

  useEffect(() => {
    // Prevent strict mode double-firing
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const processCallback = async () => {
      const searchParams = new URLSearchParams(window.location.search);
      const hashParams = new URLSearchParams(window.location.hash.substring(1));
      
      const code = searchParams.get('code') || hashParams.get('code');
      const state = searchParams.get('state') || hashParams.get('state');
      const error = searchParams.get('error') || hashParams.get('error');

      if (error) {
        const err = new Error(`OAuth Error: ${error}`);
        if (onError) onError(err);
        return;
      }

      if (code && state) {
        try {
          await handleCallback(code, state);
          if (onSuccess) onSuccess();
        } catch (err) {
          if (onError) onError(err instanceof Error ? err : new Error(String(err)));
        }
      } else if (!code) {
        const config = (client as any).config;
        window.location.assign(config.redirectRoute || '/');
      }
    };

    processCallback();
  }, [handleCallback, client, onSuccess, onError]);

  return <>{loadingComponent}</>;
};
