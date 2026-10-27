import React, { createContext, useContext, useEffect, useState, useMemo, useCallback } from 'react';
import { AuthorizeOptions, OAuth2Config, AuthState, TokenInfo, UserInfo } from '../models/types';
import { AuthClient } from '../core/AuthClient';

export interface AuthContextValue extends AuthState {
  accessToken: string | null;
  idToken: string | null;
  user: UserInfo | null;
  login: (options?: AuthorizeOptions) => Promise<void>;
  logout: () => Promise<void>;
  getToken: () => Promise<string | null>;
  navigateToAccountManagement: () => Promise<void>;
  client: AuthClient;
  handleCallback: (code: string, state: string) => Promise<TokenInfo>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{
  config: OAuth2Config;
  children: React.ReactNode;
}> = ({ config, children }) => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
  });

  const client = useMemo(() => new AuthClient(config), [config]);

  useEffect(() => {
    // Initial check on mount
    const checkAuth = async () => {
      try {
        if (client.isAuthenticated()) {
          setAuthState({ isAuthenticated: true, isLoading: false });
        } else {
          // If access token is expired or missing, try refreshing
          try {
            await client.refreshAccessToken();
            setAuthState({ isAuthenticated: true, isLoading: false });
          } catch {
            setAuthState({ isAuthenticated: false, isLoading: false });
          }
        }
      } catch (err) {
        setAuthState({ isAuthenticated: false, isLoading: false, error: err instanceof Error ? err.message : String(err) });
      }
    };
    checkAuth();
  }, [client]);

  // Auto-refresh token logic
  useEffect(() => {
    if (config.autoRefresh === false || !authState.isAuthenticated) return;

    let isRefreshing = false;

    const interval = setInterval(async () => {
      if (isRefreshing) return;

      try {
        const expiresAt = client.getExpiresAt();
        if (!expiresAt) return;
        
        // Use configured threshold or default to 60 seconds
        const thresholdMs = (config.refreshThreshold ?? 60) * 1000;
        
        if (Date.now() >= expiresAt - thresholdMs) {
          isRefreshing = true;
          try {
            const tokens = await client.refreshAccessToken();
            setAuthState(prev => ({ ...prev, tokenInfo: tokens }));
          } catch (err) {
            // Refresh failed, token is completely expired or revoked
            logout();
          } finally {
            isRefreshing = false;
          }
        }
      } catch (err) {
        client.log('error', 'Auto-refresh error:', err);
      }
    }, 10000); // Check every 10 seconds

    return () => clearInterval(interval);
  }, [config.autoRefresh, config.refreshThreshold, authState.isAuthenticated, client]);

  const login = useCallback(async (options?: AuthorizeOptions) => {
    setAuthState(prev => ({ ...prev, isLoading: true }));
    await client.startAuthorization(options);
  }, [client]);

  const logout = async () => {
    setAuthState(prev => ({ ...prev, isLoading: true }));
    try {
      await client.logout();
    } catch (err) {
      client.log('error', 'Logout error:', err);
    } finally {
      setAuthState({ isAuthenticated: false, isLoading: false });
      
      if (config.logoutEndpoint && typeof window !== 'undefined') {
        const url = new URL(config.logoutEndpoint);
        url.searchParams.set('client_id', config.clientId);
        
        // Derive absolute redirect URI for post-logout redirect
        let postLogoutUri = config.redirectUri;
        if (config.logoutRedirectRoute) {
            postLogoutUri = new URL(config.logoutRedirectRoute, window.location.origin).toString();
        }
        url.searchParams.set('redirect_uri', postLogoutUri);
        
        window.location.assign(url.toString());
      } else if (config.logoutRedirectRoute && typeof window !== 'undefined') {
        const url = new URL(config.logoutRedirectRoute, window.location.origin);
        window.location.assign(url.toString());
      }
    }
  };

  const handleCallback = async (code: string, state: string) => {
    setAuthState(prev => ({ ...prev, isLoading: true }));
    try {
      const tokens = await client.exchangeCodeForTokens(code, state);
      setAuthState({ isAuthenticated: true, isLoading: false, tokenInfo: tokens });
      
      if (config.redirectRoute && typeof window !== 'undefined') {
        setTimeout(() => {
          window.location.assign(config.redirectRoute!);
        }, 0);
      }
      
      return tokens;
    } catch (err) {
      setAuthState({ isAuthenticated: false, isLoading: false, error: err instanceof Error ? err.message : String(err) });
      throw err;
    }
  };

  const getToken = useCallback(async (): Promise<string | null> => {
    return client.getToken();
  }, [client]);

  const accessToken = authState.isAuthenticated ? client.getAccessToken() : null;
  const idToken = authState.isAuthenticated ? client.getIdToken() : null;
  const user = authState.isAuthenticated ? client.getUserProfile() : null;

  const value: AuthContextValue = {
    ...authState,
    accessToken,
    idToken,
    user,
    login,
    logout,
    getToken,
    navigateToAccountManagement: () => client.navigateToAccountManagement(),
    handleCallback,
    client
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
