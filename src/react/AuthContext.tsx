import React, { createContext, useContext, useEffect, useState, useMemo } from 'react';
import { OAuth2Config, AuthState, TokenInfo } from '../models/types';
import { AuthClient } from '../core/AuthClient';

interface AuthContextValue extends AuthState {
  login: () => Promise<void>;
  logout: () => Promise<void>;
  navigateToAccountManagement: () => void;
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

  const login = async () => {
    setAuthState(prev => ({ ...prev, isLoading: true }));
    await client.startAuthorization();
  };

  const logout = async () => {
    setAuthState(prev => ({ ...prev, isLoading: true }));
    try {
      await client.logout();
    } catch (err) {
      client.log('error', 'Logout error:', err);
    } finally {
      setAuthState({ isAuthenticated: false, isLoading: false });
      
      if (config.logoutRedirectRoute && typeof window !== 'undefined') {
        window.location.assign(config.logoutRedirectRoute);
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

  const value = {
    ...authState,
    login,
    logout,
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
