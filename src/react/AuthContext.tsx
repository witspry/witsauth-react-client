import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { AuthClient } from '../core/AuthClient.js';
import { sanitizeRelativeReturnTo } from '../core/url-security.js';
import type {
  AuthProviderConfig,
  AuthState,
  AuthorizeOptions,
  BffAuthConfig,
  BffImpersonationSessionInfo,
  BffSessionPayload,
  ClearStaleSessionResult,
  ExitImpersonationResult,
  ImpersonationActor,
  LogoutResult,
  OAuth2Config,
  TokenInfo,
  UserInfo,
} from '../models/types.js';

export interface AuthContextValue<TUser = UserInfo, TProfile = unknown> extends AuthState {
  readonly mode: 'spa' | 'bff';
  readonly accessToken: string | null;
  readonly idToken: string | null;
  readonly user: TUser | null;
  readonly profile: TProfile | null;
  readonly impersonationActor: ImpersonationActor | null;
  readonly impersonation: BffImpersonationSessionInfo | null;
  readonly isImpersonated: boolean;
  readonly login: (options?: AuthorizeOptions) => Promise<void>;
  readonly logout: () => Promise<LogoutResult>;
  readonly exitImpersonation: () => Promise<ExitImpersonationResult>;
  readonly refreshSession: () => Promise<boolean>;
  readonly clearStaleSession: () => Promise<ClearStaleSessionResult>;
  readonly getToken: () => Promise<string | null>;
  readonly navigateToAccountManagement: () => Promise<void>;
  readonly client: AuthClient | null;
  readonly handleCallback: (code: string, state: string) => Promise<TokenInfo>;
}

const AuthContext = createContext<AuthContextValue<unknown, unknown> | null>(null);

function isBffConfig<TUser, TProfile>(
  config: AuthProviderConfig<TUser, TProfile>,
): config is BffAuthConfig<TUser, TProfile> {
  return config.mode === 'bff';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseImpersonationInfo(raw: unknown): BffImpersonationSessionInfo | null {
  if (!isRecord(raw)) {
    return null;
  }
  const active = Boolean(raw['active']);
  const impersonatedByUserId =
    typeof raw['impersonatedByUserId'] === 'string' ? raw['impersonatedByUserId'] : '';
  const ticketRef = typeof raw['ticketRef'] === 'string' ? raw['ticketRef'] : '';
  const expiresAtEpochSec =
    typeof raw['expiresAtEpochSec'] === 'number' && Number.isFinite(raw['expiresAtEpochSec'])
      ? raw['expiresAtEpochSec']
      : 0;
  if (!active || !impersonatedByUserId) {
    return null;
  }
  return {
    active,
    impersonatedByUserId,
    ticketRef,
    expiresAtEpochSec,
  };
}

function normalizeBffSessionPayload<TUser, TProfile>(
  rawJson: unknown,
  mapSession?: (rawData: Record<string, unknown>) => BffSessionPayload<TUser, TProfile>,
): BffSessionPayload<TUser, TProfile> {
  if (!isRecord(rawJson)) {
    return { isAuthenticated: false, user: null, profile: null, impersonation: null };
  }
  const rawData = isRecord(rawJson['data']) ? rawJson['data'] : rawJson;
  if (mapSession) {
    return mapSession(rawData);
  }
  const isAuthenticated = Boolean(rawData['isAuthenticated']);
  const user = isAuthenticated ? ((rawData['user'] as TUser | null) ?? null) : null;
  const profile = isAuthenticated
    ? ((rawData['profile'] as TProfile | null | undefined) ?? null)
    : null;
  const impersonation = isAuthenticated ? parseImpersonationInfo(rawData['impersonation']) : null;
  return {
    isAuthenticated,
    user,
    profile,
    impersonation,
  };
}

function normalizeBasePath(path: string | undefined, fallback: string): string {
  const cleaned = (path ?? fallback).trim().replace(/\/+$/, '');
  return cleaned.length > 0 ? cleaned : fallback;
}

const SpaAuthProvider = <TUser = UserInfo, TProfile = unknown>({
  config,
  children,
}: {
  readonly config: OAuth2Config;
  readonly children: React.ReactNode;
}): React.JSX.Element => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
  });

  const client = useMemo(() => new AuthClient(config), [config]);

  useEffect(() => {
    let cancelled = false;
    const checkAuth = async () => {
      try {
        if (client.isAuthenticated()) {
          if (!cancelled) {
            setAuthState({ isAuthenticated: true, isLoading: false });
          }
          return;
        }
        if (!client.getRefreshToken()) {
          if (!cancelled) {
            setAuthState({ isAuthenticated: false, isLoading: false });
          }
          return;
        }
        try {
          await client.refreshAccessToken();
          if (!cancelled) {
            setAuthState({ isAuthenticated: true, isLoading: false });
          }
        } catch {
          if (!cancelled) {
            setAuthState({ isAuthenticated: false, isLoading: false });
          }
        }
      } catch (err) {
        if (!cancelled) {
          setAuthState({
            isAuthenticated: false,
            isLoading: false,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    };
    void checkAuth();
    return () => {
      cancelled = true;
    };
  }, [client]);

  const logout = useCallback(async (): Promise<LogoutResult> => {
    setAuthState((prev) => ({ ...prev, isLoading: true }));
    let upstreamRevoked = true;
    try {
      await client.logout();
    } catch (err) {
      upstreamRevoked = false;
      client.log('error', 'Logout error:', err);
    } finally {
      setAuthState({ isAuthenticated: false, isLoading: false });

      if (config.logoutEndpoint && typeof window !== 'undefined') {
        const url = new URL(config.logoutEndpoint);
        url.searchParams.set('client_id', config.clientId);

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
    return {
      loggedOut: true,
      upstreamRevoked,
      locallyRevoked: true,
    };
  }, [client, config.clientId, config.logoutEndpoint, config.logoutRedirectRoute, config.redirectUri]);

  useEffect(() => {
    if (config.autoRefresh === false || !authState.isAuthenticated) return;
    if (!client.getRefreshToken()) return;

    let isRefreshing = false;

    const interval = setInterval(() => {
      if (isRefreshing || !client.getRefreshToken()) return;

      const run = async () => {
        try {
          const expiresAt = client.getExpiresAt();
          if (!expiresAt) return;

          const thresholdMs = (config.refreshThreshold ?? 60) * 1000;

          if (Date.now() >= expiresAt - thresholdMs) {
            isRefreshing = true;
            try {
              const tokens = await client.refreshAccessToken();
              setAuthState((prev) => ({ ...prev, tokenInfo: tokens }));
            } catch {
              await logout();
            } finally {
              isRefreshing = false;
            }
          }
        } catch (err) {
          client.log('error', 'Auto-refresh error:', err);
        }
      };

      void run();
    }, 10000);

    return () => clearInterval(interval);
  }, [config.autoRefresh, config.refreshThreshold, authState.isAuthenticated, client, logout]);

  const login = useCallback(
    async (options?: AuthorizeOptions) => {
      setAuthState((prev) => ({ ...prev, isLoading: true }));
      await client.startAuthorization(options);
    },
    [client],
  );

  const handleCallback = useCallback(
    async (code: string, state: string): Promise<TokenInfo> => {
      setAuthState((prev) => ({ ...prev, isLoading: true }));
      try {
        const tokens = await client.exchangeCodeForTokens(code, state);
        setAuthState({ isAuthenticated: true, isLoading: false, tokenInfo: tokens });

        const storedReturnTo = client.consumeStoredReturnTo(config.redirectRoute || '/');
        if (config.redirectRoute && typeof window !== 'undefined') {
          setTimeout(() => {
            window.location.assign(storedReturnTo);
          }, 0);
        }

        return tokens;
      } catch (err) {
        setAuthState({
          isAuthenticated: false,
          isLoading: false,
          error: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    },
    [client, config.redirectRoute],
  );

  const refreshSession = useCallback(async (): Promise<boolean> => {
    if (!client.getRefreshToken()) {
      return false;
    }
    try {
      const tokens = await client.refreshAccessToken();
      setAuthState({ isAuthenticated: true, isLoading: false, tokenInfo: tokens });
      return true;
    } catch {
      setAuthState({ isAuthenticated: false, isLoading: false });
      return false;
    }
  }, [client]);

  const clearStaleSession = useCallback(async (): Promise<ClearStaleSessionResult> => {
    if (client.isAuthenticated()) {
      return { cleared: false, activeSession: true, status: 200, transientOutage: false };
    }
    if (client.getRefreshToken()) {
      const refreshed = await refreshSession();
      if (refreshed) {
        return { cleared: false, activeSession: true, status: 200, transientOutage: false };
      }
    }
    await client.logout();
    setAuthState({ isAuthenticated: false, isLoading: false });
    return {
      cleared: true,
      activeSession: false,
      status: 200,
      transientOutage: false,
      upstreamRevoked: true,
      locallyRevoked: true,
    };
  }, [client, refreshSession]);

  const exitImpersonation = useCallback(async (): Promise<ExitImpersonationResult> => {
    return { exitedImpersonation: false, upstreamExited: false };
  }, []);

  const getToken = useCallback(async (): Promise<string | null> => {
    return client.getToken();
  }, [client]);

  const navigateToAccountManagement = useCallback(
    () => client.navigateToAccountManagement(),
    [client],
  );

  const accessToken = authState.isAuthenticated ? client.getAccessToken() : null;
  const idToken = authState.isAuthenticated ? client.getIdToken() : null;
  const user = authState.isAuthenticated ? (client.getUserProfile() as TUser | null) : null;
  const impersonationActor = authState.isAuthenticated ? client.getImpersonationActor() : null;
  const isImpersonated = impersonationActor !== null;

  const value: AuthContextValue<TUser, TProfile> = useMemo(
    () => ({
      ...authState,
      mode: 'spa',
      accessToken,
      idToken,
      user,
      profile: (user as unknown as TProfile | null) ?? null,
      impersonationActor,
      impersonation: null,
      isImpersonated,
      login,
      logout,
      exitImpersonation,
      refreshSession,
      clearStaleSession,
      getToken,
      navigateToAccountManagement,
      handleCallback,
      client,
    }),
    [
      authState,
      accessToken,
      idToken,
      user,
      impersonationActor,
      isImpersonated,
      login,
      logout,
      exitImpersonation,
      refreshSession,
      clearStaleSession,
      getToken,
      navigateToAccountManagement,
      handleCallback,
      client,
    ],
  );

  return (
    <AuthContext.Provider value={value as AuthContextValue<unknown, unknown>}>
      {children}
    </AuthContext.Provider>
  );
};

const BffAuthProvider = <TUser = UserInfo, TProfile = unknown>({
  config,
  children,
}: {
  readonly config: BffAuthConfig<TUser, TProfile>;
  readonly children: React.ReactNode;
}): React.JSX.Element => {
  const bffBasePath = normalizeBasePath(config.bffBasePath, '/api/auth');
  const loginPath = config.loginPath ?? `${bffBasePath}/login`;
  const defaultReturnTo = sanitizeRelativeReturnTo(config.defaultReturnTo, '/');
  const initialSessionProvided = config.initialSession !== undefined;

  const [sessionState, setSessionState] = useState<{
    readonly isAuthenticated: boolean;
    readonly isLoading: boolean;
    readonly user: TUser | null;
    readonly profile: TProfile | null;
    readonly impersonation: BffImpersonationSessionInfo | null;
    readonly error?: string | undefined;
  }>(() => {
    if (config.initialSession !== undefined) {
      const init = config.initialSession;
      return {
        isAuthenticated: Boolean(init?.isAuthenticated),
        isLoading: false,
        user: init?.user ?? null,
        profile: init?.profile ?? null,
        impersonation: init?.impersonation ?? null,
      };
    }
    return {
      isAuthenticated: false,
      isLoading: config.skipInitialFetch !== true,
      user: null,
      profile: null,
      impersonation: null,
    };
  });

  const mapSessionRef = useRef(config.mapSession);
  mapSessionRef.current = config.mapSession;
  const fetchImplRef = useRef(config.fetchImpl);
  fetchImplRef.current = config.fetchImpl;

  const invokeFetch = useCallback((input: RequestInfo | URL, init?: RequestInit) => {
    const customFetch = fetchImplRef.current;
    return customFetch ? customFetch(input, init) : globalThis.fetch(input, init);
  }, []);

  const syncBffSession = useCallback(
    async (signal?: AbortSignal): Promise<BffSessionPayload<TUser, TProfile> | null> => {
      const response = await invokeFetch(`${bffBasePath}/session`, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { Accept: 'application/json' },
        ...(signal ? { signal } : {}),
      });
      if (!response.ok) {
        if (signal?.aborted) {
          return null;
        }
        setSessionState({
          isAuthenticated: false,
          isLoading: false,
          user: null,
          profile: null,
          impersonation: null,
        });
        return null;
      }
      const rawJson = (await response.json()) as unknown;
      if (signal?.aborted) {
        return null;
      }
      const normalized = normalizeBffSessionPayload<TUser, TProfile>(
        rawJson,
        mapSessionRef.current,
      );
      setSessionState({
        isAuthenticated: normalized.isAuthenticated,
        isLoading: false,
        user: normalized.user ?? null,
        profile: normalized.profile ?? null,
        impersonation: normalized.impersonation ?? null,
      });
      return normalized;
    },
    [bffBasePath, invokeFetch],
  );

  useEffect(() => {
    if (initialSessionProvided) {
      const init = config.initialSession;
      setSessionState({
        isAuthenticated: Boolean(init?.isAuthenticated),
        isLoading: false,
        user: init?.user ?? null,
        profile: init?.profile ?? null,
        impersonation: init?.impersonation ?? null,
      });
      return;
    }
    if (config.skipInitialFetch) {
      setSessionState((prev) => ({ ...prev, isLoading: false }));
      return;
    }

    const abortController = new AbortController();
    let cancelled = false;

    const load = async () => {
      try {
        await syncBffSession(abortController.signal);
      } catch (err) {
        if (cancelled || abortController.signal.aborted) {
          return;
        }
        setSessionState({
          isAuthenticated: false,
          isLoading: false,
          user: null,
          profile: null,
          impersonation: null,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    };

    void load();
    return () => {
      cancelled = true;
      abortController.abort();
    };
  }, [config.initialSession, config.skipInitialFetch, initialSessionProvided, syncBffSession]);

  const login = useCallback(
    async (options?: AuthorizeOptions): Promise<void> => {
      if (typeof window === 'undefined' || !window.location) {
        throw new Error('login() requires a browser environment in BFF mode.');
      }
      const targetUrl = new URL(loginPath, window.location.origin);
      const currentRelative = `${window.location.pathname}${window.location.search}`;
      const returnTo = sanitizeRelativeReturnTo(
        options?.returnTo ?? currentRelative,
        defaultReturnTo,
      );
      targetUrl.searchParams.set('returnTo', returnTo);
      const loginHint = options?.loginHint?.trim();
      if (loginHint) {
        targetUrl.searchParams.set('loginHint', loginHint);
      }
      if (options?.prompt) {
        targetUrl.searchParams.set('prompt', options.prompt);
      }
      if (options?.scope) {
        targetUrl.searchParams.set('scope', options.scope);
      }
      if (options?.audience) {
        targetUrl.searchParams.set('audience', options.audience);
      }
      if (options?.extraParams) {
        for (const [k, v] of Object.entries(options.extraParams)) {
          if (v.length > 0 && k !== 'returnTo') {
            targetUrl.searchParams.set(k, v);
          }
        }
      }
      window.location.assign(targetUrl.toString());
    },
    [defaultReturnTo, loginPath],
  );

  const logout = useCallback(async (): Promise<LogoutResult> => {
    setSessionState((prev) => ({ ...prev, isLoading: true }));
    let loggedOut = true;
    let upstreamRevoked = true;
    let locallyRevoked = true;
    try {
      const response = await invokeFetch(`${bffBasePath}/logout`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        loggedOut = false;
        upstreamRevoked = false;
        locallyRevoked = false;
      } else {
        const json = (await response.json().catch(() => ({}))) as {
          readonly data?: {
            readonly loggedOut?: unknown;
            readonly upstreamRevoked?: unknown;
            readonly locallyRevoked?: unknown;
          };
        };
        const data = json.data;
        loggedOut = data?.loggedOut !== false;
        upstreamRevoked = data?.upstreamRevoked !== false;
        locallyRevoked = data?.locallyRevoked !== false;
      }
    } catch {
      loggedOut = false;
      upstreamRevoked = false;
      locallyRevoked = false;
    } finally {
      setSessionState({
        isAuthenticated: false,
        isLoading: false,
        user: null,
        profile: null,
        impersonation: null,
      });
      if (config.logoutRedirectRoute && typeof window !== 'undefined') {
        window.location.assign(sanitizeRelativeReturnTo(config.logoutRedirectRoute, '/'));
      }
    }
    return { loggedOut, upstreamRevoked, locallyRevoked };
  }, [bffBasePath, config.logoutRedirectRoute, invokeFetch]);

  const exitImpersonation = useCallback(async (): Promise<ExitImpersonationResult> => {
    let exitedImpersonation = false;
    let upstreamExited = false;
    try {
      const response = await invokeFetch(`${bffBasePath}/impersonate/exit`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (response.ok) {
        const json = (await response.json().catch(() => ({}))) as {
          readonly data?: {
            readonly exitedImpersonation?: unknown;
            readonly upstreamExited?: unknown;
          };
        };
        exitedImpersonation = json.data?.exitedImpersonation !== false;
        upstreamExited = json.data?.upstreamExited !== false;
        await syncBffSession();
      }
    } catch {
      exitedImpersonation = false;
      upstreamExited = false;
    }
    return { exitedImpersonation, upstreamExited };
  }, [bffBasePath, invokeFetch, syncBffSession]);

  const refreshSession = useCallback(async (): Promise<boolean> => {
    try {
      const response = await invokeFetch(`${bffBasePath}/refresh`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          setSessionState({
            isAuthenticated: false,
            isLoading: false,
            user: null,
            profile: null,
            impersonation: null,
          });
        }
        return false;
      }
      await syncBffSession();
      return true;
    } catch {
      return false;
    }
  }, [bffBasePath, invokeFetch, syncBffSession]);

  const clearStaleSession = useCallback(async (): Promise<ClearStaleSessionResult> => {
    let response: Response;
    try {
      response = await invokeFetch(`${bffBasePath}/clear-stale-session`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
    } catch (err) {
      return {
        cleared: false,
        activeSession: false,
        status: 0,
        transientOutage: true,
        errorCode: 'NETWORK_ERROR',
        errorMessage:
          err instanceof Error && err.message.length > 0
            ? err.message
            : 'Authentication service is temporarily unavailable.',
      };
    }
    if (!response.ok) {
      const errJson = (await response.json().catch(() => ({}))) as {
        readonly error?: { readonly code?: unknown; readonly message?: unknown };
        readonly code?: unknown;
        readonly message?: unknown;
      };
      const rawCode = errJson.error?.code ?? errJson.code;
      const rawMessage = errJson.error?.message ?? errJson.message;
      const errorCode =
        typeof rawCode === 'string' && rawCode.length > 0 ? rawCode : undefined;
      const errorMessage =
        typeof rawMessage === 'string' && rawMessage.length > 0 ? rawMessage : undefined;
      return {
        cleared: false,
        activeSession: false,
        status: response.status,
        transientOutage:
          response.status === 502 || response.status === 503 || response.status === 504,
        ...(errorCode !== undefined ? { errorCode } : {}),
        ...(errorMessage !== undefined ? { errorMessage } : {}),
      };
    }
    const json = (await response.json().catch(() => ({}))) as {
      readonly data?: {
        readonly cleared?: unknown;
        readonly activeSession?: unknown;
        readonly upstreamRevoked?: unknown;
        readonly locallyRevoked?: unknown;
      };
    };
    const data = json.data;
    const cleared = Boolean(data?.cleared);
    const activeSession = Boolean(data?.activeSession);
    if (cleared && !activeSession) {
      setSessionState({
        isAuthenticated: false,
        isLoading: false,
        user: null,
        profile: null,
        impersonation: null,
      });
    } else if (activeSession) {
      await syncBffSession();
    }
    return {
      cleared,
      activeSession,
      status: response.status,
      transientOutage: false,
      ...(typeof data?.upstreamRevoked === 'boolean'
        ? { upstreamRevoked: data.upstreamRevoked }
        : {}),
      ...(typeof data?.locallyRevoked === 'boolean'
        ? { locallyRevoked: data.locallyRevoked }
        : {}),
    };
  }, [bffBasePath, invokeFetch, syncBffSession]);

  const getToken = useCallback(async (): Promise<string | null> => null, []);

  const navigateToAccountManagement = useCallback(async (): Promise<void> => {
    if (typeof window === 'undefined') {
      throw new Error('navigateToAccountManagement requires a browser environment.');
    }
    if (config.accountManagementEndpoint) {
      window.location.assign(config.accountManagementEndpoint);
      return;
    }
    const response = await invokeFetch(`${bffBasePath}/account-management`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    if (response.ok) {
      const json = (await response.json().catch(() => ({}))) as {
        readonly data?: { readonly redirectUrl?: unknown };
      };
      const redirectUrl = json.data?.redirectUrl;
      if (typeof redirectUrl === 'string' && redirectUrl.length > 0) {
        window.location.assign(redirectUrl);
      }
    }
  }, [bffBasePath, config.accountManagementEndpoint, invokeFetch]);

  const handleCallback = useCallback(async (): Promise<TokenInfo> => {
    throw new Error('handleCallback is only used in SPA mode; BFF mode exchanges codes server-side.');
  }, []);

  const impersonation = sessionState.impersonation;
  const impersonationActor: ImpersonationActor | null = useMemo(() => {
    if (!impersonation?.active) {
      return null;
    }
    return {
      sub: impersonation.impersonatedByUserId,
      ticket_ref: impersonation.ticketRef,
    };
  }, [impersonation]);
  const isImpersonated = Boolean(impersonation?.active);

  const value: AuthContextValue<TUser, TProfile> = useMemo(
    () => ({
      mode: 'bff',
      isAuthenticated: sessionState.isAuthenticated,
      isLoading: sessionState.isLoading,
      ...(sessionState.error !== undefined ? { error: sessionState.error } : {}),
      accessToken: null,
      idToken: null,
      user: sessionState.user,
      profile: sessionState.profile,
      impersonationActor,
      impersonation,
      isImpersonated,
      login,
      logout,
      exitImpersonation,
      refreshSession,
      clearStaleSession,
      getToken,
      navigateToAccountManagement,
      client: null,
      handleCallback,
    }),
    [
      sessionState,
      impersonationActor,
      impersonation,
      isImpersonated,
      login,
      logout,
      exitImpersonation,
      refreshSession,
      clearStaleSession,
      getToken,
      navigateToAccountManagement,
      handleCallback,
    ],
  );

  return (
    <AuthContext.Provider value={value as AuthContextValue<unknown, unknown>}>
      {children}
    </AuthContext.Provider>
  );
};

export function AuthProvider<TUser = UserInfo, TProfile = unknown>({
  config,
  children,
}: {
  readonly config: AuthProviderConfig<TUser, TProfile>;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  if (isBffConfig(config)) {
    return <BffAuthProvider config={config}>{children}</BffAuthProvider>;
  }
  return <SpaAuthProvider config={config}>{children}</SpaAuthProvider>;
}

export function WitsAuthTestProvider<TUser = UserInfo, TProfile = unknown>({
  value,
  children,
}: {
  readonly value?: Partial<AuthContextValue<TUser, TProfile>> | undefined;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  const merged = useMemo<AuthContextValue<TUser, TProfile>>(
    () => ({
      mode: 'bff',
      isAuthenticated: false,
      isLoading: false,
      accessToken: null,
      idToken: null,
      user: null,
      profile: null,
      impersonationActor: null,
      impersonation: null,
      isImpersonated: false,
      login: async () => undefined,
      logout: async () => ({
        loggedOut: true,
        upstreamRevoked: true,
        locallyRevoked: true,
      }),
      exitImpersonation: async () => ({
        exitedImpersonation: true,
        upstreamExited: true,
      }),
      refreshSession: async () => true,
      clearStaleSession: async () => ({
        cleared: false,
        activeSession: false,
      }),
      getToken: async () => null,
      navigateToAccountManagement: async () => undefined,
      client: null,
      handleCallback: async () => {
        throw new Error('WitsAuthTestProvider handleCallback mock not configured.');
      },
      ...value,
    }),
    [value],
  );

  return (
    <AuthContext.Provider value={merged as AuthContextValue<unknown, unknown>}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth<TUser = UserInfo, TProfile = unknown>(): AuthContextValue<TUser, TProfile> {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context as AuthContextValue<TUser, TProfile>;
}
