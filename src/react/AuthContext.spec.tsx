import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthCallback } from './AuthCallback.js';
import { AuthProvider, useAuth, WitsAuthTestProvider } from './AuthContext.js';
import { OAuthCallbackError } from '../models/types.js';

function encodeBase64Url(obj: Record<string, unknown>): string {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeJwt(payload: Record<string, unknown>): string {
  return `${encodeBase64Url({ alg: 'RS256', typ: 'JWT' })}.${encodeBase64Url(payload)}.sig`;
}

function SessionInspector(): React.JSX.Element {
  const {
    mode,
    isAuthenticated,
    isLoading,
    accessToken,
    user,
    impersonationActor,
    isImpersonated,
    logout,
    exitImpersonation,
    refreshSession,
    clearStaleSession,
  } = useAuth<{ readonly userId?: string; readonly name?: string }>();

  return (
    <div>
      <span data-testid="mode">{mode}</span>
      <span data-testid="auth">{String(isAuthenticated)}</span>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="token">{String(accessToken)}</span>
      <span data-testid="user">{user?.userId ?? user?.name ?? 'none'}</span>
      <span data-testid="imp">{isImpersonated ? impersonationActor?.sub ?? 'yes' : 'no'}</span>
      <button onClick={() => void logout()}>Logout</button>
      <button onClick={() => void exitImpersonation()}>ExitImp</button>
      <button onClick={() => void refreshSession()}>Refresh</button>
      <button onClick={() => void clearStaleSession()}>ClearStale</button>
    </div>
  );
}

describe('AuthProvider, useAuth, AuthCallback & WitsAuthTestProvider', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
  });

  it('hydrates BFF session in React 19 StrictMode with zero browser tokens and supports actions', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === '/api/auth/session') {
        return new Response(
          JSON.stringify({
            data: {
              isAuthenticated: true,
              user: { userId: 'usr_cust_1' },
              profile: { fullName: 'Meera' },
              impersonation: {
                active: true,
                impersonatedByUserId: 'usr_support_7',
                ticketRef: 'TKT-101',
                expiresAtEpochSec: 9999999999,
              },
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url === '/api/auth/clear-stale-session') {
        return new Response(
          JSON.stringify({ data: { cleared: false, activeSession: true } }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url === '/api/auth/impersonate/exit') {
        return new Response(
          JSON.stringify({ data: { exitedImpersonation: true, upstreamExited: true } }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url === '/api/auth/logout') {
        return new Response(
          JSON.stringify({ data: { loggedOut: true, upstreamRevoked: true, locallyRevoked: true } }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    });

    render(
      <React.StrictMode>
        <AuthProvider config={{ mode: 'bff', fetchImpl: fetchMock }}>
          <SessionInspector />
        </AuthProvider>
      </React.StrictMode>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('auth').textContent).toBe('true');
    });

    expect(screen.getByTestId('mode').textContent).toBe('bff');
    expect(screen.getByTestId('token').textContent).toBe('null');
    expect(screen.getByTestId('user').textContent).toBe('usr_cust_1');
    expect(screen.getByTestId('imp').textContent).toBe('usr_support_7');

    // clear-stale-session preserving live session keeps authenticated state intact
    fireEvent.click(screen.getByText('ClearStale'));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/auth/clear-stale-session',
        expect.objectContaining({ method: 'POST', credentials: 'same-origin' }),
      );
    });
    expect(screen.getByTestId('auth').textContent).toBe('true');

    fireEvent.click(screen.getByText('Logout'));
    await waitFor(() => {
      expect(screen.getByTestId('auth').textContent).toBe('false');
    });
    expect(screen.getByTestId('user').textContent).toBe('none');
  });

  it('supports SPA mode and surfaces OAuthCallbackError on AuthCallback error query params', async () => {
    window.history.replaceState(
      null,
      '',
      '/callback?error=access_denied&error_description=User%20cancelled',
    );
    const onCallbackError = vi.fn();
    const onError = vi.fn();

    render(
      <React.StrictMode>
        <AuthProvider
          config={{
            clientId: 'spa-1',
            authorizationEndpoint: 'https://auth.example.com/authorize',
            tokenEndpoint: 'https://auth.example.com/token',
            redirectUri: 'https://app.example.com/callback',
            onCallbackError,
          }}
        >
          <AuthCallback onError={onError} />
        </AuthProvider>
      </React.StrictMode>,
    );

    await waitFor(() => {
      expect(onError).toHaveBeenCalledTimes(1);
    });

    const err = onError.mock.calls[0]?.[0];
    expect(err).toBeInstanceOf(OAuthCallbackError);
    expect((err as OAuthCallbackError).code).toBe('access_denied');
    expect((err as OAuthCallbackError).description).toBe('User cancelled');
    expect(onCallbackError).toHaveBeenCalledWith(err);
  });

  it('renders SPA authenticated impersonated user state', async () => {
    window.localStorage.setItem(
      'witsauth_access_token',
      makeJwt({ sub: 'cust_2', act: { sub: 'staff_9' } }),
    );
    window.localStorage.setItem('witsauth_expires_at', String(Date.now() + 120_000));

    render(
      <AuthProvider
        config={{
          mode: 'spa',
          clientId: 'spa-1',
          authorizationEndpoint: 'https://auth.example.com/authorize',
          tokenEndpoint: 'https://auth.example.com/token',
          redirectUri: 'https://app.example.com/callback',
          autoRefresh: false,
        }}
      >
        <SessionInspector />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('auth').textContent).toBe('true');
    });
    expect(screen.getByTestId('mode').textContent).toBe('spa');
    expect(screen.getByTestId('imp').textContent).toBe('staff_9');
  });

  it('supports WitsAuthTestProvider for deterministic component testing', () => {
    render(
      <WitsAuthTestProvider
        value={{
          isAuthenticated: true,
          user: { sub: 'test_u', name: 'Test User' },
          isImpersonated: true,
          impersonationActor: { sub: 'admin_1', ticket_ref: 'SUP-1' },
        }}
      >
        <SessionInspector />
      </WitsAuthTestProvider>,
    );

    expect(screen.getByTestId('auth').textContent).toBe('true');
    expect(screen.getByTestId('user').textContent).toBe('Test User');
    expect(screen.getByTestId('imp').textContent).toBe('admin_1');
  });
});
