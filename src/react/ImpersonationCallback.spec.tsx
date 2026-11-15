import React from 'react';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ImpersonationCallback } from './ImpersonationCallback.js';

describe('<ImpersonationCallback />', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    window.history.replaceState(null, '', '/');
  });

  it('preserves #code across React 19 StrictMode double-effect after scrubbing URL hash and submits once', async () => {
    window.history.replaceState(
      null,
      '',
      '/impersonate/consume?returnTo=%2Fmy-bookings#code=handoff_secret_token_1234567890',
    );

    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          data: { redirectTo: '/my-bookings?tab=active' },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    const onSuccessNavigate = vi.fn();

    render(
      <React.StrictMode>
        <ImpersonationCallback
          initialReturnTo="/my-bookings"
          fetchImpl={fetchMock}
          onSuccessNavigate={onSuccessNavigate}
        />
      </React.StrictMode>,
    );

    await waitFor(() => {
      const btn = screen.getByRole('button', { name: 'Activate Support Session' });
      expect((btn as HTMLButtonElement).disabled).toBe(false);
    });

    // Fragment and search params are scrubbed from URL history immediately on mount.
    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('');
    expect(window.location.pathname).toBe('/impersonate/consume');

    fireEvent.click(screen.getByRole('button', { name: 'Activate Support Session' }));

    await waitFor(() => {
      expect(onSuccessNavigate).toHaveBeenCalledWith('/my-bookings?tab=active');
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/auth/impersonate/consume',
      expect.objectContaining({
        method: 'POST',
        credentials: 'same-origin',
        body: JSON.stringify({
          code: 'handoff_secret_token_1234567890',
          returnTo: '/my-bookings',
        }),
      }),
    );
  });

  it('renders an alert when fragment code is missing or too short', async () => {
    window.history.replaceState(null, '', '/impersonate/consume#code=short');

    render(
      <ImpersonationCallback>
        {(state) => (
          <div>
            <span data-testid="can-submit">{String(state.canSubmit)}</span>
            {state.errorMessage ? <div role="alert">{state.errorMessage}</div> : null}
          </div>
        )}
      </ImpersonationCallback>,
    );

    await waitFor(() => {
      expect(screen.getByRole('alert').textContent).toContain('Missing or invalid');
    });
    expect(screen.getByTestId('can-submit').textContent).toBe('false');
  });
});
