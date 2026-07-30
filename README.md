# @witsauth/react-client

Official React client library for integrating Witsauth Single Sign-On (SSO) authentication or similar services into your React applications.

## Installation

```bash
npm install @witsauth/react-client
# or
yarn add @witsauth/react-client
# or
pnpm add @witsauth/react-client
```

## Features
- Complete OAuth2 Authorization Code Flow with PKCE.
- Hooks (`useAuth`) for accessing user session state securely.
- Built-in Axios interceptors for automatic Bearer token injection.
- Seamless integration with Witsauth Console.
- Automatic Token Refresh with configurable thresholds.
- Configurable Storage (localStorage, sessionStorage, or custom).
- Flexible Routing Redirects for login and logout.

## Setup

Wrap your application with the `AuthProvider` and pass your configuration.

```tsx
import { AuthProvider, AuthCallback } from '@witsauth/react-client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

const authConfig = {
  clientId: 'your-client-id',
  authorizationEndpoint: 'https://api.yourdomain.com/auth/authorize',
  tokenEndpoint: 'https://api.yourdomain.com/auth/oauth/token',
  redirectUri: window.location.origin + '/auth/callback',
  scope: 'openid profile email'
};

function App() {
  return (
    <BrowserRouter>
      <AuthProvider config={authConfig}>
        <Routes>
          <Route path="/" element={<Home />} />
          {/* Ensure you map a route for the OAuth callback */}
          <Route path="/auth/callback" element={<AuthCallback />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
```

## Configuration Options

```typescript
interface OAuth2Config {
  clientId: string;                    // OAuth2 Client ID
  authorizationEndpoint: string;       // Authorization endpoint URL
  tokenEndpoint: string;               // Token endpoint URL
  redirectUri: string;                 // Redirect URI for callback
  revokeEndpoint?: string;             // Token revocation endpoint (optional)
  userInfoEndpoint?: string;           // OIDC UserInfo endpoint (optional)
  audience?: string;                   // OAuth2 audience parameter (optional)
  scope?: string;                      // OAuth2 scope parameter
  responseType?: string;               // Response type (default: 'code')
  codeChallengeMethod?: 'S256';        // PKCE method (default: 'S256')
  storage?: 'localStorage' | 'sessionStorage' | 'custom'; // Storage strategy
  customStorage?: OAuth2Storage;       // Custom storage implementation
  autoRefresh?: boolean;               // Enable auto token refresh (default: true)
  refreshThreshold?: number;           // Seconds before expiry to refresh (default: 60)
  logLevel?: 'none' | 'error' | 'warn' | 'info' | 'debug'; // Logging level
  nonce?: string;                      // Custom nonce (optional)
  redirectRoute?: string;              // Route to redirect to after login (optional)
  logoutRedirectRoute?: string;        // Route to redirect to after logout (optional)
  oAuthProvider?: 'witsauth' | string; // OAuth provider identifier
  theme?: 'light' | 'dark' | 'system' | (() => 'light' | 'dark' | 'system' | string); // Theme type for hosted pages
}
```

## Usage

Use the `useAuth` hook to access user state and login/logout functions.

```tsx
import { useAuth } from '@witsauth/react-client';

function Profile() {
  const { isAuthenticated, login, logout, isLoading } = useAuth();

  if (isLoading) return <div>Loading...</div>;

  return (
    <div>
      {isAuthenticated ? (
        <>
          <p>Welcome!</p>
          <button onClick={logout}>Logout</button>
        </>
      ) : (
        <button onClick={login}>Login</button>
      )}
    </div>
  );
}
```

### Account Management

You can seamlessly redirect the user to the Witsauth Account Management console (to update their profile, change password, etc.) by invoking the `navigateToAccountManagement()` method. This securely POSTs to the IAM backend to preserve the user's active session and safely redirects them back to your application when they are done.

```tsx
import { useAuth } from '@witsauth/react-client';

function Settings() {
  const { navigateToAccountManagement } = useAuth();

  return (
    <button onClick={navigateToAccountManagement}>
      Manage Account
    </button>
  );
}
```

## Advanced Usage

### Custom Storage

You can configure the library to use `sessionStorage` or provide your own custom storage implementation (e.g., for React Native).

```typescript
import { OAuth2Storage } from '@witsauth/react-client';

class CustomStorage implements OAuth2Storage {
  getItem(key: string): string | null {
    // Your custom storage logic
    return null;
  }
  
  setItem(key: string, value: string): void {
    // Your custom storage logic
  }
  
  removeItem(key: string): void {
    // Your custom storage logic
  }
}

// Use in configuration
const config = {
  // ... other config
  storage: 'custom',
  customStorage: new CustomStorage()
};
```

### Custom Redirect Routes For Login And Logout

If you want the library to automatically redirect the user after a successful login or logout, you can configure the redirect routes. The library will use `window.location.assign` to perform a full page navigation.

```typescript
const authConfig = {
  // ... other config
  redirectRoute: '/dashboard',
  logoutRedirectRoute: '/login'
};
```

## API Interceptors

To automatically attach the Bearer token to your secure API requests, use the `setupAxiosInterceptors` helper.

```tsx
import axios from 'axios';
import { setupAxiosInterceptors } from '@witsauth/react-client';

export const apiClient = axios.create({
  baseURL: 'https://api.yourdomain.com'
});

// The interceptor will automatically inject Authorization: Bearer <token>
// Note: You must pass the AuthClient instance, for example from useAuth().client
// setupAxiosInterceptors(apiClient, authClient);
```
