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
  scopes: ['openid', 'profile', 'email']
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

## Usage

Use the `useAuth` hook to access user state and login/logout functions.

```tsx
import { useAuth } from '@witsauth/react-client';

function Profile() {
  const { user, login, logout, isLoading } = useAuth();

  if (isLoading) return <div>Loading...</div>;

  return (
    <div>
      {user ? (
        <>
          <p>Welcome, {user.name}!</p>
          <button onClick={logout}>Logout</button>
        </>
      ) : (
        <button onClick={login}>Login</button>
      )}
    </div>
  );
}
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
setupAxiosInterceptors(apiClient);
```
