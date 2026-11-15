# @witsauth/react-client

Official React and Next.js BFF client library for integrating WitsAuth Single Sign-On (SSO) authentication into React SPAs and Next.js App Router applications.

## Installation

```bash
npm install @witsauth/react-client
# or
pnpm add @witsauth/react-client
```

> `axios` and `next` are **optional** peer dependencies (`peerDependenciesMeta`). Pure Next.js `fetch` apps do not need `axios`, and pure React SPAs do not need `next`.

## Features
- **Two First-Class Modes:**
  - **Next.js BFF (`mode: 'bff'` + `@witsauth/react-client/next`):** Zero browser token exposure (`httpOnly` cookies), Web Crypto HMAC-signed PKCE state cookies, 15s single-flight OIDC refresh grace cache, Fetch Metadata & Origin CSRF defenses, streaming request/response proxy caps, and RFC 8693 impersonation handoff support.
  - **React SPA (`mode: 'spa'`, default):** Complete OAuth2 Authorization Code Flow with `S256` PKCE, ID token `nonce` validation, automatic refresh with concurrent deduplication, `useAuth()`, `<AuthCallback />`, and optional `setupAxiosInterceptors` (`axios`).
- **Dual ESM + CJS Exports:** Works seamlessly with Next.js 15/16 Turbopack, Vite, Node 24 ESM, and Jest CommonJS test runners (`sideEffects: false`).

---

## Usage: Next.js App Router BFF (`1.4.0`)

### 1. Client Provider (`'use client'`)
```tsx
import { AuthProvider, useAuth } from '@witsauth/react-client';

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider config={{ mode: 'bff', bffBasePath: '/api/auth', defaultReturnTo: '/' }}>
      {children}
    </AuthProvider>
  );
}
```

### 2. Auth Route Handler (`app/api/auth/[...action]/route.ts`)
```ts
import { createWitsAuthNextHandler } from '@witsauth/react-client/next';

export const { GET, POST } = createWitsAuthNextHandler({
  appScope: 'web',
  cookies: {
    accessCookieName: 'witsauth_access',
    refreshCookieName: 'witsauth_refresh',
    pkceCookieName: 'witsauth_pkce',
  },
  getPublicOrigin: (reqOrigin) => process.env.PUBLIC_ORIGIN || reqOrigin,
  getCookieSecret: () => process.env.BFF_COOKIE_SECRET!,
  getClientId: () => process.env.OIDC_CLIENT_ID!,
  getAuthorizeUrl: () => `${process.env.OIDC_ISSUER}/auth/authorize`,
  getTokenEndpoint: () => `${process.env.OIDC_ISSUER}/oauth/token`,
  getRevokeEndpoint: () => `${process.env.OIDC_ISSUER}/oauth/revoke`,
  getUserInfoEndpoint: () => `${process.env.OIDC_ISSUER}/oauth/userinfo`,
  isSecureCookie: () => process.env.NODE_ENV === 'production',
  enableRefreshSessionGet: true,
  enableClearSessionGet: true,
});
```

### 3. Next.js Middleware / `proxy.ts`
```ts
import { NextResponse } from 'next/server';
import { createWitsAuthNextProxy } from '@witsauth/react-client/next';

export const proxy = createWitsAuthNextProxy({
  appScope: 'web',
  loginPath: '/login',
  defaultReturnTo: '/dashboard',
  accessCookieName: 'witsauth_access',
  refreshCookieName: 'witsauth_refresh',
  isSecureCookie: () => process.env.NODE_ENV === 'production',
  refreshTokens: async (refreshToken) => {
    // Rotate refresh token against WitsAuth or host API
    throw new Error('Provide refreshTokens implementation');
  },
  next: (headers) => NextResponse.next(headers ? { request: { headers } } : undefined),
  redirect: (url, status) => NextResponse.redirect(url, status),
});
```

---

## Usage: React SPA (`mode: 'spa'`)

```tsx
import { AuthProvider, AuthCallback } from '@witsauth/react-client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

const authConfig = {
  clientId: 'your-client-id',
  authorizationEndpoint: 'https://api.yourdomain.com/auth/authorize',
  tokenEndpoint: 'https://api.yourdomain.com/auth/oauth/token',
  redirectUri: window.location.origin + '/auth/callback',
  scope: 'openid profile email',
};

function App() {
  return (
    <BrowserRouter>
      <AuthProvider config={authConfig}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
```
