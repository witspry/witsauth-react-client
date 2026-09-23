# Changelog

All notable changes to this project will be documented in this file.

## [1.3.7] - 2026-09-23

### Fixed
- Fixed concurrent token refresh race conditions by adding in-flight request deduplication in `AuthClient.refreshAccessToken()`.
- Improved error resilience in `refreshAccessToken()`: tokens are now only cleared on client auth errors (HTTP 400/401), preserving session state during transient network issues or 5xx server errors.
- Added fallback to retain existing refresh token if server token response does not return a new rotated refresh token.
- Enhanced token refresh error logging with parsed error descriptions from response payload.

## [1.3.6] - 2026-08-07
- Corrected logout behavior

## [1.3.3] - 2026-08-07
- Kept post logout redirection clean

## [1.3.3] - 2026-08-07

### Fixed
- Fixed missing global names warning in vite build for `react/jsx-runtime` and `react/jsx-dev-runtime`.
- Appended `client_id` and `redirect_url` as query string parameters when redirecting to `logoutRedirectRoute` during logout.

## [1.3.2] - 2026-07-29
- Added theme support

## [1.3.1] - 2026-07-29
- Minor fix - Added csr to account management request

## [1.3.0] - 2026-07-29

### Added
- Added `navigateToAccountManagement()` method to the `useAuth()` hook and `AuthClient` to securely redirect the user to the IAM Account Management console while preserving context.

### Fixed
- Updated `AuthCallback` to gracefully route to `redirectRoute` when no OAuth code is present (e.g., when returning from the Account Management console).

## [1.1.0] - 2026-07-24

### Fixed
- Fixed token expiry parsing to handle corrupted/NaN values properly.
- Fixed auto-refresh race conditions by adding an in-flight guard.
- Fixed `refreshThreshold` fallback to correctly respect explicit `0` values.

## [1.2.0] - 2026-07-25

### Added
- Added feature parity with the Angular client by introducing new `OAuth2Config` properties.
- Added configurable `storage` option to support `sessionStorage` or a `custom` storage provider (via `customStorage`).
- Added support for automatic redirection via `redirectRoute` (after login) and `logoutRedirectRoute` (after logout).
- Added token revocation during logout via the new `revokeEndpoint` configuration.
- Added a `logLevel` property to control the verbosity of internal logging.
- Added support for custom `nonce` generation.
- Added strongly-typed `codeChallengeMethod` to the configuration.
