# Changelog

All notable changes to this project will be documented in this file.

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
