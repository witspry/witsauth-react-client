# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-07-24

### Fixed
- Fixed token expiry parsing to handle corrupted/NaN values properly.
- Fixed auto-refresh race conditions by adding an in-flight guard.
- Fixed `refreshThreshold` fallback to correctly respect explicit `0` values.
