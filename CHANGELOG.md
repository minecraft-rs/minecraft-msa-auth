# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

### Added

- `HttpClient` trait over the `http` crate's request and response types. Any HTTP client can drive the authentication flow by implementing it.
- `ureq` feature providing `UreqClient`, a synchronous client backed by [ureq](https://crates.io/crates/ureq). Its default agent keeps 4xx/5xx responses readable, which the Xbox error handling requires; `UreqClient::with_agent` accepts a custom agent.
- `is_sync` feature that makes the whole API synchronous through [maybe-async](https://crates.io/crates/maybe-async). Combined with the `reqwest` feature, the flow uses `reqwest::blocking::Client`.
- `HttpRequest` and `HttpResponse` type aliases.

### Changed

- Breaking: `MinecraftAuthorizationFlow` is generic over its HTTP client. With default features, `MinecraftAuthorizationFlow::new(reqwest::Client::new())` works as before.
- Breaking: `MinecraftAuthorizationError` is generic over the client's error type. The `Reqwest` variant was replaced by `Http` (transport errors), `HttpStatus` (non-success responses) and `Json` (serialization errors).
- reqwest is now an optional dependency behind the default `reqwest` feature, and was updated to 0.13.
- Updated thiserror to 2.0 and nutype to 0.6.
- Examples and documentation use the oauth2 5.0 API.

## [0.4.0] - 2024-04-21

### Changed

- Xbox security token failures are reported as specific error variants: `AddToFamily` (minor accounts that must join a Microsoft family), `NoXbox` (no Xbox profile) and `MissingClaims`, replacing the generic HTTP status error.
- Updated reqwest to 0.12 and nutype to 0.4.

## [0.3.0] - 2023-02-23

### Added

- `Serialize` implementation for `MinecraftAuthenticationResponse`.

### Changed

- `token_type` is a `MinecraftTokenType` enum instead of a string.

## [0.2.0] - 2023-02-23

### Added

- `MinecraftAccessToken` newtype whose `Debug` output redacts the token.

## [0.1.1] - 2023-02-22

### Removed

- Dependency on `oauth2`. The crate only consumes the Microsoft access token, so any OAuth library can be used to obtain it.

## [0.1.0] - 2023-02-22

Initial release.
