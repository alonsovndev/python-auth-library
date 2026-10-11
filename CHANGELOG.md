# Changelog

## 0.1.0 (unreleased)

- `AuthConfig` centralising secret, algorithm, expirations, audience/issuer, lockout thresholds, code TTLs and cookie settings.
- `TokenService`: JWT access/refresh creation and verification with token-type separation, `tv` (forced logout) and per-account extra claims.
- `PasswordHasher`: async bcrypt hashing/verification behind a swappable protocol.
- `AccountLockoutService`: progressive lockout after consecutive failures with a pluggable store (in-memory default).
- `TokenRevocationService`: single-use refresh-token rotation with hashed-at-rest identifiers.
- One-time codes for email verification and password reset (TTL, attempt limits, resend windows).
- Ports: `AuthUser`, `UserStore`, `EmailSender`, `RegistrationBuilder`, `CodeStore`, `LockoutStore`, `RevocationStore`.
- Generic services (login, register, verify email, resend verification, refresh, logout, revoke-all, forgot/resend/confirm reset).
- Optional `[fastapi]` extra: `build_auth_router`, `get_current_user`, `get_request_context`, `require_roles`, browser cookie sessions.
- Optional `[sqlalchemy]` extra: Postgres adapters for codes, lockout and token revocation.
