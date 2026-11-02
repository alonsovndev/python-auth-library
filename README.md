# pyauthkit

A framework-agnostic authentication toolkit for Python backends: JWT access/refresh
rotation, bcrypt password hashing, progressive account lockout, one-time codes backed by
hashes, and optional FastAPI + SQLAlchemy integrations.

It is a library, not a service: your application owns its user model and persistence; the
toolkit supplies the security machinery around them through small port interfaces.

## Features

- **Token service** — short-lived access + single-use refresh tokens with audience/issuer
  validation, per-type rejection (an access token can never be used as a refresh token and
  vice versa), `tv` (token-version) claim for force-logout, and extra claims per account.
- **Password hashing** — async bcrypt (off the event loop) behind a swappable
  `PasswordHasher` protocol, plus a configurable `PasswordPolicy`.
- **Progressive lockout** — configurable failure threshold with escalating durations
  (15 / 30 / 60 / 120 min) behind a pluggable store.
- **Revocation** — refresh-token rotation with hash-at-rest replay protection.
- **One-time codes** — email-verification and password-reset codes with TTLs, wrong-attempt
  caps, and resend rate limiting; only hashes are stored.
- **Account-enumeration protection** — login, registration and reset endpoints answer with
  generic messages for every edge case so they cannot be used to probe for accounts.
- **FastAPI extra** — `install()`, `build_auth_router()` (9 endpoints), `get_current_user`,
  `get_request_context`, `require_roles`, and browser cookie sessions with origin checks.
- **SQLAlchemy extra** — Postgres adapters for codes, lockout state and revocation.

## Install

```bash
pip install pyauthkit                 # core only (in-memory defaults)
pip install "pyauthkit[fastapi]"      # + FastAPI routes/guards
pip install "pyauthkit[sqlalchemy]"   # + Postgres store adapters
```

Requires Python ≥ 3.10.

## Quick start (FastAPI)

```python
from fastapi import FastAPI
from pyauthkit import AuthConfig, AuthContainer
from pyauthkit.fastapi import build_auth_router, install

# 1. Implement the ports on your own model/repository/email sender.
#    AuthUser, UserStore, RegistrationBuilder, EmailSender — see "Ports" below.
from myapp.auth import MyUserStore, MyRegistrationBuilder, MyEmailSender

config = AuthConfig(
    secret_key=os.environ["AUTH_SECRET_KEY"],   # ≥ 32 chars
    audience="myapp",
    issuer="myapp",
)
container = AuthContainer(
    config,
    users=MyUserStore(),
    email_sender=MyEmailSender(),
    registration_builder=MyRegistrationBuilder(),
)

app = FastAPI()
install(app, container)                  # sets app.state.auth + error handlers
app.include_router(build_auth_router(container))
```

The router exposes:

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth/register` | start an account, emails a verification code |
| POST | `/auth/verify-email` | confirm the code (optionally set a password) |
| POST | `/auth/resend-verification` | reissue the verification code |
| POST | `/auth/login` | credentials → access/refresh pair |
| POST | `/auth/refresh` | rotate the single-use refresh token |
| POST | `/auth/logout` | revoke the refresh token |
| POST | `/auth/forgot-password` | email a reset code |
| POST | `/auth/resend-reset-code` | reissue the reset code |
| POST | `/auth/reset-password` | apply a new password + end sessions |

Protect your own routes:

```python
from typing import Annotated
from fastapi import Depends
from pyauthkit.fastapi import get_request_context, require_roles

@router.get("/projects")
async def list_projects(ctx: Annotated[..., Depends(get_request_context)]):
    return {"user_id": ctx.user_id, "role": ctx.role}

admin_only = require_roles("admin")
```

### Browser (cookie) sessions

Frontends that cannot read a refresh token send `X-Session-Mode: cookie` plus a trusted
`Origin` on login/refresh/logout; the refresh token then lives in an HttpOnly cookie and is
never returned in the body. Cookies are only issued after the origin passes the configured
allow-list.

```python
AuthConfig(
    ...,
    trusted_origins=("https://app.example.com",),
    allow_localhost_origins=True,          # http://localhost:PORT during development
    cookie_secure=True,                    # set False only over plain HTTP
)
```

## Core usage without FastAPI

The services are plain classes wired from an `AuthContainer`; use them from any framework:

```python
from pyauthkit import AuthContainer, LoginRequest

container = AuthContainer(config, users=..., email_sender=..., registration_builder=...)
from pyauthkit.services.login import LoginService

tokens = await LoginService(
    container.users, container.token_service, container.password_hasher, container.lockout_service
).execute(LoginRequest(email="a@b.com", password="abcd1234"))
```

## Ports (implement these)

| Port | Responsibility |
| --- | --- |
| `AuthUser` | Minimal mutable view of your user entity (id, email, password hash, role, active/verified flags, token version, extra claims). |
| `UserStore` | `find_by_email`, `find_by_id`, `save`. |
| `RegistrationBuilder` | Provisions a new unverified account (hash the password, add your defaults); returns `None` to signal an email race. |
| `EmailSender` | Delivers the verification/reset emails. |

Built-in in-memory implementations exist for code stores, lockout and revocation; swap in
the Postgres adapters (`pyauthkit.sqlalchemy`) or Redis for multi-instance deployments.

## Configuration

`AuthConfig` is a frozen dataclass — read `src/pyauthkit/config.py` for the full list.
Key knobs: access/refresh lifetimes, `remember_me` lifetime, lockout thresholds, code TTLs
and attempt caps, resend windows, and cookie settings. The JWT secret is validated (length
and known-weak values) unless `validate_secret=False` (tests only).

## Development

```bash
pip install -e ".[all]" pytest pytest-cov ruff mypy pytest-asyncio
ruff check .
ruff format --check .
mypy src
pytest --cov=pyauthkit
```

## License

MIT — see [LICENSE](LICENSE).