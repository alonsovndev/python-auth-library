"""Translate pyauthkit errors into HTTP responses and install the container."""

from __future__ import annotations

import jwt
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.types import ExceptionHandler

from pyauthkit.container import AuthContainer
from pyauthkit.errors import (
    AccountLockedError,
    AuthKitError,
    EmailNotVerifiedError,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    InvalidResetCodeError,
    InvalidVerificationCodeError,
    PasswordPolicyError,
    ResetCodeRateLimitedError,
    UnauthorizedError,
    VerificationRateLimitedError,
)

# Most specific first; Starlette resolves handlers by walking the exception's MRO.
_STATUS_BY_ERROR: tuple[tuple[type[Exception], int], ...] = (
    (AccountLockedError, status.HTTP_429_TOO_MANY_REQUESTS),
    (EmailNotVerifiedError, status.HTTP_403_FORBIDDEN),
    (InvalidCredentialsError, status.HTTP_401_UNAUTHORIZED),
    (UnauthorizedError, status.HTTP_401_UNAUTHORIZED),
    (InsufficientPermissionsError, status.HTTP_403_FORBIDDEN),
    (InvalidVerificationCodeError, status.HTTP_400_BAD_REQUEST),
    (InvalidResetCodeError, status.HTTP_400_BAD_REQUEST),
    (VerificationRateLimitedError, status.HTTP_429_TOO_MANY_REQUESTS),
    (ResetCodeRateLimitedError, status.HTTP_429_TOO_MANY_REQUESTS),
    (PasswordPolicyError, status.HTTP_400_BAD_REQUEST),
    (AuthKitError, status.HTTP_400_BAD_REQUEST),
)


def _make_handler(status_code: int) -> ExceptionHandler:
    async def handler(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=status_code, content={"detail": str(exc)})

    return handler


def _jwt_handler(status_code: int = status.HTTP_401_UNAUTHORIZED) -> ExceptionHandler:
    async def handler(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={"detail": "Invalid or expired token"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    return handler


def register_exception_handlers(app: FastAPI) -> None:
    """Map every pyauthkit error (and JWT errors) to an HTTP status."""
    for error_type, status_code in _STATUS_BY_ERROR:
        app.add_exception_handler(error_type, _make_handler(status_code))
    app.add_exception_handler(jwt.PyJWTError, _jwt_handler())


def install(app: FastAPI, container: AuthContainer) -> None:
    """Attach the container to ``app.state.auth`` and register the error handlers.

    Call once at startup, then include :func:`pyauthkit.fastapi.routes.build_auth_router`.
    """
    app.state.auth = container
    register_exception_handlers(app)


__all__ = ["install", "register_exception_handlers"]
