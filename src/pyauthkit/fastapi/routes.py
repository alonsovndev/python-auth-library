"""Router builder: standard auth endpoints wired to an :class:`AuthContainer`.

Call :func:`pyauthkit.fastapi.install` once to set the container and error handlers, then
``app.include_router(build_auth_router(container, prefix="/auth"))``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import Enum
from typing import Any, cast

import jwt
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from pyauthkit.container import AuthContainer
from pyauthkit.dtos import (
    BrowserTokenPair,
    LoginRequest,
    LogoutResponse,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResendRequest,
    ResetPasswordRequest,
    TokenPair,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from pyauthkit.errors import UnauthorizedError
from pyauthkit.fastapi.sessions import (
    BROWSER_SESSION_OPENAPI,
    clear_refresh_cookie,
    is_browser_session,
    refresh_request_token,
    set_refresh_cookie,
)
from pyauthkit.services.login import LoginService
from pyauthkit.services.logout import LogoutService
from pyauthkit.services.password_reset import (
    ConfirmPasswordResetService,
    RequestPasswordResetService,
    ResendResetCodeService,
)
from pyauthkit.services.refresh import RefreshTokenService
from pyauthkit.services.register import RegisterService
from pyauthkit.services.verification import ResendVerificationService, VerifyEmailService


def _limit(limiter: Any, spec: str, endpoint: Callable[..., Any]) -> Callable[..., Any]:
    return endpoint if limiter is None else limiter.limit(spec)(endpoint)


def build_auth_router(
    container: AuthContainer,
    *,
    prefix: str = "/auth",
    limiter: Any = None,
    tags: Sequence[str] | None = None,
) -> APIRouter:
    """Build an :class:`APIRouter` with the login/register/verify/refresh/reset endpoints.

    Args:
        container: The composition root with ports and services.
        prefix: Route prefix (default ``/auth``).
        limiter: Optional slowapi-style limiter exposing ``.limit(spec)``; when provided,
            the reference rate limits are applied per route.
        tags: OpenAPI tags (default ``["auth"]``).
    """
    router = APIRouter(prefix=prefix, tags=cast("list[str | Enum]", list(tags) if tags else ["auth"]))

    login_service = LoginService(
        container.users, container.token_service, container.password_hasher, container.lockout_service
    )
    register_service = RegisterService(
        container.users,
        container.verification_codes,
        container.email_sender,
        container.email_links,
        container.password_hasher,
        container.password_policy,
        container.registration_builder,
        container.config,
    )
    verify_service = VerifyEmailService(
        container.users,
        container.verification_codes,
        container.password_hasher,
        container.password_policy,
        container.config,
        container.on_email_verified,
    )
    resend_verification_service = ResendVerificationService(
        container.users,
        container.verification_codes,
        container.email_sender,
        container.email_links,
        container.password_hasher,
        container.config,
    )
    refresh_service = RefreshTokenService(container.users, container.token_service, container.revocation_service)
    logout_service = LogoutService(container.token_service, container.revocation_service)
    request_reset_service = RequestPasswordResetService(
        container.users,
        container.reset_codes,
        container.email_sender,
        container.email_links,
        container.password_hasher,
        container.config,
    )
    resend_reset_service = ResendResetCodeService(
        container.users,
        container.reset_codes,
        container.email_sender,
        container.email_links,
        container.password_hasher,
        container.config,
    )
    confirm_reset_service = ConfirmPasswordResetService(
        container.users, container.reset_codes, container.password_hasher, container.password_policy, container.config
    )

    async def login(request: Request, payload: LoginRequest, response: Response) -> TokenPair | BrowserTokenPair:
        browser = is_browser_session(request, container)
        tokens = await login_service.execute(payload)
        if browser:
            if tokens.user is None:
                raise HTTPException(status_code=500, detail="Session identity is unavailable")
            set_refresh_cookie(response, tokens.refresh_token, container)
            return BrowserTokenPair(
                access_token=tokens.access_token, session_expires_at=tokens.session_expires_at, user=tokens.user
            )
        return tokens

    async def register(payload: RegisterRequest) -> RegisterResponse:
        return await register_service.execute(payload)

    async def verify_email(payload: VerifyEmailRequest) -> VerifyEmailResponse:
        return await verify_service.execute(payload)

    async def resend_verification(payload: ResendRequest) -> MessageResponse:
        return await resend_verification_service.execute(payload)

    async def refresh(
        request: Request, response: Response, payload: RefreshRequest | None = None
    ) -> TokenPair | BrowserTokenPair | JSONResponse:
        browser = is_browser_session(request, container)
        token = _refresh_token(request, payload, container, browser)
        try:
            tokens = await refresh_service.execute(token)
        except (jwt.PyJWTError, UnauthorizedError) as exc:
            if browser:
                clear_refresh_cookie(response, container)
                cookie = response.headers.get("set-cookie")
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or expired refresh token"},
                    headers={"set-cookie": cookie} if cookie else None,
                )
            raise exc
        if browser:
            if tokens.user is None:
                raise HTTPException(status_code=500, detail="Session identity is unavailable")
            set_refresh_cookie(response, tokens.refresh_token, container)
            return BrowserTokenPair(
                access_token=tokens.access_token, session_expires_at=tokens.session_expires_at, user=tokens.user
            )
        return tokens

    async def logout(request: Request, response: Response, payload: RefreshRequest | None = None) -> LogoutResponse:
        browser = is_browser_session(request, container)
        if browser and not request.cookies.get(container.config.refresh_cookie_name):
            if payload is not None:
                raise HTTPException(status_code=422, detail="Cookie sessions do not accept body credentials")
            clear_refresh_cookie(response, container)
            return LogoutResponse()
        token = _refresh_token(request, payload, container, browser)
        result = await logout_service.execute(token)
        if browser:
            clear_refresh_cookie(response, container)
        return result

    async def forgot_password(payload: ResendRequest) -> MessageResponse:
        return await request_reset_service.execute(payload)

    async def resend_reset_code(payload: ResendRequest) -> MessageResponse:
        return await resend_reset_service.execute(payload)

    async def reset_password(payload: ResetPasswordRequest) -> MessageResponse:
        return await confirm_reset_service.execute(payload)

    router.add_api_route(
        "/login",
        _limit(limiter, "10/minute", login),
        methods=["POST"],
        response_model=TokenPair | BrowserTokenPair,
        openapi_extra=BROWSER_SESSION_OPENAPI,
    )
    router.add_api_route(
        "/register",
        _limit(limiter, "5/minute", register),
        methods=["POST"],
        response_model=RegisterResponse,
        status_code=status.HTTP_201_CREATED,
    )
    router.add_api_route(
        "/verify-email",
        _limit(limiter, "10/15minutes", verify_email),
        methods=["POST"],
        response_model=VerifyEmailResponse,
    )
    router.add_api_route(
        "/resend-verification",
        _limit(limiter, "5/15minutes", resend_verification),
        methods=["POST"],
        response_model=MessageResponse,
    )
    router.add_api_route(
        "/refresh",
        _limit(limiter, "10/15minutes", refresh),
        methods=["POST"],
        response_model=TokenPair | BrowserTokenPair,
        response_model_exclude_none=True,
        openapi_extra=BROWSER_SESSION_OPENAPI,
    )
    router.add_api_route(
        "/logout",
        _limit(limiter, "20/minute", logout),
        methods=["POST"],
        response_model=LogoutResponse,
        openapi_extra={**BROWSER_SESSION_OPENAPI, "security": [{"HTTPBearer": []}, {}]},
    )
    router.add_api_route(
        "/forgot-password",
        _limit(limiter, "5/15minutes", forgot_password),
        methods=["POST"],
        response_model=MessageResponse,
    )
    router.add_api_route(
        "/resend-reset-code",
        _limit(limiter, "5/15minutes", resend_reset_code),
        methods=["POST"],
        response_model=MessageResponse,
    )
    router.add_api_route(
        "/reset-password",
        _limit(limiter, "10/15minutes", reset_password),
        methods=["POST"],
        response_model=MessageResponse,
    )

    return router


def _refresh_token(request: Request, payload: RefreshRequest | None, container: AuthContainer, browser: bool) -> str:
    if browser:
        if payload is not None:
            raise HTTPException(status_code=422, detail="Cookie sessions do not accept body credentials")
        return refresh_request_token(request, container)
    if payload is None:
        raise HTTPException(status_code=422, detail="Refresh token is required")
    return payload.refresh_token


__all__ = ["build_auth_router"]
