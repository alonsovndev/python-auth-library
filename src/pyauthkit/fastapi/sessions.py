"""Browser cookie sessions.

A client opts in with ``X-Session-Mode: cookie`` and a trusted ``Origin``; the refresh token
then lives in an HttpOnly cookie instead of the JSON body, and the access token stays short
lived. Origin allow-listing is enforced before any cookie is set or read.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request, Response

from pyauthkit.container import AuthContainer

SESSION_MODE_HEADER = "X-Session-Mode"
COOKIE_MODE = "cookie"

_LOCALHOST_ORIGIN = re.compile(r"http://(localhost|127\.0\.0\.1):\d+")

BROWSER_SESSION_OPENAPI: dict[str, Any] = {
    "parameters": [
        {
            "name": SESSION_MODE_HEADER,
            "in": "header",
            "schema": {"type": "string", "enum": [COOKIE_MODE]},
            "description": "Opt into an HttpOnly refresh-cookie session; requires a trusted Origin.",
        },
        {
            "name": "Origin",
            "in": "header",
            "schema": {"type": "string"},
            "description": "Required and checked against configured trusted origins in cookie mode.",
        },
    ],
}


def _allowed_origins(container: AuthContainer) -> set[str]:
    origins = set(container.config.trusted_origins)
    frontend = container.config.frontend_base_url.rstrip("/")
    if frontend:
        origins.add(frontend)
    return origins


def is_browser_session(request: Request, container: AuthContainer) -> bool:
    """Whether this request asked for cookie mode and came from a trusted origin."""
    mode = request.headers.get(SESSION_MODE_HEADER)
    if mode not in (None, COOKIE_MODE):
        raise HTTPException(status_code=400, detail="Invalid session mode")
    if mode != COOKIE_MODE:
        return False

    origin = request.headers.get("Origin")
    local_origin = (
        container.config.allow_localhost_origins and origin is not None and bool(_LOCALHOST_ORIGIN.fullmatch(origin))
    )
    if not origin or origin == "null" or (origin not in _allowed_origins(container) and not local_origin):
        raise HTTPException(status_code=403, detail="Untrusted session origin")
    return True


def refresh_request_token(request: Request, container: AuthContainer) -> str:
    """Read the refresh token from the HttpOnly cookie (cookie mode only)."""
    token = request.cookies.get(container.config.refresh_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return token


def set_refresh_cookie(response: Response, token: str, container: AuthContainer) -> None:
    """Store the refresh token in an HttpOnly cookie, honouring remember-me lifetime."""
    claims = container.token_service.decode_refresh_token(token)
    remaining = max(0, int(claims["exp"] - datetime.now(timezone.utc).timestamp()))
    remember_me = bool(claims.get("remember_me", False))
    response.set_cookie(
        container.config.refresh_cookie_name,
        token,
        httponly=True,
        secure=container.config.cookie_secure,
        samesite=container.config.cookie_samesite,
        path=container.config.refresh_cookie_path,
        max_age=remaining if remember_me else None,
    )
    response.headers["Cache-Control"] = "no-store"


def clear_refresh_cookie(response: Response, container: AuthContainer) -> None:
    """Delete the refresh cookie."""
    response.delete_cookie(
        container.config.refresh_cookie_name,
        path=container.config.refresh_cookie_path,
        httponly=True,
        secure=container.config.cookie_secure,
        samesite=container.config.cookie_samesite,
    )
    response.headers["Cache-Control"] = "no-store"


__all__ = [
    "BROWSER_SESSION_OPENAPI",
    "COOKIE_MODE",
    "SESSION_MODE_HEADER",
    "clear_refresh_cookie",
    "is_browser_session",
    "refresh_request_token",
    "set_refresh_cookie",
]
