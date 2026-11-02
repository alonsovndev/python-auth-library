"""Authenticated-user guards and RBAC for FastAPI routes.

The container is read from ``app.state.auth`` (set by :func:`pyauthkit.fastapi.install`), so
the guards can be used on any route in the host app, not only the auth router's.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pyauthkit.container import AuthContainer

# auto_error=False so a missing header is answered with our own 401 (not HTTPBearer's 403).
bearer_scheme = HTTPBearer(auto_error=False)

_RESERVED_CLAIMS = {"sub", "email", "role", "iat", "exp", "aud", "iss", "type", "jti"}


def get_container(request: Request) -> AuthContainer:
    """Fetch the installed :class:`AuthContainer` from ``app.state.auth``."""
    container: AuthContainer | None = getattr(request.app.state, "auth", None)
    if container is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="pyauthkit is not installed")
    return container


ContainerDep = Annotated[AuthContainer, Depends(get_container)]
CredentialsDep = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]


@dataclass(frozen=True)
class RequestContext:
    """Verified caller identity pulled only from the access token."""

    user_id: str
    email: str
    role: str
    claims: dict[str, Any] = field(default_factory=dict)


async def get_current_user(
    request: Request,
    credentials: CredentialsDep,
    container: ContainerDep,
) -> dict[str, Any]:
    """Return the decoded access-token payload, or raise 401."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    try:
        payload = container.token_service.decode_access_token(credentials.credentials)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if not payload.get("sub") or not payload.get("email"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.user_id = payload.get("sub")
    return payload


async def get_request_context(
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> RequestContext:
    """Project the token payload onto the fields routes usually need."""
    try:
        return RequestContext(
            user_id=str(current_user["sub"]),
            email=str(current_user["email"]),
            role=str(current_user["role"]),
            claims={k: v for k, v in current_user.items() if k not in _RESERVED_CLAIMS},
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_roles(*allowed_roles: str) -> Callable[..., Awaitable[RequestContext]]:
    """Build a dependency that admits only the given roles (403 otherwise)."""

    async def dependency(
        ctx: Annotated[RequestContext, Depends(get_request_context)],
    ) -> RequestContext:
        if ctx.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return ctx

    return dependency


__all__ = [
    "RequestContext",
    "bearer_scheme",
    "get_container",
    "get_current_user",
    "get_request_context",
    "require_roles",
]
