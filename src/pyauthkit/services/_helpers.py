"""Small shared helpers for building token responses."""

from __future__ import annotations

from datetime import datetime

from pyauthkit.dtos import TokenPair, UserInfo
from pyauthkit.ports import AuthUser
from pyauthkit.tokens import TokenService


def iso_z(value: datetime) -> str:
    """ISO-8601 with a ``Z`` suffix for UTC (matches common client expectations)."""
    return value.isoformat().replace("+00:00", "Z")


def to_user_info(user: AuthUser) -> UserInfo:
    """Project an :class:`AuthUser` onto the minimal response shape."""
    return UserInfo(id=user.id, email=user.email, role=user.role, claims=user.extra_claims())


def mask_email(email: str) -> str:
    """Mask the local part of an email for responses and logs (``al***@example.com``)."""
    local, _, domain = email.partition("@")
    if not domain:
        return email
    return f"{local[:2]}{'*' * max(len(local) - 2, 1)}@{domain}"


def issue_token_pair(tokens: TokenService, user: AuthUser, *, remember_me: bool) -> TokenPair:
    """Mint an access/refresh pair carrying the user's role, version and extra claims."""
    extra = user.extra_claims()
    access_token = tokens.create_access_token(user.id, user.email, user.role, extra_claims=extra)
    refresh_token = tokens.create_refresh_token(
        user.id,
        user.email,
        user.role,
        remember_me=remember_me,
        token_version=user.token_version,
        extra_claims=extra,
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        session_expires_at=iso_z(tokens.get_token_expiry(refresh_token)),
        user=to_user_info(user),
    )


__all__ = ["iso_z", "issue_token_pair", "mask_email", "to_user_info"]
