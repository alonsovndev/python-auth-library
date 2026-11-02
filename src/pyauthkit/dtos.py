"""Request/response models shared by the services and the FastAPI router.

All models accept snake_case (``populate_by_name``) and serialise to camelCase, matching
typical frontend contracts. Consumers can map :class:`UserInfo` into their own richer
response.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel

_CAMEL = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class LoginRequest(BaseModel):
    """Credentials for ``POST /login``."""

    model_config = _CAMEL

    email: EmailStr
    password: str
    remember_me: bool = False


class RefreshRequest(BaseModel):
    """Refresh token for ``POST /refresh`` (cookie mode supplies it instead)."""

    model_config = _CAMEL

    refresh_token: str = Field(min_length=1)


class RegisterRequest(BaseModel):
    """Inputs for public self-registration.

    ``extra="forbid"`` blocks attempts to smuggle privileged fields (e.g. a role) through
    the body. Host-specific values go through the ``attributes`` bag handled by the
    :class:`~pyauthkit.ports.RegistrationBuilder`.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")

    email: EmailStr
    password: str
    display_name: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class VerifyEmailRequest(BaseModel):
    """Inputs for ``POST /verify-email``. ``password`` lets an invitee set one here."""

    model_config = _CAMEL

    email: EmailStr
    code: str = Field(min_length=6, max_length=16)
    password: str | None = Field(default=None, max_length=72)


class ResendRequest(BaseModel):
    """Email-only request used by resend endpoints."""

    model_config = _CAMEL

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Inputs for ``POST /reset-password``."""

    model_config = _CAMEL

    email: EmailStr
    code: str
    new_password: str


class UserInfo(BaseModel):
    """Minimal account view embedded in token responses."""

    model_config = _CAMEL

    id: str
    email: str
    role: str
    claims: dict[str, Any] = Field(default_factory=dict)


class TokenPair(BaseModel):
    """Access + refresh tokens plus the session identity."""

    model_config = _CAMEL

    access_token: str
    refresh_token: str
    session_expires_at: str
    user: UserInfo | None = None


class BrowserTokenPair(BaseModel):
    """Token response for cookie sessions: the refresh token stays in the HttpOnly cookie."""

    model_config = _CAMEL

    access_token: str
    session_expires_at: str
    user: UserInfo


class RegisterResponse(BaseModel):
    """Registration accepted, pending email verification (no tokens)."""

    model_config = _CAMEL

    email: str
    verification_required: bool = True
    next_step: str = "verify-email"
    code_expires_at: str


class VerifyEmailResponse(BaseModel):
    """Email confirmed."""

    model_config = _CAMEL

    verified: bool = True


class MessageResponse(BaseModel):
    """Generic message response (resend, forgot-password, reset)."""

    model_config = _CAMEL

    message: str


class LogoutResponse(BaseModel):
    """Session invalidated."""

    model_config = _CAMEL

    message: str = "Logged out successfully."


__all__ = [
    "BrowserTokenPair",
    "LoginRequest",
    "LogoutResponse",
    "MessageResponse",
    "RefreshRequest",
    "RegisterRequest",
    "RegisterResponse",
    "ResendRequest",
    "ResetPasswordRequest",
    "TokenPair",
    "UserInfo",
    "VerifyEmailRequest",
    "VerifyEmailResponse",
]
