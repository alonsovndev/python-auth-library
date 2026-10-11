"""SQLAlchemy models for the pyauthkit stores.

Tables are prefixed ``pyauthkit_`` and use string user identifiers with no foreign key, so
they never depend on the host's user table.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for pyauthkit-owned tables."""


class VerificationCodeModel(Base):
    """One-time codes emailed for sign-up email verification."""

    __tablename__ = "pyauthkit_verification_codes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class PasswordResetCodeModel(Base):
    """One-time codes emailed for password reset."""

    __tablename__ = "pyauthkit_password_reset_codes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class AccountLockoutModel(Base):
    """Failed-attempt streak and lock expiry, keyed by identifier."""

    __tablename__ = "pyauthkit_account_lockout"

    identifier: Mapped[str] = mapped_column(String(320), primary_key=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RevokedRefreshTokenModel(Base):
    """Revoked refresh-token hashes."""

    __tablename__ = "pyauthkit_revoked_refresh_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


__all__ = [
    "AccountLockoutModel",
    "Base",
    "PasswordResetCodeModel",
    "RevokedRefreshTokenModel",
    "VerificationCodeModel",
]
