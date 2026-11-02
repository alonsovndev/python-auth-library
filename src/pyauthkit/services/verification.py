"""Email verification: issue, resend, and confirm one-time codes."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from pyauthkit.codes import CodeStore, generate_one_time_code, new_code
from pyauthkit.config import AuthConfig
from pyauthkit.dtos import MessageResponse, ResendRequest, VerifyEmailRequest, VerifyEmailResponse
from pyauthkit.errors import InvalidVerificationCodeError, VerificationRateLimitedError
from pyauthkit.passwords import PasswordHasher, PasswordPolicy
from pyauthkit.ports import AuthUser, EmailSender, UserStore
from pyauthkit.services.email_links import EmailLinks

if TYPE_CHECKING:
    from pyauthkit.container import EmailVerifiedHook

GENERIC_RESEND_MESSAGE = "If this email is awaiting verification, a new code has been sent."


async def issue_verification_code(
    user: AuthUser,
    *,
    codes: CodeStore,
    email_sender: EmailSender,
    email_links: EmailLinks,
    hasher: PasswordHasher,
    config: AuthConfig,
    ttl_minutes: int | None = None,
) -> datetime:
    """Invalidate any active code, then generate, persist and email a new one.

    Returns when the new code expires. A delivery failure is swallowed: the account and
    code already exist, so the user can recover with a resend.
    """
    await codes.invalidate_active(user.id)

    code = generate_one_time_code(config)
    code_hash = await hasher.hash(code)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes or config.verification_code_ttl_minutes)
    await codes.create(new_code(user.id, code_hash, expires_at))

    # Delivery failure is swallowed: the account and code already exist, so the user can
    # recover with a resend, and surfacing it would reopen account enumeration.
    with contextlib.suppress(Exception):
        await email_sender.send(
            to=user.email,
            subject="Verify your email",
            body=(
                f"Your verification code is {code}.\n\n"
                f"Or verify directly: {email_links.verify_email(user.email, code)}\n\n"
                f"It expires in {ttl_minutes or config.verification_code_ttl_minutes} minutes.\n\n"
                "If you weren't expecting this, you can ignore this email."
            ),
        )

    return expires_at


async def is_verification_rate_limited(codes: CodeStore, config: AuthConfig, user_id: str) -> bool:
    """Whether this user has already been issued the window's allowance of codes."""
    window_start = datetime.now(timezone.utc) - timedelta(minutes=config.verification_resend_window_minutes)
    return await codes.count_created_since(user_id, window_start) >= config.max_verification_codes_per_window


class VerifyEmailService:
    """Confirms an account's email with its code and optionally sets a password."""

    def __init__(
        self,
        users: UserStore,
        codes: CodeStore,
        hasher: PasswordHasher,
        policy: PasswordPolicy,
        config: AuthConfig,
        on_email_verified: EmailVerifiedHook | None = None,
    ) -> None:
        self._users = users
        self._codes = codes
        self._hasher = hasher
        self._policy = policy
        self._config = config
        self._on_email_verified = on_email_verified

    async def execute(self, payload: VerifyEmailRequest) -> VerifyEmailResponse:
        email = str(payload.email).lower().strip()

        # Validated before the code so a weak password never burns an attempt.
        if payload.password is not None:
            self._policy.validate(payload.password)

        user = await self._users.find_by_email(email)
        if user is None or user.is_email_verified:
            raise InvalidVerificationCodeError

        code = await self._codes.find_latest_active(user.id)
        if code is None:
            raise InvalidVerificationCodeError
        if code.is_rate_limited(self._config.max_code_attempts):
            raise VerificationRateLimitedError("Too many attempts. Please request a new code.")

        submitted = payload.code.strip().upper()
        if not await self._hasher.verify(submitted, code.code_hash):
            code.record_failed_attempt()
            await self._codes.save(code)
            raise InvalidVerificationCodeError

        if payload.password is not None:
            user.set_password_hash(await self._hasher.hash(payload.password))
        user.mark_email_verified()
        await self._users.save(user)

        if self._on_email_verified is not None:
            await self._on_email_verified(user)

        code.mark_used()
        await self._codes.save(code)
        return VerifyEmailResponse(verified=True)


class ResendVerificationService:
    """Reissues a verification code within the configured resend window."""

    def __init__(
        self,
        users: UserStore,
        codes: CodeStore,
        email_sender: EmailSender,
        email_links: EmailLinks,
        hasher: PasswordHasher,
        config: AuthConfig,
    ) -> None:
        self._users = users
        self._codes = codes
        self._email_sender = email_sender
        self._email_links = email_links
        self._hasher = hasher
        self._config = config

    async def execute(self, payload: ResendRequest) -> MessageResponse:
        email = str(payload.email).lower().strip()
        user = await self._users.find_by_email(email)
        if user is None or user.is_email_verified:
            return MessageResponse(message=GENERIC_RESEND_MESSAGE)

        if await is_verification_rate_limited(self._codes, self._config, user.id):
            raise VerificationRateLimitedError("Too many code requests. Please try again later.")

        await issue_verification_code(
            user,
            codes=self._codes,
            email_sender=self._email_sender,
            email_links=self._email_links,
            hasher=self._hasher,
            config=self._config,
        )
        return MessageResponse(message=GENERIC_RESEND_MESSAGE)


__all__ = [
    "GENERIC_RESEND_MESSAGE",
    "ResendVerificationService",
    "VerifyEmailService",
    "is_verification_rate_limited",
    "issue_verification_code",
]
