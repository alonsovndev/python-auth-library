"""Password reset via emailed one-time codes."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone

from pyauthkit.codes import CodeStore, generate_one_time_code, new_code
from pyauthkit.config import AuthConfig
from pyauthkit.dtos import MessageResponse, ResendRequest, ResetPasswordRequest
from pyauthkit.errors import InvalidResetCodeError, ResetCodeRateLimitedError
from pyauthkit.passwords import PasswordHasher, PasswordPolicy
from pyauthkit.ports import AuthUser, EmailSender, UserStore
from pyauthkit.services.email_links import EmailLinks

GENERIC_RESET_MESSAGE = "If an account exists for this email, a reset code has been sent."


async def issue_reset_code(
    user: AuthUser,
    *,
    codes: CodeStore,
    email_sender: EmailSender,
    email_links: EmailLinks,
    hasher: PasswordHasher,
    config: AuthConfig,
) -> None:
    """Invalidate any active code, then generate, persist and email a new reset code."""
    await codes.invalidate_active(user.id)

    code = generate_one_time_code(config)
    code_hash = await hasher.hash(code)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.reset_code_ttl_minutes)
    await codes.create(new_code(user.id, code_hash, expires_at))

    # Never surface a delivery failure: it would reopen account enumeration as a side
    # channel (500 vs the generic 200).
    with contextlib.suppress(Exception):
        await email_sender.send(
            to=user.email,
            subject="Your password reset code",
            body=(
                f"Your password reset code is {code}.\n\n"
                f"Or reset directly: {email_links.reset_password(user.email, code)}\n\n"
                f"It expires in {config.reset_code_ttl_minutes} minutes.\n\n"
                "If you didn't ask for this, you can ignore this email."
            ),
        )


async def is_request_rate_limited(codes: CodeStore, config: AuthConfig, user_id: str) -> bool:
    """Whether this user has already been issued the window's allowance of reset codes."""
    window_start = datetime.now(timezone.utc) - timedelta(minutes=config.reset_request_window_minutes)
    return await codes.count_created_since(user_id, window_start) >= config.max_reset_codes_per_window


class RequestPasswordResetService:
    """Sends a reset code, always answering with the same generic message.

    Hitting the rate limit here also returns the generic response (not an error): a caller
    who has not yet identified an account must not be able to tell a rate-limited address
    from an unregistered one.
    """

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
        if user is None:
            return MessageResponse(message=GENERIC_RESET_MESSAGE)

        if await is_request_rate_limited(self._codes, self._config, user.id):
            return MessageResponse(message=GENERIC_RESET_MESSAGE)

        await issue_reset_code(
            user,
            codes=self._codes,
            email_sender=self._email_sender,
            email_links=self._email_links,
            hasher=self._hasher,
            config=self._config,
        )
        return MessageResponse(message=GENERIC_RESET_MESSAGE)


class ResendResetCodeService:
    """Reissues a reset code; surfaces a 429-equivalent when the window cap is hit."""

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
        if user is None:
            return MessageResponse(message=GENERIC_RESET_MESSAGE)

        if await is_request_rate_limited(self._codes, self._config, user.id):
            raise ResetCodeRateLimitedError("Too many reset code requests. Please try again later.")

        await issue_reset_code(
            user,
            codes=self._codes,
            email_sender=self._email_sender,
            email_links=self._email_links,
            hasher=self._hasher,
            config=self._config,
        )
        return MessageResponse(message=GENERIC_RESET_MESSAGE)


class ConfirmPasswordResetService:
    """Validates a reset code, applies the new password and ends every session."""

    def __init__(
        self,
        users: UserStore,
        codes: CodeStore,
        hasher: PasswordHasher,
        policy: PasswordPolicy,
        config: AuthConfig,
    ) -> None:
        self._users = users
        self._codes = codes
        self._hasher = hasher
        self._policy = policy
        self._config = config

    async def execute(self, payload: ResetPasswordRequest) -> MessageResponse:
        # Validate up front so a malformed request never burns an attempt against a valid code.
        self._policy.validate(payload.new_password)
        email = str(payload.email).lower().strip()

        user = await self._users.find_by_email(email)
        if user is None:
            raise InvalidResetCodeError

        code = await self._codes.find_latest_active(user.id)
        if code is None:
            raise InvalidResetCodeError
        if code.is_rate_limited(self._config.max_code_attempts):
            raise ResetCodeRateLimitedError("Too many attempts. Please request a new code.")

        if not await self._hasher.verify(payload.code, code.code_hash):
            code.record_failed_attempt()
            await self._codes.save(code)
            raise InvalidResetCodeError

        user.set_password_hash(await self._hasher.hash(payload.new_password))
        user.bump_token_version()
        await self._users.save(user)

        code.mark_used()
        await self._codes.save(code)
        return MessageResponse(message="Password has been reset successfully.")


__all__ = [
    "GENERIC_RESET_MESSAGE",
    "ConfirmPasswordResetService",
    "RequestPasswordResetService",
    "ResendResetCodeService",
    "is_request_rate_limited",
    "issue_reset_code",
]
