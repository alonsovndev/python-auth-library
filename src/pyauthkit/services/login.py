"""Login: authenticate a password and issue tokens, with lockout protection."""

from __future__ import annotations

from pyauthkit.dtos import LoginRequest, TokenPair
from pyauthkit.errors import AccountLockedError, EmailNotVerifiedError, InvalidCredentialsError
from pyauthkit.lockout import AccountLockoutService
from pyauthkit.passwords import PasswordHasher
from pyauthkit.ports import UserStore
from pyauthkit.services._helpers import issue_token_pair
from pyauthkit.tokens import TokenService


class LoginService:
    """Validates credentials and returns an access/refresh pair.

    Failure ordering is deliberate: the account is locked check first, then credentials
    (recording a failure even for unknown emails so timing cannot enumerate accounts), and
    the "email not verified" state only after the password matches — so it is never
    revealed to someone guessing at emails.
    """

    def __init__(
        self,
        users: UserStore,
        tokens: TokenService,
        hasher: PasswordHasher,
        lockout: AccountLockoutService,
    ) -> None:
        self._users = users
        self._tokens = tokens
        self._hasher = hasher
        self._lockout = lockout

    async def execute(self, payload: LoginRequest) -> TokenPair:
        email = str(payload.email).lower().strip()

        if await self._lockout.is_locked_out(email):
            info = await self._lockout.get_lockout_info(email) or {}
            raise AccountLockedError(
                message="Account temporarily locked. Try again later.",
                remaining_seconds=int(info.get("remaining_seconds", 0)),
                failed_attempts=int(info.get("failed_attempts", 0)),
            )

        user = await self._users.find_by_email(email)
        if user is None or not user.is_active:
            await self._lockout.record_failed_attempt(email)
            raise InvalidCredentialsError

        if not await self._hasher.verify(payload.password, user.password_hash):
            await self._lockout.record_failed_attempt(email)
            raise InvalidCredentialsError

        if not user.is_email_verified:
            raise EmailNotVerifiedError

        await self._lockout.record_successful_login(email)
        return issue_token_pair(self._tokens, user, remember_me=payload.remember_me)


__all__ = ["LoginService"]
