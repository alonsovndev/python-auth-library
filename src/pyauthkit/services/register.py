"""Public self-registration pending email verification."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone

from pyauthkit.codes import CodeStore
from pyauthkit.config import AuthConfig
from pyauthkit.dtos import RegisterRequest, RegisterResponse
from pyauthkit.passwords import PasswordHasher, PasswordPolicy
from pyauthkit.ports import EmailSender, RegistrationBuilder, RegistrationData, UserStore
from pyauthkit.services._helpers import iso_z, mask_email
from pyauthkit.services.email_links import EmailLinks
from pyauthkit.services.verification import issue_verification_code


class RegisterService:
    """Creates an unverified account and emails it a code.

    No tokens are issued: the account signs in only after ``VerifyEmailService`` succeeds.
    The response is identical whether the email is new or already held by a verified
    account (the owner is notified by email instead), so the form cannot probe for accounts.
    """

    def __init__(
        self,
        users: UserStore,
        codes: CodeStore,
        email_sender: EmailSender,
        email_links: EmailLinks,
        hasher: PasswordHasher,
        policy: PasswordPolicy,
        builder: RegistrationBuilder,
        config: AuthConfig,
    ) -> None:
        self._users = users
        self._codes = codes
        self._email_sender = email_sender
        self._email_links = email_links
        self._hasher = hasher
        self._policy = policy
        self._builder = builder
        self._config = config

    async def execute(self, payload: RegisterRequest) -> RegisterResponse:
        self._policy.validate(payload.password)
        email = str(payload.email).lower().strip()

        existing = await self._users.find_by_email(email)
        if existing is not None and existing.is_email_verified:
            await self._notify_existing_account(email)
            return self._generic_response(email)

        data = RegistrationData(
            email=email,
            password=payload.password,
            display_name=payload.display_name.strip(),
            attributes=payload.attributes,
        )
        created = await self._builder.create_user(data, replacing=existing)
        if created is None:
            # Another request claimed the email between the check and the insert.
            return self._generic_response(email)

        expires_at = await issue_verification_code(
            created,
            codes=self._codes,
            email_sender=self._email_sender,
            email_links=self._email_links,
            hasher=self._hasher,
            config=self._config,
        )
        return RegisterResponse(email=mask_email(created.email), code_expires_at=iso_z(expires_at))

    async def _notify_existing_account(self, email: str) -> None:
        # A delivery failure must not surface: it would leak account existence (500 vs the
        # generic 201 response).
        with contextlib.suppress(Exception):
            await self._email_sender.send(
                to=email,
                subject="You already have an account",
                body=(
                    "Someone tried to create an account with this email, but you already have one.\n\n"
                    f"Sign in: {self._email_links.sign_in()}\n\n"
                    'If you forgot your password, use "Forgot password" on the sign-in page.\n\n'
                    "If this wasn't you, you can ignore this email."
                ),
            )

    def _generic_response(self, email: str) -> RegisterResponse:
        decoy_expires_at = datetime.now(timezone.utc) + timedelta(minutes=self._config.verification_code_ttl_minutes)
        return RegisterResponse(email=mask_email(email), code_expires_at=iso_z(decoy_expires_at))


__all__ = ["RegisterService"]
