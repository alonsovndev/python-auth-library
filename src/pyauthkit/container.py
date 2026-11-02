"""Composition root: the single object a host passes to the services and router builder.

``AuthContainer`` wires the toolkit's own dependencies (token service, hasher, policy,
lockout, revocation, code stores) and holds the ports the host supplies (user store, email
sender, registration builder). Nothing here reaches into a database or framework.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from pyauthkit.codes import CodeStore, InMemoryCodeStore
from pyauthkit.config import AuthConfig
from pyauthkit.lockout import AccountLockoutService
from pyauthkit.passwords import BcryptPasswordHasher, PasswordHasher, PasswordPolicy
from pyauthkit.ports import AuthUser, EmailSender, RegistrationBuilder, UserStore
from pyauthkit.revocation import TokenRevocationService
from pyauthkit.services.email_links import EmailLinks
from pyauthkit.tokens import TokenService

# Called after an email is verified; a host uses it to grant defaults (e.g. initial credits).
EmailVerifiedHook = Callable[[AuthUser], Awaitable[None]]


class AuthContainer:
    """Holds every collaborator the login/register/reset services and router need.

    Four collaborators are required; everything else defaults to the built-in
    implementations and can be overridden for production (durable stores) or tests.
    Exceeding the usual parameter guideline is intentional: this is the composition root,
    and splitting it would only add indirection.
    """

    def __init__(
        self,
        config: AuthConfig,
        users: UserStore,
        email_sender: EmailSender,
        registration_builder: RegistrationBuilder,
        *,
        token_service: TokenService | None = None,
        password_hasher: PasswordHasher | None = None,
        password_policy: PasswordPolicy | None = None,
        lockout_service: AccountLockoutService | None = None,
        revocation_service: TokenRevocationService | None = None,
        verification_codes: CodeStore | None = None,
        reset_codes: CodeStore | None = None,
        email_links: EmailLinks | None = None,
        on_email_verified: EmailVerifiedHook | None = None,
    ) -> None:
        self.config = config
        self.users = users
        self.email_sender = email_sender
        self.registration_builder = registration_builder
        self.token_service = token_service or TokenService(config)
        self.password_hasher = password_hasher or BcryptPasswordHasher()
        self.password_policy = password_policy or PasswordPolicy(min_length=config.min_password_length)
        self.lockout_service = lockout_service or AccountLockoutService(config)
        self.revocation_service = revocation_service or TokenRevocationService()
        self.verification_codes = verification_codes or InMemoryCodeStore()
        self.reset_codes = reset_codes or InMemoryCodeStore()
        self.email_links = email_links or EmailLinks(config.frontend_base_url)
        self.on_email_verified = on_email_verified


__all__ = ["AuthContainer", "EmailVerifiedHook"]
