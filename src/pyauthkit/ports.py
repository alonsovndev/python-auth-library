"""Ports the host application implements to plug its own domain into pyauthkit.

The toolkit never knows how a user is stored. Instead it depends on the small
:class:`AuthUser` protocol and the :class:`UserStore`, :class:`RegistrationBuilder` and
:class:`EmailSender` ports. A consumer adapts their existing entity/repository/transport
without leaking their schema into the library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuthUser(Protocol):
    """The minimal, mutable view pyauthkit needs of an account.

    Implement it on (or adapt) your own user entity. Only the members below are used; the
    toolkit never assumes workspaces, credits or any other host concept.
    """

    @property
    def id(self) -> str:
        """Stable unique identifier (stringified, e.g. a UUID)."""
        ...

    @property
    def email(self) -> str:
        """Normalised email address (lower-case)."""
        ...

    @property
    def password_hash(self) -> str:
        """Hash produced by the configured :class:`~pyauthkit.passwords.PasswordHasher`."""
        ...

    @property
    def role(self) -> str:
        """Role used for RBAC (e.g. ``"admin"`` / ``"member"``)."""
        ...

    @property
    def is_active(self) -> bool:
        """Whether the account may sign in."""
        ...

    @property
    def is_email_verified(self) -> bool:
        """Whether the email has been confirmed."""
        ...

    @property
    def token_version(self) -> int:
        """Session generation; bumping it invalidates every existing refresh token."""
        ...

    def set_password_hash(self, password_hash: str) -> None:
        """Replace the stored password hash."""
        ...

    def mark_email_verified(self) -> None:
        """Record that the email was confirmed."""
        ...

    def bump_token_version(self) -> None:
        """Increment :attr:`token_version` to force a logout across devices."""
        ...

    def extra_claims(self) -> dict[str, Any]:
        """Additional JWT claims to embed on every token (e.g. a tenant id).

        Optional in practice: implementations that have none return an empty mapping.
        """
        ...


@dataclass
class RegistrationData:
    """Inputs passed to :class:`RegistrationBuilder.create_user`.

    ``password`` is the plain-text secret (already validated against the policy); the
    builder is responsible for hashing it or calling the toolkit's hasher.
    """

    email: str
    password: str
    display_name: str
    attributes: dict[str, Any] = field(default_factory=dict)


class UserStore(Protocol):
    """Persistence port for accounts."""

    async def find_by_email(self, email: str) -> AuthUser | None:
        """Return the account with this (already lower-cased) email, or ``None``."""
        ...

    async def find_by_id(self, user_id: str) -> AuthUser | None:
        """Return the account with this id, or ``None``."""
        ...

    async def save(self, user: AuthUser) -> AuthUser:
        """Persist a new or updated account and return the stored value."""
        ...


class RegistrationBuilder(Protocol):
    """Creates and persists a new, unverified account.

    Lives in the host because only it knows how to provision whatever else an account
    needs (workspaces, defaults, quotas). Returning ``None`` signals a race — another
    request claimed the email between the check and the insert.
    """

    async def create_user(self, data: RegistrationData, *, replacing: AuthUser | None) -> AuthUser | None:
        """Create the account, replacing ``replacing`` when an unverified duplicate exists."""
        ...


class EmailSender(Protocol):
    """Outbound transactional email port."""

    async def send(self, to: str, subject: str, body: str) -> None:
        """Send a plain-text email. Raises on delivery failure."""
        ...


__all__ = ["AuthUser", "EmailSender", "RegistrationBuilder", "RegistrationData", "UserStore"]
