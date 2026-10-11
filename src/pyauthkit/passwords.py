"""Password hashing and policy.

Hashing runs in a worker thread so bcrypt never blocks the event loop. The hashing
strategy is behind the :class:`PasswordHasher` protocol, so a project can swap in Argon2
without touching the services.
"""

from __future__ import annotations

import asyncio
import re
from typing import Protocol, runtime_checkable

from pyauthkit.errors import PasswordPolicyError


@runtime_checkable
class PasswordHasher(Protocol):
    """Hashing strategy used for passwords and one-time codes."""

    async def hash(self, plain: str) -> str:
        """Hash a plain-text secret."""
        ...

    async def verify(self, plain: str, hashed: str) -> bool:
        """Check a plain-text secret against a hash."""
        ...


class BcryptPasswordHasher:
    """Default hasher: bcrypt with a fresh salt, off the event loop."""

    async def hash(self, plain: str) -> str:
        """Hash ``plain`` with bcrypt in a thread."""

        def _hash() -> str:
            import bcrypt

            return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        return await asyncio.to_thread(_hash)

    async def verify(self, plain: str, hashed: str) -> bool:
        """Verify ``plain`` against ``hashed``; returns False on any error (e.g. bad hash)."""

        def _verify() -> bool:
            import bcrypt

            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

        try:
            return await asyncio.to_thread(_verify)
        except Exception:
            return False


class PasswordPolicy:
    """Configurable password rules applied before hashing.

    The defaults match common backend expectations: a minimum length plus at least one
    letter and one digit. Stricter rules can be layered on top by the host.
    """

    def __init__(self, *, min_length: int = 8, require_letter: bool = True, require_digit: bool = True) -> None:
        self.min_length = min_length
        self.require_letter = require_letter
        self.require_digit = require_digit

    def validate(self, password: str) -> None:
        """Raise :class:`PasswordPolicyError` if ``password`` is unacceptable."""
        if len(password) < self.min_length:
            raise PasswordPolicyError(f"Password must be at least {self.min_length} characters long")
        if self.require_letter and not re.search(r"[a-zA-Z]", password):
            raise PasswordPolicyError("Password must contain at least one letter")
        if self.require_digit and not re.search(r"\d", password):
            raise PasswordPolicyError("Password must contain at least one digit")


__all__ = ["BcryptPasswordHasher", "PasswordHasher", "PasswordPolicy"]
