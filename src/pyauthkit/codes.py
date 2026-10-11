"""One-time codes for email verification and password reset.

Both flows use the same shape: a short, single-use, time-bound code whose hash is stored
(never the code itself), a wrong-guess counter, and a "used" marker. The store is a port so
the host can back it with its own database table.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from pyauthkit.config import AuthConfig


def generate_one_time_code(config: AuthConfig) -> str:
    """Generate a code from the configured alphabet and length using ``secrets``."""
    return "".join(secrets.choice(config.one_time_code_alphabet) for _ in range(config.one_time_code_length))


@dataclass
class OneTimeCode:
    """A single-use, time-bound code."""

    id: str
    user_id: str
    code_hash: str
    expires_at: datetime
    attempt_count: int = 0
    used_at: datetime | None = None
    created_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def is_rate_limited(self, max_attempts: int) -> bool:
        return self.attempt_count >= max_attempts

    def record_failed_attempt(self) -> None:
        self.attempt_count += 1

    def mark_used(self, now: datetime | None = None) -> None:
        self.used_at = now or datetime.now(timezone.utc)

    @property
    def is_active(self) -> bool:
        return self.used_at is None and not self.is_expired()


class CodeStore(Protocol):
    """Persistence port for one-time codes (verification and reset share the shape)."""

    async def create(self, code: OneTimeCode) -> OneTimeCode:
        """Persist a newly issued code."""
        ...

    async def find_latest_active(self, user_id: str) -> OneTimeCode | None:
        """Most recent non-expired, unused code for this user, or ``None``."""
        ...

    async def count_created_since(self, user_id: str, since: datetime) -> int:
        """Number of codes issued to this user since ``since`` (resend rate limit)."""
        ...

    async def save(self, code: OneTimeCode) -> None:
        """Persist ``attempt_count`` / ``used_at`` changes on an existing code."""
        ...

    async def invalidate_active(self, user_id: str) -> None:
        """Mark every still-active code for this user as used (superseded)."""
        ...


class InMemoryCodeStore:
    """Process-local code store. Lost on restart; use an adapter for durability."""

    def __init__(self) -> None:
        self._codes: dict[str, OneTimeCode] = {}

    async def create(self, code: OneTimeCode) -> OneTimeCode:
        if code.created_at is None:
            code.created_at = datetime.now(timezone.utc)
        self._codes[code.id] = code
        return code

    async def find_latest_active(self, user_id: str) -> OneTimeCode | None:
        active = [c for c in self._codes.values() if c.user_id == user_id and c.is_active]
        if not active:
            return None
        return max(active, key=lambda c: c.created_at or datetime.min.replace(tzinfo=timezone.utc))

    async def count_created_since(self, user_id: str, since: datetime) -> int:
        return sum(
            1
            for c in self._codes.values()
            if c.user_id == user_id and c.created_at is not None and c.created_at >= since
        )

    async def save(self, code: OneTimeCode) -> None:
        self._codes[code.id] = code

    async def invalidate_active(self, user_id: str) -> None:
        now = datetime.now(timezone.utc)
        for code in self._codes.values():
            if code.user_id == user_id and code.is_active:
                code.mark_used(now)


def new_code(user_id: str, code_hash: str, expires_at: datetime) -> OneTimeCode:
    """Build a code with a fresh id."""
    return OneTimeCode(id=str(uuid4()), user_id=user_id, code_hash=code_hash, expires_at=expires_at)


__all__ = ["CodeStore", "InMemoryCodeStore", "OneTimeCode", "generate_one_time_code", "new_code"]
