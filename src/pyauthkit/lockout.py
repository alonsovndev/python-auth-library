"""Progressive account lockout to blunt brute-force login attempts.

State lives behind :class:`LockoutStore` (in-memory by default) so a durable adapter can
share it across instances. The policy is driven entirely by :class:`AuthConfig`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from pyauthkit.config import AuthConfig


@dataclass
class LockoutState:
    """Failure streak and lock expiry for one account identifier."""

    failed_attempts: int
    locked_until: datetime | None
    last_attempt: datetime


class LockoutStore(Protocol):
    """Persistence port for lockout state, keyed by identifier (usually email)."""

    async def get(self, identifier: str) -> LockoutState | None: ...

    async def save(self, identifier: str, state: LockoutState) -> None: ...

    async def delete(self, identifier: str) -> None: ...

    async def list_all(self) -> dict[str, LockoutState]: ...


class InMemoryLockoutStore:
    """Process-local store. Lost on restart; not shared across instances."""

    def __init__(self) -> None:
        self._state: dict[str, LockoutState] = {}

    async def get(self, identifier: str) -> LockoutState | None:
        return self._state.get(identifier)

    async def save(self, identifier: str, state: LockoutState) -> None:
        self._state[identifier] = state

    async def delete(self, identifier: str) -> None:
        self._state.pop(identifier, None)

    async def list_all(self) -> dict[str, LockoutState]:
        return dict(self._state)


class AccountLockoutService:
    """Tracks failures per identifier and locks the account after too many.

    With ``progressive_lockout`` the duration escalates: 5 failures -> base, 10 -> 2x, 15 -> 4x,
    20+ -> 8x (base 15 min => 15/30/60/120). A failure streak older than the attempt window
    resets.
    """

    def __init__(self, config: AuthConfig, store: LockoutStore | None = None) -> None:
        self.config = config
        self._store: LockoutStore = store or InMemoryLockoutStore()
        self._lock = asyncio.Lock()

    async def record_failed_attempt(self, identifier: str) -> None:
        """Count one failure, applying a lockout once the threshold is reached."""
        async with self._lock:
            now = datetime.now(timezone.utc)
            state = await self._store.get(identifier)

            if state is None:
                state = LockoutState(failed_attempts=1, locked_until=None, last_attempt=now)
            else:
                within_window = (now - state.last_attempt).total_seconds() <= self.config.attempt_window_minutes * 60
                state.failed_attempts = state.failed_attempts + 1 if within_window else 1
                if not within_window:
                    state.locked_until = None
                state.last_attempt = now
                if state.failed_attempts >= self.config.max_failed_attempts:
                    duration = self._lockout_duration(state.failed_attempts)
                    state.locked_until = now + timedelta(minutes=duration)

            await self._store.save(identifier, state)

    async def record_successful_login(self, identifier: str) -> None:
        """Clear the failure streak after a successful login."""
        async with self._lock:
            await self._store.delete(identifier)

    async def is_locked_out(self, identifier: str) -> bool:
        """Whether the account is locked right now (expired locks self-clear)."""
        async with self._lock:
            state = await self._store.get(identifier)
            if state is None or state.locked_until is None:
                return False
            if datetime.now(timezone.utc) >= state.locked_until:
                await self._store.delete(identifier)
                return False
            return True

    async def get_lockout_info(self, identifier: str) -> dict[str, Any] | None:
        """Details for a locked or partially-failed account, or ``None``."""
        async with self._lock:
            state = await self._store.get(identifier)
            if state is None:
                return None
            now = datetime.now(timezone.utc)
            if state.locked_until and now < state.locked_until:
                remaining_seconds = int((state.locked_until - now).total_seconds())
                return {
                    "locked": True,
                    "failed_attempts": state.failed_attempts,
                    "locked_until": state.locked_until.isoformat(),
                    "remaining_seconds": remaining_seconds,
                    "remaining_minutes": round(remaining_seconds / 60, 1),
                }
            if state.locked_until and now >= state.locked_until:
                await self._store.delete(identifier)
                return None
            return {
                "locked": False,
                "failed_attempts": state.failed_attempts,
                "remaining_attempts": self.config.max_failed_attempts - state.failed_attempts,
            }

    async def get_failed_attempts(self, identifier: str) -> int:
        """Current failure count within the window."""
        async with self._lock:
            state = await self._store.get(identifier)
            if state is None:
                return 0
            if (
                datetime.now(timezone.utc) - state.last_attempt
            ).total_seconds() > self.config.attempt_window_minutes * 60:
                await self._store.delete(identifier)
                return 0
            return state.failed_attempts

    async def clear_lockout(self, identifier: str) -> bool:
        """Clear state for one account; returns whether anything was cleared."""
        async with self._lock:
            if await self._store.get(identifier) is None:
                return False
            await self._store.delete(identifier)
            return True

    def _lockout_duration(self, failed_attempts: int) -> int:
        base = self.config.lockout_duration_minutes
        if not self.config.progressive_lockout:
            return base
        if failed_attempts >= 20:
            return base * 8
        if failed_attempts >= 15:
            return base * 4
        if failed_attempts >= 10:
            return base * 2
        return base


__all__ = ["AccountLockoutService", "InMemoryLockoutStore", "LockoutState", "LockoutStore"]
