"""Single-use refresh-token revocation.

On every refresh the presented token is recorded here, so a replay is rejected. Tokens are
stored as a SHA-256 digest, never raw. Storage is a port; the in-memory default is fine for
a single process, and a durable adapter (SQL/Redis) is needed to share state across
instances.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Protocol

DEFAULT_REVOCATION_TTL_MINUTES = 10080  # 7 days: covers the longest refresh-token lifetime


def hash_token(token: str) -> str:
    """Digest a token for storage so raw bearer tokens never sit at rest."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RevocationStore(Protocol):
    """Persistence port for revoked-token identifiers, keyed by token hash."""

    async def add(self, token_hash: str, expires_at: datetime) -> bool:
        """Record the hash; return False if it was already present (concurrent replay)."""
        ...

    async def contains(self, token_hash: str) -> bool: ...

    async def clear_all(self) -> None: ...

    async def count(self) -> int: ...


class InMemoryRevocationStore:
    """Process-local store. Lost on restart; not shared across instances."""

    def __init__(self) -> None:
        self._revoked: dict[str, datetime] = {}

    async def add(self, token_hash: str, expires_at: datetime) -> bool:
        self._cleanup_expired()
        is_new = token_hash not in self._revoked
        self._revoked[token_hash] = expires_at
        return is_new

    async def contains(self, token_hash: str) -> bool:
        self._cleanup_expired()
        return token_hash in self._revoked

    async def clear_all(self) -> None:
        self._revoked.clear()

    async def count(self) -> int:
        self._cleanup_expired()
        return len(self._revoked)

    def _cleanup_expired(self) -> None:
        now = datetime.now(timezone.utc)
        for token_hash in [h for h, expiry in self._revoked.items() if expiry <= now]:
            del self._revoked[token_hash]


class TokenRevocationService:
    """Tracks used/revoked refresh tokens."""

    def __init__(self, store: RevocationStore | None = None) -> None:
        self._store: RevocationStore = store or InMemoryRevocationStore()
        self._lock = asyncio.Lock()

    async def revoke_token(self, token: str, ttl_minutes: int = DEFAULT_REVOCATION_TTL_MINUTES) -> bool:
        """Mark a token revoked. Returns True if this call revoked it, False if already revoked."""
        async with self._lock:
            expiry = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
            return await self._store.add(hash_token(token), expiry)

    async def is_revoked(self, token: str) -> bool:
        """Whether the token has already been revoked."""
        async with self._lock:
            return await self._store.contains(hash_token(token))

    async def clear_all(self) -> None:
        """Clear all revocations (testing)."""
        async with self._lock:
            await self._store.clear_all()

    async def get_revoked_count(self) -> int:
        """Number of currently revoked tokens (monitoring)."""
        async with self._lock:
            return await self._store.count()


__all__ = [
    "DEFAULT_REVOCATION_TTL_MINUTES",
    "InMemoryRevocationStore",
    "RevocationStore",
    "TokenRevocationService",
    "hash_token",
]
