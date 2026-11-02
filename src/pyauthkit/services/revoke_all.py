"""Force a logout across every device by bumping the account's token version."""

from __future__ import annotations

from pyauthkit.ports import UserStore


class RevokeAllSessionsService:
    """Invalidates every refresh token issued before the call.

    Refresh tokens embed the ``tv`` they were minted under; bumping the account's version
    makes older tokens fail validation in :class:`~pyauthkit.services.refresh.RefreshTokenService`.
    """

    def __init__(self, users: UserStore) -> None:
        self._users = users

    async def execute(self, user_id: str) -> None:
        user = await self._users.find_by_id(user_id)
        if user is None:
            return
        user.bump_token_version()
        await self._users.save(user)


__all__ = ["RevokeAllSessionsService"]
