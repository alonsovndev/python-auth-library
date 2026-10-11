"""Logout: revoke the presented refresh token server-side."""

from __future__ import annotations

from pyauthkit.dtos import LogoutResponse
from pyauthkit.revocation import TokenRevocationService
from pyauthkit.tokens import TokenService


class LogoutService:
    """Revokes a refresh token so it cannot be replayed to mint new access tokens.

    Idempotent: an already-invalid or expired token is treated as a successful logout
    rather than an error.
    """

    def __init__(self, tokens: TokenService, revocation: TokenRevocationService) -> None:
        self._tokens = tokens
        self._revocation = revocation

    async def execute(self, refresh_token: str) -> LogoutResponse:
        try:
            self._tokens.decode_refresh_token(refresh_token)
        except Exception:
            return LogoutResponse()
        await self._revocation.revoke_token(refresh_token)
        return LogoutResponse()


__all__ = ["LogoutService"]
