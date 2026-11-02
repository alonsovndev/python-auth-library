"""Refresh: rotate a single-use refresh token into a new access/refresh pair."""

from __future__ import annotations

import jwt

from pyauthkit.dtos import TokenPair
from pyauthkit.errors import UnauthorizedError
from pyauthkit.ports import UserStore
from pyauthkit.revocation import TokenRevocationService
from pyauthkit.services._helpers import issue_token_pair
from pyauthkit.tokens import TokenService


class RefreshTokenService:
    """Rotates a refresh token.

    The presented token is checked against the revocation store and then revoked, so it can
    never be replayed; only the caller that revokes it wins a concurrent race. Tokens whose
    ``tv`` no longer matches the account (a forced logout) are rejected even if unused.
    """

    def __init__(self, users: UserStore, tokens: TokenService, revocation: TokenRevocationService) -> None:
        self._users = users
        self._tokens = tokens
        self._revocation = revocation

    async def execute(self, refresh_token: str) -> TokenPair:
        payload = self._tokens.decode_refresh_token(refresh_token)
        user_id = str(payload["sub"])
        email = str(payload["email"])
        remember_me = bool(payload.get("remember_me", False))

        if await self._revocation.is_revoked(refresh_token):
            raise jwt.InvalidTokenError("Refresh token has already been used")
        if not await self._revocation.revoke_token(refresh_token):
            raise jwt.InvalidTokenError("Refresh token has already been used")

        user = await self._users.find_by_email(email)
        if user is None or not user.is_active:
            raise UnauthorizedError("User not found")
        if user.id != user_id:
            raise jwt.InvalidTokenError("Invalid user credentials in token")
        if int(payload.get("tv", 0)) != user.token_version:
            raise jwt.InvalidTokenError("Session has been revoked")

        return issue_token_pair(self._tokens, user, remember_me=remember_me)


__all__ = ["RefreshTokenService"]
