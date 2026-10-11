"""JWT issuance and verification.

Access and refresh tokens share a signing key, so each decoder rejects the other's token
type. Refresh tokens carry a ``tv`` (token-version) claim that a forced logout invalidates,
and both carry ``extra_claims`` supplied by the account (e.g. a tenant id).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from pyauthkit.config import AuthConfig
from pyauthkit.errors import AuthConfigError

# Common weak/default secrets that pass a length check but must be rejected outright.
WEAK_SECRETS = frozenset(
    {
        "secret",
        "your-secret-key-here",
        "changeme",
        "default",
        "test",
        "password",
        "12345",
        "supersecret",
        "your-super-secret-jwt-key-change-this-in-production-min-32-chars",
    }
)

_DECODE_OPTIONS: dict[str, Any] = {
    "require": ["exp", "iat", "sub", "aud", "iss"],
    "verify_exp": True,
    "verify_aud": True,
    "verify_iss": True,
}


class TokenService:
    """Creates and verifies access and refresh tokens for one :class:`AuthConfig`."""

    def __init__(self, config: AuthConfig) -> None:
        if config.validate_secret:
            self._validate_secret_key(config.secret_key)
        self.config = config

    @staticmethod
    def _validate_secret_key(secret_key: str) -> None:
        if not secret_key or len(secret_key) < 32:
            raise AuthConfigError(
                f"JWT secret key must be at least 32 characters (got {len(secret_key)}). Use a random value."
            )
        if secret_key.lower() in WEAK_SECRETS:
            raise AuthConfigError("JWT secret key is a known weak/default value. Use a random value.")

    def create_access_token(
        self,
        user_id: str,
        email: str,
        role: str,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Mint a short-lived access token."""
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": user_id,
            "email": email,
            "role": role,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=self.config.access_expiration_minutes),
            "aud": self.config.audience,
            "iss": self.config.issuer,
        }
        if extra_claims:
            payload.update(extra_claims)
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

    def create_refresh_token(
        self,
        user_id: str,
        email: str,
        role: str,
        *,
        remember_me: bool = False,
        token_version: int = 0,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Mint a long-lived refresh token carrying the session generation and remember-me flag."""
        now = datetime.now(timezone.utc)
        duration = self.config.remember_me_expiration_minutes if remember_me else self.config.refresh_expiration_minutes
        payload: dict[str, Any] = {
            "sub": user_id,
            "email": email,
            "role": role,
            "type": "refresh",
            "jti": _new_jti(),
            "remember_me": remember_me,
            "tv": token_version,
            "iat": now,
            "exp": now + timedelta(minutes=duration),
            "aud": self.config.audience,
            "iss": self.config.issuer,
        }
        if extra_claims:
            payload.update(extra_claims)
        return jwt.encode(payload, self.config.secret_key, algorithm=self.config.algorithm)

    def decode_access_token(self, token: str) -> dict[str, Any]:
        """Decode and validate an access token.

        Raises:
            jwt.ExpiredSignatureError: token expired.
            jwt.InvalidTokenError: signature/audience/issuer wrong, or it is a refresh token.
        """
        payload = self._decode(token)
        if payload.get("type") == "refresh":
            raise jwt.InvalidTokenError("Refresh token cannot be used as an access token")
        return payload

    def decode_refresh_token(self, token: str) -> dict[str, Any]:
        """Decode and validate a refresh token.

        Raises:
            jwt.ExpiredSignatureError: token expired.
            jwt.InvalidTokenError: invalid, or not a refresh token.
        """
        payload = self._decode(token)
        if payload.get("type") != "refresh":
            raise jwt.InvalidTokenError("Token is not a refresh token")
        return payload

    def _decode(self, token: str) -> dict[str, Any]:
        payload: dict[str, Any] = jwt.decode(
            token,
            self.config.secret_key,
            algorithms=[self.config.algorithm],
            audience=self.config.audience,
            issuer=self.config.issuer,
            options=_DECODE_OPTIONS,
        )
        return payload

    def get_token_expiry(self, token: str) -> datetime:
        """Read ``exp`` off a token this service issued (no signature verification).

        Only for tokens you already trust; validate with ``decode_*_token`` first otherwise.
        """
        exp: int = jwt.decode(token, options={"verify_signature": False})["exp"]
        return datetime.fromtimestamp(exp, tz=timezone.utc)


def _new_jti() -> str:
    from uuid import uuid4

    return str(uuid4())


__all__ = ["WEAK_SECRETS", "TokenService"]
