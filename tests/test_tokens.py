"""TokenService: issuance, type separation, claim handling and secret validation."""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
import pytest

from pyauthkit import AuthConfig, TokenService
from pyauthkit.errors import AuthConfigError


@pytest.fixture
def service() -> TokenService:
    return TokenService(AuthConfig(secret_key="a" * 32, validate_secret=False))


def test_access_token_round_trip(service: TokenService) -> None:
    payload = service.decode_access_token(service.create_access_token("u1", "a@b.com", "member"))
    assert payload["sub"] == "u1"
    assert payload["email"] == "a@b.com"
    assert payload["role"] == "member"
    assert payload["type"] == "access"


def test_refresh_token_round_trip(service: TokenService) -> None:
    payload = service.decode_refresh_token(service.create_refresh_token("u1", "a@b.com", "member", token_version=3))
    assert payload["type"] == "refresh"
    assert payload["tv"] == 3


def test_refresh_token_rejected_as_access(service: TokenService) -> None:
    token = service.create_refresh_token("u1", "a@b.com", "member")
    with pytest.raises(jwt.InvalidTokenError):
        service.decode_access_token(token)


def test_access_token_rejected_as_refresh(service: TokenService) -> None:
    token = service.create_access_token("u1", "a@b.com", "member")
    with pytest.raises(jwt.InvalidTokenError):
        service.decode_refresh_token(token)


def test_extra_claims_are_embedded(service: TokenService) -> None:
    token = service.create_access_token("u1", "a@b.com", "member", extra_claims={"tenant": "t1"})
    assert service.decode_access_token(token)["tenant"] == "t1"


def test_get_token_expiry_is_in_the_future(service: TokenService) -> None:
    token = service.create_refresh_token("u1", "a@b.com", "member")
    assert service.get_token_expiry(token) > datetime.now(timezone.utc)


def test_short_secret_rejected() -> None:
    with pytest.raises(AuthConfigError):
        TokenService(AuthConfig(secret_key="too-short"))


def test_weak_secret_rejected() -> None:
    with pytest.raises(AuthConfigError):
        TokenService(AuthConfig(secret_key="changeme"))


def test_audience_mismatch_rejected() -> None:
    issuer = TokenService(AuthConfig(secret_key="a" * 32, audience="one", validate_secret=False))
    verifier = TokenService(AuthConfig(secret_key="a" * 32, audience="two", validate_secret=False))
    token = issuer.create_access_token("u1", "a@b.com", "member")
    with pytest.raises(jwt.InvalidTokenError):
        verifier.decode_access_token(token)
