"""Single-use refresh-token revocation."""

from __future__ import annotations

import pytest

from pyauthkit import TokenRevocationService, hash_token


@pytest.mark.asyncio
async def test_revoke_is_single_use() -> None:
    service = TokenRevocationService()
    assert await service.revoke_token("token-a") is True
    assert await service.revoke_token("token-a") is False
    assert await service.is_revoked("token-a") is True
    assert await service.is_revoked("token-b") is False


@pytest.mark.asyncio
async def test_clear_and_count() -> None:
    service = TokenRevocationService()
    await service.revoke_token("token-a")
    await service.revoke_token("token-b")
    assert await service.get_revoked_count() == 2
    await service.clear_all()
    assert await service.get_revoked_count() == 0


def test_hash_is_stable_and_not_the_raw_token() -> None:
    assert hash_token("secret") == hash_token("secret")
    assert hash_token("secret") != "secret"
    assert len(hash_token("secret")) == 64
