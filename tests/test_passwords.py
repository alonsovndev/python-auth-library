"""Password hashing and policy."""

from __future__ import annotations

import pytest

from pyauthkit import BcryptPasswordHasher, PasswordPolicy
from pyauthkit.errors import PasswordPolicyError


@pytest.mark.parametrize("password", ["short1", "alllowercase", "12345678"])
def test_policy_rejects_weak_passwords(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        PasswordPolicy().validate(password)


def test_policy_accepts_valid_password() -> None:
    PasswordPolicy().validate("abcd1234")


@pytest.mark.asyncio
async def test_hash_then_verify() -> None:
    hasher = BcryptPasswordHasher()
    hashed = await hasher.hash("abcd1234")
    assert hashed != "abcd1234"
    assert await hasher.verify("abcd1234", hashed)
    assert not await hasher.verify("wrong9999", hashed)


@pytest.mark.asyncio
async def test_verify_returns_false_on_garbage_hash() -> None:
    assert not await BcryptPasswordHasher().verify("abcd1234", "not-a-bcrypt-hash")
