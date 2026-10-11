"""Progressive account lockout."""

from __future__ import annotations

import pytest

from pyauthkit import AccountLockoutService, AuthConfig


@pytest.fixture
def lockout() -> AccountLockoutService:
    return AccountLockoutService(AuthConfig(secret_key="a" * 32, validate_secret=False, max_failed_attempts=3))


@pytest.mark.asyncio
async def test_not_locked_before_threshold(lockout: AccountLockoutService) -> None:
    await lockout.record_failed_attempt("a@b.com")
    await lockout.record_failed_attempt("a@b.com")
    assert await lockout.is_locked_out("a@b.com") is False


@pytest.mark.asyncio
async def test_locked_at_threshold(lockout: AccountLockoutService) -> None:
    for _ in range(3):
        await lockout.record_failed_attempt("a@b.com")
    assert await lockout.is_locked_out("a@b.com") is True
    info = await lockout.get_lockout_info("a@b.com")
    assert info is not None
    assert info["locked"] is True
    assert info["remaining_seconds"] > 0


@pytest.mark.asyncio
async def test_successful_login_clears_streak(lockout: AccountLockoutService) -> None:
    await lockout.record_failed_attempt("a@b.com")
    await lockout.record_successful_login("a@b.com")
    assert await lockout.get_failed_attempts("a@b.com") == 0


@pytest.mark.asyncio
async def test_clear_lockout_reports_whether_anything_was_cleared(lockout: AccountLockoutService) -> None:
    assert await lockout.clear_lockout("a@b.com") is False
    await lockout.record_failed_attempt("a@b.com")
    assert await lockout.clear_lockout("a@b.com") is True
