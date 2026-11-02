"""Shared test fixtures: in-memory ports and a ready-to-use container."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import pytest

from pyauthkit import AuthConfig, AuthContainer, BcryptPasswordHasher, RegistrationData

_CODE_RE = re.compile(r"code is ([0-9A-Z]+)")


@dataclass
class FakeUser:
    """Minimal :class:`~pyauthkit.ports.AuthUser` implementation."""

    id: str
    email: str
    password_hash: str = ""
    role: str = "member"
    is_active: bool = True
    is_email_verified: bool = False
    token_version: int = 0
    claims: dict[str, Any] = field(default_factory=dict)

    def set_password_hash(self, password_hash: str) -> None:
        self.password_hash = password_hash

    def mark_email_verified(self) -> None:
        self.is_email_verified = True

    def bump_token_version(self) -> None:
        self.token_version += 1

    def extra_claims(self) -> dict[str, Any]:
        return dict(self.claims)


class InMemoryUserStore:
    """:class:`~pyauthkit.ports.UserStore` backed by a dict."""

    def __init__(self) -> None:
        self._by_id: dict[str, FakeUser] = {}

    async def find_by_email(self, email: str) -> FakeUser | None:
        return next((user for user in self._by_id.values() if user.email == email), None)

    async def find_by_id(self, user_id: str) -> FakeUser | None:
        return self._by_id.get(user_id)

    async def save(self, user: FakeUser) -> FakeUser:
        self._by_id[user.id] = user
        return user


class RecordingEmailSender:
    """Captures sent emails so tests can read the one-time code."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []

    async def send(self, to: str, subject: str, body: str) -> None:
        self.sent.append((to, subject, body))

    def last_code(self) -> str:
        match = _CODE_RE.search(self.sent[-1][2])
        assert match is not None, f"no code in email body: {self.sent[-1][2]!r}"
        return match.group(1)


class FakeRegistrationBuilder:
    """Creates unverified accounts; reuses an existing unverified one."""

    def __init__(self, store: InMemoryUserStore, hasher: Any) -> None:
        self._store = store
        self._hasher = hasher
        self._counter = 0

    async def create_user(self, data: RegistrationData, *, replacing: FakeUser | None) -> FakeUser:
        if replacing is not None:
            return replacing
        self._counter += 1
        user = FakeUser(id=f"user-{self._counter}", email=data.email)
        user.set_password_hash(await self._hasher.hash(data.password))
        await self._store.save(user)
        return user


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(
        secret_key="t" * 40,
        audience="test",
        issuer="test",
        validate_secret=False,
        cookie_secure=False,
        trusted_origins=("http://testserver",),
    )


def make_container(config: AuthConfig) -> AuthContainer:
    store = InMemoryUserStore()
    hasher = BcryptPasswordHasher()
    builder = FakeRegistrationBuilder(store, hasher)
    return AuthContainer(config, store, RecordingEmailSender(), builder, password_hasher=hasher)


@pytest.fixture
def container(config: AuthConfig) -> AuthContainer:
    return make_container(config)
