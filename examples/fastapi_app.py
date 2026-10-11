"""Minimal pyauthkit + FastAPI example with in-memory ports.

Run: uvicorn examples.fastapi_app:app --reload
Then POST /auth/register, read the printed verification code from the terminal, verify,
and sign in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, FastAPI

from pyauthkit import (
    AuthConfig,
    AuthContainer,
    BcryptPasswordHasher,
    RegistrationData,
)
from pyauthkit.fastapi import (
    RequestContext,
    build_auth_router,
    get_request_context,
    install,
)


@dataclass
class User:
    """Host user entity implementing the AuthUser port."""

    id: str
    email: str
    password_hash: str = ""
    is_email_verified: bool = False
    token_version: int = 0
    claims: dict[str, Any] | None = None

    @property
    def role(self) -> str:
        return "member"

    @property
    def is_active(self) -> bool:
        return True

    def set_password_hash(self, password_hash: str) -> None:
        self.password_hash = password_hash

    def mark_email_verified(self) -> None:
        self.is_email_verified = True

    def bump_token_version(self) -> None:
        self.token_version += 1

    def extra_claims(self) -> dict[str, Any]:
        return self.claims or {}


class UserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    async def find_by_email(self, email: str) -> User | None:
        return next((user for user in self._users.values() if user.email == email), None)

    async def find_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    async def save(self, user: User) -> User:
        self._users[user.id] = user
        return user


class RegistrationBuilder:
    """Host provisioner: hashes the password and creates the account."""

    def __init__(self, store: UserStore, hasher: BcryptPasswordHasher) -> None:
        self._store = store
        self._hasher = hasher

    async def create_user(self, data: RegistrationData, *, replacing: User | None) -> User | None:
        if replacing is not None:
            return replacing
        user = User(id=f"user-{len(self._store._users) + 1}", email=data.email)
        user.set_password_hash(await self._hasher.hash(data.password))
        await self._store.save(user)
        return user


class EmailSender:
    async def send(self, to: str, subject: str, body: str) -> None:
        print(f"\n--- Email to {to}: {subject} ---\n{body}\n")


store = UserStore()
hasher = BcryptPasswordHasher()
config = AuthConfig(
    secret_key=os.environ.get("AUTH_SECRET_KEY", "dev-secret-key-0123456789-0123456789-012345"),
    audience="example",
    issuer="example",
    allow_localhost_origins=True,
)

container = AuthContainer(
    config,
    users=store,
    email_sender=EmailSender(),
    registration_builder=RegistrationBuilder(store, hasher),
    password_hasher=hasher,
)

app = FastAPI()
install(app, container)
app.include_router(build_auth_router(container))


@app.get("/me")
async def me(ctx: Annotated[RequestContext, Depends(get_request_context)]) -> dict[str, str]:
    return {"user_id": ctx.user_id, "role": ctx.role}
