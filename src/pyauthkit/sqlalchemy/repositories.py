"""SQLAlchemy-backed store adapters.

Each adapter takes an :class:`~sqlalchemy.ext.asyncio.async_sessionmaker` so it can open its
own short transaction per call — safe to share across requests and instances.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import cast

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from pyauthkit.codes import OneTimeCode
from pyauthkit.lockout import LockoutState
from pyauthkit.sqlalchemy.models import (
    AccountLockoutModel,
    PasswordResetCodeModel,
    RevokedRefreshTokenModel,
    VerificationCodeModel,
)

CodeModel = VerificationCodeModel | PasswordResetCodeModel
SessionFactory = async_sessionmaker[AsyncSession]


def _to_code(row: CodeModel) -> OneTimeCode:
    return OneTimeCode(
        id=str(row.id),
        user_id=row.user_id,
        code_hash=row.code_hash,
        expires_at=row.expires_at,
        attempt_count=row.attempt_count,
        used_at=row.used_at,
        created_at=row.created_at,
    )


class SqlCodeStore:
    """One-time code store backed by a Postgres table.

    Pass ``model=VerificationCodeModel`` (verification codes) or
    ``model=PasswordResetCodeModel`` (reset codes).
    """

    def __init__(
        self,
        session_factory: SessionFactory,
        model: type[VerificationCodeModel] | type[PasswordResetCodeModel] = VerificationCodeModel,
    ) -> None:
        self._session_factory = session_factory
        self._model = model

    async def create(self, code: OneTimeCode) -> OneTimeCode:
        async with self._session_factory() as session:
            row = self._model(
                id=uuid.UUID(code.id),
                user_id=code.user_id,
                code_hash=code.code_hash,
                expires_at=code.expires_at,
                attempt_count=code.attempt_count,
                used_at=code.used_at,
                created_at=code.created_at or datetime.now(timezone.utc),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return _to_code(row)

    async def find_latest_active(self, user_id: str) -> OneTimeCode | None:
        async with self._session_factory() as session:
            stmt = (
                select(self._model)
                .where(
                    self._model.user_id == user_id,
                    self._model.used_at.is_(None),
                    self._model.expires_at > datetime.now(timezone.utc),
                )
                .order_by(self._model.created_at.desc())
                .limit(1)
            )
            row = (await session.execute(stmt)).scalars().first()
            return _to_code(cast("CodeModel", row)) if row is not None else None

    async def count_created_since(self, user_id: str, since: datetime) -> int:
        async with self._session_factory() as session:
            stmt = select(func.count()).where(self._model.user_id == user_id, self._model.created_at >= since)
            return int((await session.execute(stmt)).scalar_one())

    async def save(self, code: OneTimeCode) -> None:
        async with self._session_factory() as session:
            stmt = (
                update(self._model)
                .where(self._model.id == uuid.UUID(code.id))
                .values(attempt_count=code.attempt_count, used_at=code.used_at)
            )
            await session.execute(stmt)
            await session.commit()

    async def invalidate_active(self, user_id: str) -> None:
        async with self._session_factory() as session:
            stmt = (
                update(self._model)
                .where(
                    self._model.user_id == user_id,
                    self._model.used_at.is_(None),
                    self._model.expires_at > datetime.now(timezone.utc),
                )
                .values(used_at=datetime.now(timezone.utc))
            )
            await session.execute(stmt)
            await session.commit()


class SqlLockoutStore:
    """Account lockout store backed by a Postgres table."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def get(self, identifier: str) -> LockoutState | None:
        async with self._session_factory() as session:
            row = await session.get(AccountLockoutModel, identifier)
            if row is None:
                return None
            return LockoutState(
                failed_attempts=row.failed_attempts, locked_until=row.locked_until, last_attempt=row.last_attempt
            )

    async def save(self, identifier: str, state: LockoutState) -> None:
        async with self._session_factory() as session:
            await session.merge(
                AccountLockoutModel(
                    identifier=identifier,
                    failed_attempts=state.failed_attempts,
                    locked_until=state.locked_until,
                    last_attempt=state.last_attempt,
                )
            )
            await session.commit()

    async def delete(self, identifier: str) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(AccountLockoutModel).where(AccountLockoutModel.identifier == identifier))
            await session.commit()

    async def list_all(self) -> dict[str, LockoutState]:
        async with self._session_factory() as session:
            rows = (await session.execute(select(AccountLockoutModel))).scalars().all()
            return {
                row.identifier: LockoutState(
                    failed_attempts=row.failed_attempts, locked_until=row.locked_until, last_attempt=row.last_attempt
                )
                for row in rows
            }


class SqlRevocationStore:
    """Revoked-token store backed by a Postgres table."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def add(self, token_hash: str, expires_at: datetime) -> bool:
        async with self._session_factory() as session:
            stmt = (
                pg_insert(RevokedRefreshTokenModel)
                .values(token_hash=token_hash, expires_at=expires_at)
                .on_conflict_do_nothing(index_elements=["token_hash"])
            )
            result = await session.execute(stmt)
            await session.commit()
            return bool(result.rowcount > 0)

    async def contains(self, token_hash: str) -> bool:
        async with self._session_factory() as session:
            row = await session.get(RevokedRefreshTokenModel, token_hash)
            return row is not None

    async def clear_all(self) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(RevokedRefreshTokenModel))
            await session.commit()

    async def count(self) -> int:
        async with self._session_factory() as session:
            return int((await session.execute(select(func.count()).select_from(RevokedRefreshTokenModel))).scalar_one())


__all__ = ["SqlCodeStore", "SqlLockoutStore", "SqlRevocationStore"]
