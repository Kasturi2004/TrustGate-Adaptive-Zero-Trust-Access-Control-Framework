"""PostgreSQL integration coverage for atomic rate-limit attempt consumption."""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.core.config import Settings
from app.core.rate_limit import mfa_ip_rate_limit_key, mfa_user_rate_limit_key
from app.db.models.rate_limit_state import RateLimitState
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.db.session import create_async_engine_for_url
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.integration.database import ScratchDatabase

_NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
_WINDOW = timedelta(minutes=5)
_MFA_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    rate_limit_key_secret="integration-mfa-rate-limit-secret",
)


def test_rate_limit_attempts_enforce_limit_and_reset_expired_window(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        key = f"integration:rate-limit:attempt:{uuid4()}"
        repository = RateLimitStateRepository(session)

        assert await repository.consume_attempt(key, _NOW, 5, _WINDOW) is True
        state = await repository.get_for_update(key)
        assert state is not None
        assert state.counter == 1
        assert state.window_reset_at == _NOW + _WINDOW

        for expected_counter in range(2, 6):
            assert await repository.consume_attempt(key, _NOW, 5, _WINDOW) is True
            state = await repository.get_for_update(key)
            assert state is not None
            assert state.counter == expected_counter
            assert state.window_reset_at == _NOW + _WINDOW

        assert await repository.consume_attempt(key, _NOW, 5, _WINDOW) is False
        state = await repository.get_for_update(key)
        assert state is not None
        assert state.counter == 5
        assert state.window_reset_at == _NOW + _WINDOW

        expired_state = RateLimitState(
            key=key,
            counter=5,
            window_reset_at=_NOW - timedelta(seconds=1),
            updated_at=_NOW - timedelta(minutes=6),
        )
        await repository.add_or_update(expired_state)
        assert await repository.consume_attempt(key, _NOW, 5, _WINDOW) is True

        state = await repository.get_for_update(key)
        assert state is not None
        assert state.counter == 1
        assert state.window_reset_at == _NOW + _WINDOW
        assert state.updated_at == _NOW

    migrated_test_database.run_in_transaction(exercise)


def test_mfa_user_rate_limit_concurrent_attempts_are_atomic(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise_concurrently() -> None:
        key = mfa_user_rate_limit_key(uuid4(), window="15m", settings=_MFA_SETTINGS)
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)

        async def consume() -> bool:
            async with session_factory() as session:
                async with session.begin():
                    return await RateLimitStateRepository(session).consume_attempt(
                        key, _NOW, 5, _WINDOW
                    )

        try:
            admissions = await asyncio.gather(*(consume() for _ in range(12)))
            assert sum(admissions) == 5

            async with session_factory() as session:
                state = await session.scalar(
                    select(RateLimitState).where(RateLimitState.key == key)
                )
                assert state is not None
                assert state.counter == 5
        finally:
            async with engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM public.rate_limit_state WHERE key = :key"),
                    {"key": key},
                )
            await engine.dispose()

    asyncio.run(exercise_concurrently())


def test_mfa_rate_limit_scopes_enforce_independent_thresholds(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id = uuid4()
        user_short_key = mfa_user_rate_limit_key(user_id, window="15m", settings=_MFA_SETTINGS)
        user_daily_key = mfa_user_rate_limit_key(user_id, window="24h", settings=_MFA_SETTINGS)
        ip_key = mfa_ip_rate_limit_key("192.0.2.71", settings=_MFA_SETTINGS)
        repository = RateLimitStateRepository(session)

        for attempt in range(1, 6):
            assert (
                await repository.consume_attempt(user_short_key, _NOW, 5, timedelta(minutes=15))
                is True
            )
            state = await repository.get_for_update(user_short_key)
            assert state is not None
            assert state.counter == attempt
        assert (
            await repository.consume_attempt(user_short_key, _NOW, 5, timedelta(minutes=15))
            is False
        )

        for attempt in range(1, 11):
            assert (
                await repository.consume_attempt(user_daily_key, _NOW, 10, timedelta(hours=24))
                is True
            )
            state = await repository.get_for_update(user_daily_key)
            assert state is not None
            assert state.counter == attempt
        assert (
            await repository.consume_attempt(user_daily_key, _NOW, 10, timedelta(hours=24)) is False
        )

        for attempt in range(1, 61):
            assert await repository.consume_attempt(ip_key, _NOW, 60, timedelta(minutes=15)) is True
            state = await repository.get_for_update(ip_key)
            assert state is not None
            assert state.counter == attempt
        assert await repository.consume_attempt(ip_key, _NOW, 60, timedelta(minutes=15)) is False

        assert user_short_key != user_daily_key
        assert len({user_short_key, user_daily_key, ip_key}) == 3

    migrated_test_database.run_in_transaction(exercise)
