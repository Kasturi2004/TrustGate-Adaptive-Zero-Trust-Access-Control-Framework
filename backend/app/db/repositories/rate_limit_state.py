"""Persistence queries and upserts for rate-limit state."""

from datetime import datetime, timedelta

from sqlalchemy import case, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.rate_limit_state import RateLimitState


class RateLimitStateRepository:
    """Read and upsert rate-limit state using a caller-owned session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_for_update(self, key: str) -> RateLimitState | None:
        """Lock and return the row for a key, if present."""
        statement = select(RateLimitState).where(RateLimitState.key == key).with_for_update()
        result = await self._session.scalars(statement)
        return result.first()

    async def add_or_update(self, state: RateLimitState) -> None:
        """Insert or update the row identified by its primary key without committing."""
        statement = insert(RateLimitState).values(
            key=state.key,
            counter=state.counter,
            window_reset_at=state.window_reset_at,
            updated_at=state.updated_at,
        )
        upsert_statement = statement.on_conflict_do_update(
            index_elements=[RateLimitState.key],
            set_={
                "counter": statement.excluded.counter,
                "window_reset_at": statement.excluded.window_reset_at,
                "updated_at": statement.excluded.updated_at,
            },
        )
        result = await self._session.scalars(
            upsert_statement.returning(RateLimitState),
            execution_options={"populate_existing": True},
        )
        result.all()

    async def consume_attempt(
        self,
        key: str,
        current_time: datetime,
        attempt_limit: int,
        window_duration: timedelta,
    ) -> bool:
        """Atomically consume one attempt, returning whether it was admitted.

        The caller supplies the timestamp and owns the transaction. A rejected
        active window is left untouched and returns no row from PostgreSQL.
        """
        if current_time.utcoffset() is None:
            raise ValueError("current_time must be timezone-aware")
        if attempt_limit < 1:
            raise ValueError("attempt_limit must be positive")
        if window_duration <= timedelta(0):
            raise ValueError("window_duration must be positive")

        reset_at = current_time + window_duration
        expired = RateLimitState.window_reset_at <= current_time
        below_limit = RateLimitState.counter < attempt_limit

        statement = insert(RateLimitState).values(
            key=key,
            counter=1,
            window_reset_at=reset_at,
            updated_at=current_time,
        )
        upsert_statement = statement.on_conflict_do_update(
            index_elements=[RateLimitState.key],
            set_={
                "counter": case(
                    (expired, 1),
                    else_=RateLimitState.counter + 1,
                ),
                "window_reset_at": case(
                    (expired, reset_at),
                    else_=RateLimitState.window_reset_at,
                ),
                "updated_at": current_time,
            },
            where=or_(expired, below_limit),
        ).returning(RateLimitState)

        result = await self._session.scalars(
            upsert_statement,
            execution_options={"populate_existing": True},
        )
        return result.first() is not None
