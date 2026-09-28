"""Persistence queries and upsert for rate-limit state."""

from sqlalchemy import select
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
        statement = statement.on_conflict_do_update(
            index_elements=[RateLimitState.key],
            set_={
                "counter": statement.excluded.counter,
                "window_reset_at": statement.excluded.window_reset_at,
                "updated_at": statement.excluded.updated_at,
            },
        )
        result = await self._session.scalars(
            statement.returning(RateLimitState),
            execution_options={"populate_existing": True},
        )
        result.all()
