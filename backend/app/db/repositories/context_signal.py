"""Append-only persistence queries for context signal snapshots."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.context_signal import ContextSignal


class ContextSignalRepository:
    """Read and insert context signals using a caller-owned session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_access_request(self, access_request_id: UUID) -> ContextSignal | None:
        """Return the context snapshot for an access request, if present."""
        statement = select(ContextSignal).where(
            ContextSignal.access_request_id == access_request_id
        )
        result = await self._session.scalars(statement)
        return result.first()

    def add(self, context_signal: ContextSignal) -> None:
        """Stage a context signal without committing the transaction."""
        self._session.add(context_signal)
