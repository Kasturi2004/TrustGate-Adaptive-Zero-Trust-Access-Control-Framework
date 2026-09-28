"""Append-only persistence queries for security events."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.security_event import SecurityEvent


class SecurityEventRepository:
    """Read and insert security events using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, security_event: SecurityEvent) -> None:
        """Stage a security event without committing the transaction."""
        self._session.add(security_event)

    async def list(
        self,
        *,
        event_type: str | None = None,
        actor_id: UUID | None = None,
        access_request_id: UUID | None = None,
        created_after: datetime | None = None,
        created_before: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Return matching events newest first with stable ID tie-breaking.

        Time bounds are inclusive and apply to created_at.
        """
        statement = select(SecurityEvent)
        if event_type is not None:
            statement = statement.where(SecurityEvent.event_type == event_type)
        if actor_id is not None:
            statement = statement.where(SecurityEvent.actor_id == actor_id)
        if access_request_id is not None:
            statement = statement.where(SecurityEvent.access_request_id == access_request_id)
        if created_after is not None:
            statement = statement.where(SecurityEvent.created_at >= created_after)
        if created_before is not None:
            statement = statement.where(SecurityEvent.created_at <= created_before)
        statement = statement.order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())

        result = await self._session.scalars(statement)
        return list(result.all())
