"""Append-only read queries for versioned policy configuration."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.policy_version import PolicyVersion


class PolicyVersionRepository:
    """Read policy versions using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_active(self) -> PolicyVersion | None:
        """Return the active policy version, if one exists."""
        statement = select(PolicyVersion).where(PolicyVersion.is_active.is_(True))
        result = await self._session.scalars(statement)
        return result.first()

    async def get_by_label(self, version_label: str) -> PolicyVersion | None:
        """Return the policy version with the requested unique label, if present."""
        statement = select(PolicyVersion).where(PolicyVersion.version_label == version_label)
        result = await self._session.scalars(statement)
        return result.first()
