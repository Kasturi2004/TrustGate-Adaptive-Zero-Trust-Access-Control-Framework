"""Persistence queries for user profiles."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.profile import Profile


class ProfileRepository:
    """Read profile records using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, user_id: UUID) -> Profile | None:
        """Return a profile by its Supabase Auth user ID."""
        return await self._session.get(Profile, user_id)

    async def get_by_email(self, email: str) -> Profile | None:
        """Return the first profile matching an email address."""
        result = await self._session.scalars(select(Profile).where(Profile.email == email))
        return result.first()
