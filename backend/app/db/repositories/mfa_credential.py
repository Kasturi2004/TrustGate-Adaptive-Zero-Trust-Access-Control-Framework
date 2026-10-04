"""Persistence access for per-profile MFA credentials."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.mfa_credential import MfaCredential
from app.db.models.profile import Profile


class MfaCredentialRepository:
    """Read and stage MFA credentials without committing a caller-owned session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_user_id(self, user_id: UUID) -> MfaCredential | None:
        """Return the credential record for a profile, if one exists."""
        return await self._session.get(MfaCredential, user_id)

    async def get_by_user_id_for_update(self, user_id: UUID) -> MfaCredential | None:
        """Lock the owning profile and credential, returning None if no credential exists.

        Locking the profile serializes first-time enrollment while no credential row
        exists. The caller owns the surrounding transaction and its completion.
        """
        profile_statement = select(Profile).where(Profile.id == user_id).with_for_update()
        profile_result = await self._session.scalars(profile_statement)
        if profile_result.first() is None:
            return None

        credential_statement = (
            select(MfaCredential).where(MfaCredential.user_id == user_id).with_for_update()
        )
        credential_result = await self._session.scalars(credential_statement)
        return credential_result.first()

    def add(self, credential: MfaCredential) -> None:
        """Stage a credential without committing the transaction."""
        self._session.add(credential)
