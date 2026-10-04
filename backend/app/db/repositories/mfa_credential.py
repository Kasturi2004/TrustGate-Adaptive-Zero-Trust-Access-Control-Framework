"""Persistence access for per-profile MFA credentials."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.mfa_credential import MfaCredential


class MfaCredentialRepository:
    """Read and stage MFA credentials without committing a caller-owned session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_user_id(self, user_id: UUID) -> MfaCredential | None:
        """Return the credential record for a profile, if one exists."""
        return await self._session.get(MfaCredential, user_id)

    def add(self, credential: MfaCredential) -> None:
        """Stage a credential without committing the transaction."""
        self._session.add(credential)
