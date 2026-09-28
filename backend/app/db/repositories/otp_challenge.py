"""Persistence queries for OTP challenges."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.otp_challenge import OtpChallenge


class OtpChallengeRepository:
    """Manage OTP challenge records using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_pending_for_update(self, access_request_id: UUID) -> OtpChallenge | None:
        """Lock and return the pending challenge for an access request, if present."""
        statement = (
            select(OtpChallenge)
            .where(
                OtpChallenge.access_request_id == access_request_id,
                OtpChallenge.status == "PENDING",
            )
            .with_for_update()
        )
        result = await self._session.scalars(statement)
        return result.first()

    def add(self, otp_challenge: OtpChallenge) -> None:
        """Stage a challenge without committing the transaction."""
        self._session.add(otp_challenge)

    async def update_status(self, otp_challenge_id: UUID, status: str) -> OtpChallenge | None:
        """Change only status, returning None if the challenge does not exist."""
        otp_challenge = await self._session.get(OtpChallenge, otp_challenge_id)
        if otp_challenge is None:
            return None
        otp_challenge.status = status
        return otp_challenge
