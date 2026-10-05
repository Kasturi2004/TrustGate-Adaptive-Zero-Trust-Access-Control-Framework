"""Persistence queries and outcome updates for access requests."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.access_request import AccessRequest


class AccessRequestRepository:
    """Manage access requests using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, access_request_id: UUID) -> AccessRequest | None:
        """Return an access request by its ID."""
        return await self._session.get(AccessRequest, access_request_id)

    async def list_by_user(self, user_id: UUID) -> list[AccessRequest]:
        """Return a user's requests newest first with stable ID tie-breaking."""
        statement = (
            select(AccessRequest)
            .where(AccessRequest.user_id == user_id)
            .order_by(AccessRequest.requested_at.desc(), AccessRequest.id)
        )
        result = await self._session.scalars(statement)
        return list(result.all())

    def add(self, access_request: AccessRequest) -> None:
        """Stage an access request without committing the transaction."""
        self._session.add(access_request)

    async def set_final_outcome(
        self, access_request_id: UUID, outcome: str
    ) -> AccessRequest | None:
        """Set only final_outcome, returning None if the request does not exist."""
        access_request = await self.get_by_id(access_request_id)
        if access_request is None:
            return None
        access_request.final_outcome = outcome
        return access_request

    async def resolve_step_up(
        self,
        access_request_id: UUID,
        user_id: UUID,
        resolved_at: datetime,
    ) -> AccessRequest | None:
        """Atomically resolve one still-pending MFA STEP_UP request to ALLOW."""
        statement = (
            update(AccessRequest)
            .where(
                AccessRequest.id == access_request_id,
                AccessRequest.user_id == user_id,
                AccessRequest.initial_decision == "STEP_UP",
                AccessRequest.mfa_required.is_(True),
                AccessRequest.final_outcome.is_(None),
                AccessRequest.resolved_at.is_(None),
            )
            .values(final_outcome="ALLOW", resolved_at=resolved_at)
            .returning(AccessRequest)
        )
        result = await self._session.scalars(
            statement,
            execution_options={"populate_existing": True},
        )
        return result.first()
