"""Append-only persistence queries for policy decisions."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.policy_decision import PolicyDecision


class PolicyDecisionRepository:
    """Read and insert policy decisions using a caller-owned session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_access_request(self, access_request_id: UUID) -> PolicyDecision | None:
        """Return the request's decision, newest first with stable ID tie-breaking."""
        statement = (
            select(PolicyDecision)
            .where(PolicyDecision.access_request_id == access_request_id)
            .order_by(PolicyDecision.decided_at.desc(), PolicyDecision.id)
        )
        result = await self._session.scalars(statement)
        return result.first()

    def add(self, policy_decision: PolicyDecision) -> None:
        """Stage a policy decision without committing the transaction."""
        self._session.add(policy_decision)
