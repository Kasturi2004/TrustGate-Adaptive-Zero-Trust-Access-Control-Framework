"""Append-only persistence queries for trust evaluations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.trust_evaluation import TrustEvaluation


class TrustEvaluationRepository:
    """Read and insert trust evaluations using a caller-owned session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, evaluation_id: UUID) -> TrustEvaluation | None:
        """Return an evaluation by its ID."""
        return await self._session.get(TrustEvaluation, evaluation_id)

    async def get_by_access_request(self, access_request_id: UUID) -> TrustEvaluation | None:
        """Return the evaluation associated with an access request, if present."""
        statement = select(TrustEvaluation).where(
            TrustEvaluation.access_request_id == access_request_id
        )
        result = await self._session.scalars(statement)
        return result.first()

    def add(self, trust_evaluation: TrustEvaluation) -> None:
        """Stage an evaluation without committing the transaction."""
        self._session.add(trust_evaluation)
