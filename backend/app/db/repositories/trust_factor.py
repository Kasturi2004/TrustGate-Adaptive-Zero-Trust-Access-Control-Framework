"""Append-only persistence queries for trust evaluation factors."""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.trust_factor import TrustFactor


class TrustFactorRepository:
    """Read and insert trust factors using a caller-owned async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_by_evaluation(self, evaluation_id: UUID) -> list[TrustFactor]:
        """Return factors for an evaluation in stable name and ID order."""
        statement = (
            select(TrustFactor)
            .where(TrustFactor.trust_evaluation_id == evaluation_id)
            .order_by(TrustFactor.factor_name, TrustFactor.id)
        )
        result = await self._session.scalars(statement)
        return list(result.all())

    def add_many(self, trust_factors: Sequence[TrustFactor]) -> None:
        """Stage multiple factors without committing the transaction."""
        self._session.add_all(trust_factors)
