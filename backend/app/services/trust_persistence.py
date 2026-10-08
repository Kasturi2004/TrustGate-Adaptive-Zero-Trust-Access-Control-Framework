"""Persist one trust evaluation and its complete factor breakdown atomically."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from app.schemas.trust import TrustEvaluationResult
from app.services.risk_classifier import classify_risk

_EXPECTED_FACTORS = {
    "device_familiarity",
    "device_health",
    "location_normality",
    "time_normality",
}


async def persist_trust_evaluation(
    session: AsyncSession,
    *,
    result: TrustEvaluationResult,
    access_request_id: UUID,
    policy_version_id: UUID,
    evaluated_at: datetime,
) -> TrustEvaluation:
    """Stage an evaluation and exactly four factors in one savepoint.

    The caller owns the surrounding transaction and decides whether to commit
    it. If either insert/flush fails, this operation rolls back both the
    evaluation and its factors while preserving the outer transaction.
    """
    factor_names = [factor.factor_name for factor in result.factors]
    if len(factor_names) != 4 or set(factor_names) != _EXPECTED_FACTORS:
        raise ValueError("A trust evaluation must contain each of the four factors exactly once")
    if not Decimal("0") <= result.trust_score <= Decimal("100"):
        raise ValueError("Trust score must be between 0 and 100")

    evaluation = TrustEvaluation(
        id=uuid4(),
        access_request_id=access_request_id,
        policy_version_id=policy_version_id,
        trust_score=result.trust_score,
        risk_classification=classify_risk(result.trust_score),
        status="COMPLETE",
        evaluated_at=evaluated_at,
    )

    async with session.begin_nested():
        TrustEvaluationRepository(session).add(evaluation)
        await session.flush()

        TrustFactorRepository(session).add_many(
            [
                TrustFactor(
                    id=uuid4(),
                    trust_evaluation_id=evaluation.id,
                    factor_name=factor.factor_name,
                    raw_value=factor.raw_value,
                    normalized_score=factor.normalized_score,
                    weight=factor.weight,
                    weighted_contribution=factor.weighted_contribution,
                )
                for factor in result.factors
            ]
        )
        await session.flush()

    return evaluation
