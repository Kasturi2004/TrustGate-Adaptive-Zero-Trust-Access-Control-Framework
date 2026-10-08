"""PostgreSQL integration tests for atomic trust evaluation persistence."""

from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pytest
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.policy_version import PolicyVersion
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from app.schemas.trust import TrustSignals, TrustWeights
from app.services.trust_engine import evaluate
from app.services.trust_persistence import persist_trust_evaluation
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

_NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
_WEIGHTS = TrustWeights(
    device_familiarity=Decimal("0.350"),
    device_health=Decimal("0.300"),
    location_normality=Decimal("0.200"),
    time_normality=Decimal("0.150"),
)
_RESULT = evaluate(
    TrustSignals(
        device_familiarity_raw="known_device",
        device_health_raw="partially_healthy",
        location_raw="new_region",
        time_raw="outside_normal_window",
    ),
    _WEIGHTS,
)


async def _create_access_request(session: AsyncSession) -> tuple[AccessRequest, UUID]:
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"trust-persistence-{user_id}@integration.test"},
    )
    device = Device(
        id=uuid4(),
        user_id=user_id,
        device_hash=f"trust-persistence-device-{user_id}",
        first_seen_at=_NOW,
        last_seen_at=_NOW,
    )
    session.add(device)
    await session.flush()

    request = AccessRequest(
        id=uuid4(),
        user_id=user_id,
        device_id=device.id,
        source_ip=IPv4Address("192.0.2.35"),
        initial_decision="STEP_UP",
        mfa_required=True,
        requested_at=_NOW,
    )
    AccessRequestRepository(session).add(request)
    await session.flush()

    policy_id = await session.scalar(
        select(PolicyVersion.id).where(PolicyVersion.version_label == "POL-1.0")
    )
    assert policy_id is not None
    return request, policy_id


def test_trust_evaluation_persists_with_exactly_four_linked_decimal_factors(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        access_request, policy_id = await _create_access_request(session)

        evaluation = await persist_trust_evaluation(
            session,
            result=_RESULT,
            access_request_id=access_request.id,
            policy_version_id=policy_id,
            evaluated_at=_NOW,
        )

        found_evaluation = await TrustEvaluationRepository(session).get_by_access_request(
            access_request.id
        )
        factors = await TrustFactorRepository(session).list_by_evaluation(evaluation.id)

        assert found_evaluation is not None
        assert found_evaluation.id == evaluation.id
        assert found_evaluation.access_request_id == access_request.id
        assert found_evaluation.policy_version_id == policy_id
        assert found_evaluation.trust_score == Decimal("65.50")
        assert found_evaluation.risk_classification == "MEDIUM"
        assert found_evaluation.status == "COMPLETE"
        assert found_evaluation.evaluated_at == _NOW
        assert len(factors) == 4
        assert {factor.factor_name for factor in factors} == {
            "device_familiarity",
            "device_health",
            "location_normality",
            "time_normality",
        }
        assert all(factor.trust_evaluation_id == evaluation.id for factor in factors)
        by_name = {factor.factor_name: factor for factor in factors}
        expected = {
            "device_familiarity": (
                "known_device",
                Decimal("100.00"),
                Decimal("0.350"),
                Decimal("35.000"),
            ),
            "device_health": (
                "partially_healthy",
                Decimal("60.00"),
                Decimal("0.300"),
                Decimal("18.000"),
            ),
            "location_normality": (
                "new_region",
                Decimal("40.00"),
                Decimal("0.200"),
                Decimal("8.000"),
            ),
            "time_normality": (
                "outside_normal_window",
                Decimal("30.00"),
                Decimal("0.150"),
                Decimal("4.500"),
            ),
        }
        for name, values in expected.items():
            factor = by_name[name]
            assert factor.raw_value == values[0]
            assert factor.normalized_score == values[1]
            assert factor.weight == values[2]
            assert factor.weighted_contribution == values[3]

    migrated_test_database.run_in_transaction(exercise)


def test_factor_insert_failure_rolls_back_evaluation_and_all_factors(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        access_request, policy_id = await _create_access_request(session)
        invalid_result = _RESULT.model_copy(
            update={
                "factors": (
                    _RESULT.factors[0].model_copy(update={"normalized_score": Decimal("101")}),
                    *_RESULT.factors[1:],
                )
            }
        )

        with pytest.raises(IntegrityError):
            await persist_trust_evaluation(
                session,
                result=invalid_result,
                access_request_id=access_request.id,
                policy_version_id=policy_id,
                evaluated_at=_NOW,
            )

        assert (
            await session.scalar(
                select(func.count())
                .select_from(TrustEvaluation)
                .where(TrustEvaluation.access_request_id == access_request.id)
            )
            == 0
        )
        assert (
            await session.scalar(
                select(func.count())
                .select_from(TrustFactor)
                .join(TrustEvaluation)
                .where(TrustEvaluation.access_request_id == access_request.id)
            )
            == 0
        )

    migrated_test_database.run_in_transaction(exercise)
