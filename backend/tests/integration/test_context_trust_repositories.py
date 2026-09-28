"""Real PostgreSQL round trips for context and trust repositories."""

from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pytest
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.policy_version import PolicyVersion
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.repositories.context_signal import ContextSignalRepository
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

_CREATED_AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


async def _create_access_request(session: AsyncSession) -> AccessRequest:
    """Create only auth/profile, device, and request prerequisites for a test."""
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"context-trust-{user_id}@integration.test"},
    )
    device = Device(
        id=uuid4(),
        user_id=user_id,
        device_hash=f"context-trust-device-{user_id}",
        first_seen_at=_CREATED_AT,
        last_seen_at=_CREATED_AT,
    )
    session.add(device)
    await session.flush()

    access_request = AccessRequest(
        id=uuid4(),
        user_id=user_id,
        device_id=device.id,
        source_ip=IPv4Address("192.0.2.25"),
        initial_decision="STEP_UP",
        mfa_required=True,
        requested_at=_CREATED_AT,
    )
    session.add(access_request)
    await session.flush()
    return access_request


async def _active_policy_version_id(session: AsyncSession) -> UUID:
    policy = await session.scalar(
        select(PolicyVersion).where(PolicyVersion.version_label == "POL-1.0")
    )
    assert policy is not None
    return policy.id


async def _create_evaluation(session: AsyncSession) -> TrustEvaluation:
    access_request = await _create_access_request(session)
    evaluation = TrustEvaluation(
        id=uuid4(),
        access_request_id=access_request.id,
        policy_version_id=await _active_policy_version_id(session),
        trust_score=Decimal("82.50"),
        risk_classification="LOW",
        status="COMPLETE",
        evaluated_at=_CREATED_AT,
    )
    session.add(evaluation)
    await session.flush()
    return evaluation


def test_context_signal_repository_persists_and_retrieves_single_signal_per_request(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        access_request = await _create_access_request(session)
        context_signal = ContextSignal(
            id=uuid4(),
            access_request_id=access_request.id,
            device_familiarity_raw="known_device",
            device_health_raw="healthy",
            location_raw="expected_region",
            time_raw="within_normal_window",
            raw_context={"fixture": "integration"},
            captured_at=_CREATED_AT,
        )
        repository = ContextSignalRepository(session)
        repository.add(context_signal)
        await session.flush()

        found = await repository.get_by_access_request(access_request.id)
        assert found is not None
        assert found.id == context_signal.id
        assert found.access_request_id == access_request.id
        assert found.device_familiarity_raw == "known_device"
        assert found.device_health_raw == "healthy"
        assert found.location_raw == "expected_region"
        assert found.time_raw == "within_normal_window"
        assert found.raw_context == {"fixture": "integration"}
        assert found.captured_at == _CREATED_AT

        duplicate = ContextSignal(
            id=uuid4(),
            access_request_id=access_request.id,
            device_familiarity_raw="unknown_device",
            device_health_raw="healthy",
            location_raw="expected_region",
            time_raw="within_normal_window",
            raw_context={},
            captured_at=_CREATED_AT,
        )
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                repository.add(duplicate)
                await session.flush()

        # The model's unique access_request_id permits only one signal per request.
        assert await repository.get_by_access_request(access_request.id) is found

    migrated_test_database.run_in_transaction(exercise)


def test_trust_evaluation_repository_round_trips_by_id_and_access_request(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        access_request = await _create_access_request(session)
        policy_version_id = await _active_policy_version_id(session)
        evaluation = TrustEvaluation(
            id=uuid4(),
            access_request_id=access_request.id,
            policy_version_id=policy_version_id,
            trust_score=Decimal("82.50"),
            risk_classification="LOW",
            status="COMPLETE",
            evaluated_at=_CREATED_AT,
        )
        repository = TrustEvaluationRepository(session)
        repository.add(evaluation)
        await session.flush()

        by_id = await repository.get_by_id(evaluation.id)
        by_request = await repository.get_by_access_request(access_request.id)

        assert by_id is not None
        assert by_id.id == evaluation.id
        assert by_id.access_request_id == access_request.id
        assert by_id.policy_version_id == policy_version_id
        assert by_id.trust_score == Decimal("82.50")
        assert by_id.risk_classification == "LOW"
        assert by_id.status == "COMPLETE"
        assert by_id.evaluated_at == _CREATED_AT
        assert by_request is not None
        assert by_request.id == evaluation.id

    migrated_test_database.run_in_transaction(exercise)


def test_trust_factor_repository_persists_many_and_returns_stable_order(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        evaluation = await _create_evaluation(session)
        factors = [
            TrustFactor(
                id=uuid4(),
                trust_evaluation_id=evaluation.id,
                factor_name="time_normality",
                raw_value="within_normal_window",
                normalized_score=Decimal("90.00"),
                weight=Decimal("0.150"),
                weighted_contribution=Decimal("13.500"),
            ),
            TrustFactor(
                id=uuid4(),
                trust_evaluation_id=evaluation.id,
                factor_name="device_health",
                raw_value="healthy",
                normalized_score=Decimal("80.00"),
                weight=Decimal("0.300"),
                weighted_contribution=Decimal("24.000"),
            ),
            TrustFactor(
                id=uuid4(),
                trust_evaluation_id=evaluation.id,
                factor_name="location_normality",
                raw_value="expected_region",
                normalized_score=Decimal("85.00"),
                weight=Decimal("0.200"),
                weighted_contribution=Decimal("17.000"),
            ),
            TrustFactor(
                id=uuid4(),
                trust_evaluation_id=evaluation.id,
                factor_name="device_familiarity",
                raw_value="known_device",
                normalized_score=Decimal("90.00"),
                weight=Decimal("0.350"),
                weighted_contribution=Decimal("31.500"),
            ),
        ]
        repository = TrustFactorRepository(session)
        repository.add_many(factors)
        await session.flush()

        found = await repository.list_by_evaluation(evaluation.id)

        assert [factor.factor_name for factor in found] == [
            "device_familiarity",
            "device_health",
            "location_normality",
            "time_normality",
        ]
        assert all(factor.trust_evaluation_id == evaluation.id for factor in found)
        by_name = {factor.factor_name: factor for factor in found}
        assert by_name["device_familiarity"].raw_value == "known_device"
        assert by_name["device_familiarity"].normalized_score == Decimal("90.00")
        assert by_name["device_familiarity"].weight == Decimal("0.350")
        assert by_name["device_familiarity"].weighted_contribution == Decimal("31.500")
        assert by_name["device_health"].weighted_contribution == Decimal("24.000")
        assert by_name["location_normality"].weighted_contribution == Decimal("17.000")
        assert by_name["time_normality"].weighted_contribution == Decimal("13.500")

    migrated_test_database.run_in_transaction(exercise)
