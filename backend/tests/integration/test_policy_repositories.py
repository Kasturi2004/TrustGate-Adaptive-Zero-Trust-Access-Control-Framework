"""Real PostgreSQL round trips for policy repositories."""

from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import IPv4Address
from uuid import uuid4

from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.repositories.policy_decision import PolicyDecisionRepository
from app.db.repositories.policy_version import PolicyVersionRepository
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

_CREATED_AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def test_policy_version_repository_reads_seeded_pol_1_0(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        repository = PolicyVersionRepository(session)

        active = await repository.get_active()
        by_label = await repository.get_by_label("POL-1.0")

        assert active is not None
        assert active.version_label == "POL-1.0"
        assert active.is_active is True
        assert active.weights_json == {
            "device_familiarity": 0.35,
            "device_health": 0.30,
            "location_normality": 0.20,
            "time_normality": 0.15,
        }
        assert active.allow_threshold == Decimal("70.00")
        assert active.stepup_threshold == Decimal("40.00")
        assert by_label is not None
        assert by_label.id == active.id
        assert await repository.get_by_label("NONEXISTENT-POLICY-LABEL") is None

    migrated_test_database.run_in_transaction(exercise)


def test_policy_decision_repository_persists_and_reads_by_access_request(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id = uuid4()
        await session.execute(
            text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
            {"id": user_id, "email": f"policy-decision-{user_id}@integration.test"},
        )

        device = Device(
            id=uuid4(),
            user_id=user_id,
            device_hash=f"policy-decision-device-{user_id}",
            first_seen_at=_CREATED_AT,
            last_seen_at=_CREATED_AT,
        )
        session.add(device)
        await session.flush()

        access_request = AccessRequest(
            id=uuid4(),
            user_id=user_id,
            device_id=device.id,
            source_ip=IPv4Address("192.0.2.40"),
            initial_decision="ALLOW",
            requested_at=_CREATED_AT,
        )
        session.add(access_request)
        await session.flush()

        policy_version = await session.scalar(
            select(PolicyVersion).where(PolicyVersion.version_label == "POL-1.0")
        )
        assert policy_version is not None
        evaluation = TrustEvaluation(
            id=uuid4(),
            access_request_id=access_request.id,
            policy_version_id=policy_version.id,
            trust_score=Decimal("88.25"),
            risk_classification="LOW",
            status="COMPLETE",
            evaluated_at=_CREATED_AT,
        )
        session.add(evaluation)
        await session.flush()

        decision = PolicyDecision(
            id=uuid4(),
            access_request_id=access_request.id,
            trust_evaluation_id=evaluation.id,
            policy_version_id=policy_version.id,
            decision="ALLOW",
            decision_reason="integration round-trip",
            decided_at=_CREATED_AT,
        )
        repository = PolicyDecisionRepository(session)
        repository.add(decision)
        await session.flush()

        found = await repository.get_by_access_request(access_request.id)

        assert found is not None
        assert found.id == decision.id
        assert found.access_request_id == access_request.id
        assert found.trust_evaluation_id == evaluation.id
        assert found.policy_version_id == policy_version.id
        assert found.decision == "ALLOW"
        assert found.decision_reason == "integration round-trip"
        assert found.decided_at == _CREATED_AT

    migrated_test_database.run_in_transaction(exercise)
