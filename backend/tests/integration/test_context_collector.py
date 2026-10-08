"""PostgreSQL proof that a collected snapshot persists through the gateway."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

import app.services.access_gateway as gateway_service
import pytest
from app.api.deps import AuthenticatedPrincipal
from app.core.clock import FixedClock
from app.core.config import Settings
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.schemas.policy import PolicyDecisionResult, PolicyThresholds
from app.services.access_gateway import (
    CompletePipelineResult,
    DeviceResult,
    PipelineResult,
    TrustFactorResult,
    access_gateway,
)
from app.services.context.collector import ContextSnapshot
from app.services.context.device_familiarity import device_token_hash
from app.services.context.location import GeoRegion
from app.services.policy_engine import evaluate_policy as evaluate_policy_engine
from app.services.protected_resource import get_protected_resource
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.types import Scope

from tests.integration.database import ScratchDatabase

_TOKEN = "integration-only-device-token"
_DEVICE_SECRET = "integration-only-device-hash-secret"
_NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class StubGeoResolver:
    def resolve(self, address: IPv4Address | IPv6Address) -> GeoRegion:
        del address
        return GeoRegion("US", "CA")


def _request() -> Request:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/access/evaluate",
        "raw_path": b"/access/evaluate",
        "query_string": b"",
        "headers": [
            (b"x-device-token", _TOKEN.encode()),
            (b"user-agent", _USER_AGENT.encode()),
            (b"authorization", b"Bearer integration-jwt-not-for-storage"),
        ],
        "client": ("8.8.8.8", 44321),
        "server": ("trustgate.test", 443),
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    return Request(scope, receive)


class CollectorPipeline:
    def __init__(self, policy_version_id: UUID, risk_classification: str = "MEDIUM") -> None:
        self.policy_version_id = policy_version_id
        self.risk_classification = risk_classification
        self.snapshot: ContextSnapshot | None = None
        self.result: CompletePipelineResult | None = None

    async def run(
        self,
        *,
        principal: AuthenticatedPrincipal,
        resource: object,
        device_token: str,
        client_ip: str,
        user_agent: str | None,
        context_snapshot: ContextSnapshot | None = None,
    ) -> PipelineResult:
        del principal, resource, device_token, client_ip, user_agent
        assert context_snapshot is not None
        self.snapshot = context_snapshot
        self.result = _result(
            context_snapshot,
            self.policy_version_id,
            risk_classification=self.risk_classification,
        )
        return self.result


def _result(
    snapshot: ContextSnapshot,
    policy_version_id: UUID,
    *,
    risk_classification: str = "MEDIUM",
) -> CompletePipelineResult:
    return CompletePipelineResult(
        device=DeviceResult(
            device_hash=device_token_hash(
                _TOKEN,
                settings=Settings(
                    app_env="test",
                    cors_allowed_origin="http://localhost:5173",
                    device_hash_secret=_DEVICE_SECRET,
                ),
            )
            or "unavailable",
            last_user_agent_family=snapshot.device_health.browser_family,
            last_user_agent_version=snapshot.device_health.browser_version,
        ),
        context=snapshot,
        policy_version_id=policy_version_id,
        trust_score=Decimal("50.00"),
        risk_classification=risk_classification,  # type: ignore[arg-type]
        factors=(
            TrustFactorResult(
                "device_familiarity",
                snapshot.device_familiarity_raw,
                Decimal("50"),
                Decimal("0.350"),
                Decimal("17.500"),
            ),
            TrustFactorResult(
                "device_health",
                snapshot.device_health_raw,
                Decimal("50"),
                Decimal("0.300"),
                Decimal("15.000"),
            ),
            TrustFactorResult(
                "location_normality",
                snapshot.location_raw,
                Decimal("50"),
                Decimal("0.200"),
                Decimal("10.000"),
            ),
            TrustFactorResult(
                "time_normality",
                snapshot.time_raw,
                Decimal("50"),
                Decimal("0.150"),
                Decimal("7.500"),
            ),
        ),
        decision="ALLOW",
        decision_reason="integration test pipeline result",
        explanation="Synthetic result generated only by the integration test pipeline.",
    )


def test_context_snapshot_is_persisted_by_gateway_in_its_single_transaction(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_calls: list[tuple[Decimal, PolicyThresholds, PolicyDecisionResult]] = []
    original_evaluate_policy = evaluate_policy_engine

    def observe_policy_evaluation(
        score: Decimal, thresholds: PolicyThresholds
    ) -> PolicyDecisionResult:
        result = original_evaluate_policy(score, thresholds)
        policy_calls.append((score, thresholds, result))
        return result

    monkeypatch.setitem(gateway_service.__dict__, "evaluate_policy", observe_policy_evaluation)
    user_id = uuid4()
    device_id = uuid4()
    device_hash = device_token_hash(
        _TOKEN,
        settings=Settings(
            app_env="test",
            cors_allowed_origin="http://localhost:5173",
            device_hash_secret=_DEVICE_SECRET,
        ),
    )
    assert device_hash is not None

    async def exercise(session: AsyncSession) -> None:
        await session.execute(
            text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
            {"id": user_id, "email": f"context-{user_id}@integration.test"},
        )
        profile = await session.get(Profile, user_id)
        assert profile is not None
        device = Device(
            id=device_id,
            user_id=user_id,
            device_hash=device_hash,
            recognized_at=_NOW - timedelta(days=2),
            first_seen_at=_NOW - timedelta(days=2),
            last_seen_at=_NOW - timedelta(days=1),
        )
        session.add(device)
        await session.flush()
        session.add_all(
            [
                AccessRequest(
                    id=uuid4(),
                    user_id=user_id,
                    device_id=device_id,
                    source_ip=IPv4Address("8.8.8.8"),
                    initial_decision="ALLOW",
                    final_outcome="ALLOW",
                    resolved_region="US-CA",
                    requested_at=_NOW - timedelta(days=index + 1),
                )
                for index in range(9)
            ]
        )
        await session.flush()
        active_policy = await session.scalar(
            select(PolicyVersion).where(
                PolicyVersion.version_label == "POL-1.0", PolicyVersion.is_active.is_(True)
            )
        )
        assert active_policy is not None
        active_policy_id = active_policy.id
        active_allow_threshold = active_policy.allow_threshold
        active_stepup_threshold = active_policy.stepup_threshold
        pipeline = CollectorPipeline(active_policy_id, risk_classification="HIGH")
        result = await access_gateway(
            session=session,
            principal=AuthenticatedPrincipal(user_id, profile.email, "USER", UUID(int=1)),
            resource=get_protected_resource("ops-dashboard"),
            device_token=_TOKEN,
            client_ip="8.8.8.8",
            user_agent=_USER_AGENT,
            pipeline=pipeline,
            clock=FixedClock(_NOW),
            request=_request(),
            profile=profile,
            geo_resolver=StubGeoResolver(),
            settings=Settings(
                app_env="test",
                cors_allowed_origin="http://localhost:5173",
                device_hash_secret=_DEVICE_SECRET,
            ),
        )
        snapshot = pipeline.snapshot
        assert snapshot is not None
        assert pipeline.result is not None
        assert pipeline.result.risk_classification == "HIGH"

        request = await session.scalar(
            select(AccessRequest).where(
                AccessRequest.user_id == user_id,
                AccessRequest.requested_at == _NOW,
            )
        )
        assert request is not None
        assert request.resolved_region == "US-CA"
        signal = await session.scalar(
            select(ContextSignal).where(ContextSignal.access_request_id == request.id)
        )
        evaluation = await session.scalar(
            select(TrustEvaluation).where(TrustEvaluation.access_request_id == request.id)
        )
        assert signal is not None
        assert evaluation is not None
        assert signal.device_familiarity_raw == "known_device"
        assert signal.device_health_raw == "healthy"
        assert signal.location_raw == "expected_region"
        assert signal.time_raw == "within_normal_window"
        assert signal.raw_context == dict(snapshot.raw_context)
        assert signal.captured_at == _NOW
        assert result.decision == "ALLOW"
        assert request.initial_decision == "ALLOW"
        assert evaluation.policy_version_id == active_policy_id
        assert evaluation.trust_score == Decimal("100.00")
        assert evaluation.risk_classification == "LOW"
        assert len(policy_calls) == 1
        evaluated_score, thresholds, decision_result = policy_calls[0]
        assert evaluated_score == evaluation.trust_score
        assert thresholds == PolicyThresholds(
            allow_threshold=active_allow_threshold,
            stepup_threshold=active_stepup_threshold,
        )
        policy_decision = await session.scalar(
            select(PolicyDecision).where(PolicyDecision.access_request_id == request.id)
        )
        assert policy_decision is not None
        assert decision_result.decision == "ALLOW"
        assert policy_decision.decision == decision_result.decision
        assert policy_decision.decision_reason == decision_result.decision_reason
        assert policy_decision.trust_evaluation_id == evaluation.id
        assert policy_decision.policy_version_id == active_policy_id
        assert policy_decision.access_request_id == request.id
        assert request.initial_decision == decision_result.decision
        assert request.mfa_required is False
        access_events = list(
            (
                await session.scalars(
                    select(SecurityEvent).where(
                        SecurityEvent.access_request_id == request.id,
                        SecurityEvent.event_type.in_(
                            ("ACCESS_REQUEST_SUBMITTED", "ACCESS_ALLOWED")
                        ),
                    )
                )
            ).all()
        )
        assert len(access_events) == 2
        assert {event.event_type: event.risk_category for event in access_events} == {
            "ACCESS_REQUEST_SUBMITTED": "LOW",
            "ACCESS_ALLOWED": "LOW",
        }
        factors = list(
            (
                await session.scalars(
                    select(TrustFactor).where(TrustFactor.trust_evaluation_id == evaluation.id)
                )
            ).all()
        )
        assert len(factors) == 4
        factor_rows = {factor.factor_name: factor for factor in factors}
        assert set(factor_rows) == {
            "device_familiarity",
            "device_health",
            "location_normality",
            "time_normality",
        }
        assert {name: factor.weighted_contribution for name, factor in factor_rows.items()} == {
            "device_familiarity": Decimal("35.000"),
            "device_health": Decimal("30.000"),
            "location_normality": Decimal("20.000"),
            "time_normality": Decimal("15.000"),
        }
        assert (
            await session.scalar(
                select(func.count()).select_from(Device).where(Device.user_id == user_id)
            )
            == 1
        )
        await session.refresh(device)
        assert device.recognized_at == _NOW - timedelta(days=2)
        assert _TOKEN not in repr(signal.raw_context)
        assert "integration-jwt-not-for-storage" not in repr(signal.raw_context)

    migrated_test_database.run_in_transaction(exercise)


def test_repeated_device_identifier_reuses_user_scoped_unrecognized_device(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_a_id = uuid4()
    user_b_id = uuid4()
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        device_hash_secret=_DEVICE_SECRET,
    )

    async def exercise(session: AsyncSession) -> None:
        for user_id in (user_a_id, user_b_id):
            await session.execute(
                text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
                {"id": user_id, "email": f"stable-device-{user_id}@integration.test"},
            )

        policy = await session.scalar(
            select(PolicyVersion).where(PolicyVersion.is_active.is_(True))
        )
        assert policy is not None
        policy_id = policy.id
        profiles = [await session.get(Profile, user_id) for user_id in (user_a_id, user_b_id)]
        assert profiles[0] is not None
        assert profiles[1] is not None
        emails = {user_a_id: profiles[0].email, user_b_id: profiles[1].email}

        observations: list[tuple[UUID, UUID, str, datetime | None]] = []
        for user_id in (user_a_id, user_a_id, user_b_id):
            profile = await session.get(Profile, user_id)
            assert profile is not None
            pipeline = CollectorPipeline(policy_id)
            response = await access_gateway(
                session=session,
                principal=AuthenticatedPrincipal(user_id, emails[user_id], "USER", UUID(int=1)),
                resource=get_protected_resource("ops-dashboard"),
                device_token=_TOKEN,
                client_ip="8.8.8.8",
                user_agent=_USER_AGENT,
                pipeline=pipeline,
                clock=FixedClock(_NOW),
                request=_request(),
                profile=profile,
                geo_resolver=StubGeoResolver(),
                settings=settings,
            )

            assert response.access_request_id is not None
            request = await session.get(AccessRequest, response.access_request_id)
            assert request is not None
            device = await session.get(Device, request.device_id)
            assert device is not None
            assert pipeline.snapshot is not None
            assert pipeline.snapshot.device_familiarity_raw == "unknown_device"
            observations.append((user_id, device.id, device.device_hash, device.recognized_at))

            context_signal = await session.scalar(
                select(ContextSignal).where(
                    ContextSignal.access_request_id == response.access_request_id
                )
            )
            assert context_signal is not None
            assert context_signal.device_familiarity_raw == "unknown_device"
            assert _TOKEN not in repr(context_signal.raw_context)

        expected_hash = device_token_hash(_TOKEN, settings=settings)
        assert expected_hash is not None
        first_user_requests = observations[:2]
        second_user_request = observations[2]
        assert first_user_requests[0][1] == first_user_requests[1][1]
        assert first_user_requests[0][2] == first_user_requests[1][2] == expected_hash
        assert first_user_requests[0][3] is None
        assert first_user_requests[1][3] is None
        assert second_user_request[0] == user_b_id
        assert second_user_request[1] != first_user_requests[0][1]
        assert second_user_request[2] == expected_hash
        assert second_user_request[3] is None
        assert _TOKEN not in repr([item[2] for item in observations])

        device_rows = list(
            (
                await session.scalars(
                    select(Device).where(Device.user_id.in_((user_a_id, user_b_id)))
                )
            ).all()
        )
        assert len(device_rows) == 2
        assert {row.user_id for row in device_rows} == {user_a_id, user_b_id}

    migrated_test_database.run_in_transaction(exercise)
