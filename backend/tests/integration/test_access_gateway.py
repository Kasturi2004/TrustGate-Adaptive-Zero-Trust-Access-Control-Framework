"""PostgreSQL integration tests for gateway persistence and rollback."""

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
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
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.trust_factor import TrustFactorRepository
from app.db.session import create_async_engine_for_url
from app.schemas.policy import PolicyDecisionResult, PolicyThresholds
from app.services.access_gateway import (
    CompletePipelineResult,
    ContextResult,
    DeviceResult,
    PipelineExecutionError,
    PipelineResult,
    TrustFactorResult,
    access_gateway,
    get_security_pipeline,
)
from app.services.context.collector import ContextSnapshot
from app.services.context.location import GeoRegion
from app.services.decision_explanation import explain_decision
from app.services.policy_engine import evaluate_policy as evaluate_policy_engine
from app.services.protected_resource import get_protected_resource
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.types import Scope

from tests.integration.database import ScratchDatabase

_NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
_RAW_DEVICE_TOKEN = "raw-device-token-must-never-persist"
_APPLICATION_MODELS = (
    Device,
    AccessRequest,
    ContextSignal,
    TrustEvaluation,
    TrustFactor,
    PolicyDecision,
)
_ALL_GATEWAY_MODELS = (*_APPLICATION_MODELS, SecurityEvent)
_GATEWAY_DEVICE_SECRET = "phase-7c-integration-device-secret"
_GATEWAY_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class GatewayGeoResolver:
    def resolve(self, address: IPv4Address | IPv6Address) -> GeoRegion:
        del address
        return GeoRegion("US", "CA")


def _context_request() -> Request:
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
            (b"x-device-token", _RAW_DEVICE_TOKEN.encode()),
            (b"user-agent", _GATEWAY_USER_AGENT.encode()),
        ],
        "client": ("8.8.8.8", 44321),
        "server": ("trustgate.test", 443),
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    return Request(scope, receive)


async def _create_prerequisites(session: AsyncSession) -> tuple[UUID, UUID]:
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"gateway-{user_id}@integration.test"},
    )
    policy_id = await session.scalar(
        select(PolicyVersion.id).where(PolicyVersion.version_label == "POL-1.0")
    )
    assert policy_id is not None
    return user_id, policy_id


def _complete_result(policy_version_id: UUID, decision: str) -> CompletePipelineResult:
    trust_score = {
        "ALLOW": Decimal("80"),
        "STEP_UP": Decimal("50"),
        "BLOCK": Decimal("20"),
    }[decision]
    return CompletePipelineResult(
        device=DeviceResult(
            device_hash="a" * 64,
            last_user_agent_family="Integration Browser",
            last_user_agent_version="1.0",
        ),
        context=ContextResult(
            device_familiarity_raw="unknown_device",
            device_health_raw="partially_healthy",
            location_raw="unavailable",
            time_raw="within_normal_window",
            resolved_region=None,
            raw_context={"test_fixture": True},
        ),
        policy_version_id=policy_version_id,
        trust_score=trust_score,
        risk_classification="MEDIUM",
        factors=(
            TrustFactorResult(
                "device_familiarity",
                "unknown_device",
                trust_score,
                Decimal("0.350"),
                trust_score * Decimal("0.350"),
            ),
            TrustFactorResult(
                "device_health",
                "partially_healthy",
                trust_score,
                Decimal("0.300"),
                trust_score * Decimal("0.300"),
            ),
            TrustFactorResult(
                "location_normality",
                "unavailable",
                trust_score,
                Decimal("0.200"),
                trust_score * Decimal("0.200"),
            ),
            TrustFactorResult(
                "time_normality",
                "within_normal_window",
                trust_score,
                Decimal("0.150"),
                trust_score * Decimal("0.150"),
            ),
        ),
        decision=decision,  # type: ignore[arg-type]
        decision_reason="integration test pipeline result",
        explanation="Synthetic result generated only by the integration test pipeline.",
    )


class CompleteTestPipeline:
    """Test-only pipeline returning a complete synthetic server result."""

    def __init__(self, result: CompletePipelineResult) -> None:
        self.result = result
        self.seen_token: str | None = None

    async def run(
        self,
        *,
        principal: AuthenticatedPrincipal,
        resource: object,
        device_token: str,
        client_ip: str,
        user_agent: str | None,
        context_snapshot: ContextSnapshot | None = None,
    ) -> CompletePipelineResult:
        del principal, resource, client_ip, user_agent, context_snapshot
        self.seen_token = device_token
        return self.result


def test_default_pipeline_blocks_records_event_and_creates_no_application_rows(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id, _ = await _create_prerequisites(session)
        principal = AuthenticatedPrincipal(user_id, None, "USER")

        result = await access_gateway(
            session=session,
            principal=principal,
            resource=get_protected_resource("ops-dashboard"),
            device_token=_RAW_DEVICE_TOKEN,
            client_ip="192.0.2.10",
            user_agent="test",
            pipeline=get_security_pipeline(),
            clock=FixedClock(_NOW),
        )

        assert result.decision == "BLOCK"
        assert result.mfa_challenge_id is None
        for model in _APPLICATION_MODELS:
            assert await session.scalar(select(func.count()).select_from(model)) == 0
        events = list((await session.scalars(select(SecurityEvent))).all())
        assert len(events) == 1
        assert events[0].event_type == "PIPELINE_DEGRADED_FAILSAFE"
        assert events[0].actor_id == user_id
        assert events[0].decision == "BLOCK"
        assert events[0].risk_category == "HIGH"
        assert events[0].details == {}
        assert _RAW_DEVICE_TOKEN not in repr(events[0].details)

    migrated_test_database.run_in_transaction(exercise)


def test_pipeline_exception_records_only_failsafe_event_and_no_application_rows(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()
    email = f"pipeline-failure-{user_id}@integration.test"
    engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)

    class FailingPipeline:
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
            del principal, resource, device_token, client_ip, user_agent, context_snapshot
            raise RuntimeError(
                f"private exception {_RAW_DEVICE_TOKEN} Bearer access-token password"
            )

    async def create_profile() -> None:
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
                {"id": user_id, "email": email},
            )

    async def remove_profile() -> None:
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM public.profiles WHERE id = :id"), {"id": user_id}
            )
            await connection.execute(text("DELETE FROM auth.users WHERE id = :id"), {"id": user_id})

    asyncio.run(create_profile())
    try:

        async def exercise(session: AsyncSession) -> None:
            with pytest.raises(PipelineExecutionError) as error:
                await access_gateway(
                    session=session,
                    principal=AuthenticatedPrincipal(user_id, email, "USER"),
                    resource=get_protected_resource("ops-dashboard"),
                    device_token=_RAW_DEVICE_TOKEN,
                    client_ip="192.0.2.17",
                    user_agent=None,
                    pipeline=FailingPipeline(),
                    clock=FixedClock(_NOW),
                )
            assert str(error.value) == "Access evaluation is unavailable"

            for model in _APPLICATION_MODELS:
                assert await session.scalar(select(func.count()).select_from(model)) == 0
            event = await session.scalar(select(SecurityEvent))
            assert event is not None
            assert event.event_type == "PIPELINE_DEGRADED_FAILSAFE"
            assert event.actor_id == user_id
            assert event.decision == "BLOCK"
            assert event.risk_category == "HIGH"
            assert event.details == {}
            assert _RAW_DEVICE_TOKEN not in repr(event.details)

        migrated_test_database.run_in_transaction(exercise)
    finally:
        asyncio.run(remove_profile())
        asyncio.run(engine.dispose())


@pytest.mark.parametrize(
    ("decision", "expected_final"),
    [("ALLOW", "ALLOW"), ("BLOCK", "BLOCK"), ("STEP_UP", None)],
)
def test_complete_pipeline_persists_eight_rows_atomically(
    migrated_test_database: ScratchDatabase,
    decision: str,
    expected_final: str | None,
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

    async def exercise(session: AsyncSession) -> None:
        user_id, policy_id = await _create_prerequisites(session)
        principal = AuthenticatedPrincipal(user_id, None, "USER")
        pipeline = CompleteTestPipeline(_complete_result(policy_id, decision))

        result = await access_gateway(
            session=session,
            principal=principal,
            resource=get_protected_resource("ops-dashboard"),
            device_token=_RAW_DEVICE_TOKEN,
            client_ip="192.0.2.11",
            user_agent="Integration Browser/1.0",
            pipeline=pipeline,
            clock=FixedClock(_NOW),
        )

        assert pipeline.seen_token == _RAW_DEVICE_TOKEN
        request = await session.scalar(select(AccessRequest))
        assert request is not None
        assert request.user_id == user_id
        assert request.resource_id == "ops-dashboard"
        assert request.initial_decision == decision
        assert request.mfa_required is (decision == "STEP_UP")
        assert request.final_outcome == expected_final
        assert (request.resolved_at is not None) is (expected_final is not None)
        assert result.decision == decision
        assert result.explanation == explain_decision(decision)
        evaluation = await session.scalar(select(TrustEvaluation))
        assert evaluation is not None
        assert evaluation.id == result.evaluation_id
        assert evaluation.access_request_id == request.id
        assert evaluation.policy_version_id == policy_id
        assert len(policy_calls) == 1
        evaluated_score, thresholds, decision_result = policy_calls[0]
        assert evaluated_score == evaluation.trust_score
        policy_version = await session.get(PolicyVersion, policy_id)
        assert policy_version is not None and policy_version.is_active
        assert thresholds == PolicyThresholds(
            allow_threshold=policy_version.allow_threshold,
            stepup_threshold=policy_version.stepup_threshold,
        )
        assert await session.scalar(select(func.count()).select_from(Device)) == 1
        assert await session.scalar(select(func.count()).select_from(ContextSignal)) == 1
        assert await session.scalar(select(func.count()).select_from(TrustEvaluation)) == 1
        assert await session.scalar(select(func.count()).select_from(TrustFactor)) == 4
        policy_decision = await session.scalar(select(PolicyDecision))
        assert policy_decision is not None
        assert decision_result.decision == decision
        assert policy_decision.decision == decision_result.decision
        assert policy_decision.decision_reason == decision_result.decision_reason
        assert decision_result.trust_score == evaluation.trust_score
        assert decision_result.allow_threshold == thresholds.allow_threshold
        assert decision_result.stepup_threshold == thresholds.stepup_threshold
        assert policy_decision.access_request_id == request.id
        assert policy_decision.trust_evaluation_id == evaluation.id
        assert policy_decision.policy_version_id == policy_id
        device = await session.get(Device, request.device_id)
        assert device is not None
        assert device.user_id == user_id
        assert device.recognized_at is None
        assert device.device_hash != _RAW_DEVICE_TOKEN
        assert _RAW_DEVICE_TOKEN not in repr(device.device_hash)
        assert _GATEWAY_USER_AGENT not in repr(device)
        event = await session.scalar(select(SecurityEvent))
        assert event is not None
        assert (
            event.event_type
            == {
                "ALLOW": "ACCESS_ALLOWED",
                "BLOCK": "ACCESS_BLOCKED",
                "STEP_UP": "ACCESS_STEPUP",
            }[decision]
        )
        assert event.actor_id == user_id
        assert event.access_request_id == request.id
        assert event.trust_evaluation_id == evaluation.id
        assert _RAW_DEVICE_TOKEN not in repr(event.details)
        assert _GATEWAY_USER_AGENT not in repr(event.details)

    migrated_test_database.run_in_transaction(exercise)


def test_complete_result_policy_mismatch_fails_safe_without_gateway_persistence(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()
    email = f"policy-mismatch-{user_id}@integration.test"
    engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)

    async def create_profile() -> None:
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
                {"id": user_id, "email": email},
            )

    async def remove_profile() -> None:
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM public.profiles WHERE id = :id"), {"id": user_id}
            )
            await connection.execute(text("DELETE FROM auth.users WHERE id = :id"), {"id": user_id})

    asyncio.run(create_profile())
    try:

        async def exercise(session: AsyncSession) -> None:
            active_policy_id = await session.scalar(
                select(PolicyVersion.id).where(PolicyVersion.version_label == "POL-1.0")
            )
            assert active_policy_id is not None
            profile = await session.get(Profile, user_id)
            assert profile is not None
            with pytest.raises(PipelineExecutionError, match="Access evaluation is unavailable"):
                await access_gateway(
                    session=session,
                    principal=AuthenticatedPrincipal(user_id, email, "USER"),
                    resource=get_protected_resource("ops-dashboard"),
                    device_token=_RAW_DEVICE_TOKEN,
                    client_ip="192.0.2.13",
                    user_agent="test",
                    pipeline=CompleteTestPipeline(_complete_result(uuid4(), "ALLOW")),
                    clock=FixedClock(_NOW),
                )

            for model in _APPLICATION_MODELS:
                assert await session.scalar(select(func.count()).select_from(model)) == 0
            event = await session.scalar(select(SecurityEvent))
            assert event is not None
            assert event.event_type == "PIPELINE_DEGRADED_FAILSAFE"
            assert event.actor_id == user_id
            assert event.decision == "BLOCK"
            assert event.details == {}

        migrated_test_database.run_in_transaction(exercise)
    finally:
        try:
            asyncio.run(remove_profile())
        finally:
            asyncio.run(engine.dispose())


def test_failure_after_staging_records_rolls_back_everything(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_after_policy_decision_is_staged(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("private test persistence failure")

    monkeypatch.setattr(gateway_service, "record_event", fail_after_policy_decision_is_staged)

    async def exercise(session: AsyncSession) -> None:
        user_id, policy_id = await _create_prerequisites(session)
        with pytest.raises(RuntimeError, match="private test persistence failure"):
            await access_gateway(
                session=session,
                principal=AuthenticatedPrincipal(user_id, None, "USER"),
                resource=get_protected_resource("ops-dashboard"),
                device_token=_RAW_DEVICE_TOKEN,
                client_ip="192.0.2.12",
                user_agent="test",
                pipeline=CompleteTestPipeline(_complete_result(policy_id, "BLOCK")),
                clock=FixedClock(_NOW),
            )

        for model in _ALL_GATEWAY_MODELS:
            assert await session.scalar(select(func.count()).select_from(model)) == 0
        assert await session.scalar(select(func.count()).select_from(PolicyDecision)) == 0

    migrated_test_database.run_in_transaction(exercise)


def test_trust_persistence_failure_rolls_back_context_and_gateway_rows(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_add_many = TrustFactorRepository.add_many

    def fail_after_trust_factors_are_staged(
        repository: TrustFactorRepository,
        factors: object,
    ) -> None:
        original_add_many(repository, factors)  # type: ignore[arg-type]
        raise RuntimeError("private trust-factor persistence failure")

    monkeypatch.setattr(TrustFactorRepository, "add_many", fail_after_trust_factors_are_staged)

    async def exercise(session: AsyncSession) -> None:
        user_id, policy_id = await _create_prerequisites(session)
        profile = await session.get(Profile, user_id)
        assert profile is not None

        with pytest.raises(RuntimeError, match="private trust-factor persistence failure"):
            await access_gateway(
                session=session,
                principal=AuthenticatedPrincipal(user_id, None, "USER"),
                resource=get_protected_resource("ops-dashboard"),
                device_token=_RAW_DEVICE_TOKEN,
                client_ip="8.8.8.8",
                user_agent=_GATEWAY_USER_AGENT,
                pipeline=CompleteTestPipeline(_complete_result(policy_id, "BLOCK")),
                clock=FixedClock(_NOW),
                request=_context_request(),
                profile=profile,
                geo_resolver=GatewayGeoResolver(),
                settings=Settings(
                    app_env="test",
                    cors_allowed_origin="http://localhost:5173",
                    device_hash_secret=_GATEWAY_DEVICE_SECRET,
                ),
            )

        for model in _ALL_GATEWAY_MODELS:
            assert await session.scalar(select(func.count()).select_from(model)) == 0

    migrated_test_database.run_in_transaction(exercise)


def test_access_request_failure_does_not_persist_evaluation_or_device(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_before_request_add(
        repository: AccessRequestRepository,
        access_request: AccessRequest,
    ) -> None:
        del repository, access_request
        raise RuntimeError("private request persistence failure")

    monkeypatch.setattr(AccessRequestRepository, "add", fail_before_request_add)

    async def exercise(session: AsyncSession) -> None:
        user_id, policy_id = await _create_prerequisites(session)
        with pytest.raises(RuntimeError, match="private request persistence failure"):
            await access_gateway(
                session=session,
                principal=AuthenticatedPrincipal(user_id, None, "USER"),
                resource=get_protected_resource("ops-dashboard"),
                device_token=_RAW_DEVICE_TOKEN,
                client_ip="192.0.2.13",
                user_agent=None,
                pipeline=CompleteTestPipeline(_complete_result(policy_id, "BLOCK")),
                clock=FixedClock(_NOW),
            )

        for model in _ALL_GATEWAY_MODELS:
            assert await session.scalar(select(func.count()).select_from(model)) == 0

    migrated_test_database.run_in_transaction(exercise)


def test_commit_failure_rolls_back_application_rows_and_staged_event(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_commit(_session: AsyncSession) -> None:
        raise RuntimeError("private commit failure")

    monkeypatch.setattr(AsyncSession, "commit", fail_commit)

    async def exercise(session: AsyncSession) -> None:
        user_id, policy_id = await _create_prerequisites(session)
        with pytest.raises(RuntimeError, match="private commit failure"):
            await access_gateway(
                session=session,
                principal=AuthenticatedPrincipal(user_id, None, "USER"),
                resource=get_protected_resource("ops-dashboard"),
                device_token=_RAW_DEVICE_TOKEN,
                client_ip="192.0.2.16",
                user_agent=None,
                pipeline=CompleteTestPipeline(_complete_result(policy_id, "BLOCK")),
                clock=FixedClock(_NOW),
            )

        for model in _ALL_GATEWAY_MODELS:
            assert await session.scalar(select(func.count()).select_from(model)) == 0

    migrated_test_database.run_in_transaction(exercise)


def test_raw_device_token_is_not_logged(
    migrated_test_database: ScratchDatabase,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id, policy_id = await _create_prerequisites(session)
        await access_gateway(
            session=session,
            principal=AuthenticatedPrincipal(user_id, None, "USER"),
            resource=get_protected_resource("ops-dashboard"),
            device_token=_RAW_DEVICE_TOKEN,
            client_ip=str(IPv4Address("192.0.2.14")),
            user_agent=None,
            pipeline=CompleteTestPipeline(_complete_result(policy_id, "BLOCK")),
            clock=FixedClock(_NOW),
        )

    migrated_test_database.run_in_transaction(exercise)
    assert _RAW_DEVICE_TOKEN not in caplog.text


def test_gateway_rejects_pipeline_output_containing_raw_device_token(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()
    email = f"raw-token-rejection-{user_id}@integration.test"
    engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)

    async def create_profile() -> None:
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
                {"id": user_id, "email": email},
            )

    async def remove_profile() -> None:
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM public.profiles WHERE id = :id"), {"id": user_id}
            )
            await connection.execute(text("DELETE FROM auth.users WHERE id = :id"), {"id": user_id})

    asyncio.run(create_profile())
    try:

        async def exercise(session: AsyncSession) -> None:
            policy_id = await session.scalar(
                select(PolicyVersion.id).where(PolicyVersion.version_label == "POL-1.0")
            )
            assert policy_id is not None
            result = _complete_result(policy_id, "BLOCK")
            result_with_raw_token = replace(
                result,
                device=replace(result.device, device_hash=_RAW_DEVICE_TOKEN),
            )
            with pytest.raises(PipelineExecutionError) as error:
                await access_gateway(
                    session=session,
                    principal=AuthenticatedPrincipal(user_id, email, "USER"),
                    resource=get_protected_resource("ops-dashboard"),
                    device_token=_RAW_DEVICE_TOKEN,
                    client_ip="192.0.2.15",
                    user_agent=None,
                    pipeline=CompleteTestPipeline(result_with_raw_token),
                    clock=FixedClock(_NOW),
                )
            assert str(error.value) == "Access evaluation is unavailable"

            for model in _APPLICATION_MODELS:
                assert await session.scalar(select(func.count()).select_from(model)) == 0
            profile = await session.get(Profile, user_id)
            assert profile is not None
            event = await session.scalar(select(SecurityEvent))
            assert event is not None
            assert event.event_type == "PIPELINE_DEGRADED_FAILSAFE"
            assert event.actor_id == profile.id == user_id
            assert event.decision == "BLOCK"
            assert event.risk_category == "HIGH"
            assert event.details == {}
            assert _RAW_DEVICE_TOKEN not in repr(event.details)

        migrated_test_database.run_in_transaction(exercise)
    finally:
        try:
            asyncio.run(remove_profile())
        finally:
            asyncio.run(engine.dispose())
