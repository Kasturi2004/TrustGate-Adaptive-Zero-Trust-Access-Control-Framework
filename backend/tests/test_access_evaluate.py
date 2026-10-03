"""Tests for the initial fail-closed protected-resource endpoint."""

from asyncio import run
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import IPv4Address
from typing import Any, cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import app.services.access_gateway as access_gateway_service
import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal, get_clock, require_user
from app.core.clock import FixedClock
from app.core.config import Settings, get_settings
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.main import create_app
from app.schemas.trust import TrustEvaluationResult, TrustSignals, TrustWeights
from app.services.access_gateway import (
    CompletePipelineResult,
    ContextResult,
    DeviceResult,
    FailClosedPipelineResult,
    TrustFactorResult,
    get_security_pipeline,
)
from app.services.context.collector import ContextSnapshot
from app.services.context.device_familiarity import device_token_hash
from app.services.context.location import GeoRegion, IPAddress, get_geo_resolver
from app.services.protected_resource import get_protected_resource
from app.services.trust_engine import evaluate as evaluate_trust_engine
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("07b4812d-6615-40fd-84e0-9612a7fc1b12")
_DEVICE_TOKEN = "test-device-token-do-not-echo"
_DEVICE_SECRET = "phase-6f-route-test-device-secret"
_NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"


class TestGeoResolver:
    def resolve(self, address: IPAddress) -> GeoRegion:
        del address
        return GeoRegion("US", "CA")


@pytest.fixture
def client() -> TestClient:
    application = create_app()
    session = AsyncMock(spec=AsyncSession)
    session.in_transaction.return_value = True
    profile = Profile(
        id=_USER_ID,
        email="user@example.test",
        role="USER",
        timezone="UTC",
        is_deleted=False,
    )
    session.get.return_value = profile
    scalar_result = Mock()
    scalar_result.first.return_value = None
    scalar_result.all.return_value = []
    scalar_result.one.return_value = Device(
        id=UUID("e0d8881d-a9aa-4c0c-8f2c-582e389c95c5"),
        user_id=_USER_ID,
        device_hash="opaque-device-hash",
        recognized_at=None,
        first_seen_at=_NOW,
        last_seen_at=_NOW,
    )
    session.scalars.return_value = scalar_result
    application.state.test_session = session

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    application.dependency_overrides[require_user] = lambda: AuthenticatedPrincipal(
        id=_USER_ID,
        email="user@example.test",
        role="USER",
    )
    application.dependency_overrides[deps.get_db_session] = override_session
    application.dependency_overrides[get_settings] = lambda: Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        device_hash_secret=_DEVICE_SECRET,
    )
    application.dependency_overrides[get_geo_resolver] = TestGeoResolver
    return TestClient(application, client=("127.0.0.1", 12345))


def test_authenticated_request_returns_only_curated_fail_closed_response(
    client: TestClient,
) -> None:
    response = client.post(
        "/access/evaluate",
        json={"resource_id": "ops-dashboard"},
        headers={"X-Device-Token": _DEVICE_TOKEN},
    )

    assert response.status_code == 200
    assert set(response.json()) == {
        "evaluation_id",
        "decision",
        "explanation",
        "mfa_challenge_id",
    }
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["mfa_challenge_id"] is None
    assert _DEVICE_TOKEN not in response.text


def test_live_route_collects_context_and_passes_it_to_gateway_persistence(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_policy = PolicyVersion(
        id=UUID("b8ce345d-9c2b-48e2-928f-7d5abdd19f1c"),
        version_label="POL-1.0",
        weights_json={
            "device_familiarity": 0.35,
            "device_health": 0.30,
            "location_normality": 0.20,
            "time_normality": 0.15,
        },
        is_active=True,
    )

    async def get_active_policy(_repository: object) -> PolicyVersion:
        return active_policy

    from app.db.repositories.policy_version import PolicyVersionRepository

    monkeypatch.setattr(PolicyVersionRepository, "get_active", get_active_policy)
    observed: list[tuple[TrustSignals, TrustWeights]] = []

    def record_engine_inputs(signals: TrustSignals, weights: TrustWeights) -> TrustEvaluationResult:
        observed.append((signals, weights))
        return evaluate_trust_engine(signals, weights)

    monkeypatch.setattr(access_gateway_service, "evaluate_trust", record_engine_inputs)

    class SnapshotPipeline:
        snapshot: ContextSnapshot | None = None

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
            del principal, resource, client_ip, user_agent
            assert device_token == _DEVICE_TOKEN
            assert context_snapshot is not None
            self.snapshot = context_snapshot
            return CompletePipelineResult(
                device=DeviceResult(
                    device_hash=device_token_hash(
                        device_token,
                        settings=Settings(
                            app_env="test",
                            cors_allowed_origin="http://localhost:5173",
                            device_hash_secret=_DEVICE_SECRET,
                        ),
                    )
                    or "opaque-test-hash",
                    last_user_agent_family=context_snapshot.device_health.browser_family,
                    last_user_agent_version=context_snapshot.device_health.browser_version,
                ),
                context=context_snapshot,
                policy_version_id=UUID("b8ce345d-9c2b-48e2-928f-7d5abdd19f1c"),
                trust_score=Decimal("50.00"),
                risk_classification="MEDIUM",
                factors=(
                    TrustFactorResult(
                        "device_familiarity",
                        context_snapshot.device_familiarity_raw,
                        Decimal("50"),
                        Decimal("0.350"),
                        Decimal("17.500"),
                    ),
                    TrustFactorResult(
                        "device_health",
                        context_snapshot.device_health_raw,
                        Decimal("50"),
                        Decimal("0.300"),
                        Decimal("15.000"),
                    ),
                    TrustFactorResult(
                        "location_normality",
                        context_snapshot.location_raw,
                        Decimal("50"),
                        Decimal("0.200"),
                        Decimal("10.000"),
                    ),
                    TrustFactorResult(
                        "time_normality",
                        context_snapshot.time_raw,
                        Decimal("50"),
                        Decimal("0.150"),
                        Decimal("7.500"),
                    ),
                ),
                decision="STEP_UP",
                decision_reason="Test pipeline only.",
                explanation="Additional verification is required.",
            )

    pipeline = SnapshotPipeline()
    application = cast(Any, client.app)
    application.dependency_overrides[get_security_pipeline] = lambda: pipeline
    application.dependency_overrides[get_clock] = lambda: FixedClock(_NOW)

    response = client.post(
        "/access/evaluate",
        json={"resource_id": "ops-dashboard"},
        headers={"X-Device-Token": _DEVICE_TOKEN, "User-Agent": _USER_AGENT},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "STEP_UP"
    assert pipeline.snapshot is not None
    assert pipeline.snapshot.client_ip == IPv4Address("127.0.0.1")
    assert pipeline.snapshot.location_normality.category == "UNAVAILABLE"
    assert pipeline.snapshot.device_familiarity.category == "UNKNOWN"
    assert pipeline.snapshot.device_health.category == "UNHEALTHY"
    assert pipeline.snapshot.time_normality.local_hour in range(24)
    assert pipeline.snapshot.raw_context["resolved_region"] is None
    assert "region" not in pipeline.snapshot.raw_context

    session = application.state.test_session
    staged = [call.args[0] for call in session.add.call_args_list]
    staged.extend(row for call in session.add_all.call_args_list for row in call.args[0])
    access_request = next(row for row in staged if isinstance(row, AccessRequest))
    signal = next(row for row in staged if isinstance(row, ContextSignal))
    evaluation = next(row for row in staged if isinstance(row, TrustEvaluation))
    factors = [row for row in staged if isinstance(row, TrustFactor)]
    assert access_request.resolved_region == pipeline.snapshot.resolved_region
    assert signal.access_request_id == access_request.id
    assert signal.device_familiarity_raw == "unknown_device"
    assert signal.location_raw == "unavailable"
    assert signal.raw_context == dict(pipeline.snapshot.raw_context)
    assert _DEVICE_TOKEN not in repr(signal.raw_context)
    assert _USER_AGENT not in repr(signal.raw_context)
    assert evaluation.access_request_id == access_request.id
    assert evaluation.policy_version_id == active_policy.id
    assert evaluation.trust_score == Decimal("39.00")
    assert len(observed) == 1
    assert observed[0][0] == TrustSignals(
        device_familiarity_raw="unknown_device",
        device_health_raw="unhealthy",
        location_raw="unavailable",
        time_raw="within_normal_window",
    )
    assert observed[0][1].device_familiarity == Decimal("0.35")
    assert observed[0][1].device_health == Decimal("0.3")
    assert observed[0][1].location_normality == Decimal("0.2")
    assert observed[0][1].time_normality == Decimal("0.15")
    assert len(factors) == 4
    factor_rows = {factor.factor_name: factor for factor in factors}
    assert factor_rows["device_familiarity"].raw_value == "unknown_device"
    assert factor_rows["device_familiarity"].normalized_score == Decimal("20")
    assert factor_rows["device_familiarity"].weight == Decimal("0.350")
    assert factor_rows["device_familiarity"].weighted_contribution == Decimal("7.000")
    assert factor_rows["device_health"].raw_value == "unhealthy"
    assert factor_rows["device_health"].weighted_contribution == Decimal("3.000")
    assert factor_rows["location_normality"].raw_value == "unavailable"
    assert factor_rows["location_normality"].weighted_contribution == Decimal("14.000")
    assert factor_rows["time_normality"].raw_value == "within_normal_window"
    assert factor_rows["time_normality"].weighted_contribution == Decimal("15.000")


def test_trust_evaluation_failure_records_only_sanitized_block_event(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    active_policy = PolicyVersion(
        id=UUID("b8ce345d-9c2b-48e2-928f-7d5abdd19f1c"),
        version_label="POL-1.0",
        weights_json={
            "device_familiarity": 0.35,
            "device_health": 0.30,
            "location_normality": 0.20,
            "time_normality": 0.15,
        },
        is_active=True,
    )

    async def get_active_policy(_repository: object) -> PolicyVersion:
        return active_policy

    from app.db.repositories.policy_version import PolicyVersionRepository

    monkeypatch.setattr(PolicyVersionRepository, "get_active", get_active_policy)

    def fail_trust_evaluation(
        _signals: TrustSignals, _weights: TrustWeights
    ) -> TrustEvaluationResult:
        raise RuntimeError("private trust engine detail")

    monkeypatch.setattr(access_gateway_service, "evaluate_trust", fail_trust_evaluation)

    class CompletePipeline:
        async def run(self, **_kwargs: object) -> CompletePipelineResult:
            return CompletePipelineResult(
                device=DeviceResult("opaque-device-hash", None, None),
                context=ContextResult(
                    device_familiarity_raw="unknown_device",
                    device_health_raw="partially_healthy",
                    location_raw="unavailable",
                    time_raw="within_normal_window",
                    resolved_region=None,
                    raw_context={},
                ),
                policy_version_id=active_policy.id,
                trust_score=Decimal("50.00"),
                risk_classification="MEDIUM",
                factors=(
                    TrustFactorResult(
                        "device_familiarity",
                        "unknown_device",
                        Decimal("50"),
                        Decimal("0.350"),
                        Decimal("17.500"),
                    ),
                    TrustFactorResult(
                        "device_health",
                        "partially_healthy",
                        Decimal("50"),
                        Decimal("0.300"),
                        Decimal("15.000"),
                    ),
                    TrustFactorResult(
                        "location_normality",
                        "unavailable",
                        Decimal("50"),
                        Decimal("0.200"),
                        Decimal("10.000"),
                    ),
                    TrustFactorResult(
                        "time_normality",
                        "within_normal_window",
                        Decimal("50"),
                        Decimal("0.150"),
                        Decimal("7.500"),
                    ),
                ),
                decision="ALLOW",
                decision_reason="Test fixture only.",
                explanation="Test fixture only.",
            )

    application = cast(Any, client.app)
    application.dependency_overrides[get_security_pipeline] = lambda: CompletePipeline()
    response = client.post(
        "/access/evaluate",
        json={"resource_id": "ops-dashboard"},
        headers={"X-Device-Token": _DEVICE_TOKEN, "User-Agent": _USER_AGENT},
    )

    assert response.status_code == 500
    assert response.json()["error"]["message"] == "An unexpected error occurred."
    assert "private trust engine detail" not in response.text
    assert "private trust engine detail" not in caplog.text
    session = application.state.test_session
    assert session.rollback.await_count == 1
    assert session.commit.await_count == 1
    added = [call.args[0] for call in session.add.call_args_list]
    assert len(added) == 1
    assert isinstance(added[0], SecurityEvent)
    assert added[0].event_type == "PIPELINE_DEGRADED_FAILSAFE"
    assert added[0].decision == "BLOCK"
    assert added[0].risk_category == "HIGH"
    assert added[0].details == {}


def test_resource_id_is_optional_and_defaults_to_mvp_resource(client: TestClient) -> None:
    response = client.post(
        "/access/evaluate",
        json={},
        headers={"X-Device-Token": _DEVICE_TOKEN},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"


def test_unauthenticated_request_uses_existing_401_envelope() -> None:
    client = TestClient(create_app(), client=("127.0.0.1", 12345))

    response = client.post(
        "/access/evaluate",
        json={},
        headers={"X-Device-Token": _DEVICE_TOKEN},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert "request_id" in response.json()["error"]


def test_missing_device_token_uses_safe_validation_envelope(client: TestClient) -> None:
    response = client.post("/access/evaluate", json={})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert response.json()["error"]["message"] == "Request validation failed."


@pytest.mark.parametrize(
    "body",
    [
        {"resource_id": "ops-dashboard", "decision": "ALLOW"},
        {"trust_score": 100},
        {"factors": []},
        {"trust_factors": []},
        {"policy_decision": "ALLOW"},
        {"mfa_challenge_id": None},
        {"evaluation_id": str(_USER_ID)},
        {"risk_classification": "LOW"},
        {"weights": {}},
        {"thresholds": {}},
        {"policy_version_id": str(_USER_ID)},
        {"policy_version": {}},
        {"final_outcome": "ALLOW"},
        {"role": "ADMIN"},
        {"user_id": str(_USER_ID)},
        {"resource_id": "another-resource"},
    ],
)
def test_unexpected_or_unregistered_request_fields_are_rejected(
    client: TestClient,
    body: dict[str, object],
) -> None:
    response = client.post(
        "/access/evaluate",
        json=body,
        headers={"X-Device-Token": _DEVICE_TOKEN},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_device_token_is_not_logged(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    response = client.post(
        "/access/evaluate",
        json={},
        headers={"X-Device-Token": _DEVICE_TOKEN},
    )

    assert response.status_code == 200
    assert _DEVICE_TOKEN not in caplog.text
    test_session = cast(Any, client.app).state.test_session
    added = [call.args[0] for call in test_session.add.call_args_list]
    assert len(added) == 1
    assert isinstance(added[0], SecurityEvent)
    assert added[0].event_type == "PIPELINE_DEGRADED_FAILSAFE"
    assert added[0].decision == "BLOCK"
    assert added[0].risk_category == "HIGH"
    assert added[0].details == {}
    assert _DEVICE_TOKEN not in repr(added[0].details)


def test_default_pipeline_has_only_an_explicit_degraded_result() -> None:
    async def execute() -> object:
        return await get_security_pipeline().run(
            principal=AuthenticatedPrincipal(_USER_ID, "user@example.test", "USER"),
            resource=get_protected_resource("ops-dashboard"),
            device_token=_DEVICE_TOKEN,
            client_ip="127.0.0.1",
            user_agent=None,
        )

    result = run(execute())
    assert isinstance(result, FailClosedPipelineResult)
    assert result.explanation
    assert not hasattr(result, "decision")
    assert not hasattr(result, "trust_score")
    assert not hasattr(result, "factors")


def test_gateway_failure_returns_safe_error_and_records_sanitized_event(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    private_values = (
        _DEVICE_TOKEN,
        "private pipeline failure",
        "Bearer secret-access-token",
        "secret-refresh-token",
        "private-password",
    )

    class FailingPipeline:
        async def run(self, **_kwargs: object) -> object:
            raise RuntimeError(" | ".join(private_values))

    application = cast(Any, client.app)
    application.dependency_overrides[get_security_pipeline] = lambda: FailingPipeline()

    response = client.post(
        "/access/evaluate",
        json={},
        headers={
            "X-Device-Token": _DEVICE_TOKEN,
            "Authorization": "Bearer secret-access-token",
        },
    )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "HTTP_500"
    assert response.json()["error"]["message"] == "An unexpected error occurred."
    assert "request_id" in response.json()["error"]
    for private_value in private_values:
        assert private_value not in response.text
        assert private_value not in caplog.text

    test_session = cast(Any, client.app).state.test_session
    assert test_session.rollback.await_count == 1
    assert test_session.commit.await_count == 1
    added = [call.args[0] for call in test_session.add.call_args_list]
    assert len(added) == 1
    assert isinstance(added[0], SecurityEvent)
    assert added[0].event_type == "PIPELINE_DEGRADED_FAILSAFE"
    assert added[0].actor_id == _USER_ID
    assert added[0].decision == "BLOCK"
    assert added[0].risk_category == "HIGH"
    assert added[0].details == {}
