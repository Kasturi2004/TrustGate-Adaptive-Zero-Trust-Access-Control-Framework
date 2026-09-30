"""Tests for the initial fail-closed protected-resource endpoint."""

from asyncio import run
from collections.abc import AsyncIterator
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal, require_user
from app.db.models.security_event import SecurityEvent
from app.main import create_app
from app.services.access_gateway import FailClosedPipelineResult, get_security_pipeline
from app.services.protected_resource import get_protected_resource
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("07b4812d-6615-40fd-84e0-9612a7fc1b12")
_DEVICE_TOKEN = "test-device-token-do-not-echo"


@pytest.fixture
def client() -> TestClient:
    application = create_app()
    session = AsyncMock(spec=AsyncSession)
    session.in_transaction.return_value = True
    application.state.test_session = session

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    application.dependency_overrides[require_user] = lambda: AuthenticatedPrincipal(
        id=_USER_ID,
        email="user@example.test",
        role="USER",
    )
    application.dependency_overrides[deps.get_db_session] = override_session
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
