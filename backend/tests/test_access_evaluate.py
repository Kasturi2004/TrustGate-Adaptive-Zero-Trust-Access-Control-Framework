"""Tests for the initial fail-closed protected-resource endpoint."""

from uuid import UUID

import pytest
from app.api.deps import AuthenticatedPrincipal, require_user
from app.main import create_app
from fastapi.testclient import TestClient

_USER_ID = UUID("07b4812d-6615-40fd-84e0-9612a7fc1b12")
_DEVICE_TOKEN = "test-device-token-do-not-echo"


@pytest.fixture
def client() -> TestClient:
    application = create_app()
    application.dependency_overrides[require_user] = lambda: AuthenticatedPrincipal(
        id=_USER_ID,
        email="user@example.test",
        role="USER",
    )
    return TestClient(application)


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
    client = TestClient(create_app())

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
        {"trust_factors": []},
        {"policy_decision": "ALLOW"},
        {"mfa_challenge_id": None},
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
