"""Tests for router-level ADMIN authorization."""

from unittest.mock import AsyncMock

import pytest
from app.db.models.profile import Profile
from app.main import create_app
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit.test_auth_dependency import _USER_ID, _client, _profile, _token


def test_admin_profile_can_access_verification_route(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="ADMIN")
    client = _client(session, monkeypatch)

    response = client.get("/admin/verification", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    session.get.assert_awaited_once_with(Profile, _USER_ID)


def test_user_profile_gets_forbidden_envelope_even_with_admin_jwt_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _client(session, monkeypatch)

    response = client.get(
        "/admin/verification",
        headers={"Authorization": f"Bearer {_token(role='ADMIN')}", "X-Request-ID": "admin-user"},
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "FORBIDDEN",
            "message": "Insufficient permissions",
            "request_id": "admin-user",
        }
    }
    session.get.assert_awaited_once_with(Profile, _USER_ID)


@pytest.mark.parametrize("authorization", [None, "Bearer invalid"])
def test_admin_router_keeps_unauthenticated_requests_at_401(
    monkeypatch: pytest.MonkeyPatch,
    authorization: str | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _client(session, monkeypatch)
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/admin/verification", headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    session.get.assert_not_awaited()


def test_no_client_facing_profile_role_write_route_exists() -> None:
    profile_routes = [
        route for route in create_app().routes if getattr(route, "path", "").startswith("/profiles")
    ]

    assert profile_routes == []
