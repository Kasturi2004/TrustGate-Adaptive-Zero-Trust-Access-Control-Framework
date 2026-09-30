"""Tests for router-level ADMIN authorization."""

from collections.abc import AsyncIterator
from typing import cast
from unittest.mock import AsyncMock

import pytest
from app.api import deps
from app.core.config import Settings
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.main import create_app
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit.test_auth_dependency import _USER_ID, _client, _profile, _token


class _AuditTransaction:
    def __init__(self, session: AsyncMock) -> None:
        self._session = session

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, exc_type: object, *_: object) -> None:
        if exc_type is None:
            await self._session.commit()
        else:
            await self._session.rollback()


class _AuditSessionContext:
    def __init__(self, session: AsyncMock) -> None:
        self._session = session

    async def __aenter__(self) -> AsyncMock:
        return self._session

    async def __aexit__(self, *_: object) -> None:
        await self._session.close()


class _AuditEngine:
    def __init__(self) -> None:
        self.dispose = AsyncMock()


def _admin_client(
    request_session: AsyncMock,
    audit_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url="https://test-project.supabase.co",
    )
    monkeypatch.setattr(deps, "get_settings", lambda: settings)
    engine = _AuditEngine()
    monkeypatch.setattr(deps, "create_db_engine", lambda _: engine)
    transaction = _AuditTransaction(audit_session)
    audit_session.begin.return_value = transaction
    monkeypatch.setattr(
        deps,
        "create_session_factory",
        lambda _: lambda: _AuditSessionContext(audit_session),
    )

    client = _client(request_session, monkeypatch)
    application = cast(FastAPI, client.app)

    async def request_session_dependency() -> AsyncIterator[AsyncSession]:
        try:
            yield cast(AsyncSession, request_session)
        except Exception:
            await request_session.rollback()
            raise

    application.dependency_overrides[deps.get_db_session] = request_session_dependency
    return client


def test_admin_profile_can_access_verification_route(monkeypatch: pytest.MonkeyPatch) -> None:
    request_session = AsyncMock(spec=AsyncSession)
    request_session.get.return_value = _profile(role="ADMIN")
    audit_session = AsyncMock(spec=AsyncSession)
    client = _admin_client(request_session, audit_session, monkeypatch)

    response = client.get("/admin/verification", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    request_session.get.assert_awaited_once_with(Profile, _USER_ID)
    audit_session.add.assert_not_called()


def test_user_profile_gets_forbidden_envelope_even_with_admin_jwt_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_session = AsyncMock(spec=AsyncSession)
    request_session.get.return_value = _profile(role="USER")
    audit_session = AsyncMock(spec=AsyncSession)
    client = _admin_client(request_session, audit_session, monkeypatch)

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
    request_session.get.assert_awaited_once_with(Profile, _USER_ID)
    request_session.rollback.assert_awaited_once()
    request_session.add.assert_not_called()
    audit_session.commit.assert_awaited_once()
    audit_session.rollback.assert_not_awaited()
    event = audit_session.add.call_args.args[0]
    assert isinstance(event, SecurityEvent)
    assert event.event_type == "ADMIN_UNAUTHORIZED_ATTEMPT"
    assert event.actor_id == _USER_ID
    assert event.decision == "BLOCK"
    assert event.risk_category == "HIGH"
    assert event.details == {
        "attempted_role": "ADMIN",
        "path": "/admin/verification",
        "method": "GET",
    }


@pytest.mark.parametrize("authorization", [None, "Bearer invalid"])
def test_admin_router_keeps_unauthenticated_requests_at_401(
    monkeypatch: pytest.MonkeyPatch,
    authorization: str | None,
) -> None:
    request_session = AsyncMock(spec=AsyncSession)
    audit_session = AsyncMock(spec=AsyncSession)
    client = _admin_client(request_session, audit_session, monkeypatch)
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/admin/verification", headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    request_session.get.assert_not_awaited()
    audit_session.add.assert_not_called()


def test_admin_audit_failure_remains_denied_without_exposing_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_session = AsyncMock(spec=AsyncSession)
    request_session.get.return_value = _profile(role="USER")
    audit_session = AsyncMock(spec=AsyncSession)
    audit_session.commit.side_effect = RuntimeError("private connection secret")
    client = _admin_client(request_session, audit_session, monkeypatch)

    response = client.get(
        "/admin/verification",
        headers={"Authorization": f"Bearer {_token()}", "X-Request-ID": "admin-audit-failure"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "HTTP_500",
            "message": "An unexpected error occurred.",
            "request_id": "admin-audit-failure",
        }
    }
    assert "private connection secret" not in response.text
    request_session.rollback.assert_awaited_once()


def test_no_client_facing_profile_role_write_route_exists() -> None:
    profile_routes = [
        route for route in create_app().routes if getattr(route, "path", "").startswith("/profiles")
    ]

    assert profile_routes == []
