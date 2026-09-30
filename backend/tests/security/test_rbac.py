"""Focused RBAC tests using the existing mocked-auth test helpers."""

from typing import Annotated, cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit.test_auth_dependency import _USER_ID, _client, _profile, _token

_OTHER_USER_ID = UUID("f7ece3de-0143-415f-bd7e-1976202be976")
_OWNED_RESOURCE_ID = UUID("18e329ea-240b-4bdb-92ea-73d8f69f017a")
_OTHER_RESOURCE_ID = UUID("d680490a-9c66-4d39-8d5e-643869cf245d")
_RESOURCE_OWNERS = {
    _OWNED_RESOURCE_ID: _USER_ID,
    _OTHER_RESOURCE_ID: _OTHER_USER_ID,
}


def _rbac_client(session: AsyncMock, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    client = _client(session, monkeypatch)
    application = cast(FastAPI, client.app)

    async def read_user(
        principal: Annotated[AuthenticatedPrincipal, Depends(deps.require_user)],
    ) -> dict[str, str | None]:
        return {"id": str(principal.id), "email": principal.email, "role": principal.role}

    async def read_admin(
        principal: Annotated[AuthenticatedPrincipal, Depends(deps.require_role("ADMIN"))],
    ) -> dict[str, str]:
        return {"id": str(principal.id), "role": principal.role}

    application.add_api_route("/test-require-user", read_user, methods=["GET"])
    application.add_api_route("/test-require-admin", read_admin, methods=["GET"])

    async def resolve_test_resource_owner(resource_id: UUID) -> UUID:
        """Simulate loading the resource and deriving its owner server-side."""
        return _RESOURCE_OWNERS[resource_id]

    async def read_test_resource(resource_id: UUID) -> dict[str, str]:
        return {"resource_id": str(resource_id)}

    owner_guard = deps.require_resource_owner(
        resolve_test_resource_owner,
        resource="test_resource",
    )
    application.add_api_route(
        "/test-resources/{resource_id}",
        read_test_resource,
        methods=["GET"],
        dependencies=[Depends(owner_guard)],
    )
    return client


def test_require_user_accepts_valid_authenticated_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _rbac_client(session, monkeypatch)

    response = client.get("/test-require-user", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 200
    assert response.json() == {
        "id": str(_USER_ID),
        "email": "user@example.test",
        "role": "USER",
    }
    session.get.assert_awaited_once_with(Profile, _USER_ID)


@pytest.mark.parametrize("authorization", [None, "Bearer malformed"])
def test_require_user_preserves_existing_401_behavior(
    monkeypatch: pytest.MonkeyPatch,
    authorization: str | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _rbac_client(session, monkeypatch)
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/test-require-user", headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert response.json()["error"]["message"] == "Not authenticated"
    session.get.assert_not_awaited()


def test_require_admin_accepts_database_admin_role(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="ADMIN")
    client = _rbac_client(session, monkeypatch)

    response = client.get("/test-require-admin", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 200
    assert response.json() == {"id": str(_USER_ID), "role": "ADMIN"}
    session.get.assert_awaited_once_with(Profile, _USER_ID)


def test_require_admin_rejects_database_user_role_with_forbidden_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _rbac_client(session, monkeypatch)

    response = client.get(
        "/test-require-admin",
        headers={"Authorization": f"Bearer {_token()}", "X-Request-ID": "rbac-forbidden"},
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "FORBIDDEN",
            "message": "Insufficient permissions",
            "request_id": "rbac-forbidden",
        }
    }


def test_jwt_role_and_metadata_cannot_override_database_user_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _rbac_client(session, monkeypatch)

    # The shared helper puts ADMIN in both the JWT role and user_metadata claims.
    response = client.get(
        "/test-require-admin",
        headers={"Authorization": f"Bearer {_token(role='ADMIN')}"},
    )

    assert response.status_code == 403
    session.get.assert_awaited_once_with(Profile, _USER_ID)


@pytest.mark.parametrize("profile", [None, _profile(is_deleted=True)])
def test_missing_or_deleted_profile_remains_unauthenticated(
    monkeypatch: pytest.MonkeyPatch,
    profile: Profile | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = profile
    client = _rbac_client(session, monkeypatch)

    response = client.get(
        "/test-require-admin",
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    session.get.assert_awaited_once_with(Profile, _USER_ID)
    session.add.assert_not_called()


def test_profile_role_change_is_used_on_the_next_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.side_effect = [_profile(role="USER"), _profile(role="ADMIN")]
    client = _rbac_client(session, monkeypatch)
    headers = {"Authorization": f"Bearer {_token()}"}

    denied = client.get("/test-require-admin", headers=headers)
    allowed = client.get("/test-require-admin", headers=headers)

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["role"] == "ADMIN"
    assert session.get.await_count == 2


def test_authenticated_user_can_access_their_own_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _rbac_client(session, monkeypatch)

    response = client.get(
        f"/test-resources/{_OWNED_RESOURCE_ID}",
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert response.status_code == 200
    assert response.json() == {"resource_id": str(_OWNED_RESOURCE_ID)}
    session.add.assert_not_called()
    session.commit.assert_not_awaited()


def test_ownership_mismatch_records_high_risk_event_before_forbidden_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _rbac_client(session, monkeypatch)

    response = client.get(
        f"/test-resources/{_OTHER_RESOURCE_ID}",
        headers={"Authorization": f"Bearer {_token()}", "X-Request-ID": "ownership-denied"},
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "FORBIDDEN",
            "message": "Resource access is forbidden",
            "request_id": "ownership-denied",
        }
    }
    event = session.add.call_args.args[0]
    assert isinstance(event, SecurityEvent)
    assert event.event_type == "UNAUTHORIZED_ACCESS_ATTEMPT"
    assert event.actor_id == _USER_ID
    assert event.target_user_id == _OTHER_USER_ID
    assert event.risk_category == "HIGH"
    assert event.decision == "BLOCK"
    assert event.details == {
        "resource": "test_resource",
        "path": "/test-resources/{resource_id}",
        "method": "GET",
    }
    session.commit.assert_awaited_once()


def test_client_supplied_owner_id_cannot_override_resource_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _rbac_client(session, monkeypatch)

    response = client.get(
        f"/test-resources/{_OTHER_RESOURCE_ID}?owner_id={_USER_ID}",
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert response.status_code == 403
    event = session.add.call_args.args[0]
    assert isinstance(event, SecurityEvent)
    assert event.actor_id == _USER_ID
    assert event.target_user_id == _OTHER_USER_ID


def test_unauthenticated_ownership_request_keeps_401_and_records_no_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _rbac_client(session, monkeypatch)

    response = client.get(f"/test-resources/{_OTHER_RESOURCE_ID}")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    session.add.assert_not_called()
    session.commit.assert_not_awaited()
