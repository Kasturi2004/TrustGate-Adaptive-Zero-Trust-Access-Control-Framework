"""Tests enforcing authenticator onboarding for newly registered profiles."""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal, require_onboarded_user
from app.core.config import Settings
from app.db.models.mfa_credential import MfaCredential
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("4b7e0ee4-a7be-4827-b93c-06689396b7ce")
_PRINCIPAL = AuthenticatedPrincipal(
    id=_USER_ID,
    email="employee@example.test",
    role="USER",
    session_id=UUID("cb3d4fae-11a5-4c47-b682-3a11d20a0a44"),
)
_PENDING_PRINCIPAL = AuthenticatedPrincipal(
    id=_USER_ID,
    email="employee@example.test",
    role="USER",
    session_id=UUID("cb3d4fae-11a5-4c47-b682-3a11d20a0a44"),
    authenticator_required=True,
)


@pytest.mark.parametrize("path", ["/access/evaluate", "/resources/employee-handbook"])
def test_pending_signup_cannot_call_protected_access_routes(path: str) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = None
    application = create_app(Settings(app_env="test", cors_allowed_origin="http://localhost:5173"))
    application.dependency_overrides[deps.require_user] = lambda: _PENDING_PRINCIPAL

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    application.dependency_overrides[deps.get_db_session] = override_session
    client = TestClient(application)
    if path == "/access/evaluate":
        response = client.post(
            path,
            json={"resource_id": "employee-handbook"},
            headers={"X-Device-Token": "unit-test-device-token"},
        )
    else:
        response = client.post(
            path,
            json={"access_request_id": str(UUID(int=1))},
        )

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "Authenticator setup is required."
    assert any(call.args[0] is MfaCredential for call in session.get.await_args_list)


def test_existing_profiles_keep_their_login_and_access_path() -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = None

    principal = asyncio.run(require_onboarded_user(_PRINCIPAL, cast(AsyncSession, session)))

    assert principal == _PRINCIPAL
    assert not any(call.args[0] is MfaCredential for call in session.get.await_args_list)


def test_completed_enrollment_satisfies_the_onboarding_guard() -> None:
    session = AsyncMock(spec=AsyncSession)
    credential = MfaCredential(
        user_id=_USER_ID,
        secret_ciphertext=b"encrypted-test-only",
        enabled=True,
        verified_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    session.get.return_value = credential

    principal = asyncio.run(require_onboarded_user(_PENDING_PRINCIPAL, cast(AsyncSession, session)))

    assert principal == _PENDING_PRINCIPAL
