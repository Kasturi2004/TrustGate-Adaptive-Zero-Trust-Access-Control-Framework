"""Tests for the authenticated current-user endpoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID

import jwt
import pytest
from app.api import deps
from app.core import jwt as jwt_module
from app.core.config import Settings
from app.db.models.profile import Profile
from app.main import create_app
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from sqlalchemy.ext.asyncio import AsyncSession

_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "auth-me-test-key"
_SUPABASE_URL = "https://test-project.supabase.co"
_USER_ID = UUID("07b4812d-6615-40fd-84e0-9612a7fc1b12")
_OTHER_USER_ID = UUID("a87173a6-708e-459c-a1d8-3b61f7ce2a4a")
_FUTURE_EXPIRY = 2_000_000_000


def _settings() -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url=_SUPABASE_URL,
    )


def _token(user_id: UUID = _USER_ID, *, role: str = "ADMIN") -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "session_id": str(user_id),
            "aud": "authenticated",
            "iss": f"{_SUPABASE_URL}/auth/v1",
            "exp": _FUTURE_EXPIRY,
            "role": role,
            "user_metadata": {"role": role},
        },
        _TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": _TEST_KID},
    )


def _profile(
    *, email: str | None = "user@example.test", role: str = "USER", is_deleted: bool = False
) -> Profile:
    return cast(
        Profile,
        SimpleNamespace(id=_USER_ID, email=email, role=role, is_deleted=is_deleted),
    )


def _client(session: AsyncMock, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    settings = _settings()
    monkeypatch.setattr(jwt_module, "get_settings", lambda: settings)
    test_jwk = ECAlgorithm.to_jwk(_TEST_PRIVATE_KEY.public_key(), as_dict=True)
    test_jwk.update({"kid": _TEST_KID, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    monkeypatch.setattr(PyJWKClient, "fetch_data", lambda _client: {"keys": [test_jwk]})
    jwt_module._jwks_client.cache_clear()
    application = create_app(settings)

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    application.dependency_overrides[deps.get_db_session] = override_session
    return TestClient(application)


def test_valid_authenticated_request_returns_profile_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _client(session, monkeypatch)

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 200
    assert response.json() == {
        "id": str(_USER_ID),
        "email": "user@example.test",
        "role": "USER",
    }
    assert set(response.json()) == {"id", "email", "role"}
    session.get.assert_awaited_once_with(Profile, _USER_ID)


def test_profile_role_is_used_instead_of_jwt_role(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _client(session, monkeypatch)

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {_token(role='ADMIN')}"},
    )

    assert response.status_code == 200
    assert response.json()["role"] == "USER"


def test_missing_authorization_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _client(session, monkeypatch)

    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    session.get.assert_not_awaited()


@pytest.mark.parametrize("authorization", ["Bearer malformed", "Basic token", "Bearer"])
def test_malformed_or_invalid_bearer_token_returns_401(
    monkeypatch: pytest.MonkeyPatch,
    authorization: str,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _client(session, monkeypatch)

    response = client.get("/auth/me", headers={"Authorization": authorization})

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    session.get.assert_not_awaited()


@pytest.mark.parametrize("profile", [None, _profile(is_deleted=True)])
def test_missing_or_deleted_profile_returns_401(
    monkeypatch: pytest.MonkeyPatch,
    profile: Profile | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = profile
    client = _client(session, monkeypatch)

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    session.get.assert_awaited_once_with(Profile, _USER_ID)


def test_client_supplied_user_id_does_not_change_authenticated_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile()
    client = _client(session, monkeypatch)

    response = client.get(
        f"/auth/me?user_id={_OTHER_USER_ID}",
        headers={"Authorization": f"Bearer {_token()}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == str(_USER_ID)
    session.get.assert_awaited_once_with(Profile, _USER_ID)
