"""Unit tests for the current-user FastAPI dependency."""

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Annotated, cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import jwt
import pytest
from app.api import deps
from app.core import jwt as jwt_module
from app.core.config import Settings
from app.db.models.profile import Profile
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from sqlalchemy.ext.asyncio import AsyncSession

_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "auth-dependency-test-key"
_USER_ID = UUID("e77184cf-0f33-44cf-9ec1-0789a66c2cab")
_OTHER_USER_ID = UUID("f7ece3de-0143-415f-bd7e-1976202be976")
_FUTURE_EXPIRY = 2_000_000_000


def _settings() -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url="https://test-project.supabase.co",
    )


def _token(user_id: UUID = _USER_ID, *, role: str = "ADMIN") -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "aud": "authenticated",
            "iss": "https://test-project.supabase.co/auth/v1",
            "exp": _FUTURE_EXPIRY,
            "role": role,
            "user_metadata": {"role": role},
        },
        _TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": _TEST_KID},
    )


def _profile(
    user_id: UUID = _USER_ID,
    *,
    email: str | None = "user@example.test",
    role: str = "USER",
    is_deleted: bool = False,
) -> Profile:
    return cast(
        Profile,
        SimpleNamespace(id=user_id, email=email, role=role, is_deleted=is_deleted),
    )


def _client(
    session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    from app.main import create_app

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

    @application.get("/test-current-user")
    async def read_current_user(
        current_user: Annotated[deps.AuthenticatedPrincipal, Depends(deps.get_current_user)],
        user_id: UUID | None = None,
    ) -> dict[str, str | None]:
        return {
            "id": str(current_user.id),
            "email": current_user.email,
            "role": current_user.role,
            "client_user_id": str(user_id) if user_id is not None else None,
        }

    return TestClient(application)


def test_missing_authorization_returns_generic_401_and_bearer_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _client(session, monkeypatch)

    response = client.get("/test-current-user")

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"
    session.get.assert_not_awaited()


@pytest.mark.parametrize("authorization", ["Basic abc", "Bearer", "Bearer "])
def test_malformed_authorization_returns_401(
    monkeypatch: pytest.MonkeyPatch,
    authorization: str,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _client(session, monkeypatch)

    response = client.get(
        "/test-current-user",
        headers={"Authorization": authorization},
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"
    session.get.assert_not_awaited()


def test_invalid_jwt_returns_401_without_profile_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    client = _client(session, monkeypatch)

    response = client.get("/test-current-user", headers={"Authorization": "Bearer invalid"})

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"
    session.get.assert_not_awaited()
    assert "JWT" not in response.text


def test_valid_jwt_loads_profile_and_uses_database_role_not_jwt_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(role="USER")
    client = _client(session, monkeypatch)

    response = client.get(
        "/test-current-user",
        headers={"Authorization": f"Bearer {_token(role='ADMIN')}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": str(_USER_ID),
        "email": "user@example.test",
        "role": "USER",
        "client_user_id": None,
    }
    session.get.assert_awaited_once_with(Profile, _USER_ID)
    session.commit.assert_not_awaited()


def test_missing_profile_returns_generic_401(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = None
    client = _client(session, monkeypatch)

    response = client.get("/test-current-user", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"
    session.get.assert_awaited_once_with(Profile, _USER_ID)
    session.commit.assert_not_awaited()


def test_deleted_profile_returns_generic_401(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile(is_deleted=True)
    client = _client(session, monkeypatch)

    response = client.get("/test-current-user", headers={"Authorization": f"Bearer {_token()}"})

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Not authenticated"
    assert response.headers["www-authenticate"] == "Bearer"
    assert "deleted" not in response.text.lower()
    session.commit.assert_not_awaited()


def test_client_supplied_user_id_cannot_override_verified_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile()
    client = _client(session, monkeypatch)

    response = client.get(
        f"/test-current-user?user_id={_OTHER_USER_ID}",
        headers={"Authorization": f"Bearer {_token(user_id=_USER_ID)}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == str(_USER_ID)
    assert response.json()["client_user_id"] == str(_OTHER_USER_ID)
    session.get.assert_awaited_once_with(Profile, _USER_ID)
    session.commit.assert_not_awaited()


def test_current_user_dependency_uses_injected_session_without_creating_or_committing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile()
    client = _client(session, monkeypatch)
    create_engine = Mock(side_effect=AssertionError("current-user dependency created an engine"))
    monkeypatch.setattr(deps, "create_db_engine", create_engine)
    token = _token()

    response = client.get("/test-current-user", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    session.get.assert_awaited_once_with(Profile, _USER_ID)
    session.commit.assert_not_awaited()
    create_engine.assert_not_called()


def test_profile_lookup_uses_only_verified_jwt_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    session.get.return_value = _profile()
    client = _client(session, monkeypatch)

    response = client.get(
        f"/test-current-user?user_id={_OTHER_USER_ID}",
        headers={"Authorization": f"Bearer {_token(user_id=_USER_ID)}"},
    )

    assert response.status_code == 200
    session.get.assert_awaited_once_with(Profile, _USER_ID)
    session.commit.assert_not_awaited()
