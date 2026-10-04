"""API tests for verifying authenticator enrollment."""

import base64
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pyotp
import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal
from app.core import mfa_secrets
from app.core.clock import FixedClock
from app.core.config import Settings
from app.core.mfa_secrets import encrypt_totp_secret
from app.db.models.mfa_credential import MfaCredential
from app.db.models.security_event import SecurityEvent
from app.main import create_app
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("4d9603c7-2077-4aa1-8afd-530c5207507f")
_OTHER_USER_ID = UUID("c2451875-7895-4610-89e7-2a4931383c19")
_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_KEY = b"e" * 32
_VERIFIED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _settings() -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(_KEY).decode("ascii")),
    )


def _credential(*, enabled: bool = False) -> MfaCredential:
    return MfaCredential(
        user_id=_USER_ID,
        secret_ciphertext=encrypt_totp_secret(_SECRET, settings=_settings()),
        verified_at=_VERIFIED_AT if enabled else None,
        enabled=enabled,
    )


def _session(*, credential: MfaCredential | None = None) -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    profile_result = MagicMock()
    profile_result.first.return_value = object()
    credential_result = MagicMock()
    credential_result.first.return_value = credential
    session.scalars.side_effect = [profile_result, credential_result]
    return session


def _client(
    session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_id: UUID = _USER_ID,
) -> TestClient:
    settings = _settings()
    principal = AuthenticatedPrincipal(user_id, "user@example.test", "USER")
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: settings)
    app = create_app(settings)

    async def current_user() -> AuthenticatedPrincipal:
        return principal

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    async def fixed_clock() -> FixedClock:
        return FixedClock(_VERIFIED_AT)

    app.dependency_overrides[deps.get_current_user] = current_user
    app.dependency_overrides[deps.get_db_session] = override_session
    app.dependency_overrides[deps.get_clock] = fixed_clock
    return TestClient(app)


def _security_events(session: AsyncMock) -> list[SecurityEvent]:
    return [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], SecurityEvent)
    ]


def test_valid_code_enables_enrollment_with_sanitized_response_and_event(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    credential = _credential()
    session = _session(credential=credential)
    client = _client(session, monkeypatch)
    code = pyotp.TOTP(_SECRET).at(_VERIFIED_AT)
    caplog.set_level(logging.INFO)

    response = client.post("/auth/mfa/totp/enrollment/verify", json={"code": code})

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"enrollment_status", "verified_at"}
    assert body["enrollment_status"] == "verified"
    assert body["verified_at"] == _VERIFIED_AT.isoformat().replace("+00:00", "Z")
    assert code not in response.text
    assert _SECRET not in response.text
    assert credential.enabled is True
    assert credential.verified_at == _VERIFIED_AT
    assert len(_security_events(session)) == 1
    event = _security_events(session)[0]
    assert event.event_type == "MFA_TOTP_ENROLLMENT_VERIFICATION_SUCCEEDED"
    assert event.actor_id == _USER_ID
    assert event.details == {}
    assert code not in caplog.text
    assert _SECRET not in caplog.text
    assert session.commit.await_count == 1
    session.begin.assert_not_called()
    session.begin_nested.assert_not_called()


def test_invalid_code_keeps_pending_credential_and_records_empty_details(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    credential = _credential()
    original_ciphertext = credential.secret_ciphertext
    session = _session(credential=credential)
    client = _client(session, monkeypatch)
    code = "000000" if pyotp.TOTP(_SECRET).at(_VERIFIED_AT) != "000000" else "000001"
    caplog.set_level(logging.INFO)

    response = client.post("/auth/mfa/totp/enrollment/verify", json={"code": code})

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "MFA enrollment verification failed."
    assert credential.enabled is False
    assert credential.verified_at is None
    assert credential.secret_ciphertext == original_ciphertext
    assert _security_events(session)[0].details == {}
    assert _security_events(session)[0].event_type == "MFA_TOTP_ENROLLMENT_VERIFICATION_FAILED"
    assert code not in caplog.text
    assert _SECRET not in caplog.text


@pytest.mark.parametrize(
    "payload",
    [
        {"code": "12345"},
        {"code": "1234567"},
        {"code": "12a456"},
        {"code": 123456},
        {"code": "123456", "user_id": str(_OTHER_USER_ID)},
        {"code": "123456", "secret": _SECRET},
    ],
)
def test_invalid_or_extra_request_fields_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    client = _client(_session(credential=_credential()), monkeypatch)

    response = client.post("/auth/mfa/totp/enrollment/verify", json=payload)

    assert response.status_code == 422


def test_missing_credential_is_handled_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(credential=None)
    client = _client(session, monkeypatch)

    response = client.post(
        "/auth/mfa/totp/enrollment/verify",
        json={"code": pyotp.TOTP(_SECRET).at(_VERIFIED_AT)},
    )

    assert response.status_code == 404
    assert response.json()["error"]["message"] == "MFA enrollment verification failed."
    assert _security_events(session)[0].details == {}
    session.commit.assert_awaited_once()


def test_already_enabled_credential_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = _credential(enabled=True)
    original_ciphertext = credential.secret_ciphertext
    session = _session(credential=credential)
    client = _client(session, monkeypatch)

    response = client.post(
        "/auth/mfa/totp/enrollment/verify",
        json={"code": pyotp.TOTP(_SECRET).at(_VERIFIED_AT)},
    )

    assert response.status_code == 409
    assert credential.enabled is True
    assert credential.verified_at == _VERIFIED_AT
    assert credential.secret_ciphertext == original_ciphertext
    assert _security_events(session)[0].details == {}


def test_another_users_credential_cannot_be_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(credential=None)
    client = _client(session, monkeypatch)

    response = client.post(
        "/auth/mfa/totp/enrollment/verify",
        json={"code": pyotp.TOTP(_SECRET).at(_VERIFIED_AT), "user_id": str(_OTHER_USER_ID)},
    )

    assert response.status_code == 422
    session.scalars.assert_not_awaited()


def test_decryption_failure_has_same_safe_verification_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = MfaCredential(
        user_id=_USER_ID,
        secret_ciphertext=b"not-valid-ciphertext",
        verified_at=None,
        enabled=False,
    )
    session = _session(credential=credential)
    client = _client(session, monkeypatch)

    response = client.post(
        "/auth/mfa/totp/enrollment/verify",
        json={"code": pyotp.TOTP(_SECRET).at(_VERIFIED_AT)},
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "MFA enrollment verification failed."
    assert credential.enabled is False
    assert credential.verified_at is None
    assert _security_events(session)[0].details == {}


def test_unauthenticated_verification_is_rejected() -> None:
    app = create_app(_settings())

    response = TestClient(app).post("/auth/mfa/totp/enrollment/verify", json={"code": "123456"})

    assert response.status_code == 401
