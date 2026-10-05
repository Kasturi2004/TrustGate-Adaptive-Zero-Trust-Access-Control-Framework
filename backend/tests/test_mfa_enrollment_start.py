"""API tests for starting authenticator enrollment."""

import base64
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import pyotp
import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal
from app.api.routes import mfa as mfa_routes
from app.core import mfa_secrets
from app.core.config import Settings
from app.core.mfa_secrets import decrypt_totp_secret, encrypt_totp_secret
from app.db.models.mfa_credential import MfaCredential
from app.db.models.security_event import SecurityEvent
from app.main import create_app
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("4d9603c7-2077-4aa1-8afd-530c5207507f")
_OTHER_USER_ID = UUID("c2451875-7895-4610-89e7-2a4931383c19")
_EMAIL = "user@example.test"
_KEY = b"e" * 32


def _settings() -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(_KEY).decode("ascii")),
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
    email: str | None = _EMAIL,
) -> TestClient:
    settings = _settings()
    principal = AuthenticatedPrincipal(user_id, email, "USER")
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: settings)
    app = create_app(settings)

    async def current_user() -> AuthenticatedPrincipal:
        return principal

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    app.dependency_overrides[deps.get_current_user] = current_user
    app.dependency_overrides[deps.get_db_session] = override_session
    return TestClient(app)


def _mfa_records(session: AsyncMock) -> list[MfaCredential]:
    return [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], MfaCredential)
    ]


def _security_events(session: AsyncMock) -> list[SecurityEvent]:
    return [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], SecurityEvent)
    ]


def test_authenticated_user_starts_enrollment_without_selecting_user(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    session = _session()
    client = _client(session, monkeypatch)
    caplog.set_level(logging.INFO)

    response = client.post(
        "/auth/mfa/totp/enrollment",
        json={"user_id": str(_OTHER_USER_ID)},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"otpauth_uri", "manual_entry_key"}
    assert response.headers["cache-control"] == "no-store"
    secret = body["manual_entry_key"]
    uri = body["otpauth_uri"]
    parsed_uri = urlparse(uri)
    totp = pyotp.parse_uri(uri)
    assert parsed_uri.scheme == "otpauth"
    assert parsed_uri.netloc == "totp"
    assert totp.issuer == "TrustGate"
    assert totp.name == _EMAIL
    assert totp.digits == 6
    assert getattr(totp, "interval", None) == 30
    assert parse_qs(parsed_uri.query)["secret"] == [secret]

    records = _mfa_records(session)
    assert len(records) == 1
    credential = records[0]
    assert credential.user_id == _USER_ID
    assert credential.secret_ciphertext != secret.encode()
    assert secret.encode() not in credential.secret_ciphertext
    assert decrypt_totp_secret(credential.secret_ciphertext, settings=_settings()) == secret
    assert credential.verified_at is None
    assert credential.enabled is False
    assert credential.last_accepted_time_step is None

    events = _security_events(session)
    assert len(events) == 1
    assert events[0].event_type == "MFA_TOTP_ENROLLMENT_STARTED"
    assert events[0].actor_id == _USER_ID
    assert events[0].details == {}
    assert secret not in caplog.text
    assert uri not in caplog.text
    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()
    session.begin.assert_not_called()
    session.begin_nested.assert_not_called()


def test_repeated_start_replaces_only_pending_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    existing = MfaCredential(
        user_id=_USER_ID,
        secret_ciphertext=encrypt_totp_secret(previous_secret, settings=_settings()),
        verified_at=None,
        enabled=False,
        last_accepted_time_step=123,
    )
    session = _session(credential=existing)
    client = _client(session, monkeypatch)

    response = client.post("/auth/mfa/totp/enrollment")

    assert response.status_code == 200
    new_secret = response.json()["manual_entry_key"]
    assert new_secret != previous_secret
    assert existing.secret_ciphertext != encrypt_totp_secret(previous_secret, settings=_settings())
    assert decrypt_totp_secret(existing.secret_ciphertext, settings=_settings()) == new_secret
    assert existing.verified_at is None
    assert existing.enabled is False
    assert existing.last_accepted_time_step is None
    assert _mfa_records(session) == []
    assert len(_security_events(session)) == 1
    session.commit.assert_awaited_once()


def test_enabled_credential_is_rejected_without_modification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    ciphertext = encrypt_totp_secret(secret, settings=_settings())
    existing = MfaCredential(
        user_id=_USER_ID,
        secret_ciphertext=ciphertext,
        verified_at=datetime.now(UTC),
        enabled=True,
    )
    session = _session(credential=existing)
    client = _client(session, monkeypatch)

    response = client.post("/auth/mfa/totp/enrollment")

    assert response.status_code == 409
    assert response.json()["error"]["message"] == "MFA enrollment cannot be started."
    assert existing.secret_ciphertext == ciphertext
    assert existing.enabled is True
    assert existing.verified_at is not None
    assert _mfa_records(session) == []
    assert _security_events(session) == []
    session.commit.assert_not_awaited()


def test_encryption_failure_returns_safe_error_and_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session()
    client = _client(session, monkeypatch)
    monkeypatch.setattr(
        mfa_routes,
        "encrypt_totp_secret",
        lambda _secret: (_ for _ in ()).throw(RuntimeError("private encryption key detail")),
    )

    response = client.post("/auth/mfa/totp/enrollment")

    assert response.status_code == 500
    assert response.json()["error"]["message"] == "An unexpected error occurred."
    assert "private encryption key detail" not in response.text
    assert _mfa_records(session) == []
    assert _security_events(session) == []
    session.commit.assert_not_awaited()
    session.rollback.assert_awaited_once()


def test_unauthenticated_enrollment_is_rejected() -> None:
    app = create_app(_settings())

    response = TestClient(app).post("/auth/mfa/totp/enrollment")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
