"""API tests for TOTP verification against persisted STEP_UP challenges."""

import base64
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pyotp
import pytest
from app.api import deps
from app.api.deps import AuthenticatedPrincipal
from app.core import mfa_secrets
from app.core import rate_limit as rate_limit_module
from app.core.clock import FixedClock
from app.core.config import Settings
from app.core.mfa_secrets import encrypt_totp_secret
from app.core.rate_limit import mfa_ip_rate_limit_key, mfa_user_rate_limit_key
from app.db.models.mfa_credential import MfaCredential
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.security_event import SecurityEvent
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.main import create_app
from app.services.context import client_ip as client_ip_module
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("4d9603c7-2077-4aa1-8afd-530c5207507f")
_CHALLENGE_ID = UUID("a5f6ff99-5a68-43c4-b490-90622c6a721e")
_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_KEY = b"e" * 32
_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _settings() -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        rate_limit_key_secret="step-up-test-rate-limit-secret",
        totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(_KEY).decode("ascii")),
    )


def _credential(
    *,
    enabled: bool = True,
    verified: bool = True,
    last_accepted_time_step: int | None = None,
) -> MfaCredential:
    return MfaCredential(
        user_id=_USER_ID,
        secret_ciphertext=encrypt_totp_secret(_SECRET, settings=_settings()),
        verified_at=_NOW if verified else None,
        enabled=enabled,
        last_accepted_time_step=last_accepted_time_step,
    )


def _challenge(*, status: str = "PENDING", expires_at: datetime | None = None) -> OtpChallenge:
    return OtpChallenge(
        id=_CHALLENGE_ID,
        access_request_id=uuid4(),
        user_id=_USER_ID,
        otp_hash=None,
        status=status,
        attempt_count=0,
        max_attempts=3,
        created_at=_NOW - timedelta(minutes=1),
        expires_at=expires_at or _NOW + timedelta(minutes=5),
    )


def _client(
    session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    *,
    authenticated: bool = True,
) -> TestClient:
    settings = _settings()
    principal = AuthenticatedPrincipal(_USER_ID, "user@example.test", "USER")
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: settings)
    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: settings)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: settings)
    app = create_app(settings)
    app.state.rate_limit_calls = []

    async def consume_attempt(
        _repository: RateLimitStateRepository,
        key: str,
        current_time: datetime,
        attempt_limit: int,
        window_duration: timedelta,
    ) -> bool:
        app.state.rate_limit_calls.append((key, current_time, attempt_limit, window_duration))
        return True

    monkeypatch.setattr(RateLimitStateRepository, "consume_attempt", consume_attempt)

    async def current_user() -> AuthenticatedPrincipal:
        return principal

    async def override_session() -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, session)

    async def fixed_clock() -> FixedClock:
        return FixedClock(_NOW)

    if authenticated:
        app.dependency_overrides[deps.get_current_user] = current_user
    app.dependency_overrides[deps.get_db_session] = override_session
    app.dependency_overrides[deps.get_clock] = fixed_clock
    return TestClient(app, client=("127.0.0.1", 50000))


def _session(
    challenge: OtpChallenge | None,
    credential: MfaCredential | None,
) -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    state = {"challenge": challenge, "credential": credential}

    async def scalars(statement: object, *_args: object, **_kwargs: object) -> MagicMock:
        query = str(statement)
        result = MagicMock()
        if "otp_challenges" in query:
            result.first.return_value = state["challenge"]
        elif "public.profiles" in query:
            result.first.return_value = object()
        elif "mfa_credentials" in query:
            result.first.return_value = state["credential"]
        elif "access_requests" in query and query.lstrip().startswith("UPDATE"):
            result.first.return_value = object()
        else:
            raise AssertionError(f"Unexpected MFA test query: {query}")
        return result

    session.scalars.side_effect = scalars
    session.mfa_test_state = state
    session.get.return_value = credential
    return session


def _app(client: TestClient) -> FastAPI:
    return cast(FastAPI, client.app)


def _events(session: AsyncMock) -> list[SecurityEvent]:
    return [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], SecurityEvent)
    ]


def test_valid_code_completes_challenge_and_records_authorization_events(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    challenge = _challenge()
    session = _session(challenge, _credential())
    client = _client(session, monkeypatch)
    code = pyotp.TOTP(_SECRET).at(_NOW)
    caplog.set_level(logging.INFO)

    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(_CHALLENGE_ID), "code": code},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "verification_status": "verified",
        "verified_at": _NOW.isoformat().replace("+00:00", "Z"),
    }
    assert challenge.status == "SUCCESS"
    assert challenge.verified_at == _NOW
    assert challenge.attempt_count == 0
    assert session.mfa_test_state["credential"].last_accepted_time_step == pyotp.TOTP(
        _SECRET, digits=6, interval=30
    ).timecode(_NOW)
    assert [event.event_type for event in _events(session)] == [
        "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
        "ACCESS_MFA_ALLOWED",
    ]
    assert _events(session)[0].details == {}
    assert _events(session)[1].decision == "ALLOW"
    assert _events(session)[1].details == {}
    assert code not in response.text + caplog.text
    assert _SECRET not in response.text + caplog.text
    assert all(
        key not in response.text + caplog.text for key, *_ in _app(client).state.rate_limit_calls
    )
    assert session.commit.await_count == 2


def test_invalid_code_consumes_challenge_attempt_and_locks_at_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = _challenge()
    challenge.attempt_count = 2
    session = _session(challenge, _credential())
    client = _client(session, monkeypatch)
    code = "000000" if pyotp.TOTP(_SECRET).at(_NOW) != "000000" else "000001"

    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(_CHALLENGE_ID), "code": code},
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "MFA verification failed."
    assert response.headers["cache-control"] == "no-store"
    assert challenge.attempt_count == 3
    assert challenge.status == "LOCKED"
    assert session.mfa_test_state["credential"].last_accepted_time_step is None
    lock_events = [event for event in _events(session) if event.event_type == "MFA_LOCKED"]
    assert len(lock_events) == 1
    assert lock_events[0].actor_id == _USER_ID
    assert lock_events[0].access_request_id == challenge.access_request_id
    assert lock_events[0].details == {}
    assert sum(event.event_type == "MFA_LOCKED" for event in _events(session)) == 1
    failed_events = [
        event
        for event in _events(session)
        if event.event_type == "MFA_TOTP_STEP_UP_VERIFICATION_FAILED"
    ]
    assert len(failed_events) == 1
    assert failed_events[0].actor_id == _USER_ID
    assert failed_events[0].access_request_id == challenge.access_request_id
    assert failed_events[0].details == {}
    assert all(event.event_type != "MFA_EXPIRED" for event in _events(session))

    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(_CHALLENGE_ID), "code": code},
    )
    assert response.status_code == 400
    assert sum(event.event_type == "MFA_LOCKED" for event in _events(session)) == 1

    event_details = repr(lock_events[0].details)
    assert _SECRET not in event_details
    assert code not in event_details
    assert challenge.otp_hash is None or challenge.otp_hash not in event_details


def test_invalid_code_below_lock_threshold_does_not_record_lock_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = _challenge()
    challenge.attempt_count = 1
    session = _session(challenge, _credential())
    client = _client(session, monkeypatch)
    code = "000000" if pyotp.TOTP(_SECRET).at(_NOW) != "000000" else "000001"

    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(_CHALLENGE_ID), "code": code},
    )

    assert response.status_code == 400
    assert challenge.attempt_count == 2
    assert challenge.status == "PENDING"
    failed_events = [
        event
        for event in _events(session)
        if event.event_type == "MFA_TOTP_STEP_UP_VERIFICATION_FAILED"
    ]
    assert len(failed_events) == 1
    assert failed_events[0].actor_id == _USER_ID
    assert failed_events[0].access_request_id == challenge.access_request_id
    assert failed_events[0].details == {}
    assert all(event.event_type != "MFA_LOCKED" for event in _events(session))


@pytest.mark.parametrize(
    ("challenge", "credential"),
    [
        (None, _credential()),
        (_challenge(status="SUCCESS"), _credential()),
        (_challenge(status="LOCKED"), _credential()),
        (_challenge(expires_at=_NOW), _credential()),
        (_challenge(), None),
        (_challenge(), _credential(enabled=False)),
        (_challenge(), _credential(verified=False)),
    ],
)
def test_unavailable_challenge_or_credential_records_only_applicable_audit_events(
    monkeypatch: pytest.MonkeyPatch,
    challenge: OtpChallenge | None,
    credential: MfaCredential | None,
) -> None:
    if credential is not None:
        credential.last_accepted_time_step = 123
    session = _session(challenge, credential)
    client = _client(session, monkeypatch)

    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(_CHALLENGE_ID),
            "code": pyotp.TOTP(_SECRET).at(_NOW),
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["message"] == "MFA verification failed."
    if challenge is not None and challenge.expires_at <= _NOW:
        assert challenge.status == "EXPIRED"
    assert sum(event.event_type == "MFA_EXPIRED" for event in _events(session)) == int(
        challenge is not None and challenge.status == "EXPIRED"
    )
    assert all(event.event_type != "MFA_LOCKED" for event in _events(session))
    expected_failed_event = (
        challenge is not None
        and challenge.status == "PENDING"
        and (credential is None or not credential.enabled or credential.verified_at is None)
    )
    failed_events = [
        event
        for event in _events(session)
        if event.event_type == "MFA_TOTP_STEP_UP_VERIFICATION_FAILED"
    ]
    assert len(failed_events) == int(expected_failed_event)
    if expected_failed_event:
        assert failed_events[0].actor_id == _USER_ID
        assert failed_events[0].access_request_id == challenge.access_request_id
        assert failed_events[0].details == {}
    assert credential is None or credential.last_accepted_time_step == 123


def test_expired_challenge_records_one_associated_expiry_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = _challenge(expires_at=_NOW)
    session = _session(challenge, _credential())
    client = _client(session, monkeypatch)

    for _ in range(2):
        response = client.post(
            "/auth/mfa/totp/step-up/verify",
            json={
                "mfa_challenge_id": str(_CHALLENGE_ID),
                "code": pyotp.TOTP(_SECRET).at(_NOW),
            },
        )
        assert response.status_code == 400

    expiry_events = [event for event in _events(session) if event.event_type == "MFA_EXPIRED"]
    assert len(expiry_events) == 1
    assert expiry_events[0].actor_id == _USER_ID
    assert expiry_events[0].access_request_id == challenge.access_request_id
    assert expiry_events[0].details == {}
    assert all(
        event.event_type != "MFA_TOTP_STEP_UP_VERIFICATION_FAILED" for event in _events(session)
    )
    assert challenge.status == "EXPIRED"
    event_details = repr(expiry_events[0].details)
    assert _SECRET not in event_details
    assert challenge.otp_hash is None or challenge.otp_hash not in event_details


def test_same_time_step_is_rejected_on_a_second_pending_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_challenge = _challenge()
    credential = _credential()
    session = _session(first_challenge, credential)
    client = _client(session, monkeypatch)
    code = pyotp.TOTP(_SECRET).at(_NOW)

    first = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(first_challenge.id), "code": code},
    )
    assert first.status_code == 200
    accepted_step = pyotp.TOTP(_SECRET).timecode(_NOW)

    second_challenge = _challenge()
    second_challenge.id = uuid4()
    session.mfa_test_state["challenge"] = second_challenge
    second = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(second_challenge.id), "code": code},
    )

    assert second.status_code == 400
    assert second.json()["error"]["message"] == "MFA verification failed."
    assert credential.last_accepted_time_step == accepted_step
    assert second_challenge.attempt_count == 1
    assert second_challenge.status == "PENDING"


def test_invalid_payload_and_unauthenticated_request_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _session(_challenge(), _credential())
    client = _client(session, monkeypatch)
    invalid = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": "not-a-uuid", "code": "123456"},
    )
    assert invalid.status_code == 422
    assert _app(client).state.rate_limit_calls == []

    unauthenticated = _client(
        _session(_challenge(), _credential()), monkeypatch, authenticated=False
    )
    response = unauthenticated.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(_CHALLENGE_ID), "code": "123456"},
    )
    assert response.status_code == 401


def test_persistence_failure_rolls_back_challenge_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = _challenge()
    session = _session(challenge, _credential())
    session.commit.side_effect = [None, RuntimeError("database write failed")]
    client = _client(session, monkeypatch)

    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(_CHALLENGE_ID),
            "code": pyotp.TOTP(_SECRET).at(_NOW),
        },
    )

    assert response.status_code == 500
    session.rollback.assert_awaited_once()


def test_rate_limit_uses_existing_mfa_user_and_ip_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(_session(_challenge(), _credential()), monkeypatch)
    response = client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(_CHALLENGE_ID),
            "code": pyotp.TOTP(_SECRET).at(_NOW),
        },
    )
    assert response.status_code == 200
    calls = _app(client).state.rate_limit_calls
    expected_keys = {
        mfa_user_rate_limit_key(_USER_ID, window="15m", settings=_settings()),
        mfa_user_rate_limit_key(_USER_ID, window="24h", settings=_settings()),
        mfa_ip_rate_limit_key("127.0.0.1", settings=_settings()),
    }
    assert {call[0] for call in calls} == expected_keys
    assert {call[2:] for call in calls} == {
        (5, timedelta(minutes=15)),
        (10, timedelta(hours=24)),
        (60, timedelta(minutes=15)),
    }
