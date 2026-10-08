"""PostgreSQL integration coverage for the gateway's real production path."""

import asyncio
import base64
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pyotp
import pytest
from app.api.deps import AuthenticatedPrincipal
from app.api.routes import mfa as mfa_routes
from app.api.routes.access import read_operations_dashboard
from app.api.routes.devices import recognize_current_device
from app.core import mfa_secrets, rate_limit
from app.core.clock import FixedClock
from app.core.config import Settings
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.mfa_credential import MfaCredential
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.device import DeviceRepository
from app.schemas.access import ProtectedResourceRequest
from app.schemas.device import DeviceRecognitionRequest
from app.schemas.mfa import TotpStepUpVerificationRequest
from app.services.access_gateway import (
    AccessGatewayResponse,
    access_gateway,
    get_security_pipeline,
)
from app.services.context import client_ip as client_ip_module
from app.services.context.device_familiarity import device_token_hash
from app.services.context.location import UnavailableGeoResolver
from app.services.protected_resource import get_protected_resource
from fastapi import HTTPException, Response
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from tests.integration.database import (
    ScratchDatabase,
    ensure_auth_user_profile,
    remove_auth_user_profile,
)

_NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
_DEVICE_TOKEN = "real-production-pipeline-stable-device-token"
_DEVICE_SECRET = "real-production-pipeline-integration-hmac-secret"
_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_SESSION_ID = UUID("8bb02a58-97bc-4b2c-93f5-b5d267aa7614")
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    device_hash_secret=_DEVICE_SECRET,
    rate_limit_key_secret="real-production-pipeline-rate-limit-secret",
    totp_secret_encryption_key=SecretStr(
        base64.urlsafe_b64encode(b"production-pipeline-test-key-32b").decode("ascii")
    ),
)


def _request(*, scheme: str = "https") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": scheme,
            "path": "/access/evaluate",
            "raw_path": b"/access/evaluate",
            "query_string": b"",
            "headers": [
                (b"x-device-token", _DEVICE_TOKEN.encode()),
                (b"user-agent", _USER_AGENT.encode()),
            ],
            "client": ("8.8.8.8", 44321),
            "server": ("trustgate.test", 443),
        }
    )


def _run_with_committed_user(
    database: ScratchDatabase,
    operation: Callable[[AsyncSession, UUID], Awaitable[None]],
) -> None:
    user_id = uuid4()
    email = f"real-pipeline-{user_id}@integration.test"
    asyncio.run(ensure_auth_user_profile(database.url, user_id=user_id, email=email))
    try:
        database.run_in_transaction(lambda session: operation(session, user_id))
    finally:
        asyncio.run(remove_auth_user_profile(database.url, user_id=user_id))


async def _assert_user_exists(session: AsyncSession, user_id: UUID) -> None:
    profile = await session.get(Profile, user_id)
    assert profile is not None


def _principal(user_id: UUID) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(user_id, "real-pipeline@example.test", "USER", _SESSION_ID)


async def _evaluate(
    session: AsyncSession,
    *,
    user_id: UUID,
    settings: Settings = _SETTINGS,
    scheme: str = "https",
    hour: int = 12,
) -> AccessGatewayResponse:
    assert get_security_pipeline() is None
    profile = await session.get(Profile, user_id)
    assert profile is not None
    return await access_gateway(
        session=session,
        principal=_principal(user_id),
        resource=get_protected_resource("ops-dashboard"),
        device_token=_DEVICE_TOKEN,
        client_ip="8.8.8.8",
        user_agent=_USER_AGENT,
        clock=FixedClock(_NOW.replace(hour=hour)),
        request=_request(scheme=scheme),
        profile=profile,
        geo_resolver=UnavailableGeoResolver(),
        settings=settings,
    )


def test_real_pipeline_bootstraps_unknown_device_through_step_up_and_recognition(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: _SETTINGS)
    monkeypatch.setattr(rate_limit, "get_settings", lambda: _SETTINGS)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: _SETTINGS)

    async def exercise(session: AsyncSession, user_id: UUID) -> None:
        await _assert_user_exists(session, user_id)
        principal = _principal(user_id)
        session.add(
            MfaCredential(
                user_id=user_id,
                secret_ciphertext=mfa_secrets.encrypt_totp_secret(_TOTP_SECRET, settings=_SETTINGS),
                verified_at=_NOW - timedelta(days=1),
                enabled=True,
            )
        )
        await session.flush()

        first = await _evaluate(session, user_id=user_id, settings=_SETTINGS)
        assert first.decision == "STEP_UP"
        assert first.access_request_id is not None
        assert first.mfa_challenge_id is not None
        request = await session.get(AccessRequest, first.access_request_id)
        assert request is not None
        assert request.initial_decision == "STEP_UP"
        assert request.auth_session_id == _SESSION_ID
        assert request.final_outcome is None
        evaluation = await session.scalar(
            select(TrustEvaluation).where(
                TrustEvaluation.access_request_id == first.access_request_id
            )
        )
        assert evaluation is not None
        assert evaluation.trust_score == 66
        assert evaluation.risk_classification == "MEDIUM"
        challenge = await session.get(OtpChallenge, first.mfa_challenge_id)
        assert challenge is not None and challenge.status == "PENDING"
        assert not await AccessRequestRepository(session).consume_dashboard_access(
            first.access_request_id, user_id, _SESSION_ID, _NOW
        )

        verified = await mfa_routes.verify_totp_step_up(
            request=TotpStepUpVerificationRequest(
                mfa_challenge_id=challenge.id,
                code=pyotp.TOTP(_TOTP_SECRET).at(_NOW),
            ),
            http_request=_request(),
            response=Response(),
            principal=principal,
            session=session,
            clock=FixedClock(_NOW),
        )
        assert verified.verification_status == "verified"
        await session.refresh(request)
        assert request.final_outcome == "ALLOW"

        dashboard = await read_operations_dashboard(
            payload=ProtectedResourceRequest(access_request_id=first.access_request_id),
            response=Response(),
            principal=principal,
            session=session,
            clock=FixedClock(_NOW),
        )
        assert dashboard.resource_id == "ops-dashboard"
        await session.refresh(request)
        assert request.consumed_at == _NOW
        recognized = await recognize_current_device(
            DeviceRecognitionRequest(access_request_id=first.access_request_id),
            Response(),
            principal,
            _DEVICE_TOKEN,
            session,
            FixedClock(_NOW),
            _SETTINGS,
        )
        assert recognized.recognized is True
        hashed_token = device_token_hash(_DEVICE_TOKEN, settings=_SETTINGS)
        assert hashed_token is not None
        device = await DeviceRepository(session).get_by_user_and_hash(user_id, hashed_token)
        assert device is not None and device.recognized_at == _NOW

        second = await _evaluate(session, user_id=user_id)
        assert second.decision == "ALLOW"
        assert second.access_request_id is not None
        second_evaluation = await session.scalar(
            select(TrustEvaluation).where(
                TrustEvaluation.access_request_id == second.access_request_id
            )
        )
        assert second_evaluation is not None
        assert second_evaluation.trust_score == 94
        assert second_evaluation.risk_classification == "LOW"
        second_request = await session.get(AccessRequest, second.access_request_id)
        assert second_request is not None
        assert second_request.initial_decision == "ALLOW"
        assert second_request.final_outcome == "ALLOW"

        response = await read_operations_dashboard(
            payload=ProtectedResourceRequest(access_request_id=second.access_request_id),
            response=Response(),
            principal=principal,
            session=session,
            clock=FixedClock(_NOW + timedelta(seconds=1)),
        )
        assert response.status == "operational"
        await session.refresh(second_request)
        assert second_request.consumed_at == _NOW + timedelta(seconds=1)
        with pytest.raises(HTTPException) as replay:
            await read_operations_dashboard(
                payload=ProtectedResourceRequest(access_request_id=second.access_request_id),
                response=Response(),
                principal=principal,
                session=session,
                clock=FixedClock(_NOW + timedelta(seconds=2)),
            )
        assert replay.value.status_code == 403

        access_events = list(
            (
                await session.scalars(
                    select(SecurityEvent).where(
                        SecurityEvent.access_request_id.in_(
                            (first.access_request_id, second.access_request_id)
                        )
                    )
                )
            ).all()
        )
        assert any(event.event_type == "ACCESS_STEPUP" for event in access_events)
        assert any(event.event_type == "ACCESS_ALLOWED" for event in access_events)

    _run_with_committed_user(migrated_test_database, exercise)


def test_real_pipeline_blocks_poor_server_context(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession, user_id: UUID) -> None:
        await _assert_user_exists(session, user_id)
        result = await _evaluate(
            session,
            user_id=user_id,
            scheme="http",
            hour=23,
        )
        assert result.decision == "BLOCK"
        assert result.mfa_challenge_id is None
        assert result.access_request_id is not None
        evaluation = await session.scalar(
            select(TrustEvaluation).where(
                TrustEvaluation.access_request_id == result.access_request_id
            )
        )
        assert evaluation is not None
        assert evaluation.trust_score == pytest.approx(28.5)
        assert evaluation.risk_classification == "HIGH"
        request = await session.get(AccessRequest, result.access_request_id)
        assert request is not None
        assert request.final_outcome == "BLOCK"
        assert request.auth_session_id == _SESSION_ID

    _run_with_committed_user(migrated_test_database, exercise)


def test_active_policy_changes_decision_without_changing_real_trust_score(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession, user_id: UUID) -> None:
        await _assert_user_exists(session, user_id)
        hashed_token = device_token_hash(_DEVICE_TOKEN, settings=_SETTINGS)
        assert hashed_token is not None
        session.add(
            Device(
                user_id=user_id,
                device_hash=hashed_token,
                recognized_at=_NOW - timedelta(days=1),
                first_seen_at=_NOW - timedelta(days=1),
                last_seen_at=_NOW - timedelta(days=1),
            )
        )
        policy = await session.scalar(
            select(PolicyVersion).where(PolicyVersion.is_active.is_(True))
        )
        assert policy is not None
        policy.allow_threshold = Decimal("95")
        await session.flush()

        result = await _evaluate(session, user_id=user_id)
        assert result.decision == "STEP_UP"
        assert result.mfa_challenge_id is not None
        evaluation = await session.scalar(
            select(TrustEvaluation).where(
                TrustEvaluation.access_request_id == result.access_request_id
            )
        )
        assert evaluation is not None
        assert evaluation.trust_score == 94
        assert evaluation.risk_classification == "LOW"

    _run_with_committed_user(migrated_test_database, exercise)


def test_missing_device_hash_secret_fails_closed_without_access_request(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession, user_id: UUID) -> None:
        await _assert_user_exists(session, user_id)
        missing_secret_settings = Settings(
            app_env="test",
            cors_allowed_origin="http://localhost:5173",
            device_hash_secret=None,
        )
        result = await _evaluate(
            session,
            user_id=user_id,
            settings=missing_secret_settings,
        )
        assert result.decision == "BLOCK"
        assert result.access_request_id is None
        requests = list(
            (
                await session.scalars(select(AccessRequest).where(AccessRequest.user_id == user_id))
            ).all()
        )
        assert requests == []
        events = list(
            (
                await session.scalars(
                    select(SecurityEvent).where(SecurityEvent.actor_id == user_id)
                )
            ).all()
        )
        assert len(events) == 1
        assert events[0].event_type == "PIPELINE_DEGRADED_FAILSAFE"
        assert events[0].decision == "BLOCK"

    _run_with_committed_user(migrated_test_database, exercise)
