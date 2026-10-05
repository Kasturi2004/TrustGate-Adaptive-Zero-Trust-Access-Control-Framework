"""PostgreSQL persistence coverage for TOTP STEP_UP challenge verification."""

import base64
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pyotp
import pytest
from app.api.deps import AuthenticatedPrincipal
from app.api.routes import mfa as mfa_routes
from app.core import mfa_secrets
from app.core import rate_limit as rate_limit_module
from app.core.clock import FixedClock
from app.core.config import Settings
from app.core.mfa_secrets import encrypt_totp_secret
from app.core.rate_limit import mfa_user_rate_limit_key
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.mfa_credential import MfaCredential
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.rate_limit_state import RateLimitState
from app.db.models.trust_evaluation import TrustEvaluation
from app.schemas.mfa import TotpStepUpVerificationRequest
from app.services.context import client_ip as client_ip_module
from fastapi import HTTPException, Response
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from tests.integration.database import ScratchDatabase

_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    rate_limit_key_secret="mfa-step-up-integration-rate-limit-secret",
    totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(b"w" * 32).decode("ascii")),
)


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/mfa/totp/step-up/verify",
            "raw_path": b"/auth/mfa/totp/step-up/verify",
            "query_string": b"",
            "headers": [],
            "client": ("192.0.2.46", 54000),
            "server": ("testserver", 80),
        }
    )


def _configure_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: _SETTINGS)
    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _SETTINGS)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: _SETTINGS)


async def _create_challenge_records(
    session: AsyncSession,
) -> tuple[UUID, AccessRequest, OtpChallenge]:
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"mfa-step-up-{user_id}@integration.test"},
    )
    policy = PolicyVersion(
        id=uuid4(),
        version_label=f"mfa-step-up-{user_id}",
        weights_json={},
        allow_threshold=70,
        stepup_threshold=40,
        is_active=False,
    )
    session.add(policy)
    device = Device(
        id=uuid4(),
        user_id=user_id,
        device_hash=f"mfa-step-up-device-{user_id}",
        first_seen_at=_NOW,
        last_seen_at=_NOW,
    )
    session.add(device)
    await session.flush()
    access_request = AccessRequest(
        id=uuid4(),
        user_id=user_id,
        device_id=device.id,
        source_ip=IPv4Address("192.0.2.47"),
        initial_decision="STEP_UP",
        mfa_required=True,
        requested_at=_NOW,
    )
    session.add(access_request)
    await session.flush()
    evaluation = TrustEvaluation(
        id=uuid4(),
        access_request_id=access_request.id,
        policy_version_id=policy.id,
        trust_score=50,
        risk_classification="MEDIUM",
        status="COMPLETE",
        evaluated_at=_NOW,
    )
    session.add(evaluation)
    await session.flush()
    session.add(
        PolicyDecision(
            id=uuid4(),
            access_request_id=access_request.id,
            trust_evaluation_id=evaluation.id,
            policy_version_id=policy.id,
            decision="STEP_UP",
            decision_reason="Additional verification is required.",
            decided_at=_NOW,
        )
    )
    challenge = OtpChallenge(
        id=uuid4(),
        access_request_id=access_request.id,
        user_id=user_id,
        otp_hash="unused-for-totp",
        status="PENDING",
        attempt_count=0,
        max_attempts=3,
        created_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(minutes=5),
    )
    session.add(challenge)
    session.add(
        MfaCredential(
            user_id=user_id,
            secret_ciphertext=encrypt_totp_secret(_SECRET, settings=_SETTINGS),
            verified_at=_NOW - timedelta(days=1),
            enabled=True,
        )
    )
    await session.flush()
    return user_id, access_request, challenge


def test_step_up_verification_persists_success_and_rejects_replay(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)

    async def exercise(session: AsyncSession) -> None:
        user_id, access_request, challenge = await _create_challenge_records(session)
        request_id = access_request.id
        result = await mfa_routes.verify_totp_step_up(
            request=TotpStepUpVerificationRequest(
                mfa_challenge_id=challenge.id,
                code=pyotp.TOTP(_SECRET).at(_NOW),
            ),
            http_request=_request(),
            response=Response(),
            principal=AuthenticatedPrincipal(user_id, "mfa@example.test", "USER"),
            session=session,
            clock=FixedClock(_NOW),
        )
        assert result.verification_status == "verified"
        await session.refresh(challenge)
        assert challenge.status == "SUCCESS"
        assert challenge.verified_at == _NOW
        assert challenge.attempt_count == 0

        event = await session.execute(
            text(
                "SELECT details FROM public.security_events "
                "WHERE actor_id = :user_id "
                "AND access_request_id = :request_id "
                "AND event_type = 'MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED'"
            ),
            {"user_id": user_id, "request_id": request_id},
        )
        assert event.scalar_one() == {}
        limiter = await session.get(
            RateLimitState,
            mfa_user_rate_limit_key(user_id, window="15m", settings=_SETTINGS),
        )
        assert limiter is not None
        assert limiter.counter == 1

        with pytest.raises(HTTPException) as replay:
            await mfa_routes.verify_totp_step_up(
                request=TotpStepUpVerificationRequest(
                    mfa_challenge_id=challenge.id,
                    code=pyotp.TOTP(_SECRET).at(_NOW),
                ),
                http_request=_request(),
                response=Response(),
                principal=AuthenticatedPrincipal(user_id, "mfa@example.test", "USER"),
                session=session,
                clock=FixedClock(_NOW),
            )
        assert replay.value.status_code == 400
        await session.refresh(challenge)
        assert challenge.status == "SUCCESS"

    migrated_test_database.run_in_transaction(exercise)


def test_step_up_challenge_is_hidden_from_another_user(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        owner_id, _access_request, challenge = await _create_challenge_records(session)
        other_id = uuid4()
        await session.execute(
            text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
            {"id": other_id, "email": f"mfa-step-up-other-{other_id}@integration.test"},
        )
        from app.db.repositories.otp_challenge import OtpChallengeRepository

        assert (
            await OtpChallengeRepository(session).get_step_up_for_user_for_update(
                challenge.id, other_id
            )
            is None
        )
        assert (
            await OtpChallengeRepository(session).get_step_up_for_user_for_update(
                challenge.id, owner_id
            )
            is challenge
        )

    migrated_test_database.run_in_transaction(exercise)
