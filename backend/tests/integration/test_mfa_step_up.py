"""PostgreSQL persistence coverage for TOTP STEP_UP challenge verification."""

import asyncio
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
from app.core.rate_limit import mfa_ip_rate_limit_key, mfa_user_rate_limit_key
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.mfa_credential import MfaCredential
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.rate_limit_state import RateLimitState
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.session import create_async_engine_for_url
from app.schemas.mfa import TotpStepUpVerificationRequest
from app.services.context import client_ip as client_ip_module
from fastapi import HTTPException, Response
from pydantic import SecretStr
from sqlalchemy import select, text
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


def _request(client_ip: str = "192.0.2.46") -> Request:
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
            "client": (client_ip, 54000),
            "server": ("testserver", 80),
        }
    )


def _configure_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: _SETTINGS)
    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _SETTINGS)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: _SETTINGS)


async def _create_challenge_records(
    session: AsyncSession,
    *,
    policy: PolicyVersion | None = None,
    evaluation_status: str = "COMPLETE",
    policy_decision: str = "STEP_UP",
    final_outcome: str | None = None,
) -> tuple[UUID, AccessRequest, OtpChallenge]:
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"mfa-step-up-{user_id}@integration.test"},
    )
    if policy is None:
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
        final_outcome=final_outcome,
        requested_at=_NOW,
        resolved_at=_NOW if final_outcome is not None else None,
    )
    session.add(access_request)
    await session.flush()
    evaluation = TrustEvaluation(
        id=uuid4(),
        access_request_id=access_request.id,
        policy_version_id=policy.id,
        trust_score=50,
        risk_classification="MEDIUM",
        status=evaluation_status,
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
            decision=policy_decision,
            decision_reason="Additional verification is required.",
            decided_at=_NOW,
        )
    )
    challenge = OtpChallenge(
        id=uuid4(),
        access_request_id=access_request.id,
        user_id=user_id,
        otp_hash=None,
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
        await session.refresh(access_request)
        assert access_request.final_outcome == "ALLOW"
        assert access_request.resolved_at == _NOW
        assert access_request.initial_decision == "STEP_UP"
        decision = await session.scalar(
            select(PolicyDecision).where(PolicyDecision.access_request_id == request_id)
        )
        assert decision is not None
        assert decision.decision == "STEP_UP"

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
        allow_event = await session.execute(
            text(
                "SELECT decision, details FROM public.security_events "
                "WHERE actor_id = :user_id "
                "AND access_request_id = :request_id "
                "AND event_type = 'ACCESS_MFA_ALLOWED'"
            ),
            {"user_id": user_id, "request_id": request_id},
        )
        assert allow_event.one() == ("ALLOW", {})
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


def test_degraded_evaluation_cannot_be_upgraded_by_totp(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)

    async def exercise(session: AsyncSession) -> None:
        user_id, access_request, challenge = await _create_challenge_records(
            session, evaluation_status="DEGRADED_FAILSAFE"
        )
        with pytest.raises(HTTPException) as error:
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
        assert error.value.status_code == 400
        await session.refresh(access_request)
        await session.refresh(challenge)
        assert access_request.final_outcome is None
        assert access_request.resolved_at is None
        assert challenge.status == "PENDING"

    migrated_test_database.run_in_transaction(exercise)


@pytest.mark.parametrize(
    ("policy_decision", "final_outcome"),
    [("ALLOW", None), ("STEP_UP", "ALLOW")],
)
def test_non_step_up_or_resolved_request_cannot_be_authorized(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
    policy_decision: str,
    final_outcome: str | None,
) -> None:
    _configure_settings(monkeypatch)

    async def exercise(session: AsyncSession) -> None:
        user_id, access_request, challenge = await _create_challenge_records(
            session,
            policy_decision=policy_decision,
            final_outcome=final_outcome,
        )
        with pytest.raises(HTTPException) as error:
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
        assert error.value.status_code == 400
        await session.refresh(access_request)
        await session.refresh(challenge)
        assert access_request.final_outcome == final_outcome
        assert challenge.status == "PENDING"

    migrated_test_database.run_in_transaction(exercise)


def test_failed_totp_does_not_resolve_access_request(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)

    async def exercise(session: AsyncSession) -> None:
        user_id, access_request, challenge = await _create_challenge_records(session)
        invalid_code = "000000" if pyotp.TOTP(_SECRET).at(_NOW) != "000000" else "000001"
        with pytest.raises(HTTPException) as error:
            await mfa_routes.verify_totp_step_up(
                request=TotpStepUpVerificationRequest(
                    mfa_challenge_id=challenge.id,
                    code=invalid_code,
                ),
                http_request=_request(),
                response=Response(),
                principal=AuthenticatedPrincipal(user_id, "mfa@example.test", "USER"),
                session=session,
                clock=FixedClock(_NOW),
            )
        assert error.value.status_code == 400
        await session.refresh(access_request)
        await session.refresh(challenge)
        assert access_request.final_outcome is None
        assert access_request.resolved_at is None
        assert challenge.status == "PENDING"
        assert challenge.attempt_count == 1

    migrated_test_database.run_in_transaction(exercise)


def test_event_persistence_failure_rolls_back_challenge_and_access_transition(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)

    def fail_success_event(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit persistence failed")

    monkeypatch.setattr(mfa_routes, "record_event", fail_success_event)

    async def exercise(session: AsyncSession) -> None:
        user_id, access_request, challenge = await _create_challenge_records(session)
        request_id = access_request.id
        challenge_id = challenge.id
        await session.commit()

        with pytest.raises(HTTPException) as error:
            await mfa_routes.verify_totp_step_up(
                request=TotpStepUpVerificationRequest(
                    mfa_challenge_id=challenge_id,
                    code=pyotp.TOTP(_SECRET).at(_NOW),
                ),
                http_request=_request(),
                response=Response(),
                principal=AuthenticatedPrincipal(user_id, "mfa@example.test", "USER"),
                session=session,
                clock=FixedClock(_NOW),
            )
        assert error.value.status_code == 500
        stored_request = await session.get(AccessRequest, request_id)
        stored_challenge = await session.get(OtpChallenge, challenge_id)
        assert stored_request is not None
        assert stored_request.final_outcome is None
        assert stored_request.resolved_at is None
        assert stored_challenge is not None
        assert stored_challenge.status == "PENDING"
        assert stored_challenge.verified_at is None

    migrated_test_database.run_in_transaction(exercise)


def test_concurrent_verification_authorizes_the_request_once(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)
    client_ip = "192.0.2.198"
    engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)

    async def exercise() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as setup_session:
            policy = await setup_session.scalar(
                select(PolicyVersion).where(PolicyVersion.version_label == "POL-1.0")
            )
            assert policy is not None
            user_id, access_request, challenge = await _create_challenge_records(
                setup_session,
                policy=policy,
            )
            request_id = access_request.id
            challenge_id = challenge.id
            await setup_session.commit()

        async def verify_once() -> int:
            async with AsyncSession(engine, expire_on_commit=False) as session:
                try:
                    await mfa_routes.verify_totp_step_up(
                        request=TotpStepUpVerificationRequest(
                            mfa_challenge_id=challenge_id,
                            code=pyotp.TOTP(_SECRET).at(_NOW),
                        ),
                        http_request=_request(client_ip),
                        response=Response(),
                        principal=AuthenticatedPrincipal(user_id, "mfa@example.test", "USER"),
                        session=session,
                        clock=FixedClock(_NOW),
                    )
                    return 200
                except HTTPException as error:
                    return error.status_code

        statuses = await asyncio.gather(verify_once(), verify_once())
        assert sorted(statuses) == [200, 400]

        async with AsyncSession(engine) as verify_session:
            stored_request = await verify_session.get(AccessRequest, request_id)
            stored_challenge = await verify_session.get(OtpChallenge, challenge_id)
            assert stored_request is not None
            assert stored_request.final_outcome == "ALLOW"
            assert stored_request.resolved_at == _NOW
            assert stored_challenge is not None
            assert stored_challenge.status == "SUCCESS"
            access_events = await verify_session.scalar(
                text(
                    "SELECT count(*) FROM public.security_events "
                    "WHERE access_request_id = :request_id "
                    "AND event_type = 'ACCESS_MFA_ALLOWED'"
                ),
                {"request_id": request_id},
            )
            assert access_events == 1

        cleanup_keys = (
            mfa_user_rate_limit_key(user_id, window="15m", settings=_SETTINGS),
            mfa_user_rate_limit_key(user_id, window="24h", settings=_SETTINGS),
            mfa_ip_rate_limit_key(client_ip, settings=_SETTINGS),
        )
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "DELETE FROM public.rate_limit_state "
                    "WHERE key IN (:user_short, :user_daily, :client_ip)"
                ),
                {
                    "user_short": cleanup_keys[0],
                    "user_daily": cleanup_keys[1],
                    "client_ip": cleanup_keys[2],
                },
            )
            await connection.execute(
                text("DELETE FROM public.mfa_credentials WHERE user_id = :id"),
                {"id": user_id},
            )
            await connection.execute(
                text("DELETE FROM public.otp_challenges WHERE id = :id"),
                {"id": challenge_id},
            )
        # Keep the append-only audit history and its referenced request graph.
        # Random user/request IDs isolate retained rows between test runs.

    try:
        asyncio.run(exercise())
    finally:
        asyncio.run(engine.dispose())
