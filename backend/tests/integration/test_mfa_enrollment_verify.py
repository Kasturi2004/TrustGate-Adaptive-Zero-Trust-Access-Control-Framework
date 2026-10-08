"""PostgreSQL tests for atomic MFA enrollment verification."""

import base64
from datetime import UTC, datetime
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
from app.db.models.mfa_credential import MfaCredential
from app.db.models.rate_limit_state import RateLimitState
from app.schemas.mfa import TotpEnrollmentVerificationRequest
from app.services.context import client_ip as client_ip_module
from fastapi import HTTPException, Response
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from tests.integration.database import ScratchDatabase

_TEST_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_TEST_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    rate_limit_key_secret="mfa-integration-test-rate-limit-secret",
    totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(b"v" * 32).decode("ascii")),
)
_VERIFIED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


async def _create_auth_user(session: AsyncSession, user_id: object) -> None:
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"mfa-verify-{user_id}@integration.test"},
    )


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/mfa/totp/enrollment/verify",
            "raw_path": b"/auth/mfa/totp/enrollment/verify",
            "query_string": b"",
            "headers": [],
            "client": ("192.0.2.45", 54000),
            "server": ("testserver", 80),
        }
    )


def _configure_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: _TEST_SETTINGS)
    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _TEST_SETTINGS)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: _TEST_SETTINGS)


def test_enrollment_verification_transition_persists_in_postgresql(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)
    user_id = uuid4()

    async def exercise(session: AsyncSession) -> None:
        await _create_auth_user(session, user_id)
        credential = MfaCredential(
            user_id=user_id,
            secret_ciphertext=encrypt_totp_secret(_TEST_SECRET, settings=_TEST_SETTINGS),
            verified_at=None,
            enabled=False,
        )
        session.add(credential)
        await session.flush()

        result = await mfa_routes.verify_totp_enrollment(
            request=TotpEnrollmentVerificationRequest(
                code=pyotp.TOTP(_TEST_SECRET).at(_VERIFIED_AT)
            ),
            http_request=_request(),
            response=Response(),
            principal=AuthenticatedPrincipal(user_id, "user@example.test", "USER", UUID(int=1)),
            session=session,
            clock=FixedClock(_VERIFIED_AT),
        )

        assert result.enrollment_status == "verified"
        assert result.verified_at == _VERIFIED_AT
        await session.refresh(credential)
        assert credential.enabled is True
        assert credential.verified_at == _VERIFIED_AT
        expected_step = pyotp.TOTP(_TEST_SECRET, digits=6, interval=30).timecode(_VERIFIED_AT)
        persisted = await session.execute(
            text(
                "SELECT enabled, verified_at, last_accepted_time_step "
                "FROM public.mfa_credentials WHERE user_id = :id"
            ),
            {"id": user_id},
        )
        enabled, verified_at, last_accepted_time_step = persisted.one()
        assert enabled is True
        assert verified_at == _VERIFIED_AT
        assert last_accepted_time_step == expected_step
        event = await session.execute(
            text(
                "SELECT details FROM public.security_events "
                "WHERE actor_id = :id "
                "AND event_type = 'MFA_TOTP_ENROLLMENT_VERIFICATION_SUCCEEDED'"
            ),
            {"id": user_id},
        )
        assert event.scalar_one() == {}
        keys = (
            mfa_user_rate_limit_key(user_id, window="15m", settings=_TEST_SETTINGS),
            mfa_user_rate_limit_key(user_id, window="24h", settings=_TEST_SETTINGS),
            mfa_ip_rate_limit_key("192.0.2.45", settings=_TEST_SETTINGS),
        )
        counters = await session.scalars(select(RateLimitState).where(RateLimitState.key.in_(keys)))
        assert {state.key: state.counter for state in counters.all()} == dict.fromkeys(keys, 1)

    migrated_test_database.run_in_transaction(exercise)


def test_verification_failure_rolls_back_postgresql_state_transition(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_settings(monkeypatch)
    monkeypatch.setattr(
        mfa_routes,
        "record_event",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit write failed")),
    )
    user_id = uuid4()

    async def exercise(session: AsyncSession) -> None:
        await _create_auth_user(session, user_id)
        session.add(
            MfaCredential(
                user_id=user_id,
                secret_ciphertext=encrypt_totp_secret(_TEST_SECRET, settings=_TEST_SETTINGS),
                verified_at=None,
                enabled=False,
            )
        )
        await session.flush()
        await session.commit()

        with pytest.raises(HTTPException) as error:
            await mfa_routes.verify_totp_enrollment(
                request=TotpEnrollmentVerificationRequest(
                    code=pyotp.TOTP(_TEST_SECRET).at(_VERIFIED_AT)
                ),
                http_request=_request(),
                response=Response(),
                principal=AuthenticatedPrincipal(user_id, "user@example.test", "USER", UUID(int=1)),
                session=session,
                clock=FixedClock(_VERIFIED_AT),
            )
        assert error.value.status_code == 500

        persisted = await session.execute(
            text(
                "SELECT enabled, verified_at, last_accepted_time_step "
                "FROM public.mfa_credentials WHERE user_id = :id"
            ),
            {"id": user_id},
        )
        enabled, verified_at, last_accepted_time_step = persisted.one()
        assert enabled is False
        assert verified_at is None
        assert last_accepted_time_step is None
        user_key = mfa_user_rate_limit_key(user_id, window="15m", settings=_TEST_SETTINGS)
        limiter_state = await session.get(RateLimitState, user_key)
        assert limiter_state is not None
        assert limiter_state.counter == 1

    migrated_test_database.run_in_transaction(exercise)
