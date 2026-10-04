"""PostgreSQL tests for atomic MFA enrollment verification."""

import base64
from datetime import UTC, datetime
from uuid import uuid4

import pyotp
import pytest
from app.api.deps import AuthenticatedPrincipal
from app.api.routes import mfa as mfa_routes
from app.core import mfa_secrets
from app.core.clock import FixedClock
from app.core.config import Settings
from app.core.mfa_secrets import encrypt_totp_secret
from app.db.models.mfa_credential import MfaCredential
from app.schemas.mfa import TotpEnrollmentVerificationRequest
from fastapi import HTTPException, Response
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

_TEST_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_TEST_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(b"v" * 32).decode("ascii")),
)
_VERIFIED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


async def _create_auth_user(session: AsyncSession, user_id: object) -> None:
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"mfa-verify-{user_id}@integration.test"},
    )


def test_enrollment_verification_transition_persists_in_postgresql(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: _TEST_SETTINGS)
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
            response=Response(),
            principal=AuthenticatedPrincipal(user_id, "user@example.test", "USER"),
            session=session,
            clock=FixedClock(_VERIFIED_AT),
        )

        assert result.enrollment_status == "verified"
        assert result.verified_at == _VERIFIED_AT
        await session.refresh(credential)
        assert credential.enabled is True
        assert credential.verified_at == _VERIFIED_AT
        persisted = await session.execute(
            text("SELECT enabled, verified_at FROM public.mfa_credentials WHERE user_id = :id"),
            {"id": user_id},
        )
        enabled, verified_at = persisted.one()
        assert enabled is True
        assert verified_at == _VERIFIED_AT
        event = await session.execute(
            text(
                "SELECT details FROM public.security_events "
                "WHERE actor_id = :id "
                "AND event_type = 'MFA_TOTP_ENROLLMENT_VERIFICATION_SUCCEEDED'"
            ),
            {"id": user_id},
        )
        assert event.scalar_one() == {}

    migrated_test_database.run_in_transaction(exercise)


def test_verification_failure_rolls_back_postgresql_state_transition(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: _TEST_SETTINGS)
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
                response=Response(),
                principal=AuthenticatedPrincipal(user_id, "user@example.test", "USER"),
                session=session,
                clock=FixedClock(_VERIFIED_AT),
            )
        assert error.value.status_code == 500

        persisted = await session.execute(
            text("SELECT enabled, verified_at FROM public.mfa_credentials WHERE user_id = :id"),
            {"id": user_id},
        )
        enabled, verified_at = persisted.one()
        assert enabled is False
        assert verified_at is None

    migrated_test_database.run_in_transaction(exercise)
