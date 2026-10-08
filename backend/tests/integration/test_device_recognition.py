"""PostgreSQL security tests for explicit, post-redemption device recognition."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

import pytest
from app.api.deps import AuthenticatedPrincipal
from app.api.routes.devices import (
    forget_current_device,
    get_current_device_status,
    recognize_current_device,
)
from app.core.clock import FixedClock
from app.core.config import Settings
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.profile import Profile
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.device import DeviceRepository
from app.main import create_app
from app.schemas.device import DeviceRecognitionRequest
from app.services.context.device_familiarity import (
    UNKNOWN_DEVICE,
    collect_device_familiarity,
    device_token_hash,
)
from fastapi import HTTPException, Response
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

_DEVICE_TOKEN = "recognition-integration-raw-device-token"
_DEVICE_SECRET = "recognition-integration-hmac-secret"
_SESSION_1 = UUID("a7445eb8-c8d1-4e26-97a9-9c050faf1132")
_SESSION_2 = UUID("b8a25d22-0852-4b10-8a0f-22ce2c5b3311")
_NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)
_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    device_hash_secret=_DEVICE_SECRET,
)


def test_device_recognition_requires_authentication() -> None:
    response = TestClient(create_app(_SETTINGS)).post(
        "/devices/recognition",
        json={"access_request_id": str(uuid4())},
        headers={"X-Device-Token": _DEVICE_TOKEN},
    )
    assert response.status_code == 401


def test_recognition_request_rejects_client_supplied_device_state() -> None:
    with pytest.raises(ValidationError):
        DeviceRecognitionRequest.model_validate(
            {
                "access_request_id": str(uuid4()),
                "device_hash": "client-supplied-hash",
                "recognized_at": _NOW.isoformat(),
            }
        )


def test_recognition_requires_current_redeemed_request_and_is_reversible(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_a_id = uuid4()
    user_b_id = uuid4()
    raw_token_hash = device_token_hash(_DEVICE_TOKEN, settings=_SETTINGS)
    assert raw_token_hash is not None

    async def exercise(session: AsyncSession) -> None:
        for user_id in (user_a_id, user_b_id):
            await session.execute(
                text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
                {"id": user_id, "email": f"device-recognition-{user_id}@integration.test"},
            )
        profiles = [await session.get(Profile, uid) for uid in (user_a_id, user_b_id)]
        assert profiles[0] is not None and profiles[1] is not None
        emails = {user_a_id: profiles[0].email, user_b_id: profiles[1].email}

        device_a = Device(user_id=user_a_id, device_hash=raw_token_hash)
        device_b = Device(user_id=user_b_id, device_hash=raw_token_hash)
        session.add_all((device_a, device_b))
        await session.flush()
        mfa_only = AccessRequest(
            user_id=user_a_id,
            auth_session_id=_SESSION_1,
            device_id=device_a.id,
            source_ip=IPv4Address("192.0.2.61"),
            initial_decision="STEP_UP",
            mfa_required=True,
            final_outcome="ALLOW",
            resolved_at=_NOW,
            requested_at=_NOW,
        )
        redeemed_step_up = AccessRequest(
            user_id=user_a_id,
            auth_session_id=_SESSION_1,
            device_id=device_a.id,
            source_ip=IPv4Address("192.0.2.62"),
            initial_decision="STEP_UP",
            mfa_required=True,
            final_outcome="ALLOW",
            resolved_at=_NOW,
            requested_at=_NOW + timedelta(seconds=1),
        )
        wrong_session_request = AccessRequest(
            user_id=user_a_id,
            auth_session_id=_SESSION_1,
            device_id=device_a.id,
            source_ip=IPv4Address("192.0.2.63"),
            initial_decision="ALLOW",
            final_outcome="ALLOW",
            consumed_at=_NOW,
            requested_at=_NOW + timedelta(seconds=2),
        )
        blocked_request = AccessRequest(
            user_id=user_a_id,
            auth_session_id=_SESSION_1,
            device_id=device_a.id,
            source_ip=IPv4Address("192.0.2.64"),
            initial_decision="BLOCK",
            final_outcome="BLOCK",
            requested_at=_NOW + timedelta(seconds=3),
        )
        other_user_request = AccessRequest(
            user_id=user_b_id,
            auth_session_id=_SESSION_1,
            device_id=device_b.id,
            source_ip=IPv4Address("192.0.2.65"),
            initial_decision="ALLOW",
            final_outcome="ALLOW",
            consumed_at=_NOW,
            requested_at=_NOW + timedelta(seconds=4),
        )
        session.add_all(
            (mfa_only, redeemed_step_up, wrong_session_request, blocked_request, other_user_request)
        )
        await session.flush()
        session.add_all(
            [
                OtpChallenge(
                    access_request_id=request.id,
                    user_id=user_id,
                    otp_hash=None,
                    status="SUCCESS",
                    attempt_count=1,
                    max_attempts=3,
                    created_at=_NOW,
                    expires_at=_NOW + timedelta(minutes=5),
                    verified_at=_NOW,
                )
                for request, user_id in (
                    (mfa_only, user_a_id),
                    (redeemed_step_up, user_a_id),
                )
            ]
        )
        request_ids = {
            "mfa_only": mfa_only.id,
            "redeemed_step_up": redeemed_step_up.id,
            "wrong_session": wrong_session_request.id,
            "blocked": blocked_request.id,
            "other_user": other_user_request.id,
        }
        await session.commit()

        principal_a_session_1 = AuthenticatedPrincipal(
            user_a_id, emails[user_a_id], "USER", _SESSION_1
        )
        principal_a_session_2 = AuthenticatedPrincipal(
            user_a_id, emails[user_a_id], "USER", _SESSION_2
        )
        principal_b = AuthenticatedPrincipal(user_b_id, emails[user_b_id], "USER", _SESSION_1)

        async def rejected(principal: AuthenticatedPrincipal, request_id: UUID) -> None:
            with pytest.raises(HTTPException) as error:
                await recognize_current_device(
                    DeviceRecognitionRequest(access_request_id=request_id),
                    Response(),
                    principal,
                    _DEVICE_TOKEN,
                    session,
                    FixedClock(_NOW),
                    _SETTINGS,
                )
            assert error.value.status_code == 404

        # TOTP alone is insufficient; current auth session and ownership are mandatory.
        await rejected(principal_a_session_1, request_ids["mfa_only"])
        await rejected(principal_a_session_2, request_ids["wrong_session"])
        await rejected(principal_b, request_ids["wrong_session"])
        await rejected(principal_a_session_1, request_ids["blocked"])
        await rejected(principal_a_session_1, request_ids["other_user"])
        await session.refresh(device_a)
        await session.refresh(device_b)
        assert device_a.recognized_at is None
        assert device_b.recognized_at is None

        # Successful TOTP alone is insufficient; redemption must consume the same request.
        assert await AccessRequestRepository(session).consume_dashboard_access(
            request_ids["redeemed_step_up"], user_a_id, _SESSION_1, _NOW
        )
        await session.commit()
        mfa_only_request = await session.get(AccessRequest, request_ids["mfa_only"])
        assert mfa_only_request is not None and mfa_only_request.consumed_at is None

        status_before = await get_current_device_status(
            Response(), principal_a_session_1, _DEVICE_TOKEN, session, _SETTINGS
        )
        assert status_before.recognized is False

        request_data = DeviceRecognitionRequest(access_request_id=request_ids["redeemed_step_up"])
        success = await recognize_current_device(
            request_data,
            Response(),
            principal_a_session_1,
            _DEVICE_TOKEN,
            session,
            FixedClock(_NOW + timedelta(minutes=1)),
            _SETTINGS,
        )
        assert success.recognized is True
        await session.refresh(device_a)
        assert device_a.recognized_at == _NOW + timedelta(minutes=1)
        assert device_a.device_hash == raw_token_hash
        assert _DEVICE_TOKEN not in device_a.device_hash

        # Repeat calls are idempotent and do not replace the original recognition time.
        repeated = await recognize_current_device(
            request_data,
            Response(),
            principal_a_session_1,
            _DEVICE_TOKEN,
            session,
            FixedClock(_NOW + timedelta(minutes=2)),
            _SETTINGS,
        )
        await session.refresh(device_a)
        assert repeated.recognized is True
        assert device_a.recognized_at == _NOW + timedelta(minutes=1)
        assert (
            await session.scalar(select(Device.id).where(Device.user_id == user_a_id))
            == device_a.id
        )

        # The same browser identifier remains isolated to User A.
        await session.refresh(device_b)
        assert device_b.recognized_at is None
        assert (
            await collect_device_familiarity(
                user_id=user_b_id,
                device_token=_DEVICE_TOKEN,
                repository=DeviceRepository(session),
                settings=_SETTINGS,
            )
            == UNKNOWN_DEVICE
        )

        revoked = await forget_current_device(
            Response(), principal_a_session_1, _DEVICE_TOKEN, session, _SETTINGS
        )
        assert revoked.recognized is False
        await session.refresh(device_a)
        assert device_a.recognized_at is None
        assert await session.get(AccessRequest, request_ids["redeemed_step_up"]) is not None
        assert (
            await collect_device_familiarity(
                user_id=user_a_id,
                device_token=_DEVICE_TOKEN,
                repository=DeviceRepository(session),
                settings=_SETTINGS,
            )
            == UNKNOWN_DEVICE
        )

    migrated_test_database.run_in_transaction(exercise)
