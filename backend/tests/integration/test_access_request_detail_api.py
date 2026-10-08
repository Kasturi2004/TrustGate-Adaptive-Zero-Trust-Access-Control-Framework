"""PostgreSQL integration tests for the authenticated access-request detail API."""

import asyncio
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import cast
from uuid import UUID, uuid4

import app.api.deps as deps
import app.core.jwt as jwt_module
import jwt
import pytest
from app.core.config import Settings
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.session import create_async_engine_for_url
from app.main import create_app
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import (
    ScratchDatabase,
    ensure_auth_user_profile,
    remove_auth_user_profile,
)

_SUPABASE_URL = "https://detail-test.supabase.co"
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "access-detail-test-key"
_ALLOWED_FIELDS = {
    "id",
    "resource_id",
    "requested_at",
    "initial_decision",
    "final_outcome",
    "mfa_was_required",
    "mfa_status",
}
_FORBIDDEN_KEY_PARTS = (
    "trust_score",
    "factor",
    "weight",
    "threshold",
    "policy_version",
    "decision_reason",
    "device",
    "fingerprint",
    "source_ip",
    "ip_address",
    "location",
    "region",
    "risk",
    "latitude",
    "longitude",
    "otp",
    "secret",
    "token",
    "code",
)
_SENSITIVE_SENTINELS = (
    "LEAK_DEVICE_DETAIL_SENTINEL",
    "LEAK_LOCATION_DETAIL_SENTINEL",
    "LEAK_OTP_SECRET_DETAIL_SENTINEL",
    "LEAK_POLICY_DETAIL_SENTINEL",
    "203.0.113.230",
)


@dataclass(frozen=True, slots=True)
class SeededDetail:
    owner_id: UUID
    other_id: UUID
    access_request_id: UUID


async def _seed_detail(database_url: str) -> SeededDetail:
    owner_id = uuid4()
    other_id = uuid4()
    await ensure_auth_user_profile(
        database_url,
        user_id=owner_id,
        email=f"detail-owner-{owner_id}@integration.test",
    )
    await ensure_auth_user_profile(
        database_url,
        user_id=other_id,
        email=f"detail-other-{other_id}@integration.test",
    )

    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with AsyncSession(engine) as session, session.begin():
            device = Device(user_id=owner_id, device_hash=_SENSITIVE_SENTINELS[0])
            session.add(device)
            await session.flush()

            request = AccessRequest(
                user_id=owner_id,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address(_SENSITIVE_SENTINELS[4]),
                resolved_region=_SENSITIVE_SENTINELS[1],
                initial_decision="STEP_UP",
                mfa_required=True,
                final_outcome="ALLOW",
                requested_at=datetime(2026, 10, 2, tzinfo=UTC),
            )
            session.add(request)
            await session.flush()
            session.add_all(
                (
                    OtpChallenge(
                        access_request_id=request.id,
                        user_id=owner_id,
                        otp_hash=_SENSITIVE_SENTINELS[2],
                        status="EXPIRED",
                        created_at=request.requested_at + timedelta(seconds=1),
                        expires_at=request.requested_at + timedelta(minutes=5),
                    ),
                    OtpChallenge(
                        access_request_id=request.id,
                        user_id=owner_id,
                        otp_hash=_SENSITIVE_SENTINELS[2],
                        status="SUCCESS",
                        created_at=request.requested_at + timedelta(seconds=2),
                        expires_at=request.requested_at + timedelta(minutes=5),
                    ),
                )
            )
            await session.flush()
            return SeededDetail(owner_id, other_id, request.id)
    finally:
        await engine.dispose()


async def _remove_detail(database_url: str, detail: SeededDetail) -> None:
    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OtpChallenge).where(
                    OtpChallenge.access_request_id == detail.access_request_id
                )
            )
            await connection.execute(
                delete(AccessRequest).where(AccessRequest.id == detail.access_request_id)
            )
            await connection.execute(delete(Device).where(Device.user_id == detail.owner_id))
    finally:
        await engine.dispose()
    await remove_auth_user_profile(database_url, user_id=detail.owner_id)
    await remove_auth_user_profile(database_url, user_id=detail.other_id)


@pytest.fixture
def seeded_detail(migrated_test_database: ScratchDatabase) -> Iterator[SeededDetail]:
    detail = asyncio.run(_seed_detail(migrated_test_database.url))
    yield detail
    asyncio.run(_remove_detail(migrated_test_database.url, detail))


def _client(database_url: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url=_SUPABASE_URL,
        database_url=database_url,
    )
    public_jwk = cast(
        dict[str, object],
        ECAlgorithm.to_jwk(_TEST_PRIVATE_KEY.public_key(), as_dict=True),
    )
    public_jwk.update({"kid": _TEST_KID, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    monkeypatch.setattr(jwt_module, "get_settings", lambda: settings)
    monkeypatch.setattr(deps, "get_settings", lambda: settings)
    monkeypatch.setattr(PyJWKClient, "fetch_data", lambda _client: {"keys": [public_jwk]})
    jwt_module._jwks_client.cache_clear()
    return TestClient(create_app(settings))


def _token(user_id: UUID) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "session_id": str(user_id),
            "aud": "authenticated",
            "iss": f"{_SUPABASE_URL}/auth/v1",
            "exp": int(datetime.now(UTC).timestamp()) + 3600,
        },
        _TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": _TEST_KID},
    )


def _assert_no_forbidden_fields_or_values(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key)).casefold()
            normalized_key = re.sub(r"[^a-z0-9_]", "_", key_name)
            assert not any(part in normalized_key for part in _FORBIDDEN_KEY_PARTS)
            _assert_no_forbidden_fields_or_values(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_forbidden_fields_or_values(nested)
    elif isinstance(value, str):
        for sentinel in _SENSITIVE_SENTINELS:
            assert sentinel not in value


def test_access_request_detail_returns_only_owned_curated_fields(
    migrated_test_database: ScratchDatabase,
    seeded_detail: SeededDetail,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            f"/access/request/{seeded_detail.access_request_id}",
            headers={"Authorization": f"Bearer {_token(seeded_detail.owner_id)}"},
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == _ALLOWED_FIELDS
    assert "auth_session_id" not in body
    assert body["id"] == str(seeded_detail.access_request_id)
    assert body["resource_id"] == "ops-dashboard"
    assert body["initial_decision"] == "STEP_UP"
    assert body["final_outcome"] == "ALLOW"
    assert body["mfa_was_required"] is True
    assert body["mfa_status"] == "SUCCESS"
    _assert_no_forbidden_fields_or_values(body)


def test_access_request_detail_rejects_unauthenticated_request(
    migrated_test_database: ScratchDatabase,
    seeded_detail: SeededDetail,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(f"/access/request/{seeded_detail.access_request_id}")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert response.json()["error"]["message"] == "Not authenticated"


@pytest.mark.parametrize("request_exists", [True, False], ids=["owned-by-other", "nonexistent"])
def test_access_request_detail_hides_foreign_and_nonexistent_requests(
    migrated_test_database: ScratchDatabase,
    seeded_detail: SeededDetail,
    monkeypatch: pytest.MonkeyPatch,
    request_exists: bool,
) -> None:
    request_id = seeded_detail.access_request_id if request_exists else uuid4()
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            f"/access/request/{request_id}",
            headers={"Authorization": f"Bearer {_token(seeded_detail.other_id)}"},
        )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert response.json()["error"]["message"] == "Access request not found"
