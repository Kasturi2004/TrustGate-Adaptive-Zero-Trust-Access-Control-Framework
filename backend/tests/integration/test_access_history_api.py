"""PostgreSQL integration tests for the authenticated access-history API."""

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

_SUPABASE_URL = "https://history-test.supabase.co"
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "access-history-test-key"
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
)


@dataclass(frozen=True, slots=True)
class SeededHistory:
    owner_id: UUID
    other_id: UUID
    owner_request_ids: list[UUID]
    other_request_id: UUID


async def _seed_history(database_url: str) -> SeededHistory:
    owner_id = uuid4()
    other_id = uuid4()
    await ensure_auth_user_profile(
        database_url,
        user_id=owner_id,
        email=f"history-owner-{owner_id}@integration.test",
    )
    await ensure_auth_user_profile(
        database_url,
        user_id=other_id,
        email=f"history-other-{other_id}@integration.test",
    )

    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with AsyncSession(engine) as session, session.begin():
            owner_device = Device(
                user_id=owner_id,
                device_hash="LEAK_DEVICE_FINGERPRINT_SENTINEL",
            )
            other_device = Device(user_id=other_id, device_hash=f"other-{other_id}")
            session.add_all((owner_device, other_device))
            await session.flush()

            requested_at = datetime(2026, 10, 1, tzinfo=UTC)
            owner_requests = [
                AccessRequest(
                    user_id=owner_id,
                    device_id=owner_device.id,
                    resource_id="ops-dashboard",
                    source_ip=IPv4Address("203.0.113.222"),
                    resolved_region="LEAK_LOCATION_SENTINEL",
                    initial_decision="STEP_UP" if index == 51 else "ALLOW",
                    mfa_required=index == 51,
                    requested_at=requested_at + timedelta(seconds=index),
                )
                for index in range(52)
            ]
            other_request = AccessRequest(
                user_id=other_id,
                device_id=other_device.id,
                source_ip=IPv4Address("203.0.113.223"),
                initial_decision="ALLOW",
                requested_at=requested_at + timedelta(hours=1),
            )
            session.add_all((*owner_requests, other_request))
            await session.flush()

            newest_request = owner_requests[-1]
            session.add_all(
                (
                    OtpChallenge(
                        access_request_id=newest_request.id,
                        user_id=owner_id,
                        status="EXPIRED",
                        created_at=newest_request.requested_at + timedelta(seconds=1),
                        expires_at=newest_request.requested_at + timedelta(minutes=5),
                    ),
                    OtpChallenge(
                        access_request_id=newest_request.id,
                        user_id=owner_id,
                        status="SUCCESS",
                        created_at=newest_request.requested_at + timedelta(seconds=2),
                        expires_at=newest_request.requested_at + timedelta(minutes=5),
                    ),
                )
            )
            await session.flush()
            return SeededHistory(
                owner_id=owner_id,
                other_id=other_id,
                owner_request_ids=[request.id for request in owner_requests],
                other_request_id=other_request.id,
            )
    finally:
        await engine.dispose()


async def _remove_history(database_url: str, history: SeededHistory) -> None:
    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OtpChallenge).where(
                    OtpChallenge.access_request_id.in_(
                        (*history.owner_request_ids, history.other_request_id)
                    )
                )
            )
            await connection.execute(
                delete(AccessRequest).where(
                    AccessRequest.id.in_((*history.owner_request_ids, history.other_request_id))
                )
            )
            await connection.execute(
                delete(Device).where(Device.user_id.in_((history.owner_id, history.other_id)))
            )
    finally:
        await engine.dispose()
    await remove_auth_user_profile(database_url, user_id=history.owner_id)
    await remove_auth_user_profile(database_url, user_id=history.other_id)


@pytest.fixture
def seeded_history(migrated_test_database: ScratchDatabase) -> Iterator[SeededHistory]:
    history = asyncio.run(_seed_history(migrated_test_database.url))
    yield history
    asyncio.run(_remove_history(migrated_test_database.url, history))


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


def _assert_no_forbidden_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key)).casefold()
            normalized_key = re.sub(r"[^a-z0-9_]", "_", key_name)
            assert not any(part in normalized_key for part in _FORBIDDEN_KEY_PARTS)
            _assert_no_forbidden_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_forbidden_fields(nested)
    elif isinstance(value, str):
        assert "LEAK_DEVICE_FINGERPRINT_SENTINEL" not in value
        assert "LEAK_LOCATION_SENTINEL" not in value
        assert "203.0.113.222" not in value


def test_access_history_route_has_no_client_supplied_owner_parameter() -> None:
    application = create_app(Settings(app_env="test", cors_allowed_origin="http://localhost:5173"))
    operation = application.openapi()["paths"]["/access/history"]["get"]
    parameter_names = {parameter["name"] for parameter in operation["parameters"]}

    assert parameter_names == {"page", "page_size"}


def test_access_history_returns_only_authenticated_users_curated_pages(
    migrated_test_database: ScratchDatabase,
    seeded_history: SeededHistory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        headers = {"Authorization": f"Bearer {_token(seeded_history.owner_id)}"}

        first_page_response = client.get(
            "/access/history",
            params={"page": 1, "page_size": 2, "user_id": str(seeded_history.other_id)},
            headers=headers,
        )
        assert first_page_response.status_code == 200
        first_page = first_page_response.json()
        assert [row["id"] for row in first_page] == [
            str(seeded_history.owner_request_ids[-1]),
            str(seeded_history.owner_request_ids[-2]),
        ]
        assert first_page[0]["mfa_was_required"] is True
        assert first_page[0]["mfa_status"] == "SUCCESS"
        assert all(set(row) == _ALLOWED_FIELDS for row in first_page)
        assert all(row["id"] != str(seeded_history.other_request_id) for row in first_page)
        _assert_no_forbidden_fields(first_page)

        capped_page_response = client.get(
            "/access/history",
            params={"page": 1, "page_size": 51},
            headers=headers,
        )
        assert capped_page_response.status_code == 200
        capped_page = capped_page_response.json()
        assert len(capped_page) == 50
        assert capped_page[0]["id"] == str(seeded_history.owner_request_ids[-1])
        assert capped_page[-1]["id"] == str(seeded_history.owner_request_ids[2])
        assert all(row["id"] != str(seeded_history.other_request_id) for row in capped_page)
        assert (
            sum(row["id"] == str(seeded_history.owner_request_ids[-1]) for row in capped_page) == 1
        )
        assert all(set(row) == _ALLOWED_FIELDS for row in capped_page)
        _assert_no_forbidden_fields(capped_page)

        second_page_response = client.get(
            "/access/history",
            params={"page": 2, "page_size": 50},
            headers=headers,
        )
        assert second_page_response.status_code == 200
        second_page = second_page_response.json()
        assert [row["id"] for row in second_page] == [
            str(seeded_history.owner_request_ids[1]),
            str(seeded_history.owner_request_ids[0]),
        ]
        assert all(row["id"] != str(seeded_history.other_request_id) for row in second_page)


def test_access_history_rejects_unauthenticated_requests(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get("/access/history", params={"page": 1, "page_size": 10})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert response.json()["error"]["message"] == "Not authenticated"
