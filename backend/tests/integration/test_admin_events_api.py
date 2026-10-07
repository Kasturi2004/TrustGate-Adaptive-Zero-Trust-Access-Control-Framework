"""Real PostgreSQL integration tests for the ADMIN security-event list."""

import asyncio
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
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.session import create_async_engine_for_url
from app.main import create_app
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase, ensure_auth_user_profile

_SUPABASE_URL = "https://admin-events-test.supabase.co"
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "admin-events-test-key"
_SENSITIVE_SENTINELS = (
    "ADMIN_EVENTS_OTP_HASH_SENTINEL",
    "ADMIN_EVENTS_DEVICE_FINGERPRINT_SENTINEL",
    "ADMIN_EVENTS_PASSWORD_SENTINEL",
)
_FORBIDDEN_KEYS = {
    "otp_hash",
    "password",
    "token",
    "secret",
    "authorization",
    "device_hash",
    "device_fingerprint",
    "source_ip",
    "resolved_region",
    "details",
    "decision_reason",
    "policy_version_id",
    "weights_json",
}


@dataclass(frozen=True, slots=True)
class SeededEvents:
    admin_id: UUID
    user_id: UUID
    other_user_id: UUID
    device_id: UUID
    other_device_id: UUID
    event_ids: tuple[UUID, ...]
    event_time_start: datetime
    event_time_end: datetime


async def _seed_events(database_url: str) -> SeededEvents:
    admin_id, user_id, other_user_id = uuid4(), uuid4(), uuid4()
    base_time = datetime.now(UTC)
    await ensure_auth_user_profile(
        database_url, user_id=admin_id, email=f"admin-events-{admin_id}@integration.test"
    )
    await ensure_auth_user_profile(
        database_url, user_id=user_id, email=f"events-user-{user_id}@integration.test"
    )
    await ensure_auth_user_profile(
        database_url, user_id=other_user_id, email=f"events-other-{other_user_id}@integration.test"
    )
    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                update(Profile).where(Profile.id == admin_id).values(role="ADMIN")
            )

        async with AsyncSession(engine) as session, session.begin():
            policy = PolicyVersion(
                version_label=f"admin-events-test-{uuid4()}",
                weights_json={"device_familiarity": 0.4},
                is_active=False,
            )
            device = Device(user_id=user_id, device_hash=_SENSITIVE_SENTINELS[1])
            other_device = Device(user_id=other_user_id, device_hash="OTHER-DEVICE-HASH-987654")
            session.add_all((policy, device, other_device))
            await session.flush()

            requests = [
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.40"),
                    initial_decision=decision,
                    requested_at=base_time + timedelta(seconds=index),
                )
                for index, decision in enumerate(("ALLOW", "STEP_UP", "BLOCK"))
            ]
            requests.append(
                AccessRequest(
                    user_id=other_user_id,
                    device_id=other_device.id,
                    source_ip=IPv4Address("192.0.2.41"),
                    initial_decision="ALLOW",
                    requested_at=base_time + timedelta(seconds=3),
                )
            )
            session.add_all(requests)
            await session.flush()

            evaluations = [
                TrustEvaluation(
                    access_request_id=request.id,
                    policy_version_id=policy.id,
                    trust_score=score,
                    risk_classification=risk,
                    evaluated_at=base_time + timedelta(seconds=index),
                )
                for index, (request, score, risk) in enumerate(
                    zip(requests, (25, 50, 75, 100), ("LOW", "HIGH", "MEDIUM", "HIGH"), strict=True)
                )
            ]
            session.add_all(evaluations)
            await session.flush()
            session.add_all(
                PolicyDecision(
                    access_request_id=request.id,
                    trust_evaluation_id=evaluation.id,
                    policy_version_id=policy.id,
                    decision=request.initial_decision,
                    decision_reason="PRIVATE_POLICY_REASON_SENTINEL",
                )
                for request, evaluation in zip(requests, evaluations, strict=True)
            )
            event_specs = (
                ("ACCESS_ALLOWED", requests[0], "ALLOW", "LOW", base_time),
                ("ACCESS_STEPUP", requests[1], "STEP_UP", "HIGH", base_time),
                ("ACCESS_BLOCKED", requests[2], "BLOCK", "MEDIUM", base_time),
                ("ACCESS_ALLOWED", requests[3], "ALLOW", "HIGH", base_time),
            )
            events = [
                SecurityEvent(
                    event_type=event_type,
                    actor_id=request.user_id,
                    target_user_id=request.user_id,
                    access_request_id=request.id,
                    trust_evaluation_id=evaluation.id,
                    decision=decision,
                    risk_category=risk,
                    created_at=created_at,
                    details={
                        "password": _SENSITIVE_SENTINELS[2],
                        "otp_hash": _SENSITIVE_SENTINELS[0],
                    },
                )
                for (event_type, request, decision, risk, created_at), evaluation in zip(
                    event_specs, evaluations, strict=True
                )
            ]
            session.add_all(events)
            await session.flush()
            return SeededEvents(
                admin_id=admin_id,
                user_id=user_id,
                other_user_id=other_user_id,
                device_id=device.id,
                other_device_id=other_device.id,
                event_ids=tuple(event.id for event in events),
                event_time_start=base_time,
                event_time_end=base_time,
            )
    finally:
        await engine.dispose()


@pytest.fixture
def seeded_events(migrated_test_database: ScratchDatabase) -> Iterator[SeededEvents]:
    # Rows stay in the disposable DB because security-event and linked history are append-only.
    yield asyncio.run(_seed_events(migrated_test_database.url))


def _client(database_url: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url=_SUPABASE_URL,
        database_url=database_url,
    )
    public_jwk = cast(
        dict[str, object], ECAlgorithm.to_jwk(_TEST_PRIVATE_KEY.public_key(), as_dict=True)
    )
    public_jwk.update({"kid": _TEST_KID, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    monkeypatch.setattr(jwt_module, "get_settings", lambda: settings)
    monkeypatch.setattr(deps, "get_settings", lambda: settings)
    monkeypatch.setattr(PyJWKClient, "fetch_data", lambda _client: {"keys": [public_jwk]})
    jwt_module._jwks_client.cache_clear()
    return TestClient(create_app(settings))


def _token(user_id: UUID, *, role_claim: str = "USER") -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "role": role_claim,
            "aud": "authenticated",
            "iss": f"{_SUPABASE_URL}/auth/v1",
            "exp": int(datetime.now(UTC).timestamp()) + 3600,
        },
        _TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": _TEST_KID},
    )


def _headers(user_id: UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(user_id, role_claim='USER')}"}


def _assert_no_sensitive_content(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            folded_key = str(key).casefold()
            assert not any(term in folded_key for term in _FORBIDDEN_KEYS)
            _assert_no_sensitive_content(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_sensitive_content(nested)
    elif isinstance(value, str):
        for sentinel in _SENSITIVE_SENTINELS:
            assert sentinel not in value
        assert "PRIVATE_POLICY_REASON_SENTINEL" not in value


def test_admin_can_read_filtered_events_and_emits_audit_event(
    migrated_test_database: ScratchDatabase,
    seeded_events: SeededEvents,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            "/admin/events",
            params={
                "from": seeded_events.event_time_start.isoformat(),
                "to": seeded_events.event_time_end.isoformat(),
                "user_id": str(seeded_events.user_id),
                "decision": "STEP_UP",
                "risk_category": "HIGH",
                "device_id": str(seeded_events.device_id),
                "score_min": "50",
                "score_max": "50",
            },
            headers={
                "Authorization": f"Bearer {_token(seeded_events.admin_id, role_claim='USER')}"
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "total", "page", "page_size"}
    assert body["total"] == 1
    assert body["page"] == 1
    assert body["page_size"] == 20
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert set(item) == {
        "id",
        "event_type",
        "created_at",
        "user_id",
        "decision",
        "risk_category",
        "trust_score",
        "device",
    }
    assert item["id"] == str(seeded_events.event_ids[1])
    assert item["trust_score"] == "50.00"
    assert item["device"] == _SENSITIVE_SENTINELS[1][:12] + "…"
    _assert_no_sensitive_content(body)

    async def check_audit() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with AsyncSession(engine) as session:
                events = list(
                    await session.scalars(
                        select(SecurityEvent).where(
                            SecurityEvent.event_type == "ADMIN_ACCESS",
                            SecurityEvent.actor_id == seeded_events.admin_id,
                        )
                    )
                )
            assert any(
                event.details == {"path": "/admin/events", "method": "GET"} for event in events
            )
            assert all(
                not any(secret in repr(event.details) for secret in _SENSITIVE_SENTINELS)
                for event in events
            )
        finally:
            await engine.dispose()

    asyncio.run(check_audit())


def test_admin_event_filters_pagination_and_stable_ordering(
    migrated_test_database: ScratchDatabase,
    seeded_events: SeededEvents,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        headers = {"Authorization": f"Bearer {_token(seeded_events.admin_id, role_claim='ADMIN')}"}
        filtered = client.get(
            "/admin/events",
            params={
                "from": seeded_events.event_time_start.isoformat(),
                "to": seeded_events.event_time_end.isoformat(),
                "user_id": str(seeded_events.user_id),
                "risk_category": "HIGH",
            },
            headers=headers,
        )
        device_filtered = client.get(
            "/admin/events",
            params={"device_id": str(seeded_events.other_device_id)},
            headers=headers,
        )
        score_filtered = client.get(
            "/admin/events",
            params={
                "from": seeded_events.event_time_start.isoformat(),
                "to": seeded_events.event_time_end.isoformat(),
                "score_min": "75",
                "score_max": "100",
            },
            headers=headers,
        )
        first_page = client.get(
            "/admin/events",
            params={"user_id": str(seeded_events.user_id), "page": 1, "page_size": 2},
            headers=headers,
        )
        second_page = client.get(
            "/admin/events",
            params={"user_id": str(seeded_events.user_id), "page": 2, "page_size": 2},
            headers=headers,
        )

    assert filtered.status_code == device_filtered.status_code == score_filtered.status_code == 200
    assert [item["id"] for item in filtered.json()["items"]] == [str(seeded_events.event_ids[1])]
    assert [item["id"] for item in device_filtered.json()["items"]] == [
        str(seeded_events.event_ids[3])
    ]
    assert {item["id"] for item in score_filtered.json()["items"]} == {
        str(seeded_events.event_ids[2]),
        str(seeded_events.event_ids[3]),
    }
    first_ids = [item["id"] for item in first_page.json()["items"]]
    second_ids = [item["id"] for item in second_page.json()["items"]]
    expected_ids = [
        str(event_id)
        for event_id, _created_at in sorted(
            zip(
                seeded_events.event_ids[:3],
                (seeded_events.event_time_start,) * 3,
                strict=True,
            ),
            key=lambda row: (row[1], str(row[0])),
            reverse=True,
        )
    ]
    assert first_ids + second_ids == expected_ids
    assert first_page.json()["total"] == second_page.json()["total"] == 3


def test_admin_events_rejects_user_and_anonymous_callers(
    migrated_test_database: ScratchDatabase,
    seeded_events: SeededEvents,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        user_response = client.get("/admin/events", headers=_headers(seeded_events.user_id))
        anonymous_response = client.get("/admin/events")

    assert user_response.status_code == 403
    assert user_response.json()["error"]["code"] == "FORBIDDEN"
    assert anonymous_response.status_code == 401
    assert anonymous_response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_admin_events_validate_utc_bounds_and_page_size(
    migrated_test_database: ScratchDatabase,
    seeded_events: SeededEvents,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        headers = {"Authorization": f"Bearer {_token(seeded_events.admin_id, role_claim='ADMIN')}"}
        naive = client.get("/admin/events", params={"from": "2026-02-10T00:00:00"}, headers=headers)
        inverted = client.get(
            "/admin/events",
            params={"from": "2026-02-12T00:00:00Z", "to": "2026-02-10T00:00:00Z"},
            headers=headers,
        )
        too_large = client.get("/admin/events", params={"page_size": 51}, headers=headers)

    assert naive.status_code == 422
    assert inverted.status_code == 422
    assert too_large.status_code == 422
