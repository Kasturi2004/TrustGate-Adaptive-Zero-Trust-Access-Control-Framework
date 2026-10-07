"""Real PostgreSQL integration tests for the ADMIN dashboard endpoint."""

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
from app.api.deps import get_clock
from app.core.clock import Clock, FixedClock
from app.core.config import Settings, get_settings
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
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
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import (
    ScratchDatabase,
    ensure_auth_user_profile,
)

_SUPABASE_URL = "https://admin-dashboard-test.supabase.co"
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "admin-dashboard-test-key"
_DEFAULT_INDICATOR_TIME = datetime(2040, 1, 1, tzinfo=UTC)
_FROM = datetime(2026, 1, 10, tzinfo=UTC)
_TO = datetime(2026, 1, 13, tzinfo=UTC)
_ALLOWED_FIELDS = {
    "total_requests",
    "allow_count",
    "step_up_count",
    "block_count",
    "average_trust_score",
    "high_risk_count",
    "mfa_success_rate",
    "behavioral_indicators",
}
_FORBIDDEN_KEYS = {
    "otp_hash",
    "password",
    "token",
    "secret",
    "authorization",
    "hash",
    "device_hash",
    "device_fingerprint",
    "source_ip",
    "resolved_region",
    "trust_factors",
    "weights",
    "thresholds",
    "decision_reason",
    "policy_version",
}
_SENSITIVE_SENTINELS = (
    "ADMIN_DASHBOARD_OTP_HASH_SENTINEL",
    "ADMIN_DASHBOARD_DEVICE_HASH_SENTINEL",
)


@dataclass(frozen=True, slots=True)
class SeededDashboard:
    admin_id: UUID
    user_id: UUID
    policy_version_id: UUID
    device_id: UUID
    access_request_ids: tuple[UUID, ...]


def _at(day: int, *, second: int = 0) -> datetime:
    return datetime(2026, 1, day, tzinfo=UTC) + timedelta(seconds=second)


async def _seed_dashboard(database_url: str) -> SeededDashboard:
    admin_id = uuid4()
    user_id = uuid4()
    await ensure_auth_user_profile(
        database_url,
        user_id=admin_id,
        email=f"dashboard-admin-{admin_id}@integration.test",
    )
    await ensure_auth_user_profile(
        database_url,
        user_id=user_id,
        email=f"dashboard-user-{user_id}@integration.test",
    )

    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                update(Profile).where(Profile.id == admin_id).values(role="ADMIN")
            )

        async with AsyncSession(engine) as session, session.begin():
            policy = PolicyVersion(
                version_label=f"admin-dashboard-test-{uuid4()}",
                weights_json={"device_familiarity": 0.35},
                is_active=False,
            )
            device = Device(user_id=user_id, device_hash=_SENSITIVE_SENTINELS[1])
            session.add_all((policy, device))
            await session.flush()

            requests = [
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.10"),
                    initial_decision="ALLOW",
                    final_outcome="ALLOW",
                    requested_at=_at(10),
                ),
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.10"),
                    initial_decision="STEP_UP",
                    mfa_required=True,
                    final_outcome="ALLOW",
                    requested_at=_at(11),
                ),
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.10"),
                    initial_decision="BLOCK",
                    final_outcome="BLOCK",
                    requested_at=_at(12),
                ),
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.10"),
                    initial_decision="STEP_UP",
                    mfa_required=True,
                    requested_at=_at(13),
                ),
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.10"),
                    initial_decision="ALLOW",
                    final_outcome="ALLOW",
                    requested_at=_at(13, second=1),
                ),
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("192.0.2.10"),
                    initial_decision="ALLOW",
                    final_outcome="ALLOW",
                    requested_at=datetime(2026, 3, 1, tzinfo=UTC),
                ),
            ]
            session.add_all(requests)
            await session.flush()

            session.add_all(
                (
                    TrustEvaluation(
                        access_request_id=requests[0].id,
                        policy_version_id=policy.id,
                        trust_score=80,
                        risk_classification="LOW",
                        evaluated_at=_at(10),
                    ),
                    TrustEvaluation(
                        access_request_id=requests[1].id,
                        policy_version_id=policy.id,
                        trust_score=40,
                        risk_classification="HIGH",
                        evaluated_at=_at(11),
                    ),
                    TrustEvaluation(
                        access_request_id=requests[2].id,
                        policy_version_id=policy.id,
                        trust_score=60,
                        risk_classification="MEDIUM",
                        evaluated_at=_at(12),
                    ),
                    TrustEvaluation(
                        access_request_id=requests[3].id,
                        policy_version_id=policy.id,
                        trust_score=100,
                        risk_classification="HIGH",
                        evaluated_at=_at(13, second=1),
                    ),
                    TrustEvaluation(
                        access_request_id=requests[4].id,
                        policy_version_id=policy.id,
                        trust_score=99,
                        risk_classification="HIGH",
                        evaluated_at=_at(13, second=1),
                    ),
                )
            )
            session.add_all(
                (
                    OtpChallenge(
                        access_request_id=requests[1].id,
                        user_id=user_id,
                        otp_hash=_SENSITIVE_SENTINELS[0],
                        status="SUCCESS",
                        created_at=_at(11, second=1),
                        expires_at=_at(11) + timedelta(minutes=5),
                    ),
                    OtpChallenge(
                        access_request_id=requests[1].id,
                        user_id=user_id,
                        otp_hash=_SENSITIVE_SENTINELS[0],
                        status="EXPIRED",
                        created_at=_at(11, second=2),
                        expires_at=_at(11) + timedelta(minutes=5),
                    ),
                    OtpChallenge(
                        access_request_id=requests[2].id,
                        user_id=user_id,
                        otp_hash=_SENSITIVE_SENTINELS[0],
                        status="SUCCESS",
                        created_at=_at(12, second=1),
                        expires_at=_at(12) + timedelta(minutes=5),
                    ),
                    OtpChallenge(
                        access_request_id=requests[4].id,
                        user_id=user_id,
                        otp_hash=_SENSITIVE_SENTINELS[0],
                        status="SUCCESS",
                        created_at=_at(13, second=1),
                        expires_at=_at(13) + timedelta(minutes=5),
                    ),
                )
            )
            await session.flush()
            return SeededDashboard(
                admin_id=admin_id,
                user_id=user_id,
                policy_version_id=policy.id,
                device_id=device.id,
                access_request_ids=tuple(request.id for request in requests),
            )
    finally:
        await engine.dispose()


async def _seed_indicator_activity(
    database_url: str,
    *,
    seeded: SeededDashboard,
    now: datetime,
) -> UUID:
    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with AsyncSession(engine) as session, session.begin():
            blocked_request = AccessRequest(
                user_id=seeded.user_id,
                device_id=seeded.device_id,
                source_ip=IPv4Address("192.0.2.11"),
                initial_decision="BLOCK",
                final_outcome="BLOCK",
                requested_at=now,
                resolved_at=now,
            )
            session.add(blocked_request)
            session.add_all(
                SecurityEvent(
                    event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                    actor_id=seeded.user_id,
                    created_at=now,
                )
                for _ in range(4)
            )
            await session.flush()
            return blocked_request.id
    finally:
        await engine.dispose()


async def _remove_dashboard(database_url: str, seeded: SeededDashboard) -> None:
    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                delete(OtpChallenge).where(
                    OtpChallenge.access_request_id.in_(seeded.access_request_ids)
                )
            )
            await connection.execute(
                delete(TrustEvaluation).where(
                    TrustEvaluation.access_request_id.in_(seeded.access_request_ids)
                )
            )
            await connection.execute(
                delete(AccessRequest).where(AccessRequest.id.in_(seeded.access_request_ids))
            )
            await connection.execute(delete(Device).where(Device.id == seeded.device_id))
            await connection.execute(
                delete(PolicyVersion).where(PolicyVersion.id == seeded.policy_version_id)
            )
    finally:
        await engine.dispose()
    # Successful and denied admin reads append audit rows tied to these actor IDs.
    # Phase 10's database trigger correctly prevents FK-driven updates to those rows.


@pytest.fixture
def seeded_dashboard(migrated_test_database: ScratchDatabase) -> Iterator[SeededDashboard]:
    seeded = asyncio.run(_seed_dashboard(migrated_test_database.url))
    yield seeded
    asyncio.run(_remove_dashboard(migrated_test_database.url, seeded))


def _client(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    clock: Clock | None = None,
) -> TestClient:
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
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_clock] = lambda: (
        clock or FixedClock(_DEFAULT_INDICATOR_TIME)
    )
    return TestClient(application)


def _token(user_id: UUID, *, role_claim: str) -> str:
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


def _assert_no_sensitive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            assert str(key).casefold() not in _FORBIDDEN_KEYS
            _assert_no_sensitive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_sensitive_fields(nested)
    elif isinstance(value, str):
        for sentinel in _SENSITIVE_SENTINELS:
            assert sentinel not in value


def _dashboard_params() -> dict[str, str]:
    return {
        "from": "2026-01-10T05:30:00+05:30",
        "to": "2026-01-13T05:30:00+05:30",
    }


def test_admin_dashboard_returns_real_metrics_and_audits_the_read(
    migrated_test_database: ScratchDatabase,
    seeded_dashboard: SeededDashboard,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            "/admin/dashboard",
            params=_dashboard_params(),
            headers={
                "Authorization": f"Bearer {_token(seeded_dashboard.admin_id, role_claim='USER')}"
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == _ALLOWED_FIELDS
    assert {
        **body,
        "mfa_success_rate": None,
    } == {
        "total_requests": 4,
        "allow_count": 1,
        "step_up_count": 2,
        "block_count": 1,
        "average_trust_score": 70.0,
        "high_risk_count": 1,
        "mfa_success_rate": None,
        "behavioral_indicators": {
            "repeated_failed_access_attempts": {
                "count": 0,
                "normalized_value": 0.0,
                "flagged": False,
            },
            "recent_blocks": {"count": 0, "normalized_value": 0.0, "flagged": False},
        },
    }
    assert body["mfa_success_rate"] == pytest.approx(2 / 3)
    _assert_no_sensitive_fields(body)

    async def assert_audit_event() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with AsyncSession(engine) as session:
                events = await session.scalars(
                    select(SecurityEvent).where(
                        SecurityEvent.event_type == "ADMIN_ACCESS",
                        SecurityEvent.actor_id == seeded_dashboard.admin_id,
                    )
                )
            matching_events = [
                event
                for event in events
                if event.details == {"path": "/admin/dashboard", "method": "GET"}
            ]
            assert matching_events
            assert all(
                not any(secret in repr(event.details) for secret in _SENSITIVE_SENTINELS)
                for event in matching_events
            )
        finally:
            await engine.dispose()

    asyncio.run(assert_audit_event())


def test_admin_dashboard_surfaces_both_behavioral_indicators(
    migrated_test_database: ScratchDatabase,
    seeded_dashboard: SeededDashboard,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Spread synthetic timestamps so append-only test events from other runs cannot overlap.
    now = datetime(2200, 1, 1, tzinfo=UTC) + timedelta(
        seconds=uuid4().int % (365 * 24 * 60 * 60 * 1000)
    )
    blocked_request_id = asyncio.run(
        _seed_indicator_activity(
            migrated_test_database.url,
            seeded=seeded_dashboard,
            now=now,
        )
    )
    try:
        with _client(
            migrated_test_database.url,
            monkeypatch,
            clock=FixedClock(now),
        ) as client:
            response = client.get(
                "/admin/dashboard",
                params=_dashboard_params(),
                headers={
                    "Authorization": "Bearer "
                    + _token(seeded_dashboard.admin_id, role_claim="ADMIN")
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["behavioral_indicators"] == {
            "repeated_failed_access_attempts": {
                "count": 5,
                "normalized_value": 1.0,
                "flagged": True,
            },
            "recent_blocks": {
                "count": 1,
                "normalized_value": pytest.approx(1 / 3),
                "flagged": False,
            },
        }
        assert body["total_requests"] == 4
        assert body["average_trust_score"] == 70.0
        _assert_no_sensitive_fields(body)
    finally:

        async def remove_blocked_request() -> None:
            engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
            try:
                async with engine.begin() as connection:
                    await connection.execute(
                        delete(AccessRequest).where(AccessRequest.id == blocked_request_id)
                    )
            finally:
                await engine.dispose()

        asyncio.run(remove_blocked_request())


def test_admin_dashboard_has_null_metrics_when_no_evaluations_or_challenges_exist(
    migrated_test_database: ScratchDatabase,
    seeded_dashboard: SeededDashboard,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            "/admin/dashboard",
            params={
                "from": "2026-03-01T00:00:00Z",
                "to": "2026-03-02T00:00:00Z",
            },
            headers={
                "Authorization": f"Bearer {_token(seeded_dashboard.admin_id, role_claim='ADMIN')}"
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "total_requests": 1,
        "allow_count": 1,
        "step_up_count": 0,
        "block_count": 0,
        "average_trust_score": None,
        "high_risk_count": 0,
        "mfa_success_rate": None,
        "behavioral_indicators": {
            "repeated_failed_access_attempts": {
                "count": 0,
                "normalized_value": 0.0,
                "flagged": False,
            },
            "recent_blocks": {"count": 0, "normalized_value": 0.0, "flagged": False},
        },
    }


def test_admin_dashboard_rejects_non_admin_and_anonymous_requests(
    migrated_test_database: ScratchDatabase,
    seeded_dashboard: SeededDashboard,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        user_response = client.get(
            "/admin/dashboard",
            params=_dashboard_params(),
            headers={
                "Authorization": f"Bearer {_token(seeded_dashboard.user_id, role_claim='ADMIN')}"
            },
        )
        anonymous_response = client.get("/admin/dashboard", params=_dashboard_params())

    assert user_response.status_code == 403
    assert user_response.json()["error"]["code"] == "FORBIDDEN"
    assert anonymous_response.status_code == 401
    assert anonymous_response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_admin_dashboard_requires_offset_aware_ordered_bounds(
    migrated_test_database: ScratchDatabase,
    seeded_dashboard: SeededDashboard,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        headers = {
            "Authorization": f"Bearer {_token(seeded_dashboard.admin_id, role_claim='USER')}"
        }
        naive_response = client.get(
            "/admin/dashboard",
            params={"from": "2026-01-10T00:00:00", "to": "2026-01-13T00:00:00Z"},
            headers=headers,
        )
        inverted_response = client.get(
            "/admin/dashboard",
            params={"from": "2026-01-13T00:00:00Z", "to": "2026-01-10T00:00:00Z"},
            headers=headers,
        )

    assert naive_response.status_code == 422
    assert inverted_response.status_code == 422
