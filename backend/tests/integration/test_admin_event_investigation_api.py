"""Real PostgreSQL integration tests for ADMIN event investigation."""

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
from app.core.clock import FixedClock
from app.core.config import Settings, get_settings
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.models.trust_factor import TrustFactor
from app.db.session import create_async_engine_for_url
from app.main import create_app
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase, ensure_auth_user_profile

_SUPABASE_URL = "https://admin-investigation-test.supabase.co"
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "admin-investigation-test-key"
_NOW = datetime.now(UTC).replace(microsecond=0)
_OTP_HASH = "ADMIN_INVESTIGATION_OTP_HASH_SENTINEL"
_DEVICE_HASH = "ADMIN_INVESTIGATION_DEVICE_HASH_SENTINEL"
_PASSWORD = "ADMIN_INVESTIGATION_PASSWORD_SENTINEL"
_PLAINTEXT_OTP = "731904"
_FORBIDDEN_KEYS = {
    "otp_hash",
    "password",
    "token",
    "secret",
    "authorization",
    "raw_context",
    "details",
    "max_attempts",
    "weights_json",
    "policy_version_id",
    "threshold",
}


@dataclass(frozen=True, slots=True)
class SeededInvestigation:
    admin_id: UUID
    user_id: UUID
    access_request_id: UUID
    root_event_id: UUID
    event_only_id: UUID
    related_event_ids: tuple[UUID, ...]
    challenge_ids: tuple[UUID, ...]
    indicator_block_request_ids: tuple[UUID, ...]


async def _seed_investigation(database_url: str) -> SeededInvestigation:
    admin_id, user_id = uuid4(), uuid4()
    await ensure_auth_user_profile(
        database_url,
        user_id=admin_id,
        email=f"admin-investigation-{admin_id}@integration.test",
    )
    await ensure_auth_user_profile(
        database_url,
        user_id=user_id,
        email=f"investigation-user-{user_id}@integration.test",
    )
    engine = create_async_engine_for_url(database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                update(Profile).where(Profile.id == admin_id).values(role="ADMIN")
            )

        async with AsyncSession(engine) as session, session.begin():
            policy = PolicyVersion(
                version_label=f"admin-investigation-{uuid4()}",
                weights_json={
                    "device_familiarity": 0.35,
                    "device_health": 0.30,
                    "location_normality": 0.20,
                    "time_normality": 0.15,
                },
                allow_threshold=70,
                stepup_threshold=40,
                is_active=False,
            )
            device = Device(
                user_id=user_id,
                device_hash=_DEVICE_HASH,
                first_seen_at=_NOW,
                last_seen_at=_NOW,
            )
            session.add_all((policy, device))
            await session.flush()

            access_request = AccessRequest(
                user_id=user_id,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address("203.0.113.45"),
                resolved_region="Example Region",
                initial_decision="STEP_UP",
                mfa_required=True,
                final_outcome="ALLOW",
                requested_at=_NOW,
                resolved_at=_NOW + timedelta(minutes=2),
            )
            session.add(access_request)
            await session.flush()

            session.add(
                ContextSignal(
                    access_request_id=access_request.id,
                    device_familiarity_raw="known_device",
                    device_health_raw="partially_healthy",
                    location_raw="new_region",
                    time_raw="outside_normal_window",
                    raw_context={
                        "device_fingerprint": _DEVICE_HASH,
                        "password": _PASSWORD,
                    },
                    captured_at=_NOW,
                )
            )
            evaluation = TrustEvaluation(
                access_request_id=access_request.id,
                policy_version_id=policy.id,
                trust_score=65.50,
                risk_classification="MEDIUM",
                status="COMPLETE",
                evaluated_at=_NOW,
            )
            session.add(evaluation)
            await session.flush()

            factor_values = (
                ("device_familiarity", "known_device", 100, "0.350", "35.000"),
                ("device_health", "partially_healthy", 60, "0.300", "18.000"),
                ("location_normality", "new_region", 40, "0.200", "8.000"),
                ("time_normality", "outside_normal_window", 30, "0.150", "4.500"),
            )
            session.add_all(
                TrustFactor(
                    trust_evaluation_id=evaluation.id,
                    factor_name=name,
                    raw_value=raw,
                    normalized_score=normalized,
                    weight=weight,
                    weighted_contribution=contribution,
                )
                for name, raw, normalized, weight, contribution in factor_values
            )
            session.add(
                PolicyDecision(
                    access_request_id=access_request.id,
                    trust_evaluation_id=evaluation.id,
                    policy_version_id=policy.id,
                    decision="STEP_UP",
                    decision_reason="Trust score 65.50 requires additional verification.",
                    decided_at=_NOW,
                )
            )

            first_challenge = OtpChallenge(
                access_request_id=access_request.id,
                user_id=user_id,
                otp_hash=_OTP_HASH,
                status="EXPIRED",
                attempt_count=1,
                max_attempts=3,
                created_at=_NOW + timedelta(seconds=1),
                expires_at=_NOW + timedelta(minutes=5),
            )
            success_challenge = OtpChallenge(
                access_request_id=access_request.id,
                user_id=user_id,
                otp_hash=_OTP_HASH,
                status="SUCCESS",
                attempt_count=0,
                max_attempts=3,
                created_at=_NOW + timedelta(seconds=2),
                expires_at=_NOW + timedelta(minutes=6),
                verified_at=_NOW + timedelta(seconds=3),
            )
            session.add_all((first_challenge, success_challenge))
            await session.flush()

            root_event = SecurityEvent(
                event_type="ACCESS_REQUEST_SUBMITTED",
                actor_id=user_id,
                target_user_id=user_id,
                access_request_id=access_request.id,
                trust_evaluation_id=evaluation.id,
                decision="STEP_UP",
                risk_category="MEDIUM",
                created_at=_NOW,
                details={"password": _PASSWORD, "plaintext_otp": _PLAINTEXT_OTP},
            )
            related_events = [
                SecurityEvent(
                    event_type=event_type,
                    actor_id=user_id,
                    access_request_id=access_request.id,
                    trust_evaluation_id=evaluation.id,
                    decision=decision,
                    risk_category="MEDIUM",
                    created_at=_NOW + timedelta(seconds=index + 1),
                    details={"otp_hash": _OTP_HASH},
                )
                for index, (event_type, decision) in enumerate(
                    (
                        ("MFA_CHALLENGE_CREATED", "STEP_UP"),
                        ("MFA_CHALLENGE_CREATED", "STEP_UP"),
                        ("MFA_SUCCESS", "STEP_UP"),
                        ("ACCESS_MFA_ALLOWED", "ALLOW"),
                    )
                )
            ]
            event_only = SecurityEvent(
                event_type="LOGIN_FAILURE",
                actor_id=None,
                details={"password": _PASSWORD, "plaintext_otp": _PLAINTEXT_OTP},
                created_at=_NOW + timedelta(minutes=1),
            )
            session.add_all((root_event, *related_events, event_only))
            indicator_block_requests = [
                AccessRequest(
                    user_id=user_id,
                    device_id=device.id,
                    source_ip=IPv4Address("203.0.113.45"),
                    initial_decision="BLOCK",
                    final_outcome="BLOCK",
                    requested_at=_NOW - timedelta(minutes=index + 1),
                    resolved_at=_NOW - timedelta(minutes=index + 1),
                )
                for index in range(3)
            ]
            session.add_all(indicator_block_requests)
            session.add_all(
                SecurityEvent(
                    event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                    actor_id=user_id,
                    created_at=_NOW,
                )
                for _ in range(5)
            )
            await session.flush()

            return SeededInvestigation(
                admin_id=admin_id,
                user_id=user_id,
                access_request_id=access_request.id,
                root_event_id=root_event.id,
                event_only_id=event_only.id,
                related_event_ids=tuple(event.id for event in related_events),
                challenge_ids=(first_challenge.id, success_challenge.id),
                indicator_block_request_ids=tuple(
                    request.id for request in indicator_block_requests
                ),
            )
    finally:
        await engine.dispose()


@pytest.fixture
def seeded_investigation(
    migrated_test_database: ScratchDatabase,
) -> Iterator[SeededInvestigation]:
    # Rows remain in the disposable database because security events are append-only.
    seeded = asyncio.run(_seed_investigation(migrated_test_database.url))
    yield seeded

    async def remove_indicator_blocks() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    delete(AccessRequest).where(
                        AccessRequest.id.in_(seeded.indicator_block_request_ids)
                    )
                )
        finally:
            await engine.dispose()

    asyncio.run(remove_indicator_blocks())


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
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_clock] = lambda: FixedClock(_NOW)
    return TestClient(application)


def _token(user_id: UUID, *, role_claim: str) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "session_id": str(user_id),
            "role": role_claim,
            "aud": "authenticated",
            "iss": f"{_SUPABASE_URL}/auth/v1",
            "exp": int(datetime.now(UTC).timestamp()) + 3600,
        },
        _TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": _TEST_KID},
    )


def _assert_no_sensitive_content(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_lower = str(key).casefold()
            assert not any(term in key_lower for term in _FORBIDDEN_KEYS)
            _assert_no_sensitive_content(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_sensitive_content(nested)
    elif isinstance(value, str):
        for sentinel in (_OTP_HASH, _PASSWORD, _PLAINTEXT_OTP, _DEVICE_HASH):
            assert sentinel not in value


def test_admin_investigation_returns_the_full_persisted_chain_and_audits_read(
    migrated_test_database: ScratchDatabase,
    seeded_investigation: SeededInvestigation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            f"/admin/events/{seeded_investigation.root_event_id}",
            headers={
                "Authorization": "Bearer "
                + _token(seeded_investigation.admin_id, role_claim="USER")
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "event",
        "access_request",
        "context_signals",
        "trust_evaluation",
        "policy_decision",
        "otp_challenges",
        "related_events",
        "behavioral_indicators",
    }
    assert set(body["event"]) == {
        "id",
        "event_type",
        "actor_id",
        "target_user_id",
        "decision",
        "risk_category",
        "created_at",
    }
    assert body["event"]["id"] == str(seeded_investigation.root_event_id)
    assert body["access_request"]["id"] == str(seeded_investigation.access_request_id)
    assert "auth_session_id" not in body["access_request"]
    assert body["access_request"]["initial_decision"] == "STEP_UP"
    assert body["access_request"]["final_outcome"] == "ALLOW"
    assert body["access_request"]["source_ip"] == "203.0.113.45"
    assert body["access_request"]["resolved_region"] == "Example Region"
    assert body["behavioral_indicators"] == {
        "repeated_failed_access_attempts": {
            "count": 8,
            "normalized_value": 1.0,
            "flagged": True,
        },
        "recent_blocks": {"count": 3, "normalized_value": 1.0, "flagged": True},
    }
    assert body["access_request"]["device"]["device_hash"] == _DEVICE_HASH[:12] + "…"

    assert set(body["context_signals"]) == {
        "captured_at",
        "device_familiarity_raw",
        "device_health_raw",
        "location_raw",
        "time_raw",
    }
    assert len(body["trust_evaluation"]["factors"]) == 4
    factor = body["trust_evaluation"]["factors"][0]
    assert set(factor) == {
        "factor_name",
        "raw_value",
        "normalized_score",
        "weight",
        "weighted_contribution",
        "explanation",
    }
    assert factor["explanation"]
    assert body["policy_decision"]["decision"] == "STEP_UP"
    assert body["policy_decision"]["policy_version"]["version_label"].startswith(
        "admin-investigation-"
    )
    assert body["policy_decision"]["decision_reason"] == (
        "Trust score 65.50 requires additional verification."
    )
    assert [challenge["id"] for challenge in body["otp_challenges"]] == [
        str(challenge_id) for challenge_id in seeded_investigation.challenge_ids
    ]
    assert [challenge["status"] for challenge in body["otp_challenges"]] == [
        "EXPIRED",
        "SUCCESS",
    ]
    assert [event["id"] for event in body["related_events"]] == [
        str(event_id) for event_id in seeded_investigation.related_event_ids
    ]
    assert [event["created_at"] for event in body["related_events"]] == sorted(
        event["created_at"] for event in body["related_events"]
    )
    _assert_no_sensitive_content(body)

    async def assert_audit() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with AsyncSession(engine) as session:
                audit_events = list(
                    await session.scalars(
                        select(SecurityEvent).where(
                            SecurityEvent.event_type == "ADMIN_ACCESS",
                            SecurityEvent.actor_id == seeded_investigation.admin_id,
                        )
                    )
                )
            assert any(
                event.details == {"path": "/admin/events/{event_id}", "method": "GET"}
                for event in audit_events
            )
            assert all(
                _PASSWORD not in repr(event.details) and _OTP_HASH not in repr(event.details)
                for event in audit_events
            )
        finally:
            await engine.dispose()

    asyncio.run(assert_audit())


def test_event_without_access_request_returns_event_only_investigation(
    migrated_test_database: ScratchDatabase,
    seeded_investigation: SeededInvestigation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        response = client.get(
            f"/admin/events/{seeded_investigation.event_only_id}",
            headers={
                "Authorization": "Bearer "
                + _token(seeded_investigation.admin_id, role_claim="ADMIN")
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["event"]["id"] == str(seeded_investigation.event_only_id)
    assert body["event"]["event_type"] == "LOGIN_FAILURE"
    assert body["access_request"] is None
    assert body["context_signals"] is None
    assert body["trust_evaluation"] is None
    assert body["policy_decision"] is None
    assert body["otp_challenges"] == []
    assert body["related_events"] == []
    assert body["behavioral_indicators"] is None
    _assert_no_sensitive_content(body)


def test_admin_request_detail_uses_full_investigation_and_user_stays_curated(
    migrated_test_database: ScratchDatabase,
    seeded_investigation: SeededInvestigation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        admin_response = client.get(
            f"/access/request/{seeded_investigation.access_request_id}",
            headers={
                "Authorization": "Bearer "
                + _token(seeded_investigation.admin_id, role_claim="ADMIN")
            },
        )
        user_response = client.get(
            f"/access/request/{seeded_investigation.access_request_id}",
            headers={
                "Authorization": "Bearer " + _token(seeded_investigation.user_id, role_claim="USER")
            },
        )

    assert admin_response.status_code == 200
    admin_body = admin_response.json()
    assert admin_body["access_request"]["id"] == str(seeded_investigation.access_request_id)
    assert len(admin_body["otp_challenges"]) == 2
    assert admin_body["behavioral_indicators"]["repeated_failed_access_attempts"]["count"] == 8
    assert admin_body["behavioral_indicators"]["repeated_failed_access_attempts"]["flagged"] is True
    assert admin_body["behavioral_indicators"]["recent_blocks"]["count"] == 3
    assert admin_body["behavioral_indicators"]["recent_blocks"]["flagged"] is True
    _assert_no_sensitive_content(admin_body)

    assert user_response.status_code == 200
    assert set(user_response.json()) == {
        "id",
        "resource_id",
        "requested_at",
        "initial_decision",
        "final_outcome",
        "mfa_was_required",
        "mfa_status",
    }


def test_user_and_anonymous_callers_cannot_investigate_and_missing_event_is_404(
    migrated_test_database: ScratchDatabase,
    seeded_investigation: SeededInvestigation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _client(migrated_test_database.url, monkeypatch) as client:
        user_response = client.get(
            f"/admin/events/{seeded_investigation.root_event_id}",
            headers={
                "Authorization": "Bearer "
                + _token(seeded_investigation.user_id, role_claim="ADMIN")
            },
        )
        anonymous_response = client.get(f"/admin/events/{seeded_investigation.root_event_id}")
        missing_response = client.get(
            f"/admin/events/{uuid4()}",
            headers={
                "Authorization": "Bearer "
                + _token(seeded_investigation.admin_id, role_claim="ADMIN")
            },
        )

    assert user_response.status_code == 403
    assert user_response.json()["error"]["code"] == "FORBIDDEN"
    assert anonymous_response.status_code == 401
    assert anonymous_response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert missing_response.status_code == 404
