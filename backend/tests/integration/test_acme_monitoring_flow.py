"""End-to-end PostgreSQL coverage for Acme access and TrustGate admin events."""

import asyncio
import base64
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast
from uuid import UUID, uuid4

import app.api.deps as deps
import app.core.jwt as jwt_module
import jwt
import pyotp
import pytest
from app.api.deps import get_clock
from app.api.routes import access as access_routes
from app.api.routes import admin as admin_routes
from app.core import mfa_secrets, rate_limit
from app.core.clock import FixedClock
from app.core.config import Settings, get_settings
from app.core.mfa_secrets import encrypt_totp_secret
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.mfa_credential import MfaCredential
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.policy_decision import PolicyDecision
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.models.security_event import SecurityEvent
from app.db.models.trust_evaluation import TrustEvaluation
from app.db.repositories.policy_version import PolicyVersionRepository
from app.db.session import create_async_engine_for_url
from app.main import create_app
from app.services.context import client_ip as client_ip_module
from app.services.context import collector as context_collector
from app.services.context.device_familiarity import device_token_hash
from app.services.context.location import UnavailableGeoResolver, get_geo_resolver
from app.services.device_health_assessment import CHECK_WEIGHTS, EvidenceObservation
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import (
    ScratchDatabase,
    ensure_auth_user_profile,
    ensure_verified_test_authenticator,
)

_SUPABASE_URL = "https://acme-monitoring-test.supabase.co"
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_TEST_KID = "acme-monitoring-test-key"
_DEVICE_TOKEN = "acme-monitoring-recognized-device-token"
_DEVICE_SECRET = "acme-monitoring-device-hmac-secret"
_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
_TOTP_ENCRYPTION_KEY = SecretStr(
    base64.urlsafe_b64encode(b"acme-monitoring-totp-key-32bytes").decode("ascii")
)
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_TEST_POSTURE_PROOF = b"integration-test-posture-proof"


class _VerifiedTestPostureProvider:
    """Test-only evidence source used to exercise existing allow/step-up flows."""

    async def collect(
        self, *, device_binding: str | None, now: datetime
    ) -> tuple[EvidenceObservation, ...]:
        if device_binding is None:
            return ()
        return tuple(
            EvidenceObservation(
                check=check,
                state="PASS",
                source="integration-fixture",
                observed_at=now,
                device_binding=device_binding,
                proof=_TEST_POSTURE_PROOF,
            )
            for check in CHECK_WEIGHTS
        )


class _VerifiedTestPostureProof:
    def verify(self, observation: EvidenceObservation) -> bool:
        return observation.proof == _TEST_POSTURE_PROOF


def _enable_test_posture_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        context_collector,
        "get_device_health_evidence_provider",
        _VerifiedTestPostureProvider,
    )
    monkeypatch.setattr(
        context_collector,
        "get_device_health_evidence_verifier",
        _VerifiedTestPostureProof,
    )


def _token(user_id: UUID, *, session_id: UUID) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "session_id": str(session_id),
            "role": "USER",
            "aud": "authenticated",
            "iss": f"{_SUPABASE_URL}/auth/v1",
            "exp": int(datetime.now(UTC).timestamp()) + 3600,
        },
        _TEST_PRIVATE_KEY,
        algorithm="ES256",
        headers={"kid": _TEST_KID},
    )


def test_acme_access_is_redeemed_and_visible_in_admin_event_feed(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_test_posture_provider(monkeypatch)
    employee_id, admin_id = uuid4(), uuid4()
    employee_session_id = uuid4()
    asyncio.run(
        ensure_auth_user_profile(
            migrated_test_database.url,
            user_id=employee_id,
            email=f"acme-employee-{employee_id}@integration.test",
        )
    )
    asyncio.run(
        ensure_auth_user_profile(
            migrated_test_database.url,
            user_id=admin_id,
            email=f"acme-admin-{admin_id}@integration.test",
        )
    )
    asyncio.run(ensure_verified_test_authenticator(migrated_test_database.url, user_id=admin_id))

    now = datetime.now(UTC).replace(microsecond=0)
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url=_SUPABASE_URL,
        database_url=migrated_test_database.url,
        device_hash_secret=_DEVICE_SECRET,
        rate_limit_key_secret="acme-monitoring-rate-limit-secret",
        totp_secret_encryption_key=_TOTP_ENCRYPTION_KEY,
    )
    recognized_device_hash = device_token_hash(_DEVICE_TOKEN, settings=settings)
    assert recognized_device_hash is not None

    async def configure_identities_and_device() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    update(Profile).where(Profile.id == admin_id).values(role="ADMIN")
                )
            async with AsyncSession(engine) as session, session.begin():
                active_policy = await PolicyVersionRepository(session).get_active()
                assert active_policy is not None
                assert active_policy.version_label == "POL-1.0"
                session.add(
                    Device(
                        user_id=employee_id,
                        device_hash=recognized_device_hash,
                        recognized_at=now,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )
                session.add(
                    MfaCredential(
                        user_id=employee_id,
                        secret_ciphertext=encrypt_totp_secret(_TOTP_SECRET, settings=settings),
                        verified_at=now,
                        enabled=True,
                    )
                )
        finally:
            await engine.dispose()

    asyncio.run(configure_identities_and_device())

    public_jwk = cast(
        dict[str, object], ECAlgorithm.to_jwk(_TEST_PRIVATE_KEY.public_key(), as_dict=True)
    )
    public_jwk.update({"kid": _TEST_KID, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    monkeypatch.setattr(jwt_module, "get_settings", lambda: settings)
    monkeypatch.setattr(deps, "get_settings", lambda: settings)
    monkeypatch.setattr(access_routes, "get_settings", lambda: settings)
    monkeypatch.setattr(admin_routes, "get_settings", lambda: settings)
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: settings)
    monkeypatch.setattr(rate_limit, "get_settings", lambda: settings)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: settings)
    monkeypatch.setattr(PyJWKClient, "fetch_data", lambda _client: {"keys": [public_jwk]})
    jwt_module._jwks_client.cache_clear()

    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_clock] = lambda: FixedClock(now)
    application.dependency_overrides[get_geo_resolver] = UnavailableGeoResolver
    with TestClient(
        application,
        base_url="https://trustgate.test",
        client=("8.8.8.8", 44321),
    ) as client:
        employee_headers = {
            "Authorization": f"Bearer {_token(employee_id, session_id=employee_session_id)}",
            "X-Device-Token": _DEVICE_TOKEN,
            "User-Agent": _USER_AGENT,
        }
        evaluation = client.post(
            "/access/evaluate",
            json={"resource_id": "ops-dashboard"},
            headers=employee_headers,
        )

        assert evaluation.status_code == 200, evaluation.text
        evaluation_body = evaluation.json()
        decision = evaluation_body["decision"]
        assert decision in {"ALLOW", "STEP_UP"}
        access_request_id = evaluation_body["access_request_id"]
        assert access_request_id

        if decision == "STEP_UP":
            challenge_id = evaluation_body["mfa_challenge_id"]
            assert challenge_id
            verification = client.post(
                "/auth/mfa/totp/step-up/verify",
                json={
                    "mfa_challenge_id": challenge_id,
                    "code": pyotp.TOTP(_TOTP_SECRET).at(now),
                },
                headers=employee_headers,
            )
            assert verification.status_code == 200, verification.text
            assert verification.json()["verification_status"] == "verified"

        redemption_body = {"access_request_id": access_request_id}
        redemption = client.post(
            "/resources/ops-dashboard",
            json=redemption_body,
            headers=employee_headers,
        )
        assert redemption.status_code == 200, redemption.text
        assert redemption.json()["resource_id"] == "ops-dashboard"

        replay = client.post(
            "/resources/ops-dashboard",
            json=redemption_body,
            headers=employee_headers,
        )
        assert replay.status_code == 403

        admin_headers = {"Authorization": f"Bearer {_token(admin_id, session_id=uuid4())}"}
        event_feed = client.get(
            "/admin/events",
            params={"user_id": str(employee_id), "page": 1, "page_size": 50},
            headers=admin_headers,
        )
        assert event_feed.status_code == 200, event_feed.text
        feed_items = event_feed.json()["items"]
        event_ids_by_type = {
            event_type: [item["id"] for item in feed_items if item["event_type"] == event_type]
            for event_type in (
                "ACCESS_REQUEST_SUBMITTED",
                "ACCESS_STEPUP",
                "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
                "ACCESS_MFA_ALLOWED",
                "ACCESS_ALLOWED",
                "PROTECTED_RESOURCE_ACCESSED",
            )
        }
        assert len(event_ids_by_type["ACCESS_REQUEST_SUBMITTED"]) == 1
        assert len(event_ids_by_type["ACCESS_ALLOWED"]) == int(decision == "ALLOW")
        if decision == "STEP_UP":
            assert all(
                len(event_ids_by_type[event_type]) == 1
                for event_type in (
                    "ACCESS_STEPUP",
                    "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
                    "ACCESS_MFA_ALLOWED",
                )
            )
        else:
            assert all(
                not event_ids_by_type[event_type]
                for event_type in (
                    "ACCESS_STEPUP",
                    "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
                    "ACCESS_MFA_ALLOWED",
                )
            )

        non_admin_feed = client.get(
            "/admin/events",
            params={"user_id": str(employee_id)},
            headers=employee_headers,
        )
        assert non_admin_feed.status_code == 403

        investigation_event_id = (
            event_ids_by_type["ACCESS_MFA_ALLOWED"][0]
            if decision == "STEP_UP"
            else event_ids_by_type["ACCESS_ALLOWED"][0]
        )
        investigation = client.get(f"/admin/events/{investigation_event_id}", headers=admin_headers)
        assert investigation.status_code == 200, investigation.text
        investigation_body = investigation.json()
        chain_types = {
            investigation_body["event"]["event_type"],
            *(event["event_type"] for event in investigation_body["related_events"]),
        }
        assert {
            "ACCESS_REQUEST_SUBMITTED",
            "ACCESS_STEPUP" if decision == "STEP_UP" else "ACCESS_ALLOWED",
            "PROTECTED_RESOURCE_ACCESSED",
        } <= chain_types
        if decision == "STEP_UP":
            assert {
                "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
                "ACCESS_MFA_ALLOWED",
            } <= chain_types

    async def assert_persisted_chain() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with AsyncSession(engine) as session:
                request_uuid = UUID(access_request_id)
                events = list(
                    await session.scalars(
                        select(SecurityEvent).where(SecurityEvent.access_request_id == request_uuid)
                    )
                )
                request = await session.get(AccessRequest, request_uuid)
                context_signal = await session.scalar(
                    select(ContextSignal).where(ContextSignal.access_request_id == request_uuid)
                )
                device = (
                    await session.get(Device, request.device_id) if request is not None else None
                )
                policy_decision = await session.scalar(
                    select(PolicyDecision).where(PolicyDecision.access_request_id == request_uuid)
                )
                trust_evaluation = await session.scalar(
                    select(TrustEvaluation).where(TrustEvaluation.access_request_id == request_uuid)
                )
                policy = (
                    await session.get(PolicyVersion, trust_evaluation.policy_version_id)
                    if trust_evaluation is not None
                    else None
                )
                step_up_challenge = (
                    await session.scalar(
                        select(OtpChallenge).where(OtpChallenge.access_request_id == request_uuid)
                    )
                    if decision == "STEP_UP"
                    else None
                )
            assert request is not None and request.consumed_at is not None
            assert request.user_id == employee_id
            assert request.auth_session_id == employee_session_id
            assert request.resource_id == "ops-dashboard"
            assert request.initial_decision == decision
            assert request.final_outcome == "ALLOW"
            assert request.mfa_required is (decision == "STEP_UP")
            assert context_signal is not None
            assert context_signal.device_familiarity_raw == "known_device"
            assert context_signal.device_health_raw == "healthy"
            assert context_signal.location_raw == "unavailable"
            assert device is not None and device.recognized_at is not None
            assert policy_decision is not None and policy_decision.decision == decision
            assert trust_evaluation is not None
            assert policy is not None and policy.is_active
            assert trust_evaluation.risk_classification == "LOW"
            assert policy_decision.decision_reason.startswith("Trust score ")
            assert "meets the ALLOW threshold" in policy_decision.decision_reason
            assert (
                trust_evaluation.trust_score >= policy.allow_threshold
                if decision == "ALLOW"
                else policy.stepup_threshold
                <= trust_evaluation.trust_score
                < policy.allow_threshold
            )
            if decision == "STEP_UP":
                challenge = step_up_challenge
                assert challenge is not None and challenge.status == "SUCCESS"
            event_types = [event.event_type for event in events]
            assert event_types.count("ACCESS_REQUEST_SUBMITTED") == 1
            assert event_types.count("ACCESS_ALLOWED") == int(decision == "ALLOW")
            assert event_types.count("ACCESS_STEPUP") == int(decision == "STEP_UP")
            assert event_types.count("MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED") == int(
                decision == "STEP_UP"
            )
            assert event_types.count("ACCESS_MFA_ALLOWED") == int(decision == "STEP_UP")
            assert event_types.count("PROTECTED_RESOURCE_ACCESSED") == 1
            assert all(event.actor_id == employee_id for event in events)
        finally:
            await engine.dispose()

    asyncio.run(assert_persisted_chain())


def test_acme_document_rules_mfa_redemption_and_admin_event_chain(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_test_posture_provider(monkeypatch)
    employee_id, admin_id, other_id = uuid4(), uuid4(), uuid4()
    employee_session_id = uuid4()
    for user_id, label in (
        (employee_id, "document-employee"),
        (admin_id, "document-admin"),
        (other_id, "document-other"),
    ):
        asyncio.run(
            ensure_auth_user_profile(
                migrated_test_database.url,
                user_id=user_id,
                email=f"{label}-{user_id}@integration.test",
            )
        )
    asyncio.run(ensure_verified_test_authenticator(migrated_test_database.url, user_id=admin_id))
    asyncio.run(ensure_verified_test_authenticator(migrated_test_database.url, user_id=other_id))

    now = datetime.now(UTC).replace(microsecond=0)
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url=_SUPABASE_URL,
        database_url=migrated_test_database.url,
        device_hash_secret=_DEVICE_SECRET,
        rate_limit_key_secret="acme-document-rate-limit-secret",
        totp_secret_encryption_key=_TOTP_ENCRYPTION_KEY,
    )

    async def prepare_identities() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with engine.begin() as connection:
                await connection.execute(
                    update(Profile).where(Profile.id == admin_id).values(role="ADMIN")
                )
            async with AsyncSession(engine) as session, session.begin():
                session.add(
                    MfaCredential(
                        user_id=employee_id,
                        secret_ciphertext=encrypt_totp_secret(_TOTP_SECRET, settings=settings),
                        verified_at=now,
                        enabled=True,
                    )
                )
        finally:
            await engine.dispose()

    asyncio.run(prepare_identities())

    public_jwk = cast(
        dict[str, object], ECAlgorithm.to_jwk(_TEST_PRIVATE_KEY.public_key(), as_dict=True)
    )
    public_jwk.update({"kid": _TEST_KID, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    monkeypatch.setattr(jwt_module, "get_settings", lambda: settings)
    monkeypatch.setattr(deps, "get_settings", lambda: settings)
    monkeypatch.setattr(access_routes, "get_settings", lambda: settings)
    monkeypatch.setattr(admin_routes, "get_settings", lambda: settings)
    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: settings)
    monkeypatch.setattr(rate_limit, "get_settings", lambda: settings)
    monkeypatch.setattr(client_ip_module, "get_settings", lambda: settings)
    monkeypatch.setattr(PyJWKClient, "fetch_data", lambda _client: {"keys": [public_jwk]})
    jwt_module._jwks_client.cache_clear()

    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_clock] = lambda: FixedClock(now)
    application.dependency_overrides[get_geo_resolver] = UnavailableGeoResolver
    request_id = ""
    with TestClient(
        application,
        base_url="https://trustgate.test",
        client=("8.8.8.8", 44321),
    ) as client:
        employee_headers = {
            "Authorization": f"Bearer {_token(employee_id, session_id=employee_session_id)}",
            "X-Device-Token": _DEVICE_TOKEN,
            "User-Agent": _USER_AGENT,
        }
        admin_headers = {"Authorization": f"Bearer {_token(admin_id, session_id=uuid4())}"}
        other_headers = {"Authorization": f"Bearer {_token(other_id, session_id=uuid4())}"}

        evaluation = client.post(
            "/access/evaluate",
            json={"resource_id": "employee-handbook"},
            headers=employee_headers,
        )
        assert evaluation.status_code == 200, evaluation.text
        evaluation_body = evaluation.json()
        assert evaluation_body["decision"] == "STEP_UP"
        request_id = evaluation_body["access_request_id"]
        assert request_id
        challenge_id = evaluation_body["mfa_challenge_id"]
        assert challenge_id

        wrong_resource = client.post(
            "/resources/company-policies",
            json={"access_request_id": request_id},
            headers=employee_headers,
        )
        assert wrong_resource.status_code == 403
        wrong_user = client.post(
            "/resources/employee-handbook",
            json={"access_request_id": request_id},
            headers=other_headers,
        )
        assert wrong_user.status_code == 403
        wrong_session_headers = {
            **employee_headers,
            "Authorization": f"Bearer {_token(employee_id, session_id=uuid4())}",
        }
        wrong_session = client.post(
            "/resources/employee-handbook",
            json={"access_request_id": request_id},
            headers=wrong_session_headers,
        )
        assert wrong_session.status_code == 403

        verification = client.post(
            "/auth/mfa/totp/step-up/verify",
            json={
                "mfa_challenge_id": challenge_id,
                "code": pyotp.TOTP(_TOTP_SECRET).at(now),
            },
            headers=employee_headers,
        )
        assert verification.status_code == 200, verification.text
        assert verification.json()["verification_status"] == "verified"

        redemption = client.post(
            "/resources/employee-handbook",
            json={"access_request_id": request_id},
            headers=employee_headers,
        )
        assert redemption.status_code == 200, redemption.text
        body = redemption.json()
        assert body["resource_id"] == "employee-handbook"
        assert body["title"] == "Employee Handbook"
        assert body["content"].startswith("FICTIONAL SAMPLE")
        replay = client.post(
            "/resources/employee-handbook",
            json={"access_request_id": request_id},
            headers=employee_headers,
        )
        assert replay.status_code == 403

        restricted = client.post(
            "/access/evaluate",
            json={"resource_id": "confidential-financial-report"},
            headers=employee_headers,
        )
        assert restricted.status_code == 200, restricted.text
        restricted_body = restricted.json()
        assert restricted_body["decision"] == "BLOCK"
        assert "group grant" in restricted_body["explanation"].lower()
        assert restricted_body["access_request_id"]
        restricted_redemption = client.post(
            "/resources/confidential-financial-report",
            json={"access_request_id": restricted_body["access_request_id"]},
            headers=employee_headers,
        )
        assert restricted_redemption.status_code == 403
        assert "content" not in restricted_redemption.text

        feed = client.get(
            "/admin/events",
            params={"user_id": str(employee_id), "page": 1, "page_size": 50},
            headers=admin_headers,
        )
        assert feed.status_code == 200, feed.text
        event_types = [item["event_type"] for item in feed.json()["items"]]
        assert "ACCESS_REQUEST_SUBMITTED" in event_types
        assert "ACCESS_STEPUP" in event_types
        assert "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED" in event_types
        assert "ACCESS_MFA_ALLOWED" in event_types
        assert "ACCESS_BLOCKED" in event_types
        assert "PROTECTED_RESOURCE_ACCESSED" in event_types

        allowed_event = next(
            item for item in feed.json()["items"] if item["event_type"] == "ACCESS_MFA_ALLOWED"
        )
        investigation = client.get(f"/admin/events/{allowed_event['id']}", headers=admin_headers)
        assert investigation.status_code == 200, investigation.text
        investigation_body = investigation.json()
        assert investigation_body["access_request"]["id"] == request_id
        assert investigation_body["access_request"]["resource_id"] == "employee-handbook"
        chain_types = {
            investigation_body["event"]["event_type"],
            *(item["event_type"] for item in investigation_body["related_events"]),
        }
        assert {
            "ACCESS_REQUEST_SUBMITTED",
            "ACCESS_STEPUP",
            "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
            "ACCESS_MFA_ALLOWED",
            "PROTECTED_RESOURCE_ACCESSED",
        } <= chain_types

    async def verify_consumption_state() -> None:
        engine = create_async_engine_for_url(migrated_test_database.url, null_pool=True)
        try:
            async with AsyncSession(engine) as session:
                request_uuid = UUID(request_id)
                request = await session.get(AccessRequest, request_uuid)
                assert request is not None
                assert request.consumed_at is not None
                context_signal = await session.scalar(
                    select(ContextSignal).where(ContextSignal.access_request_id == request_uuid)
                )
                trust_evaluation = await session.scalar(
                    select(TrustEvaluation).where(TrustEvaluation.access_request_id == request_uuid)
                )
                policy_decision = await session.scalar(
                    select(PolicyDecision).where(PolicyDecision.access_request_id == request_uuid)
                )
                policy = (
                    await session.get(PolicyVersion, trust_evaluation.policy_version_id)
                    if trust_evaluation is not None
                    else None
                )
                blocked_request = await session.get(
                    AccessRequest, UUID(restricted_body["access_request_id"])
                )
                assert blocked_request is not None
                assert blocked_request.final_outcome == "BLOCK"
                assert blocked_request.consumed_at is None
            assert context_signal is not None
            assert context_signal.device_familiarity_raw == "unknown_device"
            assert context_signal.device_health_raw == "healthy"
            assert context_signal.location_raw == "unavailable"
            assert trust_evaluation is not None
            assert Decimal("40") <= trust_evaluation.trust_score < Decimal("70")
            assert trust_evaluation.risk_classification == "MEDIUM"
            assert policy is not None
            assert policy.stepup_threshold == Decimal("40.00")
            assert policy.allow_threshold == Decimal("70.00")
            assert policy_decision is not None and policy_decision.decision == "STEP_UP"
            assert "STEP_UP threshold" in policy_decision.decision_reason
            assert "below the ALLOW threshold" in policy_decision.decision_reason
        finally:
            await engine.dispose()

    asyncio.run(verify_consumption_state())
