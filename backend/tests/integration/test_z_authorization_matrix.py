"""End-to-end PostgreSQL authorization checks through authenticated API routes."""

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any, cast
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

import jwt
import pyotp
import pytest
from app.core import jwt as jwt_module
from app.core.config import Settings, get_settings
from app.core.mfa_secrets import encrypt_totp_secret
from app.db.models import Base
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.mfa_credential import MfaCredential
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.db.session import create_async_engine_for_url
from app.main import create_app
from app.services.access_gateway import get_security_pipeline
from app.services.context import client_ip
from app.services.context.device_familiarity import device_token_hash
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm
from pydantic import SecretStr
from sqlalchemy import Column, Table, select
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import configure_mappers

from tests.integration.database import ScratchDatabase, ensure_auth_user_profile
from tests.integration.test_access_gateway import CompleteTestPipeline, _complete_result

_JWT_KID = "trustgate-r2-4-5-local-test"
_ISSUER = "https://trustgate-test.invalid/auth/v1"
_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


class AuthorizationMatrix:
    """Real API client, database sessions, and locally signed authenticated users."""

    def __init__(self, database: ScratchDatabase, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.engine = create_async_engine_for_url(database.url, null_pool=True)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.app = create_app(settings)
        self.decision = "ALLOW"
        self.policy_id = asyncio.run(self._active_policy_id())

        async def database_session() -> Any:
            async with self.session_factory() as session:
                yield session

        self.app.dependency_overrides[get_security_pipeline] = lambda: CompleteTestPipeline(
            _complete_result(self.policy_id, self.decision)
        )
        from app.api import deps

        self.app.dependency_overrides[deps.get_db_session] = database_session
        self.app.dependency_overrides[get_settings] = lambda: settings
        self.client = TestClient(self.app, client=("127.0.0.1", 12345))

    async def _active_policy_id(self) -> UUID:
        async with self.engine.connect() as connection:
            result = await connection.scalar(
                select(PolicyVersion.id).where(PolicyVersion.is_active.is_(True))
            )
        assert result is not None
        return result

    def headers(self, user_id: UUID, *, token: str | None = None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token or self.token(user_id)}",
            "X-Device-Token": self.device_token(user_id),
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
            ),
        }

    @staticmethod
    def device_token(user_id: UUID) -> str:
        return f"matrix-device-{user_id}"

    @staticmethod
    def token(user_id: UUID, *, session_id: UUID | None = None) -> str:
        return jwt.encode(
            {
                "sub": str(user_id),
                "session_id": str(session_id or user_id),
                "aud": "authenticated",
                "iss": _ISSUER,
                "exp": int(datetime.now(UTC).timestamp()) + 3600,
            },
            _JWT_PRIVATE_KEY,
            algorithm="ES256",
            headers={"kid": _JWT_KID},
        )

    async def access_request(self, request_id: UUID) -> AccessRequest:
        async with self.session_factory() as session:
            request = await session.get(AccessRequest, request_id)
        assert request is not None
        return request

    async def add_enabled_totp(self, user_id: UUID) -> None:
        async with self.session_factory.begin() as session:
            session.add(
                MfaCredential(
                    user_id=user_id,
                    secret_ciphertext=encrypt_totp_secret(_TOTP_SECRET, settings=self.settings),
                    verified_at=datetime.now(UTC) - timedelta(days=1),
                    enabled=True,
                )
            )

    async def prepare_context(
        self,
        user_id: UUID,
        *,
        known_device: bool = False,
        outside_normal_hours: bool = False,
    ) -> None:
        now = datetime.now(UTC)
        timezones = (
            "UTC",
            "Asia/Kolkata",
            "Pacific/Kiritimati",
            "Pacific/Pago_Pago",
            "America/Adak",
            "Etc/GMT+12",
            "Etc/GMT-12",
        )
        timezone_name = next(
            name
            for name in timezones
            if (
                (now.astimezone(ZoneInfo(name)).hour < 8)
                or (now.astimezone(ZoneInfo(name)).hour >= 20)
            )
            == outside_normal_hours
        )
        async with self.session_factory.begin() as session:
            profile = await session.get(Profile, user_id)
            assert profile is not None
            profile.timezone = timezone_name
            if known_device:
                fingerprint = device_token_hash(self.device_token(user_id), settings=self.settings)
                assert fingerprint is not None
                session.add(
                    Device(
                        user_id=user_id,
                        device_hash=fingerprint,
                        recognized_at=now,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )

    async def add_other_resource_approval(self, user_id: UUID) -> UUID:
        request_id = uuid4()
        async with self.session_factory.begin() as session:
            device = Device(user_id=user_id, device_hash=f"other-resource-{request_id}")
            session.add(device)
            await session.flush()
            session.add(
                AccessRequest(
                    id=request_id,
                    user_id=user_id,
                    device_id=device.id,
                    resource_id="different-resource",
                    source_ip=IPv4Address("192.0.2.85"),
                    initial_decision="ALLOW",
                    final_outcome="ALLOW",
                    requested_at=datetime.now(UTC),
                )
            )
        return request_id

    async def close(self) -> None:
        await self.engine.dispose()


_JWT_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
_JWT_JWK = ECAlgorithm.to_jwk(_JWT_PRIVATE_KEY.public_key(), as_dict=True)
_JWT_JWK.update({"kid": _JWT_KID, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})


@pytest.fixture
def authorization_matrix(
    migrated_test_database: ScratchDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    auth_users = Base.metadata.tables.get("auth.users")
    registered_auth_table = auth_users is None
    if auth_users is None:
        auth_users = Table(
            "users",
            Base.metadata,
            Column("id", PG_UUID(as_uuid=True), primary_key=True),
            schema="auth",
        )
    configure_mappers()
    if registered_auth_table:
        Base.metadata.remove(auth_users)

    settings = Settings(
        app_env="local",
        cors_allowed_origin="http://localhost:5173",
        database_url=migrated_test_database.url,
        supabase_url="https://trustgate-test.invalid",
        device_hash_secret="r2-4-5-device-hash-test-key",
        rate_limit_key_secret="r2-4-5-rate-limit-test-key",
        totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(b"r" * 32).decode("ascii")),
        treat_localhost_as_secure=True,
    )

    def fetch_test_jwks(_client: PyJWKClient) -> dict[str, Any]:
        return {"keys": [_JWT_JWK]}

    monkeypatch.setattr(PyJWKClient, "fetch_data", fetch_test_jwks)
    jwt_module._jwks_client.cache_clear()
    monkeypatch.setattr(jwt_module, "get_settings", lambda: settings)
    from app.core import mfa_secrets, rate_limit

    monkeypatch.setattr(mfa_secrets, "get_settings", lambda: settings)
    monkeypatch.setattr(rate_limit, "get_settings", lambda: settings)
    monkeypatch.setattr(client_ip, "get_settings", lambda: settings)
    matrix = AuthorizationMatrix(migrated_test_database, settings)
    try:
        yield matrix
    finally:
        matrix.client.close()
        asyncio.run(matrix.close())
        jwt_module._jwks_client.cache_clear()


async def _new_user(matrix: AuthorizationMatrix, label: str) -> UUID:
    user_id = uuid4()
    await ensure_auth_user_profile(
        matrix.database.url,
        user_id=user_id,
        email=f"matrix-{label}-{user_id}@integration.test",
    )
    return user_id


def _evaluate(
    matrix: AuthorizationMatrix,
    user_id: UUID,
    *,
    user_agent: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    headers = matrix.headers(user_id, token=token)
    if user_agent is not None:
        headers["User-Agent"] = user_agent
    response = matrix.client.post(
        "/access/evaluate",
        json={"resource_id": "ops-dashboard"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


def _redeem(
    matrix: AuthorizationMatrix,
    user_id: UUID,
    request_id: UUID,
    *,
    token: str | None = None,
) -> Any:
    return matrix.client.post(
        "/resources/ops-dashboard",
        json={"access_request_id": str(request_id)},
        headers=matrix.headers(user_id, token=token),
    )


def test_allow_block_direct_api_binding_and_cross_user_flows(
    authorization_matrix: AuthorizationMatrix,
) -> None:
    matrix = authorization_matrix
    owner_id = asyncio.run(_new_user(matrix, "allow-owner"))
    other_id = asyncio.run(_new_user(matrix, "other-user"))
    asyncio.run(matrix.prepare_context(owner_id, known_device=True))

    unauthenticated = matrix.client.post(
        "/resources/ops-dashboard", json={"access_request_id": str(uuid4())}
    )
    assert unauthenticated.status_code == 401
    no_approval = _redeem(matrix, owner_id, uuid4())
    assert no_approval.status_code == 403
    assert "protected" not in no_approval.text.lower()

    matrix.decision = "ALLOW"
    allow = _evaluate(matrix, owner_id)
    assert allow["decision"] == "ALLOW"
    allow_id = UUID(allow["access_request_id"])
    wrong_owner = _redeem(matrix, other_id, allow_id)
    assert wrong_owner.status_code == 403
    assert asyncio.run(matrix.access_request(allow_id)).consumed_at is None

    content = _redeem(matrix, owner_id, allow_id)
    assert content.status_code == 200
    assert content.json()["resource_id"] == "ops-dashboard"
    assert content.json()["status"] == "operational"
    assert asyncio.run(matrix.access_request(allow_id)).consumed_at is not None
    assert _redeem(matrix, owner_id, allow_id).status_code == 403

    other_resource_id = asyncio.run(matrix.add_other_resource_approval(owner_id))
    assert _redeem(matrix, owner_id, other_resource_id).status_code == 403
    nonexistent = _redeem(matrix, owner_id, uuid4())
    assert nonexistent.status_code == 403
    manipulated = matrix.client.post(
        "/resources/ops-dashboard",
        json={"access_request_id": str(allow_id), "resource_id": "different-resource"},
        headers=matrix.headers(owner_id),
    )
    assert manipulated.status_code == 422

    matrix.decision = "BLOCK"
    blocked_user_id = asyncio.run(_new_user(matrix, "blocked"))
    asyncio.run(matrix.prepare_context(blocked_user_id, outside_normal_hours=True))
    blocked = _evaluate(
        matrix,
        blocked_user_id,
        user_agent=(
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) "
            "AppleWebKit/537.36 Chrome/90.0.0.0 Safari/537.36"
        ),
    )
    assert blocked["decision"] == "BLOCK"
    blocked_id = UUID(blocked["access_request_id"])
    denied = _redeem(matrix, blocked_user_id, blocked_id)
    assert denied.status_code == 403
    assert "summary" not in denied.json()
    assert asyncio.run(matrix.access_request(blocked_id)).consumed_at is None


def test_step_up_requires_same_request_totp_and_cannot_authorize_another_request(
    authorization_matrix: AuthorizationMatrix,
) -> None:
    matrix = authorization_matrix
    owner_id = asyncio.run(_new_user(matrix, "stepup-owner"))
    other_id = asyncio.run(_new_user(matrix, "stepup-other"))
    asyncio.run(matrix.add_enabled_totp(owner_id))
    asyncio.run(matrix.add_enabled_totp(other_id))
    asyncio.run(matrix.prepare_context(owner_id))
    asyncio.run(matrix.prepare_context(other_id))

    matrix.decision = "STEP_UP"
    result = _evaluate(matrix, owner_id)
    assert result["decision"] == "STEP_UP"
    request_id = UUID(result["access_request_id"])
    challenge_id = UUID(result["mfa_challenge_id"])
    assert _redeem(matrix, owner_id, request_id).status_code == 403

    wrong_user_verification = matrix.client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(challenge_id),
            "code": pyotp.TOTP(_TOTP_SECRET).now(),
        },
        headers=matrix.headers(other_id),
    )
    assert wrong_user_verification.status_code == 400
    other_session_verification = matrix.client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(challenge_id),
            "code": pyotp.TOTP(_TOTP_SECRET).now(),
        },
        headers=matrix.headers(owner_id, token=matrix.token(owner_id, session_id=uuid4())),
    )
    assert other_session_verification.status_code == 400
    assert asyncio.run(matrix.access_request(request_id)).final_outcome is None
    wrong_code = matrix.client.post(
        "/auth/mfa/totp/step-up/verify",
        json={"mfa_challenge_id": str(challenge_id), "code": "000000"},
        headers=matrix.headers(owner_id),
    )
    assert wrong_code.status_code == 400
    assert _redeem(matrix, owner_id, request_id).status_code == 403
    verify = matrix.client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(challenge_id),
            "code": pyotp.TOTP(_TOTP_SECRET).now(),
        },
        headers=matrix.headers(owner_id),
    )
    assert verify.status_code == 200, verify.text

    access_request = asyncio.run(matrix.access_request(request_id))
    assert access_request.final_outcome == "ALLOW"
    challenge_state = matrix.client.get(
        f"/access/request/{request_id}", headers=matrix.headers(owner_id)
    )
    assert challenge_state.status_code == 200
    assert challenge_state.json()["mfa_status"] == "SUCCESS"
    assert _redeem(matrix, owner_id, request_id).status_code == 200
    assert _redeem(matrix, owner_id, request_id).status_code == 403

    replay = matrix.client.post(
        "/auth/mfa/totp/step-up/verify",
        json={
            "mfa_challenge_id": str(challenge_id),
            "code": pyotp.TOTP(_TOTP_SECRET).now(),
        },
        headers=matrix.headers(owner_id),
    )
    assert replay.status_code == 400

    second = _evaluate(matrix, owner_id)
    second_id = UUID(second["access_request_id"])
    assert second_id != request_id
    assert _redeem(matrix, owner_id, second_id).status_code == 403
    assert asyncio.run(matrix.access_request(second_id)).consumed_at is None


def test_fresh_allow_is_request_scoped_across_later_login_and_concurrent_redemption(
    authorization_matrix: AuthorizationMatrix,
) -> None:
    matrix = authorization_matrix
    user_id = asyncio.run(_new_user(matrix, "fresh"))
    matrix.decision = "ALLOW"
    asyncio.run(matrix.prepare_context(user_id, known_device=True))
    session_1 = matrix.token(user_id, session_id=uuid4())
    session_2 = matrix.token(user_id, session_id=uuid4())
    first = _evaluate(matrix, user_id, token=session_1)
    first_id = UUID(first["access_request_id"])
    assert asyncio.run(matrix.access_request(first_id)).consumed_at is None
    assert _redeem(matrix, user_id, first_id, token=session_2).status_code == 403
    assert asyncio.run(matrix.access_request(first_id)).consumed_at is None

    second = _evaluate(matrix, user_id, token=session_2)
    second_id = UUID(second["access_request_id"])
    assert second_id != first_id
    assert _redeem(matrix, user_id, second_id, token=session_2).status_code == 200
    assert _redeem(matrix, user_id, second_id, token=session_2).status_code == 403

    concurrent_request = _evaluate(matrix, user_id, token=session_2)
    concurrent_id = UUID(concurrent_request["access_request_id"])

    def attempt_redemption() -> int:
        response = matrix.client.post(
            "/resources/ops-dashboard",
            json={"access_request_id": str(concurrent_id)},
            headers=matrix.headers(user_id, token=session_2),
        )
        return response.status_code

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _index: attempt_redemption(), range(2)))
    assert sorted(statuses) == [200, 403]
    assert asyncio.run(matrix.access_request(concurrent_id)).consumed_at is not None
