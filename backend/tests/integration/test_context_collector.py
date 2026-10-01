"""PostgreSQL proof that a collected snapshot persists through the gateway."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

from app.api.deps import AuthenticatedPrincipal
from app.core.clock import FixedClock
from app.core.config import Settings
from app.db.models.access_request import AccessRequest
from app.db.models.context_signal import ContextSignal
from app.db.models.device import Device
from app.db.models.policy_version import PolicyVersion
from app.db.models.profile import Profile
from app.services.access_gateway import (
    CompletePipelineResult,
    DeviceResult,
    PipelineResult,
    TrustFactorResult,
    access_gateway,
)
from app.services.context.collector import ContextSnapshot
from app.services.context.device_familiarity import device_token_hash
from app.services.context.location import GeoRegion
from app.services.protected_resource import get_protected_resource
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.types import Scope

from tests.integration.database import ScratchDatabase

_TOKEN = "integration-only-device-token"
_DEVICE_SECRET = "integration-only-device-hash-secret"
_NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class StubGeoResolver:
    def resolve(self, address: IPv4Address | IPv6Address) -> GeoRegion:
        del address
        return GeoRegion("US", "CA")


def _request() -> Request:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/access/evaluate",
        "raw_path": b"/access/evaluate",
        "query_string": b"",
        "headers": [
            (b"x-device-token", _TOKEN.encode()),
            (b"user-agent", _USER_AGENT.encode()),
            (b"authorization", b"Bearer integration-jwt-not-for-storage"),
        ],
        "client": ("8.8.8.8", 44321),
        "server": ("trustgate.test", 443),
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    return Request(scope, receive)


class CollectorPipeline:
    def __init__(self, policy_version_id: UUID) -> None:
        self.policy_version_id = policy_version_id
        self.snapshot: ContextSnapshot | None = None

    async def run(
        self,
        *,
        principal: AuthenticatedPrincipal,
        resource: object,
        device_token: str,
        client_ip: str,
        user_agent: str | None,
        context_snapshot: ContextSnapshot | None = None,
    ) -> PipelineResult:
        del principal, resource, device_token, client_ip, user_agent
        assert context_snapshot is not None
        self.snapshot = context_snapshot
        return _result(context_snapshot, self.policy_version_id)


def _result(snapshot: ContextSnapshot, policy_version_id: UUID) -> CompletePipelineResult:
    return CompletePipelineResult(
        device=DeviceResult(
            device_hash=device_token_hash(
                _TOKEN,
                settings=Settings(
                    app_env="test",
                    cors_allowed_origin="http://localhost:5173",
                    device_hash_secret=_DEVICE_SECRET,
                ),
            )
            or "unavailable",
            last_user_agent_family=snapshot.device_health.browser_family,
            last_user_agent_version=snapshot.device_health.browser_version,
        ),
        context=snapshot,
        policy_version_id=policy_version_id,
        trust_score=Decimal("50.00"),
        risk_classification="MEDIUM",
        factors=(
            TrustFactorResult(
                "device_familiarity",
                snapshot.device_familiarity_raw,
                Decimal("50"),
                Decimal("0.350"),
                Decimal("17.500"),
            ),
            TrustFactorResult(
                "device_health",
                snapshot.device_health_raw,
                Decimal("50"),
                Decimal("0.300"),
                Decimal("15.000"),
            ),
            TrustFactorResult(
                "location_normality",
                snapshot.location_raw,
                Decimal("50"),
                Decimal("0.200"),
                Decimal("10.000"),
            ),
            TrustFactorResult(
                "time_normality",
                snapshot.time_raw,
                Decimal("50"),
                Decimal("0.150"),
                Decimal("7.500"),
            ),
        ),
        decision="BLOCK",
        decision_reason="Synthetic integration fixture only.",
        explanation="Blocked by a synthetic integration pipeline.",
    )


def test_context_snapshot_is_persisted_by_gateway_in_its_single_transaction(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()
    device_id = uuid4()
    device_hash = device_token_hash(
        _TOKEN,
        settings=Settings(
            app_env="test",
            cors_allowed_origin="http://localhost:5173",
            device_hash_secret=_DEVICE_SECRET,
        ),
    )
    assert device_hash is not None

    async def exercise(session: AsyncSession) -> None:
        await session.execute(
            text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
            {"id": user_id, "email": f"context-{user_id}@integration.test"},
        )
        profile = await session.get(Profile, user_id)
        assert profile is not None
        device = Device(
            id=device_id,
            user_id=user_id,
            device_hash=device_hash,
            recognized_at=_NOW - timedelta(days=2),
            first_seen_at=_NOW - timedelta(days=2),
            last_seen_at=_NOW - timedelta(days=1),
        )
        session.add(device)
        await session.flush()
        session.add_all(
            [
                AccessRequest(
                    id=uuid4(),
                    user_id=user_id,
                    device_id=device_id,
                    source_ip=IPv4Address("8.8.8.8"),
                    initial_decision="ALLOW",
                    final_outcome="ALLOW",
                    resolved_region="US-CA",
                    requested_at=_NOW - timedelta(days=index + 1),
                )
                for index in range(9)
            ]
        )
        await session.flush()
        policy_id = await session.scalar(
            select(PolicyVersion.id).where(PolicyVersion.version_label == "POL-1.0")
        )
        assert policy_id is not None
        pipeline = CollectorPipeline(policy_id)
        result = await access_gateway(
            session=session,
            principal=AuthenticatedPrincipal(user_id, profile.email, "USER"),
            resource=get_protected_resource("ops-dashboard"),
            device_token=_TOKEN,
            client_ip="8.8.8.8",
            user_agent=_USER_AGENT,
            pipeline=pipeline,
            clock=FixedClock(_NOW),
            request=_request(),
            profile=profile,
            geo_resolver=StubGeoResolver(),
            settings=Settings(
                app_env="test",
                cors_allowed_origin="http://localhost:5173",
                device_hash_secret=_DEVICE_SECRET,
            ),
        )
        snapshot = pipeline.snapshot
        assert snapshot is not None

        request = await session.scalar(
            select(AccessRequest).where(
                AccessRequest.user_id == user_id,
                AccessRequest.requested_at == _NOW,
            )
        )
        assert request is not None
        assert request.resolved_region == "US-CA"
        signal = await session.scalar(
            select(ContextSignal).where(ContextSignal.access_request_id == request.id)
        )
        assert signal is not None
        assert signal.device_familiarity_raw == "known_device"
        assert signal.device_health_raw == "healthy"
        assert signal.location_raw == "expected_region"
        assert signal.time_raw == "within_normal_window"
        assert signal.raw_context == dict(snapshot.raw_context)
        assert signal.captured_at == _NOW
        assert result.decision == "BLOCK"
        assert await session.scalar(select(func.count()).select_from(Device)) == 1
        await session.refresh(device)
        assert device.recognized_at == _NOW - timedelta(days=2)
        assert _TOKEN not in repr(signal.raw_context)
        assert "integration-jwt-not-for-storage" not in repr(signal.raw_context)

    migrated_test_database.run_in_transaction(exercise)
