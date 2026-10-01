"""Unit tests for the read-only Phase 6 context collector."""

import asyncio
from collections.abc import MutableMapping
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from app.core.clock import FixedClock
from app.core.config import Settings
from app.db.models.profile import Profile
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.device import DeviceRepository
from app.services.context import collector
from app.services.context.device_familiarity import KNOWN_DEVICE
from app.services.context.location import GeoRegion
from starlette.requests import Request
from starlette.types import Scope

_DEVICE_SECRET = "phase-6f-test-device-hash-secret"
_DEVICE_TOKEN = "phase-6f-raw-device-token-must-not-persist"
_AUTH_TOKEN = "Bearer phase-6f-auth-jwt-must-not-persist"
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_NOW = datetime(2026, 4, 1, 12, tzinfo=UTC)


class StubGeoResolver:
    def __init__(self, result: GeoRegion | None) -> None:
        self.result = result
        self.addresses: list[IPv4Address | IPv6Address] = []

    def resolve(self, address: IPv4Address | IPv6Address) -> GeoRegion | None:
        self.addresses.append(address)
        return self.result


def _settings() -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        device_hash_secret=_DEVICE_SECRET,
    )


def _request(
    *,
    peer: str = "8.8.8.8",
    body: bytes = b"{}",
    user_agent: str | None = _USER_AGENT,
) -> Request:
    headers = [
        (b"x-device-token", _DEVICE_TOKEN.encode()),
        (b"authorization", _AUTH_TOKEN.encode()),
    ]
    if user_agent is not None:
        headers.append((b"user-agent", user_agent.encode()))
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/access/evaluate",
        "raw_path": b"/access/evaluate",
        "query_string": b"",
        "headers": headers,
        "client": (peer, 4321),
        "server": ("trustgate.test", 443),
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _profile() -> Profile:
    return Profile(
        id=uuid4(),
        email="phase6f@example.test",
        role="USER",
        timezone="UTC",
        is_deleted=False,
    )


def _history(*, count: int = 9, resolved_region: str | None = None) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            final_outcome="ALLOW",
            requested_at=_NOW - timedelta(days=index + 1),
            resolved_region=resolved_region,
        )
        for index in range(count)
    ]


def _prepare_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    history: list[SimpleNamespace],
    device: object | None = None,
) -> tuple[AsyncMock, AsyncMock]:
    access_repository = AsyncMock(spec=AccessRequestRepository)
    access_repository.list_by_user.return_value = history
    device_repository = AsyncMock(spec=DeviceRepository)
    device_repository.get_by_user_and_hash.return_value = device
    monkeypatch.setattr(collector, "AccessRequestRepository", Mock(return_value=access_repository))
    monkeypatch.setattr(collector, "DeviceRepository", Mock(return_value=device_repository))
    return access_repository, device_repository


def test_collector_gathers_four_signals_without_persisting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    access_repository, device_repository = _prepare_dependencies(
        monkeypatch,
        history=_history(resolved_region=" us-ca "),
        device=SimpleNamespace(recognized_at=_NOW - timedelta(days=2)),
    )
    resolver = StubGeoResolver(GeoRegion("US", "CA"))
    session = AsyncMock()

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(),
            profile=profile,
            session=session,
            clock=FixedClock(_NOW),
            geo_resolver=resolver,
            settings=_settings(),
        )
    )

    assert snapshot.device_familiarity == KNOWN_DEVICE
    assert snapshot.device_health.category == "HEALTHY"
    assert snapshot.location_normality.category == "EXPECTED"
    assert snapshot.time_normality.baseline_type == "default"
    assert snapshot.client_ip == IPv4Address("8.8.8.8")
    assert snapshot.device_familiarity_raw == "known_device"
    assert snapshot.device_health_raw == "healthy"
    assert snapshot.location_raw == "expected_region"
    assert snapshot.time_raw == "within_normal_window"
    assert snapshot.resolved_region == "US-CA"
    assert snapshot.raw_context == {
        "connection_secure": True,
        "resolved_region": "US-CA",
        "local_access_hour": 12,
        "time_baseline_type": "default",
    }
    assert access_repository.list_by_user.await_count == 2
    access_repository.list_by_user.assert_awaited_with(profile.id)
    device_repository.add.assert_not_called()
    device_repository.upsert_for_access.assert_not_awaited()
    session.flush.assert_not_awaited()
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()


@pytest.mark.parametrize(
    ("region", "peer", "expected_category", "expected_region"),
    [
        (GeoRegion("GB", "ENG"), "8.8.8.8", "NEW", "GB-ENG"),
        (GeoRegion("US", "CA"), "10.0.0.1", "UNAVAILABLE", None),
        (None, "8.8.8.8", "UNAVAILABLE", None),
    ],
)
def test_collector_represents_new_and_unavailable_location(
    monkeypatch: pytest.MonkeyPatch,
    region: GeoRegion | None,
    peer: str,
    expected_category: str,
    expected_region: str | None,
) -> None:
    profile = _profile()
    _prepare_dependencies(monkeypatch, history=_history(resolved_region="US-CA"))

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(peer=peer),
            profile=profile,
            session=AsyncMock(),
            clock=FixedClock(_NOW),
            geo_resolver=StubGeoResolver(region),
            settings=_settings(),
        )
    )

    assert snapshot.location_normality.category == expected_category
    assert snapshot.resolved_region == expected_region
    assert (
        snapshot.location_raw
        == {
            "NEW": "new_region",
            "UNAVAILABLE": "unavailable",
        }[expected_category]
    )


def test_collector_supports_personalized_time_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile()
    history = [
        SimpleNamespace(
            final_outcome="ALLOW",
            requested_at=_NOW.replace(hour=12) - timedelta(days=index + 1),
            resolved_region=None,
        )
        for index in range(10)
    ]
    _prepare_dependencies(monkeypatch, history=history)

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(),
            profile=profile,
            session=AsyncMock(),
            clock=FixedClock(_NOW),
            geo_resolver=StubGeoResolver(None),
            settings=_settings(),
        )
    )

    assert snapshot.time_normality.baseline_type == "personalized"
    assert snapshot.time_normality.within_normal_window is True
    assert snapshot.time_raw == "within_normal_window"


def test_snapshot_is_immutable_and_never_contains_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    _prepare_dependencies(monkeypatch, history=_history())

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(),
            profile=profile,
            session=AsyncMock(),
            clock=FixedClock(_NOW),
            geo_resolver=StubGeoResolver(GeoRegion("US", "CA")),
            settings=_settings(),
        )
    )

    with pytest.raises(FrozenInstanceError):
        snapshot.__setattr__("client_ip", IPv4Address("1.1.1.1"))
    with pytest.raises(TypeError):
        cast(MutableMapping[str, object], snapshot.raw_context)["new_field"] = "client override"
    assert set(snapshot.raw_context) == {
        "connection_secure",
        "resolved_region",
        "local_access_hour",
        "time_baseline_type",
    }
    assert _DEVICE_TOKEN not in repr(snapshot)
    assert _AUTH_TOKEN not in repr(snapshot)


def test_raw_user_agent_is_not_persisted(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile()
    _prepare_dependencies(monkeypatch, history=_history())

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(user_agent=_USER_AGENT),
            profile=profile,
            session=AsyncMock(),
            clock=FixedClock(_NOW),
            geo_resolver=StubGeoResolver(None),
            settings=_settings(),
        )
    )

    assert "user_agent" not in snapshot.raw_context
    assert _USER_AGENT not in repr(snapshot.raw_context)


@pytest.mark.parametrize(
    "user_agent",
    [
        f"browser password=secret {_DEVICE_TOKEN}",
        "browser api_key=secret",
        f"browser Bearer {_AUTH_TOKEN.removeprefix('Bearer ')}",
        "browser eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
    ],
)
def test_sensitive_or_malicious_user_agent_is_not_persisted(
    monkeypatch: pytest.MonkeyPatch,
    user_agent: str,
) -> None:
    profile = _profile()
    _prepare_dependencies(monkeypatch, history=_history())

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(user_agent=user_agent),
            profile=profile,
            session=AsyncMock(),
            clock=FixedClock(_NOW),
            geo_resolver=StubGeoResolver(None),
            settings=_settings(),
        )
    )

    assert "user_agent" not in snapshot.raw_context
    assert user_agent not in repr(snapshot.raw_context)
    assert _DEVICE_TOKEN not in repr(snapshot.raw_context)
    assert _AUTH_TOKEN not in repr(snapshot.raw_context)


def test_client_payload_context_fields_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile()
    _prepare_dependencies(monkeypatch, history=_history())

    snapshot = asyncio.run(
        collector.collect_context_snapshot(
            request=_request(
                body=b'{"region":"attacker-region","health":"UNHEALTHY",'
                b'"time":"23:59","trust_score":100}'
            ),
            profile=profile,
            session=AsyncMock(),
            clock=FixedClock(_NOW),
            geo_resolver=StubGeoResolver(GeoRegion("US", "CA")),
            settings=_settings(),
        )
    )

    assert snapshot.resolved_region == "US-CA"
    assert snapshot.device_health.category == "HEALTHY"
    assert snapshot.time_normality.local_hour == 12


def test_deleted_profile_is_rejected_without_writes() -> None:
    profile = _profile()
    profile.is_deleted = True
    session = AsyncMock()

    with pytest.raises(ValueError, match="active server-loaded profile"):
        asyncio.run(
            collector.collect_context_snapshot(
                request=_request(),
                profile=profile,
                session=session,
                clock=FixedClock(_NOW),
                geo_resolver=StubGeoResolver(None),
                settings=_settings(),
            )
        )

    session.flush.assert_not_awaited()
    session.commit.assert_not_awaited()


def test_history_failure_propagates_without_partial_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    access_repository, _ = _prepare_dependencies(monkeypatch, history=[])
    access_repository.list_by_user.side_effect = RuntimeError("private history failure")
    session = AsyncMock()

    with pytest.raises(RuntimeError, match="private history failure"):
        asyncio.run(
            collector.collect_context_snapshot(
                request=_request(),
                profile=profile,
                session=session,
                clock=FixedClock(_NOW),
                geo_resolver=StubGeoResolver(None),
                settings=_settings(),
            )
        )

    session.flush.assert_not_awaited()
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()
