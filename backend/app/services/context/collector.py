"""Collect immutable, server-derived context for an access evaluation.

The collector is read-only. The access gateway owns the single persistence
operation for a completed evaluation and its context signal.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from types import MappingProxyType

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.client_ip import ClientIPResolutionError, resolve_client_ip
from app.core.clock import Clock, FixedClock
from app.core.config import Settings, get_settings
from app.db.models.profile import Profile
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.device import DeviceRepository
from app.services.context.device_familiarity import (
    DeviceFamiliarityResult,
    collect_device_familiarity,
)
from app.services.context.health import (
    DeviceHealthResult,
    evaluate_device_health,
    is_connection_secure,
)
from app.services.context.location import (
    GeoResolver,
    LocationResult,
    evaluate_location_normality,
)
from app.services.context.timebaseline import TimeBaselineResult, evaluate_time_normality

IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class ContextSnapshot:
    """Immutable signal results and approved context for one server request."""

    captured_at: datetime
    client_ip: IPAddress | None
    device_familiarity: DeviceFamiliarityResult
    device_health: DeviceHealthResult
    location_normality: LocationResult
    time_normality: TimeBaselineResult
    connection_secure: bool
    raw_context: Mapping[str, object]

    @property
    def device_familiarity_raw(self) -> str:
        return "known_device" if self.device_familiarity.category == "KNOWN" else "unknown_device"

    @property
    def device_health_raw(self) -> str:
        return {
            "HEALTHY": "healthy",
            "PARTIAL": "partially_healthy",
            "UNHEALTHY": "unhealthy",
        }[self.device_health.category]

    @property
    def location_raw(self) -> str:
        return {
            "EXPECTED": "expected_region",
            "NEW": "new_region",
            "UNAVAILABLE": "unavailable",
        }[self.location_normality.category]

    @property
    def time_raw(self) -> str:
        return (
            "within_normal_window"
            if self.time_normality.within_normal_window
            else "outside_normal_window"
        )

    @property
    def resolved_region(self) -> str | None:
        return self.location_normality.resolved_region


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _client_ip(request: Request, settings: Settings) -> IPAddress | None:
    try:
        return ip_address(resolve_client_ip(request, settings=settings))
    except (ClientIPResolutionError, ValueError):
        return None


async def collect_context_snapshot(
    *,
    request: Request,
    profile: Profile,
    session: AsyncSession,
    clock: Clock,
    geo_resolver: GeoResolver,
    settings: Settings | None = None,
) -> ContextSnapshot:
    """Collect all four signals from server-owned request/profile/history data.

    This function performs reads only. It neither creates an access request nor
    writes a context row; the caller passes the returned snapshot into the
    access gateway, which persists both records in its existing transaction.
    """
    if profile.is_deleted:
        raise ValueError("Context collection requires an active server-loaded profile")

    configuration = settings if settings is not None else get_settings()
    captured_at = _utc_timestamp(clock.now())
    # The same timestamp is used by all time calculations for this request.
    request_clock = FixedClock(captured_at)
    raw_device_token = request.headers.get("x-device-token")
    user_agent = request.headers.get("user-agent")
    client_ip_value = _client_ip(request, configuration)
    secure = is_connection_secure(request, settings=configuration)

    familiarity = await collect_device_familiarity(
        user_id=profile.id,
        device_token=raw_device_token,
        repository=DeviceRepository(session),
        settings=configuration,
    )
    health = evaluate_device_health(connection_secure=secure, user_agent=user_agent)

    access_requests = AccessRequestRepository(session)
    history = await access_requests.list_by_user(profile.id)
    location = evaluate_location_normality(
        server_resolved_ip=client_ip_value,
        historical_resolved_regions=[
            item.resolved_region for item in history if item.resolved_region is not None
        ],
        geo_resolver=geo_resolver,
    )
    time = await evaluate_time_normality(
        user_id=profile.id,
        profile_timezone=profile.timezone,
        repository=access_requests,
        clock=request_clock,
    )

    explainability: dict[str, object] = {
        "connection_secure": secure,
        "resolved_region": location.resolved_region,
        "local_access_hour": time.local_hour,
        "time_baseline_type": time.baseline_type,
    }
    return ContextSnapshot(
        captured_at=captured_at,
        client_ip=client_ip_value,
        device_familiarity=familiarity,
        device_health=health,
        location_normality=location,
        time_normality=time,
        connection_secure=secure,
        raw_context=MappingProxyType(explainability),
    )
