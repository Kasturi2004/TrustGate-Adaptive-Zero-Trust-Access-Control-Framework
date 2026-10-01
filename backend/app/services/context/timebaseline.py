"""Evaluate whether the server request time is normal for a user's history.

Time-of-day is a coarse context signal. Request time comes from the injected
server clock, timezone comes from the server-loaded profile, and history comes
from ``access_requests.final_outcome``; no client time or timezone is accepted.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Literal
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.core.clock import Clock
from app.db.models.access_request import AccessRequest
from app.db.repositories.access_request import AccessRequestRepository

BaselineType = Literal["default", "personalized"]
_DEFAULT_START_HOUR = 8
_DEFAULT_END_HOUR = 20
_PERSONALIZED_MIN_EVENTS = 10
_HISTORY_WINDOW = timedelta(days=90)


@dataclass(frozen=True, slots=True)
class TimeBaselineResult:
    """Normalized time-normality result for later context collection."""

    within_normal_window: bool
    local_hour: int
    baseline_type: BaselineType


def _as_utc(value: datetime) -> datetime:
    """Normalize stored timestamps, treating legacy naive values as UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _user_zone(timezone_name: str | None) -> timezone | ZoneInfo:
    """Resolve a profile IANA timezone, falling back safely to UTC."""
    if not timezone_name:
        return UTC
    try:
        return ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, TypeError, ValueError):
        return UTC


def _recent_allow_events(
    events: Iterable[AccessRequest], *, cutoff: datetime, now: datetime
) -> tuple[list[AccessRequest], int]:
    qualifying_count = 0
    recent: list[AccessRequest] = []
    for event in events:
        if event.final_outcome != "ALLOW":
            continue
        qualifying_count += 1
        requested_at = _as_utc(event.requested_at)
        if cutoff <= requested_at <= now:
            recent.append(event)
    return recent, qualifying_count


async def evaluate_time_normality(
    *,
    user_id: UUID,
    profile_timezone: str | None,
    repository: AccessRequestRepository,
    clock: Clock,
) -> TimeBaselineResult:
    """Evaluate server time against default or recent personalized history.

    The injected clock provides the server-side request instant. Profile
    timezone and access history must be loaded by trusted server-side code.
    This service is read-only and does not persist context signals.
    """
    now = _as_utc(clock.now())
    zone = _user_zone(profile_timezone)
    local_hour = now.astimezone(zone).hour
    events = await repository.list_by_user(user_id)
    cutoff = now - _HISTORY_WINDOW
    recent_events, qualifying_count = _recent_allow_events(events, cutoff=cutoff, now=now)

    if qualifying_count < _PERSONALIZED_MIN_EVENTS:
        return TimeBaselineResult(
            within_normal_window=_DEFAULT_START_HOUR <= local_hour < _DEFAULT_END_HOUR,
            local_hour=local_hour,
            baseline_type="default",
        )

    baseline_hours = {_as_utc(event.requested_at).astimezone(zone).hour for event in recent_events}
    if not baseline_hours:
        return TimeBaselineResult(
            within_normal_window=_DEFAULT_START_HOUR <= local_hour < _DEFAULT_END_HOUR,
            local_hour=local_hour,
            baseline_type="default",
        )

    normal_hours = {
        (baseline_hour + offset) % 24 for baseline_hour in baseline_hours for offset in (-1, 0, 1)
    }
    return TimeBaselineResult(
        within_normal_window=local_hour in normal_hours,
        local_hour=local_hour,
        baseline_type="personalized",
    )
