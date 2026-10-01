"""Tests for the Phase 6E server-side time-normality signal."""

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import pytest
from app.core.clock import FixedClock
from app.db.repositories.access_request import AccessRequestRepository
from app.services.context.timebaseline import (
    TimeBaselineResult,
    evaluate_time_normality,
)


class StubAccessRequestRepository:
    def __init__(self, events: list[SimpleNamespace]) -> None:
        self.events = events
        self.requested_user_ids: list[UUID] = []

    async def list_by_user(self, user_id: UUID) -> list[SimpleNamespace]:
        self.requested_user_ids.append(user_id)
        return self.events


def _event(requested_at: datetime, final_outcome: str = "ALLOW") -> SimpleNamespace:
    return SimpleNamespace(requested_at=requested_at, final_outcome=final_outcome)


def _evaluate(
    *,
    now: datetime,
    events: list[SimpleNamespace] | None = None,
    timezone_name: str | None = "UTC",
) -> tuple[TimeBaselineResult, StubAccessRequestRepository]:
    repository = StubAccessRequestRepository(events or [])
    result = asyncio.run(
        evaluate_time_normality(
            user_id=uuid4(),
            profile_timezone=timezone_name,
            repository=cast(AccessRequestRepository, repository),
            clock=FixedClock(now),
        )
    )
    return result, repository


@pytest.mark.parametrize(
    ("timestamp", "expected_hour", "expected_within"),
    [
        (datetime(2026, 1, 1, 7, 59, tzinfo=UTC), 7, False),
        (datetime(2026, 1, 1, 8, 0, tzinfo=UTC), 8, True),
        (datetime(2026, 1, 1, 19, 59, tzinfo=UTC), 19, True),
        (datetime(2026, 1, 1, 20, 0, tzinfo=UTC), 20, False),
    ],
)
def test_default_window_boundaries(
    timestamp: datetime, expected_hour: int, expected_within: bool
) -> None:
    result, _ = _evaluate(now=timestamp)

    assert result == TimeBaselineResult(expected_within, expected_hour, "default")


def test_nine_qualifying_events_use_default_window() -> None:
    now = datetime(2026, 1, 20, 8, tzinfo=UTC)
    events = [_event(now - timedelta(days=index)) for index in range(9)]

    result, _ = _evaluate(now=now, events=events)

    assert result.baseline_type == "default"
    assert result.within_normal_window is True


def test_exactly_ten_qualifying_events_use_personalized_baseline() -> None:
    now = datetime(2026, 1, 20, 3, tzinfo=UTC)
    events = [_event(now - timedelta(days=index, hours=1)) for index in range(10)]

    result, _ = _evaluate(now=now, events=events)

    assert result == TimeBaselineResult(True, 3, "personalized")


def test_non_allow_outcomes_do_not_qualify_for_history() -> None:
    now = datetime(2026, 1, 20, 3, tzinfo=UTC)
    events = [_event(now - timedelta(days=index, hours=1)) for index in range(9)]
    events.append(_event(now - timedelta(days=10), final_outcome="BLOCK"))

    result, _ = _evaluate(now=now, events=events)

    assert result.baseline_type == "default"


def test_personalized_exact_hour_and_one_hour_tolerance() -> None:
    now = datetime(2026, 1, 20, 12, tzinfo=UTC)
    events = [_event((now - timedelta(days=index)).replace(hour=12)) for index in range(10)]

    exact, _ = _evaluate(now=now, events=events)
    adjacent, _ = _evaluate(now=now.replace(hour=13), events=events)

    assert exact == TimeBaselineResult(True, 12, "personalized")
    assert adjacent == TimeBaselineResult(True, 13, "personalized")


def test_hour_outside_personalized_baseline_is_abnormal() -> None:
    now = datetime(2026, 1, 20, 12, tzinfo=UTC)
    events = [_event(now - timedelta(days=index, hours=1)) for index in range(10)]

    result, _ = _evaluate(now=now.replace(hour=16), events=events)

    assert result == TimeBaselineResult(False, 16, "personalized")


def test_personalized_baseline_wraps_across_midnight() -> None:
    now = datetime(2026, 1, 20, 0, tzinfo=UTC)
    events = [_event((now - timedelta(days=index)).replace(hour=23)) for index in range(10)]

    result, _ = _evaluate(now=now, events=events)

    assert result == TimeBaselineResult(True, 0, "personalized")


def test_history_older_than_90_days_does_not_contribute_hour() -> None:
    now = datetime(2026, 4, 1, 3, tzinfo=UTC)
    old_events = [
        _event((now - timedelta(days=91 + index)).replace(hour=23)) for index in range(10)
    ]

    result, _ = _evaluate(now=now, events=old_events)

    assert result == TimeBaselineResult(False, 3, "default")


def test_event_exactly_on_90_day_boundary_is_included() -> None:
    now = datetime(2026, 4, 1, 23, tzinfo=UTC)
    boundary = now - timedelta(days=90)
    events = [_event(boundary)] + [
        _event((now - timedelta(days=index)).replace(hour=23)) for index in range(1, 10)
    ]

    result, _ = _evaluate(now=now, events=events)

    assert result.baseline_type == "personalized"
    assert result.within_normal_window is True


def test_invalid_or_missing_timezone_falls_back_to_utc() -> None:
    timestamp = datetime(2026, 1, 1, 8, tzinfo=UTC)

    missing, _ = _evaluate(now=timestamp, timezone_name=None)
    invalid, _ = _evaluate(now=timestamp, timezone_name="No/Such_Zone")

    assert missing == TimeBaselineResult(True, 8, "default")
    assert invalid == TimeBaselineResult(True, 8, "default")


def test_request_time_is_converted_to_profile_timezone() -> None:
    timestamp = datetime(2026, 1, 15, 8, 30, tzinfo=UTC)

    result, _ = _evaluate(now=timestamp, timezone_name="America/Los_Angeles")

    assert result == TimeBaselineResult(False, 0, "default")


def test_empty_recent_baseline_falls_back_to_default_window() -> None:
    now = datetime(2026, 4, 1, 8, tzinfo=UTC)
    events = [_event(now - timedelta(days=91 + index)) for index in range(10)]

    result, _ = _evaluate(now=now, events=events)

    assert result == TimeBaselineResult(True, 8, "default")


def test_history_is_loaded_for_authenticated_user() -> None:
    now = datetime(2026, 1, 1, 8, tzinfo=UTC)
    repository = StubAccessRequestRepository([])
    user_id = uuid4()
    asyncio.run(
        evaluate_time_normality(
            user_id=user_id,
            profile_timezone="UTC",
            repository=cast(AccessRequestRepository, repository),
            clock=FixedClock(now),
        )
    )

    assert repository.requested_user_ids == [user_id]


def test_evaluator_has_no_client_time_or_timezone_override_parameters() -> None:
    assert set(inspect.signature(evaluate_time_normality).parameters) == {
        "user_id",
        "profile_timezone",
        "repository",
        "clock",
    }


def test_naive_historical_timestamp_is_treated_as_utc() -> None:
    now = datetime(2026, 1, 1, 12, tzinfo=UTC)
    events = [_event(datetime(2026, 1, 1, 12) - timedelta(days=index)) for index in range(10)]

    result, _ = _evaluate(now=now, events=events)

    assert result == TimeBaselineResult(True, 12, "personalized")
