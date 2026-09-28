from datetime import UTC, datetime, timedelta, timezone

import pytest
from app.core.clock import FixedClock, SystemClock


def test_system_clock_returns_timezone_aware_utc_time() -> None:
    before = datetime.now(UTC)

    current = SystemClock().now()

    after = datetime.now(UTC)
    assert current.tzinfo is UTC
    assert current.utcoffset() == timedelta(0)
    assert before <= current <= after


def test_fixed_clock_returns_exact_injected_aware_timestamp_repeatedly() -> None:
    timestamp = datetime(2026, 9, 28, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    clock = FixedClock(timestamp)

    first = clock.now()
    second = clock.now()

    assert first is timestamp
    assert second is timestamp
    assert first == timestamp
    assert first.tzinfo is timestamp.tzinfo


def test_fixed_clock_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        FixedClock(datetime(2026, 9, 28, 12, 30))
