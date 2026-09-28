"""Injectable timezone-aware clock implementations."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Source of timezone-aware timestamps for application services."""

    def now(self) -> datetime:
        """Return the current instant as a timezone-aware datetime."""


class SystemClock:
    """Production clock that returns the current time in UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True)
class FixedClock:
    """Clock that always returns the injected timezone-aware timestamp."""

    timestamp: datetime

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("FixedClock requires a timezone-aware datetime")

    def now(self) -> datetime:
        return self.timestamp
