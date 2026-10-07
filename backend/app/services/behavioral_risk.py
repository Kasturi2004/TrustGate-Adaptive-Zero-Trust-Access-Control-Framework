"""Read-time behavioral risk indicators based on persisted access activity."""

from datetime import UTC, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import Clock
from app.db.models.access_request import AccessRequest
from app.db.models.security_event import SecurityEvent
from app.schemas.admin import AdminBehavioralRiskIndicators, AdminRiskIndicator

_INDICATOR_WINDOW = timedelta(hours=1)
_FAILED_OTP_EVENT = "MFA_TOTP_STEP_UP_VERIFICATION_FAILED"
_REPEATED_FAILURE_LIMIT = 5


async def get_behavioral_risk_indicators(
    session: AsyncSession,
    *,
    clock: Clock,
    block_indicator_limit: int,
    user_id: UUID | None = None,
) -> AdminBehavioralRiskIndicators:
    """Compute indicators for one user or all users over the preceding hour.

    The window includes records exactly at ``now - 1 hour`` and ``now``.
    Block requests are timed by ``resolved_at``. Incorrect OTP attempts use
    their one-per-attempt security-event timestamp, since the OTP challenge
    row stores only a cumulative count and its creation timestamp.
    """
    if block_indicator_limit < 1:
        raise ValueError("block_indicator_limit must be positive")

    now = clock.now()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware timestamp")
    now_utc = now.astimezone(UTC)
    window_start = now_utc - _INDICATOR_WINDOW

    block_filters = [
        AccessRequest.final_outcome == "BLOCK",
        AccessRequest.resolved_at.between(window_start, now_utc),
    ]
    otp_failure_filters = [
        SecurityEvent.event_type == _FAILED_OTP_EVENT,
        SecurityEvent.created_at.between(window_start, now_utc),
    ]
    if user_id is not None:
        block_filters.append(AccessRequest.user_id == user_id)
        otp_failure_filters.append(SecurityEvent.actor_id == user_id)

    block_count = int(
        await session.scalar(select(func.count(AccessRequest.id)).where(*block_filters)) or 0
    )
    incorrect_otp_count = int(
        await session.scalar(select(func.count(SecurityEvent.id)).where(*otp_failure_filters)) or 0
    )
    failed_count = block_count + incorrect_otp_count

    return AdminBehavioralRiskIndicators(
        repeated_failed_access_attempts=AdminRiskIndicator(
            count=failed_count,
            normalized_value=min(1.0, failed_count / _REPEATED_FAILURE_LIMIT),
            flagged=failed_count >= _REPEATED_FAILURE_LIMIT,
        ),
        recent_blocks=AdminRiskIndicator(
            count=block_count,
            normalized_value=min(1.0, block_count / block_indicator_limit),
            flagged=block_count >= block_indicator_limit,
        ),
    )
