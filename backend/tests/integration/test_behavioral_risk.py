"""Real PostgreSQL tests for read-time behavioral risk indicators."""

import asyncio
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from app.core.clock import FixedClock
from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.security_event import SecurityEvent
from app.services.behavioral_risk import get_behavioral_risk_indicators
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import (
    ScratchDatabase,
    ensure_auth_user_profile,
    remove_auth_user_profile,
)

_NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
_WINDOW_START = _NOW - timedelta(hours=1)


async def _seed_activity(
    session: AsyncSession,
    *,
    user_id: UUID,
    block_times: tuple[datetime, ...],
    incorrect_otp_times: tuple[datetime, ...],
) -> None:
    device = Device(user_id=user_id, device_hash=f"behavior-{user_id}")
    session.add(device)
    await session.flush()
    session.add_all(
        AccessRequest(
            user_id=user_id,
            device_id=device.id,
            source_ip=IPv4Address("192.0.2.80"),
            initial_decision="BLOCK",
            final_outcome="BLOCK",
            requested_at=at,
            resolved_at=at,
        )
        for at in block_times
    )
    session.add_all(
        SecurityEvent(
            event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
            actor_id=user_id,
            created_at=at,
        )
        for at in incorrect_otp_times
    )
    await session.flush()


def test_behavioral_indicators_use_utc_window_and_cap_normalized_values(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_ids = [uuid4() for _ in range(5)]
    for index, user_id in enumerate(user_ids):
        asyncio.run(
            ensure_auth_user_profile(
                migrated_test_database.url,
                user_id=user_id,
                email=f"behavior-{index}-{user_id}@integration.test",
            )
        )

    async def exercise(session: AsyncSession) -> None:
        await _seed_activity(
            session,
            user_id=user_ids[1],
            block_times=(_NOW - timedelta(minutes=10),),
            incorrect_otp_times=(_NOW - timedelta(minutes=5),),
        )
        await _seed_activity(
            session,
            user_id=user_ids[2],
            block_times=(_NOW - timedelta(minutes=10),) * 3,
            incorrect_otp_times=(_NOW - timedelta(minutes=5),) * 2,
        )
        await _seed_activity(
            session,
            user_id=user_ids[3],
            block_times=(_NOW - timedelta(minutes=10),) * 6,
            incorrect_otp_times=(_NOW - timedelta(minutes=5),) * 5,
        )
        await _seed_activity(
            session,
            user_id=user_ids[4],
            block_times=(
                _WINDOW_START,
                _NOW,
                _WINDOW_START - timedelta(microseconds=1),
                _NOW + timedelta(microseconds=1),
            ),
            incorrect_otp_times=(
                _WINDOW_START,
                _WINDOW_START - timedelta(microseconds=1),
                _NOW + timedelta(microseconds=1),
            ),
        )

        clock = FixedClock(_NOW)
        zero = await get_behavioral_risk_indicators(
            session, clock=clock, block_indicator_limit=3, user_id=user_ids[0]
        )
        below = await get_behavioral_risk_indicators(
            session, clock=clock, block_indicator_limit=3, user_id=user_ids[1]
        )
        exact = await get_behavioral_risk_indicators(
            session, clock=clock, block_indicator_limit=3, user_id=user_ids[2]
        )
        above = await get_behavioral_risk_indicators(
            session, clock=clock, block_indicator_limit=3, user_id=user_ids[3]
        )
        boundary = await get_behavioral_risk_indicators(
            session, clock=clock, block_indicator_limit=3, user_id=user_ids[4]
        )

        assert zero.repeated_failed_access_attempts.count == 0
        assert zero.repeated_failed_access_attempts.normalized_value == 0
        assert zero.repeated_failed_access_attempts.flagged is False
        assert zero.recent_blocks.count == 0
        assert zero.recent_blocks.normalized_value == 0
        assert zero.recent_blocks.flagged is False

        assert below.repeated_failed_access_attempts.count == 2
        assert below.repeated_failed_access_attempts.normalized_value == 0.4
        assert below.repeated_failed_access_attempts.flagged is False
        assert below.recent_blocks.count == 1
        assert below.recent_blocks.normalized_value == 1 / 3
        assert below.recent_blocks.flagged is False

        assert exact.repeated_failed_access_attempts.count == 5
        assert exact.repeated_failed_access_attempts.normalized_value == 1
        assert exact.repeated_failed_access_attempts.flagged is True
        assert exact.recent_blocks.count == 3
        assert exact.recent_blocks.normalized_value == 1
        assert exact.recent_blocks.flagged is True

        assert above.repeated_failed_access_attempts.count == 11
        assert above.repeated_failed_access_attempts.normalized_value == 1
        assert above.repeated_failed_access_attempts.flagged is True
        assert above.recent_blocks.count == 6
        assert above.recent_blocks.normalized_value == 1
        assert above.recent_blocks.flagged is True

        assert boundary.repeated_failed_access_attempts.count == 3
        assert boundary.repeated_failed_access_attempts.normalized_value == 0.6
        assert boundary.recent_blocks.count == 2
        assert boundary.recent_blocks.normalized_value == 2 / 3
        repeated = await get_behavioral_risk_indicators(
            session, clock=clock, block_indicator_limit=3, user_id=user_ids[4]
        )
        assert repeated == boundary

    try:
        migrated_test_database.run_in_transaction(exercise)
    finally:
        for user_id in user_ids:
            asyncio.run(remove_auth_user_profile(migrated_test_database.url, user_id=user_id))
