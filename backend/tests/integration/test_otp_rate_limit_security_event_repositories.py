"""Real PostgreSQL round trips for OTP, rate-limit, and security-event repositories."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.models.rate_limit_state import RateLimitState
from app.db.models.security_event import SecurityEvent
from app.db.repositories.otp_challenge import OtpChallengeRepository
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.db.repositories.security_event import SecurityEventRepository
from app.services.security_events import record_event
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase

_CREATED_AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


async def _create_access_request(session: AsyncSession) -> tuple[UUID, AccessRequest]:
    """Create the auth/profile and device prerequisites for a request."""
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"otp-security-{user_id}@integration.test"},
    )
    device = Device(
        id=uuid4(),
        user_id=user_id,
        device_hash=f"otp-security-device-{user_id}",
        first_seen_at=_CREATED_AT,
        last_seen_at=_CREATED_AT,
    )
    session.add(device)
    await session.flush()
    access_request = AccessRequest(
        id=uuid4(),
        user_id=user_id,
        device_id=device.id,
        source_ip=IPv4Address("192.0.2.60"),
        initial_decision="STEP_UP",
        mfa_required=True,
        requested_at=_CREATED_AT,
    )
    session.add(access_request)
    await session.flush()
    return user_id, access_request


def test_otp_challenge_repository_persists_locks_pending_and_updates_only_status(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id, access_request = await _create_access_request(session)
        completed_user_id, completed_request = await _create_access_request(session)
        pending = OtpChallenge(
            id=uuid4(),
            access_request_id=access_request.id,
            user_id=user_id,
            otp_hash="test-hash-pending",
            status="PENDING",
            attempt_count=1,
            max_attempts=4,
            created_at=_CREATED_AT,
            expires_at=_CREATED_AT + timedelta(minutes=5),
        )
        completed = OtpChallenge(
            id=uuid4(),
            access_request_id=completed_request.id,
            user_id=completed_user_id,
            otp_hash="test-hash-completed",
            status="SUCCESS",
            attempt_count=2,
            max_attempts=4,
            created_at=_CREATED_AT + timedelta(seconds=1),
            expires_at=_CREATED_AT + timedelta(minutes=5),
            verified_at=_CREATED_AT + timedelta(seconds=2),
        )
        repository = OtpChallengeRepository(session)
        repository.add(pending)
        repository.add(completed)
        await session.flush()

        found = await repository.get_pending_for_update(access_request.id)
        assert found is not None
        assert found.id == pending.id
        assert found.otp_hash == "test-hash-pending"
        assert found.status == "PENDING"
        assert found.attempt_count == 1
        assert found.max_attempts == 4
        assert found.created_at == _CREATED_AT
        assert found.expires_at == _CREATED_AT + timedelta(minutes=5)
        assert await repository.get_pending_for_update(completed_request.id) is None

        updated = await repository.update_status(pending.id, "SUCCESS")
        assert updated is found
        assert updated.status == "SUCCESS"
        assert updated.id == pending.id
        assert updated.access_request_id == access_request.id
        assert updated.user_id == user_id
        assert updated.otp_hash == "test-hash-pending"
        assert updated.attempt_count == 1
        assert updated.max_attempts == 4
        assert updated.created_at == _CREATED_AT
        assert updated.expires_at == _CREATED_AT + timedelta(minutes=5)
        assert updated.verified_at is None
        assert await repository.get_pending_for_update(access_request.id) is None

    migrated_test_database.run_in_transaction(exercise)


def test_rate_limit_state_repository_locks_and_upserts_existing_key(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        repository = RateLimitStateRepository(session)
        initial = RateLimitState(
            key="integration:rate-limit:round-trip",
            counter=2,
            window_reset_at=_CREATED_AT + timedelta(minutes=1),
            updated_at=_CREATED_AT,
        )
        await repository.add_or_update(initial)

        created = await repository.get_for_update(initial.key)
        assert created is not None
        assert created.key == initial.key
        assert created.counter == 2
        assert created.window_reset_at == _CREATED_AT + timedelta(minutes=1)
        assert created.updated_at == _CREATED_AT

        replacement = RateLimitState(
            key=initial.key,
            counter=5,
            window_reset_at=_CREATED_AT + timedelta(minutes=2),
            updated_at=_CREATED_AT + timedelta(seconds=30),
        )
        await repository.add_or_update(replacement)

        updated = await repository.get_for_update(initial.key)
        assert updated is not None
        assert updated.key == initial.key
        assert updated.counter == 5
        assert updated.window_reset_at == _CREATED_AT + timedelta(minutes=2)
        assert updated.updated_at == _CREATED_AT + timedelta(seconds=30)
        assert await repository.get_for_update("integration:rate-limit:missing") is None

    migrated_test_database.run_in_transaction(exercise)


def test_security_event_repository_filters_orders_and_includes_time_bounds(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        actor_id, access_request = await _create_access_request(session)
        other_actor_id, _ = await _create_access_request(session)
        events = [
            SecurityEvent(
                id=UUID(int=10),
                event_type="ACCESS_DECISION",
                actor_id=actor_id,
                access_request_id=access_request.id,
                decision="ALLOW",
                risk_category="LOW",
                details={"tag": "tie-low-id"},
                created_at=_CREATED_AT,
            ),
            SecurityEvent(
                id=UUID(int=20),
                event_type="ACCESS_DECISION",
                actor_id=actor_id,
                access_request_id=access_request.id,
                decision="ALLOW",
                risk_category="LOW",
                details={"tag": "tie-high-id"},
                created_at=_CREATED_AT,
            ),
            SecurityEvent(
                id=UUID(int=30),
                event_type="OTHER_EVENT",
                actor_id=actor_id,
                access_request_id=access_request.id,
                decision="BLOCK",
                risk_category="HIGH",
                details={"tag": "other-type"},
                created_at=_CREATED_AT,
            ),
            SecurityEvent(
                id=UUID(int=40),
                event_type="ACCESS_DECISION",
                actor_id=other_actor_id,
                access_request_id=access_request.id,
                decision="STEP_UP",
                risk_category="MEDIUM",
                details={"tag": "other-actor"},
                created_at=_CREATED_AT,
            ),
            SecurityEvent(
                id=UUID(int=50),
                event_type="ACCESS_DECISION",
                actor_id=actor_id,
                decision="BLOCK",
                risk_category="HIGH",
                details={"tag": "other-request"},
                created_at=_CREATED_AT,
            ),
            SecurityEvent(
                id=UUID(int=60),
                event_type="ACCESS_DECISION",
                actor_id=actor_id,
                access_request_id=access_request.id,
                decision="BLOCK",
                risk_category="HIGH",
                details={"tag": "before-range"},
                created_at=_CREATED_AT - timedelta(seconds=1),
            ),
            SecurityEvent(
                id=UUID(int=70),
                event_type="ACCESS_DECISION",
                actor_id=actor_id,
                access_request_id=access_request.id,
                decision="ALLOW",
                risk_category="LOW",
                details={"tag": "after-range"},
                created_at=_CREATED_AT + timedelta(seconds=1),
            ),
        ]
        repository = SecurityEventRepository(session)
        for event in events:
            repository.add(event)
        await session.flush()

        by_type = await repository.list(event_type="ACCESS_DECISION")
        assert {event.id for event in by_type} == {
            UUID(int=10),
            UUID(int=20),
            UUID(int=40),
            UUID(int=50),
            UUID(int=60),
            UUID(int=70),
        }
        assert [event.id for event in by_type[:2]] == [UUID(int=70), UUID(int=50)]

        by_actor = await repository.list(actor_id=actor_id)
        assert UUID(int=40) not in {event.id for event in by_actor}
        assert {UUID(int=10), UUID(int=20)} <= {event.id for event in by_actor}

        by_request = await repository.list(access_request_id=access_request.id)
        assert UUID(int=50) not in {event.id for event in by_request}
        assert {UUID(int=10), UUID(int=20)} <= {event.id for event in by_request}

        inclusive_range = await repository.list(
            event_type="ACCESS_DECISION",
            actor_id=actor_id,
            access_request_id=access_request.id,
            created_after=_CREATED_AT,
            created_before=_CREATED_AT,
        )
        assert [event.id for event in inclusive_range] == [UUID(int=20), UUID(int=10)]
        assert all(event.created_at == _CREATED_AT for event in inclusive_range)
        assert inclusive_range[0].details == {"tag": "tie-high-id"}
        assert inclusive_range[1].details == {"tag": "tie-low-id"}

    migrated_test_database.run_in_transaction(exercise)


def test_security_event_writer_uses_database_server_timestamp(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        actor_id, _ = await _create_access_request(session)
        event = record_event(
            session,
            event_type="LOGIN_SUCCESS",
            actor_id=actor_id,
        )

        assert event.created_at is None
        await session.flush()

        persisted_created_at = await session.scalar(
            select(SecurityEvent.created_at).where(SecurityEvent.id == event.id)
        )
        assert event.created_at is not None
        assert persisted_created_at == event.created_at

    migrated_test_database.run_in_transaction(exercise)
