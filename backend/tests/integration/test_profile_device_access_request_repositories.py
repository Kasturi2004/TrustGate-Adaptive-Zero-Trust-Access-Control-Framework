"""Real persistence round trips for the first Phase 2G repository group."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.profile import Profile
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.device import DeviceRepository
from app.db.repositories.profile import ProfileRepository
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase


async def _create_auth_user(session: AsyncSession, user_id: UUID, email: str) -> None:
    """Insert a test-only auth identity; the migration trigger creates its profile."""
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": email},
    )


def test_profile_repository_reads_persisted_auth_created_profile(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id = uuid4()
        email = f"profile-{user_id}@integration.test"
        await _create_auth_user(session, user_id, email)

        repository = ProfileRepository(session)
        by_id = await repository.get_by_id(user_id)
        by_email = await repository.get_by_email(email)

        assert isinstance(by_id, Profile)
        assert by_id.id == user_id
        assert by_id.email == email
        assert by_id.role == "USER"
        assert by_email is not None
        assert by_email.id == user_id
        assert by_email.email == email
        assert await repository.get_by_id(uuid4()) is None
        assert await repository.get_by_email(f"missing-{user_id}@integration.test") is None

    migrated_test_database.run_in_transaction(exercise)


def test_device_repository_persists_queries_orders_and_updates_last_seen(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        first_user_id = uuid4()
        second_user_id = uuid4()
        await _create_auth_user(
            session, first_user_id, f"device-a-{first_user_id}@integration.test"
        )
        await _create_auth_user(
            session, second_user_id, f"device-b-{second_user_id}@integration.test"
        )

        first_seen = datetime(2026, 1, 1, tzinfo=UTC)
        devices = [
            Device(
                id=UUID(int=20),
                user_id=first_user_id,
                device_hash="integration-device-a",
                first_seen_at=first_seen,
                last_seen_at=first_seen,
            ),
            Device(
                id=UUID(int=10),
                user_id=first_user_id,
                device_hash="integration-device-b",
                first_seen_at=first_seen,
                last_seen_at=first_seen,
            ),
            Device(
                id=UUID(int=30),
                user_id=second_user_id,
                device_hash="integration-device-c",
                first_seen_at=first_seen,
                last_seen_at=first_seen,
            ),
        ]
        repository = DeviceRepository(session)
        for device in devices:
            repository.add(device)
        await session.flush()

        found_by_id = await repository.get_by_id(devices[0].id)
        found_by_hash = await repository.get_by_user_and_hash(first_user_id, "integration-device-a")
        user_devices = await repository.list_by_user(first_user_id)

        assert found_by_id is not None
        assert found_by_id.device_hash == "integration-device-a"
        assert found_by_hash is not None
        assert found_by_hash.id == devices[0].id
        assert [device.id for device in user_devices] == [UUID(int=10), UUID(int=20)]
        assert all(device.user_id == first_user_id for device in user_devices)

        updated_at = first_seen + timedelta(days=1)
        updated = await repository.update_last_seen(devices[0].id, updated_at)
        assert updated is not None
        await session.flush()
        await session.refresh(updated)
        assert updated.last_seen_at == updated_at
        assert updated.first_seen_at == first_seen

    migrated_test_database.run_in_transaction(exercise)


def test_access_request_repository_persists_lists_and_sets_final_outcome(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id = uuid4()
        other_user_id = uuid4()
        await _create_auth_user(session, user_id, f"request-a-{user_id}@integration.test")
        await _create_auth_user(
            session, other_user_id, f"request-b-{other_user_id}@integration.test"
        )

        timestamp = datetime(2026, 2, 1, tzinfo=UTC)
        devices = [
            Device(
                id=UUID(int=101),
                user_id=user_id,
                device_hash="request-device-a",
                first_seen_at=timestamp,
                last_seen_at=timestamp,
            ),
            Device(
                id=UUID(int=102),
                user_id=user_id,
                device_hash="request-device-b",
                first_seen_at=timestamp,
                last_seen_at=timestamp,
            ),
            Device(
                id=UUID(int=103),
                user_id=other_user_id,
                device_hash="request-device-c",
                first_seen_at=timestamp,
                last_seen_at=timestamp,
            ),
        ]
        session.add_all(devices)
        await session.flush()

        requests = [
            AccessRequest(
                id=UUID(int=202),
                user_id=user_id,
                device_id=devices[0].id,
                source_ip=IPv4Address("192.0.2.10"),
                initial_decision="ALLOW",
                requested_at=timestamp,
            ),
            AccessRequest(
                id=UUID(int=201),
                user_id=user_id,
                device_id=devices[1].id,
                source_ip=IPv4Address("192.0.2.11"),
                initial_decision="STEP_UP",
                mfa_required=True,
                requested_at=timestamp,
            ),
            AccessRequest(
                id=UUID(int=203),
                user_id=other_user_id,
                device_id=devices[2].id,
                source_ip=IPv4Address("192.0.2.12"),
                initial_decision="BLOCK",
                final_outcome="BLOCK",
                requested_at=timestamp - timedelta(seconds=1),
            ),
        ]
        repository = AccessRequestRepository(session)
        for access_request in requests:
            repository.add(access_request)
        await session.flush()

        found = await repository.get_by_id(requests[0].id)
        user_requests = await repository.list_by_user(user_id)
        assert found is not None
        assert found.id == requests[0].id
        assert found.source_ip == IPv4Address("192.0.2.10")
        assert [request.id for request in user_requests] == [UUID(int=201), UUID(int=202)]
        assert all(request.user_id == user_id for request in user_requests)

        original_resolved_at = found.resolved_at
        changed = await repository.set_final_outcome(found.id, "ALLOW")
        assert changed is found
        assert found.final_outcome == "ALLOW"
        assert found.resolved_at == original_resolved_at
        assert found.initial_decision == "ALLOW"

    migrated_test_database.run_in_transaction(exercise)
