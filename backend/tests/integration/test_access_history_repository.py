"""Real PostgreSQL tests for the user access-history query foundation."""

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.repositories.access_request import (
    AccessHistoryRecord,
    AccessRequestRepository,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase


async def _create_user_and_device(session: AsyncSession, label: str) -> tuple[UUID, Device]:
    user_id = uuid4()
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"{label}-{user_id}@integration.test"},
    )
    device = Device(user_id=user_id, device_hash=f"history-{label}-{user_id}")
    session.add(device)
    await session.flush()
    return user_id, device


def test_access_history_uses_latest_challenge_once_and_paginates_newest_first(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id, device = await _create_user_and_device(session, "owner")
        other_user_id, other_device = await _create_user_and_device(session, "other")
        requested_at = datetime(2026, 10, 1, tzinfo=UTC)
        requests = [
            AccessRequest(
                user_id=user_id,
                device_id=device.id,
                source_ip=IPv4Address("192.0.2.10"),
                initial_decision="ALLOW",
                requested_at=requested_at,
            ),
            AccessRequest(
                user_id=user_id,
                device_id=device.id,
                source_ip=IPv4Address("192.0.2.10"),
                initial_decision="ALLOW",
                requested_at=requested_at + timedelta(minutes=1),
            ),
            AccessRequest(
                user_id=user_id,
                device_id=device.id,
                source_ip=IPv4Address("192.0.2.10"),
                initial_decision="STEP_UP",
                mfa_required=True,
                requested_at=requested_at + timedelta(minutes=2),
            ),
            AccessRequest(
                user_id=other_user_id,
                device_id=other_device.id,
                source_ip=IPv4Address("192.0.2.11"),
                initial_decision="ALLOW",
                requested_at=requested_at + timedelta(minutes=3),
            ),
        ]
        session.add_all(requests)
        await session.flush()

        session.add_all(
            [
                OtpChallenge(
                    access_request_id=requests[2].id,
                    user_id=user_id,
                    status="EXPIRED",
                    created_at=requested_at + timedelta(minutes=2, seconds=1),
                    expires_at=requested_at + timedelta(minutes=3),
                ),
                OtpChallenge(
                    access_request_id=requests[2].id,
                    user_id=user_id,
                    status="SUCCESS",
                    created_at=requested_at + timedelta(minutes=2, seconds=2),
                    expires_at=requested_at + timedelta(minutes=3),
                ),
            ]
        )
        await session.flush()

        repository = AccessRequestRepository(session)
        first_page = await repository.list_history_by_user(user_id, page=1, page_size=2)
        second_page = await repository.list_history_by_user(user_id, page=2, page_size=2)

        assert [row.id for row in first_page] == [requests[2].id, requests[1].id]
        assert [row.id for row in second_page] == [requests[0].id]
        assert first_page[0].mfa_was_required is True
        assert first_page[0].mfa_status == "SUCCESS"
        assert sum(row.id == requests[2].id for row in first_page + second_page) == 1
        assert all(row.id != requests[3].id for row in first_page + second_page)
        assert [field.name for field in fields(AccessHistoryRecord)] == [
            "id",
            "resource_id",
            "requested_at",
            "initial_decision",
            "final_outcome",
            "mfa_was_required",
            "mfa_status",
        ]

    migrated_test_database.run_in_transaction(exercise)


def test_access_history_caps_page_size_at_fifty(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        user_id, device = await _create_user_and_device(session, "page-cap")
        requested_at = datetime(2026, 10, 2, tzinfo=UTC)
        requests = [
            AccessRequest(
                user_id=user_id,
                device_id=device.id,
                source_ip=IPv4Address("192.0.2.20"),
                initial_decision="ALLOW",
                requested_at=requested_at + timedelta(seconds=index),
            )
            for index in range(51)
        ]
        session.add_all(requests)
        await session.flush()

        repository = AccessRequestRepository(session)
        first_page = await repository.list_history_by_user(user_id, page=1, page_size=51)
        second_page = await repository.list_history_by_user(user_id, page=2, page_size=51)

        assert len(first_page) == 50
        assert len(second_page) == 1
        assert first_page[0].id == requests[-1].id
        assert second_page[0].id == requests[0].id

    migrated_test_database.run_in_transaction(exercise)
