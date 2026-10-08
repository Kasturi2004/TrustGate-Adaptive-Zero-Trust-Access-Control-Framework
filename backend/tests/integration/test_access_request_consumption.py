"""PostgreSQL coverage for one-time protected dashboard authorization."""

import asyncio
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from app.db.models.access_request import AccessRequest
from app.db.models.device import Device
from app.db.models.otp_challenge import OtpChallenge
from app.db.repositories.access_request import AccessRequestRepository
from app.db.session import create_async_engine_for_url
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import (
    ScratchDatabase,
    ensure_auth_user_profile,
    remove_auth_user_profile,
)

_SESSION_1 = UUID("44444444-4444-4444-8444-444444444444")
_SESSION_2 = UUID("55555555-5555-4555-8555-555555555555")


def test_dashboard_approval_is_consumed_once_with_database_enforced_mfa(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()
    email = f"consumption-{user_id}@integration.test"
    asyncio.run(
        ensure_auth_user_profile(
            migrated_test_database.url,
            user_id=user_id,
            email=email,
        )
    )
    now = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    try:

        async def exercise(session: AsyncSession) -> None:
            device = Device(user_id=user_id, device_hash=f"consumption-{user_id}")
            session.add(device)
            await session.flush()

            approved = AccessRequest(
                user_id=user_id,
                auth_session_id=_SESSION_1,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address("192.0.2.40"),
                initial_decision="ALLOW",
                final_outcome="ALLOW",
                requested_at=now,
            )
            step_up = AccessRequest(
                user_id=user_id,
                auth_session_id=_SESSION_1,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address("192.0.2.41"),
                initial_decision="STEP_UP",
                mfa_required=True,
                final_outcome="ALLOW",
                requested_at=now,
            )
            session.add_all((approved, step_up))
            await session.flush()

            repository = AccessRequestRepository(session)
            # A fresh login for the same user cannot redeem Session 1's unused approval.
            assert not await repository.consume_dashboard_access(
                approved.id, user_id, _SESSION_2, now
            )
            assert not await repository.consume_dashboard_access(
                approved.id, uuid4(), _SESSION_1, now
            )
            assert await repository.consume_dashboard_access(approved.id, user_id, _SESSION_1, now)
            assert not await repository.consume_dashboard_access(
                approved.id, user_id, _SESSION_1, now
            )

            fresh_session_2_request = AccessRequest(
                user_id=user_id,
                auth_session_id=_SESSION_2,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address("192.0.2.42"),
                initial_decision="ALLOW",
                final_outcome="ALLOW",
                requested_at=now,
            )
            session.add(fresh_session_2_request)
            await session.flush()
            assert not await repository.consume_dashboard_access(
                fresh_session_2_request.id, uuid4(), _SESSION_2, now
            )
            assert await repository.consume_dashboard_access(
                fresh_session_2_request.id, user_id, _SESSION_2, now
            )

            legacy_request = AccessRequest(
                user_id=user_id,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address("192.0.2.44"),
                initial_decision="ALLOW",
                final_outcome="ALLOW",
                requested_at=now,
            )
            session.add(legacy_request)
            await session.flush()
            assert legacy_request.auth_session_id is None
            assert not await repository.consume_dashboard_access(
                legacy_request.id, user_id, _SESSION_1, now
            )

            assert not await repository.consume_dashboard_access(
                step_up.id, user_id, _SESSION_2, now
            )
            session.add(
                OtpChallenge(
                    access_request_id=step_up.id,
                    user_id=user_id,
                    otp_hash=None,
                    status="SUCCESS",
                    attempt_count=1,
                    max_attempts=3,
                    created_at=now - timedelta(minutes=1),
                    expires_at=now + timedelta(minutes=5),
                    verified_at=now,
                )
            )
            await session.flush()
            assert await repository.consume_dashboard_access(step_up.id, user_id, _SESSION_1, now)

            await session.refresh(approved)
            await session.refresh(step_up)
            assert approved.consumed_at == now
            assert step_up.consumed_at == now

        migrated_test_database.run_in_transaction(exercise)
    finally:
        asyncio.run(remove_auth_user_profile(migrated_test_database.url, user_id=user_id))


def test_concurrent_dashboard_redemption_has_exactly_one_winner(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()
    email = f"concurrent-consumption-{user_id}@integration.test"
    asyncio.run(
        ensure_auth_user_profile(
            migrated_test_database.url,
            user_id=user_id,
            email=email,
        )
    )
    engine = create_async_engine_for_url(migrated_test_database.url)
    now = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    async def exercise() -> None:
        async with AsyncSession(engine) as session, session.begin():
            device = Device(user_id=user_id, device_hash=f"concurrent-consumption-{user_id}")
            session.add(device)
            await session.flush()
            request = AccessRequest(
                user_id=user_id,
                auth_session_id=_SESSION_1,
                device_id=device.id,
                resource_id="ops-dashboard",
                source_ip=IPv4Address("192.0.2.43"),
                initial_decision="ALLOW",
                final_outcome="ALLOW",
                requested_at=now,
            )
            session.add(request)
            await session.flush()
            assert request.consumed_at is None
            request_id = request.id

        async def redeem() -> bool:
            async with AsyncSession(engine) as session, session.begin():
                return await AccessRequestRepository(session).consume_dashboard_access(
                    request_id, user_id, _SESSION_1, now
                )

        outcomes = await asyncio.gather(redeem(), redeem())
        assert sorted(outcomes) == [False, True]
        assert not await redeem()

        async with AsyncSession(engine) as session:
            consumed_request = await session.get(AccessRequest, request_id)
            assert consumed_request is not None
            assert consumed_request.consumed_at == now

    try:
        asyncio.run(exercise())
    finally:
        asyncio.run(engine.dispose())
        cleanup_engine = create_async_engine_for_url(
            migrated_test_database.url, null_pool=True
        )
        try:
            async def remove_committed_request_and_device() -> None:
                async with cleanup_engine.begin() as connection:
                    await connection.execute(
                        text("DELETE FROM public.access_requests WHERE user_id = :user_id"),
                        {"user_id": user_id},
                    )
                    await connection.execute(
                        text("DELETE FROM public.devices WHERE user_id = :user_id"),
                        {"user_id": user_id},
                    )

            asyncio.run(remove_committed_request_and_device())
        finally:
            asyncio.run(cleanup_engine.dispose())
        asyncio.run(remove_auth_user_profile(migrated_test_database.url, user_id=user_id))
