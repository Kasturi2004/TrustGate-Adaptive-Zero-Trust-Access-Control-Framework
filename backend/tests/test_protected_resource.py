"""Focused tests for atomic one-time protected resource authorization."""

from asyncio import run
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

from app.db.repositories.access_request import AccessRequestRepository
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession


def test_dashboard_redemption_is_one_atomic_owner_resource_outcome_mfa_check() -> None:
    session = AsyncMock(spec=AsyncSession)
    session.execute.return_value = Mock(scalar_one_or_none=Mock(return_value=uuid4()))
    request_id = uuid4()
    user_id = uuid4()
    now = datetime(2026, 10, 8, tzinfo=UTC)

    consumed = run(
        AccessRequestRepository(cast(AsyncSession, session)).consume_dashboard_access(
            request_id, user_id, UUID(int=1), now
        )
    )

    assert consumed is True
    session.execute.assert_awaited_once()
    statement: Any = session.execute.await_args.args[0]
    postgres_module: Any = postgresql
    sql = str(statement.compile(dialect=postgres_module.dialect()))
    assert sql.startswith("UPDATE public.access_requests SET consumed_at=")
    assert "public.access_requests.user_id" in sql
    assert "public.access_requests.auth_session_id" in sql
    assert "public.access_requests.resource_id" in sql
    assert "public.access_requests.final_outcome" in sql
    assert "public.access_requests.consumed_at IS NULL" in sql
    assert "public.otp_challenges.status" in sql
    assert "public.otp_challenges.verified_at IS NOT NULL" in sql
    assert statement._returning


def test_dashboard_redemption_fails_closed_when_atomic_update_returns_no_row() -> None:
    session = AsyncMock(spec=AsyncSession)
    session.execute.return_value = Mock(scalar_one_or_none=Mock(return_value=None))

    consumed = run(
        AccessRequestRepository(cast(AsyncSession, session)).consume_dashboard_access(
            uuid4(), uuid4(), UUID(int=1), datetime(2026, 10, 8, tzinfo=UTC)
        )
    )

    assert consumed is False


def test_second_redemption_of_the_same_approval_is_rejected() -> None:
    session = AsyncMock(spec=AsyncSession)
    session.execute.side_effect = [
        Mock(scalar_one_or_none=Mock(return_value=uuid4())),
        Mock(scalar_one_or_none=Mock(return_value=None)),
    ]
    repository = AccessRequestRepository(cast(AsyncSession, session))
    request_id = uuid4()
    user_id = uuid4()
    now = datetime(2026, 10, 8, tzinfo=UTC)

    first = run(repository.consume_dashboard_access(request_id, user_id, UUID(int=1), now))
    second = run(repository.consume_dashboard_access(request_id, user_id, UUID(int=1), now))

    assert first is True
    assert second is False
    assert session.execute.await_count == 2
