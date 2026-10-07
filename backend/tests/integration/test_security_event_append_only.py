"""Real PostgreSQL checks for owner-role security-event append-only triggers."""

import pytest
from app.db.models.security_event import SecurityEvent
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase


def _postgres_sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def test_privileged_role_cannot_update_or_delete_security_events(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        event = SecurityEvent(event_type="LOGIN_FAILURE", details={})
        session.add(event)
        await session.flush()

        privileges = await session.execute(
            text(
                """
                SELECT current_user,
                    has_table_privilege(current_user, 'public.security_events', 'UPDATE'),
                    has_table_privilege(current_user, 'public.security_events', 'DELETE')
                """
            )
        )
        current_user, can_update, can_delete = privileges.one()
        assert current_user != "trustgate_app"
        assert can_update is True
        assert can_delete is True

        with pytest.raises(DBAPIError) as update_error:
            async with session.begin_nested():
                await session.execute(
                    text(
                        "UPDATE public.security_events "
                        "SET event_type = 'TRIGGER_TEST_UPDATE' WHERE id = :event_id"
                    ),
                    {"event_id": event.id},
                )
        assert _postgres_sqlstate(update_error.value) == "P0001"
        assert "security_events is append-only" in str(update_error.value)

        with pytest.raises(DBAPIError) as delete_error:
            async with session.begin_nested():
                await session.execute(
                    text("DELETE FROM public.security_events WHERE id = :event_id"),
                    {"event_id": event.id},
                )
        assert _postgres_sqlstate(delete_error.value) == "P0001"
        assert "security_events is append-only" in str(delete_error.value)

    migrated_test_database.run_in_transaction(exercise)
