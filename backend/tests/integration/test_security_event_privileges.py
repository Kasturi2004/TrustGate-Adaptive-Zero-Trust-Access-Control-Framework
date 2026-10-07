"""Real PostgreSQL checks for runtime security-event table privileges."""

import pytest
from app.db.models.security_event import SecurityEvent
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase


def _postgres_sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def test_trustgate_app_can_read_insert_but_not_update_or_delete_security_events(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        event = SecurityEvent(event_type="LOGIN_FAILURE", details={})
        session.add(event)
        await session.flush()

        await session.execute(text("SET LOCAL ROLE trustgate_app"))
        current_role = await session.scalar(text("SELECT current_user"))
        assert current_role == "trustgate_app"

        privileges = await session.execute(
            text(
                """
                SELECT
                    has_table_privilege(current_user, 'public.security_events', 'SELECT'),
                    has_table_privilege(current_user, 'public.security_events', 'INSERT'),
                    has_table_privilege(current_user, 'public.security_events', 'UPDATE'),
                    has_table_privilege(current_user, 'public.security_events', 'DELETE')
                """
            )
        )
        assert privileges.one() == (True, True, False, False)

        with pytest.raises(DBAPIError) as update_error:
            async with session.begin_nested():
                await session.execute(
                    text(
                        "UPDATE public.security_events "
                        "SET event_type = 'PRIVILEGE_TEST_UPDATE' WHERE id = :event_id"
                    ),
                    {"event_id": event.id},
                )
        assert _postgres_sqlstate(update_error.value) == "42501"
        assert "append-only" not in str(update_error.value).casefold()

        with pytest.raises(DBAPIError) as delete_error:
            async with session.begin_nested():
                await session.execute(
                    text("DELETE FROM public.security_events WHERE id = :event_id"),
                    {"event_id": event.id},
                )
        assert _postgres_sqlstate(delete_error.value) == "42501"
        assert "append-only" not in str(delete_error.value).casefold()

    migrated_test_database.run_in_transaction(exercise)
