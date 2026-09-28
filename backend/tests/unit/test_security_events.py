"""Unit tests for the security event recording service."""

from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from app.services.security_events import email_identifier, record_event
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("e77184cf-0f33-44cf-9ec1-0789a66c2cab")


def test_login_success_keeps_only_allowed_email_identifier() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="LOGIN_SUCCESS",
        actor_id=_USER_ID,
        details={
            "email_identifier": "keyed-email-123",
            "password": "super-secret-password",
            "access_token": "access-token-secret",
            "refresh_token": "refresh-token-secret",
            "unexpected": "should-be-removed",
        },
    )

    assert event.event_type == "LOGIN_SUCCESS"
    assert event.actor_id == _USER_ID
    assert event.details == {"email_identifier": "keyed-email-123"}
    session.commit.assert_not_awaited()


def test_login_failure_allows_null_actor_and_filters_sensitive_data() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="LOGIN_FAILURE",
        actor_id=None,
        details={
            "email_identifier": "keyed-email-456",
            "password": "super-secret-password",
            "access_token": "access-token-secret",
            "refresh_token": "refresh-token-secret",
        },
    )

    assert event.event_type == "LOGIN_FAILURE"
    assert event.actor_id is None
    assert event.details == {"email_identifier": "keyed-email-456"}
    session.commit.assert_not_awaited()


def test_unknown_event_type_drops_all_details() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="UNKNOWN_EVENT",
        details={
            "email_identifier": "keyed-email-789",
            "anything": "should-be-removed",
        },
    )

    assert event.event_type == "UNKNOWN_EVENT"
    assert event.details == {}


def test_missing_details_produces_empty_object() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="LOGIN_SUCCESS",
    )

    assert event.details == {}


def test_email_identifier_is_stable_and_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import Settings
    from app.services import security_events

    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        security_event_key_secret="test-security-event-secret",
    )
    monkeypatch.setattr(security_events, "get_settings", lambda: settings)

    first = email_identifier("User@Example.com")
    second = email_identifier("  user@example.com ")

    assert first == second
    assert first.startswith("email:v1:")
    assert "user@example.com" not in first


def test_email_identifier_changes_for_different_emails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import Settings
    from app.services import security_events

    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        security_event_key_secret="test-security-event-secret",
    )
    monkeypatch.setattr(security_events, "get_settings", lambda: settings)

    first = email_identifier("user1@example.com")
    second = email_identifier("user2@example.com")

    assert first != second


def test_email_identifier_requires_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import Settings
    from app.services import security_events

    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        security_event_key_secret=None,
    )
    monkeypatch.setattr(security_events, "get_settings", lambda: settings)

    try:
        email_identifier("user@example.com")
    except RuntimeError as error:
        assert str(error) == "SECURITY_EVENT_KEY_SECRET is not configured"
    else:
        raise AssertionError("Expected RuntimeError")
