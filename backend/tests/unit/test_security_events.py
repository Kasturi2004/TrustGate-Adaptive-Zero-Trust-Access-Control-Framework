"""Unit tests for the security event recording service."""

from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from app.services import security_events
from app.services.security_events import email_identifier, record_event
from sqlalchemy.ext.asyncio import AsyncSession

_USER_ID = UUID("e77184cf-0f33-44cf-9ec1-0789a66c2cab")
_SENSITIVE_DETAIL_KEYS = ("password", "otp", "token", "secret", "authorization", "hash")
_VALID_DECISIONS = ("ALLOW", "STEP_UP", "BLOCK")
_VALID_RISK_CATEGORIES = ("LOW", "MEDIUM", "HIGH")


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
    assert event.decision is None
    assert event.risk_category is None
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
    assert event.decision is None
    assert event.risk_category is None
    assert event.details == {"email_identifier": "keyed-email-456"}
    session.commit.assert_not_awaited()


@pytest.mark.parametrize(
    ("event_type", "decision", "risk_category"),
    (
        ("LOGIN_SUCCESS", None, None),
        ("ACCESS_ALLOWED", "ALLOW", "LOW"),
        ("MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED", "ALLOW", None),
        ("ADMIN_ACCESS", None, None),
        ("ADMIN_UNAUTHORIZED_ATTEMPT", None, "HIGH"),
    ),
)
def test_authenticated_event_rejects_missing_actor(
    event_type: str,
    decision: str | None,
    risk_category: str | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(ValueError, match="actor violates the event contract"):
        record_event(
            session,
            event_type=event_type,
            decision=decision,
            risk_category=risk_category,
        )

    session.add.assert_not_called()
    session.commit.assert_not_awaited()


def test_authenticated_event_accepts_actor() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="ACCESS_ALLOWED",
        actor_id=_USER_ID,
        decision="ALLOW",
        risk_category="LOW",
    )

    assert event.actor_id == _USER_ID
    session.add.assert_called_once_with(event)


@pytest.mark.parametrize("event_type", ("LOGIN_SUCCESS", "LOGIN_FAILURE"))
@pytest.mark.parametrize(
    ("decision", "risk_category"),
    (("ALLOW", None), (None, "LOW"), ("BLOCK", "HIGH")),
)
def test_login_events_reject_non_null_decision_or_risk(
    event_type: str,
    decision: str | None,
    risk_category: str | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(ValueError, match="metadata violates the event contract"):
        record_event(
            session,
            event_type=event_type,
            decision=decision,
            risk_category=risk_category,
        )

    session.add.assert_not_called()
    session.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "event_type",
    ("ACCESS_REQUEST_SUBMITTED", "ACCESS_ALLOWED", "ACCESS_STEPUP", "ACCESS_BLOCKED"),
)
@pytest.mark.parametrize(
    ("decision", "risk_category"),
    tuple((decision, risk) for decision in _VALID_DECISIONS for risk in _VALID_RISK_CATEGORIES),
)
def test_access_events_accept_defined_decisions_and_risk_categories(
    event_type: str,
    decision: str,
    risk_category: str,
) -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type=event_type,
        actor_id=_USER_ID,
        decision=decision,
        risk_category=risk_category,
    )

    assert event.decision == decision
    assert event.risk_category == risk_category


@pytest.mark.parametrize(
    "event_type",
    ("ACCESS_REQUEST_SUBMITTED", "ACCESS_ALLOWED", "ACCESS_STEPUP", "ACCESS_BLOCKED"),
)
@pytest.mark.parametrize(
    ("decision", "risk_category"),
    (
        (None, "LOW"),
        ("ALLOW", None),
        ("INVALID", "LOW"),
        ("ALLOW", "INVALID"),
    ),
)
def test_access_events_reject_missing_or_invalid_metadata(
    event_type: str,
    decision: str | None,
    risk_category: str | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(ValueError, match="metadata violates the event contract"):
        record_event(
            session,
            event_type=event_type,
            decision=decision,
            risk_category=risk_category,
        )

    session.add.assert_not_called()


@pytest.mark.parametrize(
    "event_type",
    (
        "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
        "MFA_EXPIRED",
        "MFA_LOCKED",
    ),
)
def test_mfa_terminal_events_require_a_valid_decision(event_type: str) -> None:
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(ValueError, match="metadata violates the event contract"):
        record_event(session, event_type=event_type)

    event = record_event(
        session,
        event_type=event_type,
        actor_id=_USER_ID,
        decision="STEP_UP",
    )
    assert event.decision == "STEP_UP"


@pytest.mark.parametrize("decision", _VALID_DECISIONS)
def test_mfa_terminal_contract_does_not_invent_a_specific_decision_value(
    decision: str,
) -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
        actor_id=_USER_ID,
        decision=decision,
    )

    assert event.decision == decision


@pytest.mark.parametrize("risk_category", (None, "LOW", "MEDIUM"))
def test_unauthorized_admin_requires_high_risk(
    risk_category: str | None,
) -> None:
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(ValueError, match="metadata violates the event contract"):
        record_event(
            session,
            event_type="ADMIN_UNAUTHORIZED_ATTEMPT",
            risk_category=risk_category,
        )


@pytest.mark.parametrize("decision", (None, "ALLOW", "INVALID"))
def test_degraded_failsafe_only_accepts_step_up_or_block(decision: str | None) -> None:
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(ValueError, match="metadata violates the event contract"):
        record_event(session, event_type="PIPELINE_DEGRADED_FAILSAFE", decision=decision)

    assert (
        record_event(
            session,
            event_type="PIPELINE_DEGRADED_FAILSAFE",
            actor_id=_USER_ID,
            decision="STEP_UP",
        ).decision
        == "STEP_UP"
    )
    assert (
        record_event(
            session,
            event_type="PIPELINE_DEGRADED_FAILSAFE",
            actor_id=_USER_ID,
            decision="BLOCK",
        ).decision
        == "BLOCK"
    )


def test_admin_access_has_no_invented_metadata_requirements() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(session, event_type="ADMIN_ACCESS", actor_id=_USER_ID)

    assert event.decision is None
    assert event.risk_category is None


def test_metadata_validation_error_does_not_expose_supplied_value() -> None:
    session = AsyncMock(spec=AsyncSession)
    supplied_value = "password-value-that-must-not-appear"

    with pytest.raises(ValueError) as error:
        record_event(
            session,
            event_type="ACCESS_ALLOWED",
            decision=supplied_value,
            risk_category="LOW",
        )

    assert supplied_value not in str(error.value)


def test_unknown_event_type_drops_all_details() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="UNKNOWN_EVENT",
        actor_id=_USER_ID,
        details={
            "email_identifier": "keyed-email-789",
            "anything": "should-be-removed",
        },
    )

    assert event.event_type == "UNKNOWN_EVENT"
    assert event.details == {}


def test_admin_unauthorized_attempt_keeps_only_allowlisted_details() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="ADMIN_UNAUTHORIZED_ATTEMPT",
        actor_id=_USER_ID,
        decision="BLOCK",
        risk_category="HIGH",
        details={
            "attempted_role": "ADMIN",
            "path": "/admin/verification",
            "method": "GET",
            "password": "must-not-persist",
            "access_token": "must-not-persist",
            "secret": "must-not-persist",
            "unexpected": "must-not-persist",
        },
    )

    assert event.details == {
        "attempted_role": "ADMIN",
        "path": "/admin/verification",
        "method": "GET",
    }
    session.commit.assert_not_awaited()


@pytest.mark.parametrize("sensitive_key", _SENSITIVE_DETAIL_KEYS)
def test_sensitive_detail_denylist_overrides_event_allowlist(
    monkeypatch: pytest.MonkeyPatch,
    sensitive_key: str,
) -> None:
    session = AsyncMock(spec=AsyncSession)
    monkeypatch.setitem(
        security_events._EVENT_DETAIL_ALLOWLISTS,
        "ADMIN_ACCESS",
        frozenset({"path", sensitive_key}),
    )
    original_details = {
        "path": "/admin/verification",
        sensitive_key: "sensitive-value",
        "unexpected": "unknown-value",
    }

    event = record_event(
        session,
        event_type="ADMIN_ACCESS",
        actor_id=_USER_ID,
        details=original_details,
    )

    assert event.details == {"path": "/admin/verification"}
    assert original_details == {
        "path": "/admin/verification",
        sensitive_key: "sensitive-value",
        "unexpected": "unknown-value",
    }


def test_sensitive_detail_denylist_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AsyncMock(spec=AsyncSession)
    monkeypatch.setitem(
        security_events._EVENT_DETAIL_ALLOWLISTS,
        "ADMIN_ACCESS",
        frozenset({"path", "Authorization"}),
    )

    event = record_event(
        session,
        event_type="ADMIN_ACCESS",
        actor_id=_USER_ID,
        details={"path": "/admin/verification", "Authorization": "secret-value"},
    )

    assert event.details == {"path": "/admin/verification"}


def test_missing_details_produces_empty_object() -> None:
    session = AsyncMock(spec=AsyncSession)

    event = record_event(
        session,
        event_type="LOGIN_SUCCESS",
        actor_id=_USER_ID,
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
