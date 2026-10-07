"""Security event recording service."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models.security_event import SecurityEvent
from app.db.repositories.security_event import SecurityEventRepository

_EVENT_DETAIL_ALLOWLISTS: dict[str, frozenset[str]] = {
    "LOGIN_SUCCESS": frozenset({"email_identifier"}),
    "LOGIN_FAILURE": frozenset({"email_identifier"}),
    "MFA_TOTP_ENROLLMENT_STARTED": frozenset(),
    "MFA_TOTP_ENROLLMENT_VERIFICATION_FAILED": frozenset(),
    "MFA_TOTP_ENROLLMENT_VERIFICATION_SUCCEEDED": frozenset(),
    "MFA_TOTP_STEP_UP_VERIFICATION_FAILED": frozenset(),
    "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED": frozenset(),
    "MFA_EXPIRED": frozenset(),
    "MFA_LOCKED": frozenset(),
    "ACCESS_MFA_ALLOWED": frozenset(),
    "PIPELINE_DEGRADED_FAILSAFE": frozenset(),
    "UNAUTHORIZED_ACCESS_ATTEMPT": frozenset({"resource", "path", "method"}),
    "ADMIN_UNAUTHORIZED_ATTEMPT": frozenset({"attempted_role", "path", "method"}),
    "ADMIN_ACCESS": frozenset({"path", "method"}),
}

_SENSITIVE_DETAIL_DENYLIST = frozenset(
    {"password", "otp", "token", "secret", "authorization", "hash"}
)

# Map the established application names to the event names used in plan §3.2.
_PLAN_EVENT_NAME_ALIASES = {
    "ACCESS_REQUEST_SUBMITTED": "ACCESS_REQUESTED",
    "MFA_TOTP_STEP_UP_VERIFICATION_FAILED": "MFA_ATTEMPT_FAILED",
    "MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED": "MFA_SUCCESS",
}
_LOGIN_EVENT_TYPES = frozenset({"LOGIN_SUCCESS", "LOGIN_FAILURE"})
_ACCESS_DECISION_EVENT_TYPES = frozenset(
    {"ACCESS_REQUESTED", "ACCESS_ALLOWED", "ACCESS_STEPUP", "ACCESS_BLOCKED"}
)
_MFA_TERMINAL_EVENT_TYPES = frozenset({"MFA_SUCCESS", "MFA_EXPIRED", "MFA_LOCKED"})
_VALID_DECISIONS = frozenset({"ALLOW", "STEP_UP", "BLOCK"})
_VALID_RISK_CATEGORIES = frozenset({"LOW", "MEDIUM", "HIGH"})
_PRE_AUTH_EVENT_TYPES = frozenset({"LOGIN_FAILURE"})


def _validate_event_metadata(
    event_type: str,
    decision: str | None,
    risk_category: str | None,
) -> None:
    """Reject metadata that violates the event contract before staging a row."""
    contract_type = _PLAN_EVENT_NAME_ALIASES.get(event_type, event_type)

    if contract_type in _LOGIN_EVENT_TYPES:
        if decision is not None or risk_category is not None:
            raise ValueError("Security event metadata violates the event contract.")
    elif contract_type in _ACCESS_DECISION_EVENT_TYPES:
        if decision not in _VALID_DECISIONS or risk_category not in _VALID_RISK_CATEGORIES:
            raise ValueError("Security event metadata violates the event contract.")
    elif contract_type in _MFA_TERMINAL_EVENT_TYPES:
        if decision not in _VALID_DECISIONS:
            raise ValueError("Security event metadata violates the event contract.")
    elif event_type == "ADMIN_UNAUTHORIZED_ATTEMPT":
        if risk_category != "HIGH":
            raise ValueError("Security event metadata violates the event contract.")
    elif event_type == "PIPELINE_DEGRADED_FAILSAFE":
        if decision not in {"STEP_UP", "BLOCK"}:
            raise ValueError("Security event metadata violates the event contract.")


def _validate_event_actor(event_type: str, actor_id: UUID | None) -> None:
    """Require an actor for events other than the established pre-auth event."""
    if actor_id is None and event_type not in _PRE_AUTH_EVENT_TYPES:
        raise ValueError("Security event actor violates the event contract.")


def _safe_details(
    event_type: str,
    details: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return only fields explicitly allowed for the event type."""
    allowed = _EVENT_DETAIL_ALLOWLISTS.get(event_type, frozenset())
    if not details:
        return {}

    return {
        key: value
        for key, value in details.items()
        if key in allowed and key.casefold() not in _SENSITIVE_DETAIL_DENYLIST
    }


def email_identifier(email: str) -> str:
    """Return a stable opaque identifier for a login email address."""
    normalized_email = email.strip().casefold()
    secret = get_settings().security_event_key_secret

    if not secret:
        raise RuntimeError("SECURITY_EVENT_KEY_SECRET is not configured")

    digest = hmac.new(
        secret.encode("utf-8"),
        normalized_email.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"email:v1:{digest}"


def record_event(
    session: AsyncSession,
    *,
    event_type: str,
    actor_id: UUID | None = None,
    target_user_id: UUID | None = None,
    access_request_id: UUID | None = None,
    trust_evaluation_id: UUID | None = None,
    decision: str | None = None,
    risk_category: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> SecurityEvent:
    """Stage a security event without committing the transaction."""
    _validate_event_metadata(event_type, decision, risk_category)
    _validate_event_actor(event_type, actor_id)
    event = SecurityEvent(
        event_type=event_type,
        actor_id=actor_id,
        target_user_id=target_user_id,
        access_request_id=access_request_id,
        trust_evaluation_id=trust_evaluation_id,
        decision=decision,
        risk_category=risk_category,
        details=_safe_details(event_type, details),
    )

    SecurityEventRepository(session).add(event)
    return event
