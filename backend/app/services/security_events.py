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
    "UNAUTHORIZED_ACCESS_ATTEMPT": frozenset({"resource", "path", "method"}),
    "ADMIN_UNAUTHORIZED_ATTEMPT": frozenset({"attempted_role", "path", "method"}),
}


def _safe_details(
    event_type: str,
    details: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return only fields explicitly allowed for the event type."""
    allowed = _EVENT_DETAIL_ALLOWLISTS.get(event_type, frozenset())
    if not details:
        return {}

    return {key: value for key, value in details.items() if key in allowed}


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
