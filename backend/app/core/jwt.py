"""Validation of Supabase-issued access tokens."""

from dataclasses import dataclass
from uuid import UUID

import jwt

from app.core.config import Settings, get_settings

_ALGORITHM = "HS256"
_AUDIENCE = "authenticated"


class InvalidJWTError(ValueError):
    """An access token is absent, invalid, or cannot be validated."""


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """Verified token identity; authorization roles must be loaded separately."""

    id: UUID


def validate_access_token(
    token: str | None,
    *,
    settings: Settings | None = None,
) -> AuthenticatedUser:
    """Validate a Supabase access token and return its UUID identity."""
    if not isinstance(token, str) or not token.strip():
        raise InvalidJWTError("Invalid access token")

    resolved_settings = settings if settings is not None else get_settings()
    secret = resolved_settings.supabase_jwt_secret
    if secret is None or not secret:
        raise InvalidJWTError("JWT validation is not configured")

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],
            audience=_AUDIENCE,
            options={"require": ["exp", "aud", "sub"]},
        )
    except (jwt.PyJWTError, TypeError, ValueError, OverflowError):
        raise InvalidJWTError("Invalid access token") from None

    subject = claims.get("sub")
    if not isinstance(subject, str):
        raise InvalidJWTError("Invalid access token")
    try:
        user_id = UUID(subject)
    except ValueError:
        raise InvalidJWTError("Invalid access token") from None

    return AuthenticatedUser(id=user_id)
