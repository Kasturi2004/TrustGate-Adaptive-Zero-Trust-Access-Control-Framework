"""Validation of Supabase-issued access tokens."""

from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit
from uuid import UUID

import jwt
from jwt import PyJWK, PyJWKClient

from app.core.config import Settings, get_settings

_ALGORITHM = "ES256"
_AUDIENCE = "authenticated"
_JWKS_PATH = "/auth/v1/.well-known/jwks.json"
_ISSUER_PATH = "/auth/v1"
_JWKS_CACHE_TTL_SECONDS = 300
_JWKS_FETCH_TIMEOUT_SECONDS = 5


class InvalidJWTError(ValueError):
    """An access token is absent, invalid, or cannot be validated."""


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """Verified user and authentication-session identities from the signed token."""

    id: UUID
    session_id: UUID


def _supabase_auth_urls(supabase_url: str | None) -> tuple[str, str]:
    if not isinstance(supabase_url, str) or not supabase_url.strip():
        raise InvalidJWTError("JWT validation is not configured")

    base_url = supabase_url.strip().rstrip("/")
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise InvalidJWTError("JWT validation is not configured")

    return f"{base_url}{_JWKS_PATH}", f"{base_url}{_ISSUER_PATH}"


@lru_cache(maxsize=8)
def _jwks_client(jwks_url: str) -> PyJWKClient:
    """Return a bounded-lifetime client keyed only by trusted Supabase config."""
    return PyJWKClient(
        jwks_url,
        cache_keys=False,
        cache_jwk_set=True,
        lifespan=_JWKS_CACHE_TTL_SECONDS,
        timeout=_JWKS_FETCH_TIMEOUT_SECONDS,
        cooldown_duration=0,
    )


def _verification_key(token: str, settings: Settings) -> tuple[PyJWK, str]:
    jwks_url, issuer = _supabase_auth_urls(settings.supabase_url)
    try:
        header = jwt.get_unverified_header(token)
    except (jwt.PyJWTError, TypeError, ValueError):
        raise InvalidJWTError("Invalid access token") from None

    kid = header.get("kid")
    if header.get("alg") != _ALGORITHM or not isinstance(kid, str) or not kid:
        raise InvalidJWTError("Invalid access token")

    try:
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token)
    except (jwt.PyJWTError, TypeError, ValueError, OSError):
        raise InvalidJWTError("Invalid access token") from None

    if signing_key.key_id != kid or signing_key.algorithm_name != _ALGORITHM:
        raise InvalidJWTError("Invalid access token")
    return signing_key, issuer


def validate_access_token(
    token: str | None,
    *,
    settings: Settings | None = None,
) -> AuthenticatedUser:
    """Validate a Supabase ES256 token and return its user and session UUIDs."""
    if not isinstance(token, str) or not token.strip():
        raise InvalidJWTError("Invalid access token")

    resolved_settings = settings if settings is not None else get_settings()
    signing_key, issuer = _verification_key(token, resolved_settings)
    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=[_ALGORITHM],
            audience=_AUDIENCE,
            issuer=issuer,
            options={"require": ["exp", "aud", "sub", "iss", "session_id"]},
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

    session_subject = claims.get("session_id")
    if not isinstance(session_subject, str):
        raise InvalidJWTError("Invalid access token")
    try:
        session_id = UUID(session_subject)
    except ValueError:
        raise InvalidJWTError("Invalid access token") from None

    return AuthenticatedUser(id=user_id, session_id=session_id)
