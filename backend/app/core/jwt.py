"""Validation of Supabase-issued access tokens."""

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from urllib.parse import urlsplit
from uuid import UUID

import jwt
from jwt import PyJWK, PyJWKClient

from app.core.config import Settings, get_settings

_ASYMMETRIC_ALGORITHM = "ES256"
_LEGACY_ALGORITHM = "HS256"
_AUDIENCE = "authenticated"
_JWKS_PATH = "/auth/v1/.well-known/jwks.json"
_ISSUER_PATH = "/auth/v1"
_JWKS_CACHE_TTL_SECONDS = 300
_JWKS_FETCH_TIMEOUT_SECONDS = 5
# Keep the existing small issuance-skew allowance scoped to iat only.
_IAT_LEEWAY_SECONDS = 10


class InvalidJWTError(ValueError):
    """An access token is absent, invalid, or cannot be validated."""

    def __init__(self, message: str, *, category: str = "jwt_invalid") -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """Verified user and authentication-session identities from the signed token."""

    id: UUID
    session_id: UUID


def _supabase_auth_urls(supabase_url: str | None) -> tuple[str, str]:
    if not isinstance(supabase_url, str) or not supabase_url.strip():
        raise InvalidJWTError("JWT validation is not configured", category="jwt_config")

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
        raise InvalidJWTError("JWT validation is not configured", category="jwt_config")

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


def _verification_key(token: str, settings: Settings) -> tuple[PyJWK | str, str, str]:
    jwks_url, issuer = _supabase_auth_urls(settings.supabase_url)
    try:
        header = jwt.get_unverified_header(token)
    except (jwt.PyJWTError, TypeError, ValueError):
        raise InvalidJWTError("Invalid access token", category="jwt_header_invalid") from None

    algorithm = header.get("alg")
    if algorithm == _LEGACY_ALGORITHM:
        secret = settings.supabase_jwt_secret
        if not isinstance(secret, str) or not secret:
            raise InvalidJWTError("Invalid access token", category="jwt_hs256_secret_unconfigured")
        return secret, issuer, _LEGACY_ALGORITHM

    if algorithm != _ASYMMETRIC_ALGORITHM:
        raise InvalidJWTError("Invalid access token", category="jwt_algorithm_unsupported")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise InvalidJWTError("Invalid access token", category="jwt_key_id_missing")

    try:
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token)
    except (jwt.PyJWTError, TypeError, ValueError, OSError):
        raise InvalidJWTError("Invalid access token", category="jwt_key_lookup_failed") from None

    if signing_key.key_id != kid or signing_key.algorithm_name != _ASYMMETRIC_ALGORITHM:
        raise InvalidJWTError("Invalid access token", category="jwt_key_mismatch")
    return signing_key, issuer, _ASYMMETRIC_ALGORITHM


def _claim_failure_category(error: Exception) -> str:
    """Map PyJWT's validation errors to fixed, non-sensitive diagnostic categories."""
    if isinstance(error, jwt.MissingRequiredClaimError):
        claim_categories = {
            "exp": "jwt_exp_missing",
            "aud": "jwt_audience_missing",
            "sub": "jwt_subject_missing",
            "iss": "jwt_issuer_missing",
            "session_id": "jwt_session_claim_missing",
        }
        return claim_categories.get(error.claim, "jwt_required_claim_missing")
    if isinstance(error, jwt.InvalidIssuedAtError):
        return "jwt_iat_invalid"
    if isinstance(error, jwt.ImmatureSignatureError):
        message = str(error)
        if message == "The token is not yet valid (iat)":
            return "jwt_iat_in_future"
        if message == "The token is not yet valid (nbf)":
            return "jwt_nbf_in_future"
        return "jwt_temporal_claim_invalid"
    if isinstance(error, jwt.DecodeError):
        message_categories = {
            "Expiration Time claim (exp) must be an integer.": "jwt_exp_type_invalid",
            "Not Before claim (nbf) must be an integer.": "jwt_nbf_type_invalid",
        }
        return message_categories.get(str(error), "jwt_claim_encoding_invalid")
    if isinstance(error, jwt.InvalidTokenError):
        message_categories = {
            "Subject must be a string": "jwt_subject_type_invalid",
            "Invalid subject": "jwt_subject_invalid",
            "JWT ID must be a string": "jwt_jti_type_invalid",
        }
        return message_categories.get(str(error), "jwt_claims_invalid")
    if isinstance(error, (TypeError, ValueError, OverflowError)):
        return "jwt_claim_value_invalid"
    return "jwt_claims_invalid"


def validate_access_token(
    token: str | None,
    *,
    settings: Settings | None = None,
) -> AuthenticatedUser:
    """Validate a supported Supabase token and return its user and session UUIDs."""
    if not isinstance(token, str) or not token.strip():
        raise InvalidJWTError("Invalid access token", category="jwt_token_missing")

    resolved_settings = settings if settings is not None else get_settings()
    signing_key, issuer, algorithm = _verification_key(token, resolved_settings)
    verification_key = signing_key.key if isinstance(signing_key, PyJWK) else signing_key
    try:
        claims = jwt.decode(
            token,
            verification_key,
            algorithms=[algorithm],
            audience=_AUDIENCE,
            issuer=issuer,
            leeway=0,
            options={
                "require": ["exp", "aud", "sub", "iss", "session_id"],
                "verify_iat": False,
            },
        )
        if "iat" in claims:
            try:
                issued_at = int(claims["iat"])
            except (TypeError, ValueError, OverflowError):
                raise jwt.InvalidIssuedAtError(
                    "Issued At claim (iat) must be an integer."
                ) from None
            now = datetime.now(UTC).timestamp()
            if issued_at > now + _IAT_LEEWAY_SECONDS:
                raise jwt.ImmatureSignatureError("The token is not yet valid (iat)")
    except jwt.ExpiredSignatureError:
        raise InvalidJWTError("Invalid access token", category="jwt_expired") from None
    except jwt.InvalidIssuerError:
        raise InvalidJWTError("Invalid access token", category="jwt_issuer_invalid") from None
    except jwt.InvalidAudienceError:
        raise InvalidJWTError("Invalid access token", category="jwt_audience_invalid") from None
    except jwt.InvalidSignatureError:
        raise InvalidJWTError("Invalid access token", category="jwt_signature_invalid") from None
    except jwt.MissingRequiredClaimError as exc:
        raise InvalidJWTError(
            "Invalid access token", category=_claim_failure_category(exc)
        ) from None
    except (jwt.PyJWTError, TypeError, ValueError, OverflowError) as exc:
        raise InvalidJWTError(
            "Invalid access token", category=_claim_failure_category(exc)
        ) from None

    subject = claims.get("sub")
    if not isinstance(subject, str):
        raise InvalidJWTError("Invalid access token", category="jwt_subject_invalid")
    try:
        user_id = UUID(subject)
    except ValueError:
        raise InvalidJWTError("Invalid access token", category="jwt_subject_invalid") from None

    session_subject = claims.get("session_id")
    if not isinstance(session_subject, str):
        raise InvalidJWTError("Invalid access token", category="jwt_session_claim_type_invalid")
    try:
        session_id = UUID(session_subject)
    except ValueError:
        raise InvalidJWTError(
            "Invalid access token", category="jwt_session_claim_value_invalid"
        ) from None

    return AuthenticatedUser(id=user_id, session_id=session_id)
