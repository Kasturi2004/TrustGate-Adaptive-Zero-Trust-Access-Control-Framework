"""Unit tests for Supabase access-token validation."""

from uuid import UUID

import jwt
import pytest
from app.core.config import Settings
from app.core.jwt import AuthenticatedUser, InvalidJWTError, validate_access_token

_TEST_SECRET = "unit-test-only-jwt-secret-" + ("x" * 48)
_USER_ID = UUID("2b0cb051-348f-41f5-8bac-bec1636f3ed2")
_FUTURE_EXPIRY = 2_000_000_000


def _settings(secret: str | None = _TEST_SECRET) -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_jwt_secret=secret,
    )


def _token(
    *,
    sub: str | None = str(_USER_ID),
    audience: str = "authenticated",
    expiry: int | None = _FUTURE_EXPIRY,
    algorithm: str = "HS256",
    secret: str = _TEST_SECRET,
) -> str:
    claims: dict[str, object] = {"aud": audience}
    if sub is not None:
        claims["sub"] = sub
    if expiry is not None:
        claims["exp"] = expiry
    return jwt.encode(claims, secret, algorithm=algorithm)


def test_valid_token_returns_uuid_identity_and_ignores_role_claims() -> None:
    claims = {
        "sub": str(_USER_ID),
        "aud": "authenticated",
        "exp": _FUTURE_EXPIRY,
        "role": "ADMIN",
        "user_metadata": {"role": "ADMIN"},
    }
    token = jwt.encode(claims, _TEST_SECRET, algorithm="HS256")

    identity = validate_access_token(token, settings=_settings())

    assert identity == AuthenticatedUser(id=_USER_ID)
    assert identity.id == _USER_ID
    assert not hasattr(identity, "role")


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token_is_rejected(token: str | None) -> None:
    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_malformed_token_is_rejected() -> None:
    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token("not-a-jwt", settings=_settings())


def test_invalid_signature_is_rejected() -> None:
    token = _token(secret="different-unit-test-secret-" + ("y" * 48))

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_expired_token_is_rejected() -> None:
    token = _token(expiry=1)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_wrong_audience_is_rejected() -> None:
    token = _token(audience="other-service")

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_missing_expiration_is_rejected() -> None:
    token = _token(expiry=None)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


@pytest.mark.parametrize("algorithm", ["HS384", "HS512"])
def test_attacker_selected_algorithm_is_rejected(algorithm: str) -> None:
    token = _token(algorithm=algorithm)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_alg_none_is_rejected() -> None:
    token = jwt.encode(
        {"sub": str(_USER_ID), "aud": "authenticated", "exp": _FUTURE_EXPIRY},
        key="",
        algorithm="none",
    )

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_missing_subject_is_rejected() -> None:
    token = _token(sub=None)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_non_uuid_subject_is_rejected() -> None:
    token = _token(sub="not-a-uuid")

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_missing_jwt_secret_fails_without_leaking_configuration() -> None:
    token = _token()

    with pytest.raises(InvalidJWTError, match="JWT validation is not configured"):
        validate_access_token(token, settings=_settings(secret=None))
