"""Unit tests for Supabase ES256 access-token validation."""

from collections.abc import Callable
from typing import Any
from uuid import UUID

import jwt
import pytest
from app.core import jwt as jwt_module
from app.core.config import Settings
from app.core.jwt import AuthenticatedUser, InvalidJWTError, validate_access_token
from cryptography.hazmat.primitives.asymmetric import ec
from jwt import PyJWKClient
from jwt.algorithms import ECAlgorithm

_USER_ID = UUID("2b0cb051-348f-41f5-8bac-bec1636f3ed2")
_OTHER_USER_ID = UUID("ecec9bc6-913a-4c9f-9bd3-a4b2a7756061")
_SUPABASE_URL = "https://test-project.supabase.co"
_ISSUER = f"{_SUPABASE_URL}/auth/v1"
_FUTURE_EXPIRY = 2_000_000_000
_KID = "unit-test-es256-key"


def _settings(supabase_url: str | None = _SUPABASE_URL) -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url=supabase_url,
    )


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _jwk(private_key: ec.EllipticCurvePrivateKey, kid: str = _KID) -> dict[str, Any]:
    jwk = ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    return jwk


def _token(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    sub: str | None = str(_USER_ID),
    audience: str = "authenticated",
    expiry: int | None = _FUTURE_EXPIRY,
    issuer: str = _ISSUER,
    kid: str | None = _KID,
    algorithm: str = "ES256",
) -> str:
    claims: dict[str, object] = {"aud": audience, "iss": issuer}
    if sub is not None:
        claims["sub"] = sub
    if expiry is not None:
        claims["exp"] = expiry
    headers: dict[str, str] = {}
    if kid is not None:
        headers["kid"] = kid
    return jwt.encode(claims, private_key, algorithm=algorithm, headers=headers)


def _install_jwks(
    monkeypatch: pytest.MonkeyPatch,
    initial_jwks: dict[str, Any],
) -> tuple[list[int], Callable[[dict[str, Any]], None]]:
    current_jwks = [initial_jwks]
    fetch_count = [0]

    def fetch_data(_client: PyJWKClient) -> dict[str, Any]:
        fetch_count[0] += 1
        return current_jwks[0]

    monkeypatch.setattr(PyJWKClient, "fetch_data", fetch_data)
    jwt_module._jwks_client.cache_clear()

    def replace_jwks(value: dict[str, Any]) -> None:
        current_jwks[0] = value

    return fetch_count, replace_jwks


@pytest.fixture(autouse=True)
def clear_jwks_clients() -> Any:
    jwt_module._jwks_client.cache_clear()
    yield
    jwt_module._jwks_client.cache_clear()


def test_valid_es256_token_returns_uuid_identity_and_ignores_role_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = _new_key()
    claims = {
        "sub": str(_USER_ID),
        "aud": "authenticated",
        "iss": _ISSUER,
        "exp": _FUTURE_EXPIRY,
        "role": "ADMIN",
        "user_metadata": {"role": "ADMIN"},
    }
    token = jwt.encode(claims, private_key, algorithm="ES256", headers={"kid": _KID})
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})

    identity = validate_access_token(token, settings=_settings())

    assert identity == AuthenticatedUser(id=_USER_ID)
    assert identity.id == _USER_ID
    assert not hasattr(identity, "role")


@pytest.mark.parametrize("token", [None, ""])
def test_missing_token_is_rejected(token: str | None) -> None:
    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_malformed_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_jwks(monkeypatch, {"keys": []})
    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token("not-a-jwt", settings=_settings())


def test_invalid_signature_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    trusted_key = _new_key()
    attacker_key = _new_key()
    token = _token(attacker_key)
    _install_jwks(monkeypatch, {"keys": [_jwk(trusted_key)]})

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_expired_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, expiry=1)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_wrong_audience_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, audience="other-service")

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_wrong_issuer_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, issuer="https://another-project.supabase.co/auth/v1")

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_missing_expiration_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, expiry=None)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_missing_subject_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, sub=None)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_non_uuid_subject_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, sub="not-a-uuid")

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_missing_kid_is_rejected_before_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    calls, _ = _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, kid=None)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())
    assert calls == [0]


def test_unknown_kid_is_rejected_after_single_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    calls, _ = _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key, kid="unknown-key")

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())
    assert calls == [2]


@pytest.mark.parametrize("jwks", [{"invalid": []}, {"keys": []}])
def test_malformed_or_empty_jwks_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    jwks: dict[str, Any],
) -> None:
    private_key = _new_key()
    _install_jwks(monkeypatch, jwks)
    token = _token(private_key)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_invalid_jwks_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    _install_jwks(
        monkeypatch,
        {"keys": [{"kty": "EC", "crv": "P-256", "kid": _KID, "alg": "ES256"}]},
    )
    token = _token(private_key)

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())


def test_jwks_fetch_failure_without_cache_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_fetch(_client: PyJWKClient) -> dict[str, Any]:
        raise OSError("private network detail")

    monkeypatch.setattr(PyJWKClient, "fetch_data", fail_fetch)
    jwt_module._jwks_client.cache_clear()
    private_key = _new_key()
    token = _token(private_key)

    with pytest.raises(InvalidJWTError, match="Invalid access token") as error:
        validate_access_token(token, settings=_settings())
    assert "private network detail" not in str(error.value)


def test_alg_none_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    calls, _ = _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = jwt.encode(
        {"sub": str(_USER_ID), "aud": "authenticated", "iss": _ISSUER, "exp": _FUTURE_EXPIRY},
        key="",
        algorithm="none",
        headers={"kid": _KID},
    )

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())
    assert calls == [0]


def test_unsupported_algorithm_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    calls, _ = _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = jwt.encode(
        {"sub": str(_USER_ID), "aud": "authenticated", "iss": _ISSUER, "exp": _FUTURE_EXPIRY},
        "unit-test-hs256-secret-that-is-not-used-for-validation",
        algorithm="HS256",
        headers={"kid": _KID},
    )

    with pytest.raises(InvalidJWTError, match="Invalid access token"):
        validate_access_token(token, settings=_settings())
    assert calls == [0]


def test_unknown_kid_refresh_accepts_a_rotated_key_once(monkeypatch: pytest.MonkeyPatch) -> None:
    current_key = _new_key()
    rotated_key = _new_key()
    calls, replace_jwks = _install_jwks(monkeypatch, {"keys": [_jwk(current_key, "old-key")]})

    first_token = _token(current_key, kid="old-key")
    assert validate_access_token(first_token, settings=_settings()) == AuthenticatedUser(
        id=_USER_ID
    )
    replace_jwks({"keys": [_jwk(rotated_key, "new-key")]})

    rotated_token = _token(rotated_key, kid="new-key")
    assert validate_access_token(rotated_token, settings=_settings()) == AuthenticatedUser(
        id=_USER_ID
    )
    assert calls == [2]


def test_cached_jwks_avoids_fetching_on_every_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = _new_key()
    calls, _ = _install_jwks(monkeypatch, {"keys": [_jwk(private_key)]})
    token = _token(private_key)

    assert validate_access_token(token, settings=_settings()) == AuthenticatedUser(id=_USER_ID)
    assert validate_access_token(token, settings=_settings()) == AuthenticatedUser(id=_USER_ID)
    assert calls == [1]


def test_missing_supabase_url_fails_without_exposing_configuration() -> None:
    with pytest.raises(InvalidJWTError, match="JWT validation is not configured"):
        validate_access_token("not-a-jwt", settings=_settings(supabase_url=None))
