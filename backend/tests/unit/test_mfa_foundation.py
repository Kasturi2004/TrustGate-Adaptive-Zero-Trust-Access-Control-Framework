"""Unit coverage for the MFA persistence and secret-protection boundary."""

import base64
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.api.routes.auth import AuthMeResponse
from app.core.config import Settings
from app.core.mfa_secrets import decrypt_totp_secret, encrypt_totp_secret
from app.db.models import MfaCredential, target_metadata
from app.schemas import access, policy, trust
from pydantic import SecretStr
from sqlalchemy import CheckConstraint, ForeignKeyConstraint


def _settings(key: bytes | str = b"\xfb\xff" * 16) -> Settings:
    encoded_key = key if isinstance(key, str) else base64.urlsafe_b64encode(key).decode("ascii")
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        totp_secret_encryption_key=SecretStr(encoded_key),
    )


def test_totp_secret_is_encrypted_and_authenticated() -> None:
    secret = "BASE32-TOTP-SEED-DO-NOT-EXPOSE"
    ciphertext = encrypt_totp_secret(secret, settings=_settings())

    assert secret.encode() not in ciphertext
    assert decrypt_totp_secret(ciphertext, settings=_settings()) == secret
    with pytest.raises(RuntimeError, match="could not be decrypted"):
        decrypt_totp_secret(ciphertext, settings=_settings(b"n" * 32))


def test_totp_ciphertext_contains_nonce_ciphertext_and_authentication_tag() -> None:
    secret = "BASE32-TOTP-SEED"
    first = encrypt_totp_secret(secret, settings=_settings())
    second = encrypt_totp_secret(secret, settings=_settings())

    assert len(first) == 12 + len(secret.encode()) + 16
    assert first[:12] != second[:12]
    assert secret.encode() not in first


def test_tampered_totp_ciphertext_or_tag_is_rejected() -> None:
    ciphertext = encrypt_totp_secret("BASE32-TOTP-SEED", settings=_settings())
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(RuntimeError, match="could not be decrypted"):
        decrypt_totp_secret(tampered, settings=_settings())


def test_encryption_errors_never_include_the_secret() -> None:
    secret = "PRIVATE-TOTP-SEED"
    bad_settings = _settings(b"short")
    with pytest.raises(RuntimeError) as error:
        encrypt_totp_secret(secret, settings=bad_settings)
    assert secret not in str(error.value)


_VALID_ENCODED_KEY = base64.urlsafe_b64encode(b"m" * 32).decode("ascii")


@pytest.mark.parametrize(
    "malformed_key",
    [
        _VALID_ENCODED_KEY[:10] + "#" + _VALID_ENCODED_KEY[11:],
        _VALID_ENCODED_KEY + "###",
        _VALID_ENCODED_KEY[:-2] + "==",
        base64.urlsafe_b64encode(b"m" * 31).decode("ascii"),
    ],
    ids=("invalid-character", "trailing-invalid-characters", "malformed-padding", "wrong-length"),
)
def test_malformed_or_wrong_length_key_is_rejected(malformed_key: str) -> None:
    with pytest.raises(RuntimeError, match="not configured correctly"):
        encrypt_totp_secret("dummy", settings=_settings(malformed_key))


def test_mfa_model_has_profile_integrity_and_safe_state_constraints() -> None:
    table = target_metadata.tables["public.mfa_credentials"]
    foreign_keys = [
        constraint
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    ]
    checks = [
        constraint for constraint in table.constraints if isinstance(constraint, CheckConstraint)
    ]

    assert table.primary_key.columns.keys() == ["user_id"]
    assert [foreign_key.target_fullname for foreign_key in foreign_keys[0].elements] == [
        "public.profiles.id"
    ]
    assert "verified_at IS NOT NULL" in str(checks[0].sqltext)
    assert {"secret_ciphertext", "enabled", "created_at", "updated_at"}.issubset(
        table.columns.keys()
    )


def test_mfa_secret_is_absent_from_public_schemas_and_model_repr() -> None:
    secret = "NEVER-RETURN-THIS-SEED"
    credential = MfaCredential(
        user_id=uuid4(),
        secret_ciphertext=secret.encode(),
        verified_at=datetime.now(UTC),
        enabled=True,
    )
    representation = repr(credential)
    public_schema_fields = {
        field
        for module in (access, policy, trust)
        for schema in vars(module).values()
        if isinstance(schema, type) and hasattr(schema, "model_fields")
        for field in schema.model_fields
    }

    assert secret not in representation
    assert "secret_ciphertext" not in public_schema_fields
    assert "totp_secret" not in public_schema_fields
    assert "secret_ciphertext" not in AuthMeResponse.model_fields
    assert "totp_secret" not in AuthMeResponse.model_fields
