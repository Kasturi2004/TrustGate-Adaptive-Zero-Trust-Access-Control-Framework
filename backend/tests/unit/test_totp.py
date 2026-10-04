"""Focused unit tests for TrustGate's TOTP service foundation."""

import base64
from datetime import UTC, datetime
from urllib.parse import parse_qs, unquote, urlparse

import pyotp
import pytest
from app.services.totp import (
    generate_totp_provisioning_uri,
    generate_totp_secret,
    verify_totp_code,
)


def test_generated_secret_is_valid_and_not_reused() -> None:
    first = generate_totp_secret()
    second = generate_totp_secret()

    assert len(base64.b32decode(first)) >= 20
    assert first != second


def test_provisioning_uri_has_standard_totp_settings_and_account_label() -> None:
    secret = generate_totp_secret()
    account_label = "alex@example.test"
    uri = generate_totp_provisioning_uri(secret, account_label)
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    totp = pyotp.parse_uri(uri)

    assert isinstance(totp, pyotp.TOTP)
    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    assert unquote(parsed.path.removeprefix("/")) == f"TrustGate:{account_label}"
    assert query["issuer"] == ["TrustGate"]
    assert totp.digits == 6
    assert totp.interval == 30
    assert query["secret"] == [secret]


def test_current_totp_code_verifies() -> None:
    secret = generate_totp_secret()
    now = datetime.now(UTC)
    code = pyotp.TOTP(secret, digits=6, interval=30).at(now)

    assert verify_totp_code(secret, code, for_time=now)


def test_invalid_and_malformed_totp_codes_fail_safely() -> None:
    secret = generate_totp_secret()
    now = datetime.now(UTC)
    valid_code = pyotp.TOTP(secret, digits=6, interval=30).at(now)
    invalid_code = f"{(int(valid_code) + 1) % 1_000_000:06d}"

    assert not verify_totp_code(secret, invalid_code, for_time=now)
    for malformed_code in ("", "12345", "1234567", "abcdef", "１２３４５６"):
        assert not verify_totp_code(secret, malformed_code, for_time=now)


def test_malformed_secret_does_not_escape_through_verification_error() -> None:
    secret = "PRIVATE-MALFORMED-TOTP-SECRET"

    try:
        result = verify_totp_code(secret, "123456")
    except Exception as error:  # Verification errors must not disclose secret input.
        assert secret not in str(error)
        pytest.fail("Malformed TOTP secret should be rejected without raising")

    assert result is False
