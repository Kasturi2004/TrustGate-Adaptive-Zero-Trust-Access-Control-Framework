"""Tests for opaque login rate-limit key construction."""

import inspect
from uuid import UUID

import pytest
from app.core.config import Settings
from app.core.rate_limit import (
    RateLimitKeyConfigurationError,
    account_rate_limit_key,
    ip_rate_limit_key,
    mfa_ip_rate_limit_key,
    mfa_user_rate_limit_key,
)


def _settings(secret: str = "unit-test-rate-limit-secret-" + ("x" * 40)) -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        rate_limit_key_secret=secret,
    )


def test_account_key_is_deterministic_for_the_same_email() -> None:
    settings = _settings()

    assert account_rate_limit_key("user@example.test", settings=settings) == account_rate_limit_key(
        "user@example.test", settings=settings
    )


def test_account_key_normalizes_whitespace_and_case() -> None:
    settings = _settings()

    assert account_rate_limit_key(
        "  User@Example.Test  ", settings=settings
    ) == account_rate_limit_key("user@example.test", settings=settings)


def test_account_key_does_not_contain_raw_email() -> None:
    email = "private-address@example.test"

    key = account_rate_limit_key(email, settings=_settings())

    assert key.startswith("login:account:v1:")
    assert email not in key
    assert "private-address" not in key


def test_different_emails_produce_different_keys() -> None:
    settings = _settings()

    assert account_rate_limit_key("one@example.test", settings=settings) != account_rate_limit_key(
        "two@example.test", settings=settings
    )


def test_changing_rate_limit_secret_changes_account_digest() -> None:
    assert account_rate_limit_key("user@example.test", settings=_settings("first-secret")) != (
        account_rate_limit_key("user@example.test", settings=_settings("second-secret"))
    )


def test_account_key_function_accepts_no_password_token_or_otp_parameters() -> None:
    assert tuple(inspect.signature(account_rate_limit_key).parameters) == ("email", "settings")


def test_account_key_requires_its_dedicated_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RATE_LIMIT_KEY_SECRET", raising=False)
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        rate_limit_key_secret=None,
    )

    with pytest.raises(RateLimitKeyConfigurationError):
        account_rate_limit_key("user@example.test", settings=settings)


def test_ip_rate_limit_key_is_deterministic_for_ipv4() -> None:
    assert ip_rate_limit_key("192.0.2.1") == "login:ip:v1:192.0.2.1"
    assert ip_rate_limit_key("192.0.2.1") == ip_rate_limit_key("192.0.2.1")


def test_ip_rate_limit_key_supports_ipv6_and_canonicalizes_it() -> None:
    assert ip_rate_limit_key("2001:0DB8:0000:0000:0000:0000:0000:0001") == (
        "login:ip:v1:2001:db8::1"
    )
    assert ip_rate_limit_key("2001:db8::1") == "login:ip:v1:2001:db8::1"


def test_mfa_user_keys_are_opaque_versioned_and_window_scoped() -> None:
    settings = _settings()
    user_id = UUID("4d9603c7-2077-4aa1-8afd-530c5207507f")
    short_window = mfa_user_rate_limit_key(user_id, window="15m", settings=settings)
    daily_window = mfa_user_rate_limit_key(user_id, window="24h", settings=settings)

    assert short_window.startswith("mfa:totp:verify:user:15m:v1:")
    assert daily_window.startswith("mfa:totp:verify:user:24h:v1:")
    assert short_window != daily_window
    assert str(user_id) not in short_window
    assert short_window == mfa_user_rate_limit_key(user_id, window="15m", settings=settings)
    assert short_window != mfa_user_rate_limit_key(UUID(int=1), window="15m", settings=settings)


def test_mfa_ip_key_is_opaque_canonical_and_separate_from_login_ip_key() -> None:
    settings = _settings()
    first = mfa_ip_rate_limit_key("2001:0DB8:0000:0000:0000:0000:0000:0001", settings=settings)
    second = mfa_ip_rate_limit_key("2001:db8::1", settings=settings)

    assert first.startswith("mfa:totp:verify:ip:15m:v1:")
    assert first == second
    assert "2001:db8::1" not in first
    assert first != ip_rate_limit_key("2001:db8::1")


def test_mfa_keys_require_the_existing_rate_limit_secret() -> None:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        rate_limit_key_secret=None,
    )

    with pytest.raises(RateLimitKeyConfigurationError):
        mfa_user_rate_limit_key(UUID(int=1), window="15m", settings=settings)

    with pytest.raises(RateLimitKeyConfigurationError):
        mfa_ip_rate_limit_key("192.0.2.1", settings=settings)
