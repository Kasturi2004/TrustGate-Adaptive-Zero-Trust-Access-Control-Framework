"""Deterministic, opaque rate-limit keys."""

import hashlib
import hmac
import ipaddress
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
from uuid import UUID

from app.core.config import Settings, get_settings


class RateLimitKeyConfigurationError(RuntimeError):
    """Raised when the dedicated rate-limit key secret is not configured."""


def _mfa_key(scope: str, value: str, *, settings: Settings | None = None) -> str:
    """Return a namespaced opaque key for MFA verification rate-limit state."""
    resolved_settings = settings if settings is not None else get_settings()
    secret = resolved_settings.rate_limit_key_secret
    if not secret:
        raise RateLimitKeyConfigurationError("RATE_LIMIT_KEY_SECRET is not configured")

    digest = hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"mfa:totp:verify:{scope}:v1:{digest}"


def mfa_user_rate_limit_key(
    user_id: UUID,
    *,
    window: Literal["15m", "24h"],
    settings: Settings | None = None,
) -> str:
    """Return an opaque user-scoped MFA verification key for one fixed window."""
    return _mfa_key(f"user:{window}", str(user_id), settings=settings)


def mfa_ip_rate_limit_key(
    ip_address: str | IPv4Address | IPv6Address,
    *,
    settings: Settings | None = None,
) -> str:
    """Return an opaque, canonical-IP-scoped MFA verification key."""
    try:
        normalized_ip = ipaddress.ip_address(ip_address).compressed
    except ValueError:
        raise ValueError("Invalid IP address") from None
    return _mfa_key("ip:15m", normalized_ip, settings=settings)


def account_rate_limit_key(
    email: str,
    *,
    settings: Settings | None = None,
) -> str:
    """Return a stable keyed digest for a normalized email address."""
    normalized_email = email.strip().casefold()
    if not normalized_email:
        raise ValueError("Email must not be empty")

    resolved_settings = settings if settings is not None else get_settings()
    secret = resolved_settings.rate_limit_key_secret
    if not secret:
        raise RateLimitKeyConfigurationError("RATE_LIMIT_KEY_SECRET is not configured")

    digest = hmac.new(
        secret.encode("utf-8"),
        normalized_email.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"login:account:v1:{digest}"


def ip_rate_limit_key(ip_address: str | IPv4Address | IPv6Address) -> str:
    """Return a key containing only the canonical IP address representation."""
    try:
        normalized_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValueError("Invalid IP address") from None
    return f"login:ip:v1:{normalized_ip.compressed}"
