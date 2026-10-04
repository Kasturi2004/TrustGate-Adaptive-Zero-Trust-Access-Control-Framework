"""TOTP secret, provisioning, and verification helpers."""

import re
from datetime import datetime

import pyotp

_ISSUER_NAME = "TrustGate"
_DIGITS = 6
_INTERVAL_SECONDS = 30
_CODE_PATTERN = re.compile(r"[0-9]{6}\Z", re.ASCII)


def generate_totp_secret() -> str:
    """Generate a new secret using PyOTP's secure random generator."""
    return pyotp.random_base32()


def generate_totp_provisioning_uri(secret: str, account_label: str) -> str:
    """Build the standard authenticator-app URI for one TOTP account."""
    totp = pyotp.TOTP(secret, digits=_DIGITS, interval=_INTERVAL_SECONDS)
    return totp.provisioning_uri(name=account_label, issuer_name=_ISSUER_NAME)


def verify_totp_code(
    secret: str,
    code: str,
    *,
    for_time: datetime | None = None,
) -> bool:
    """Verify one six-digit code, returning false for malformed input or secrets."""
    if not isinstance(code, str) or _CODE_PATTERN.fullmatch(code) is None:
        return False
    try:
        totp = pyotp.TOTP(secret, digits=_DIGITS, interval=_INTERVAL_SECONDS)
        return totp.verify(code, for_time=for_time)
    except (TypeError, ValueError):
        return False
