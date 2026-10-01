"""Derive device familiarity from an existing user's recognized device."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from app.core.config import Settings, get_settings
from app.db.repositories.device import DeviceRepository

FamiliarityCategory = Literal["KNOWN", "UNKNOWN"]
NormalizedFamiliarity = Literal[20, 100]


class DeviceHashConfigurationError(RuntimeError):
    """Raised when device hashing is requested without its dedicated secret."""


@dataclass(frozen=True, slots=True)
class DeviceFamiliarityResult:
    """Safe device familiarity signal; it never contains the submitted token."""

    category: FamiliarityCategory
    normalized_value: NormalizedFamiliarity


UNKNOWN_DEVICE = DeviceFamiliarityResult(category="UNKNOWN", normalized_value=20)
KNOWN_DEVICE = DeviceFamiliarityResult(category="KNOWN", normalized_value=100)


def device_token_hash(
    device_token: str | None,
    *,
    settings: Settings | None = None,
) -> str | None:
    """Return a keyed opaque device hash, or None for a missing/malformed token."""
    if (
        not isinstance(device_token, str)
        or not device_token
        or device_token != device_token.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in device_token)
    ):
        return None

    configuration = settings if settings is not None else get_settings()
    secret = configuration.device_hash_secret
    if not secret:
        raise DeviceHashConfigurationError("DEVICE_HASH_SECRET is not configured")

    return hmac.new(
        secret.encode("utf-8"),
        device_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def collect_device_familiarity(
    *,
    user_id: UUID,
    device_token: str | None,
    repository: DeviceRepository,
    settings: Settings | None = None,
) -> DeviceFamiliarityResult:
    """Look up a recognized device without inserting or changing device state."""
    fingerprint = device_token_hash(device_token, settings=settings)
    if fingerprint is None:
        return UNKNOWN_DEVICE

    device = await repository.get_by_user_and_hash(user_id, fingerprint)
    if device is None or device.recognized_at is None:
        return UNKNOWN_DEVICE

    return KNOWN_DEVICE
