"""Unit tests for Phase 6B device hashing and familiarity lookup."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from app.core.config import Settings
from app.db.models.device import Device
from app.db.repositories.device import DeviceRepository
from app.services.context.device_familiarity import (
    KNOWN_DEVICE,
    UNKNOWN_DEVICE,
    DeviceHashConfigurationError,
    collect_device_familiarity,
    device_token_hash,
)

_DEVICE_HASH_SECRET = "test-device-hash-secret-for-unit-tests"


def _settings(secret: str | None = _DEVICE_HASH_SECRET) -> Settings:
    return Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        device_hash_secret=secret,
    )


def _device(*, recognized_at: datetime | None) -> Device:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return Device(
        id=uuid4(),
        user_id=uuid4(),
        device_hash="opaque-device-fingerprint",
        recognized_at=recognized_at,
        first_seen_at=now,
        last_seen_at=now,
    )


def test_valid_device_token_hash_is_deterministic() -> None:
    settings = _settings()

    first = device_token_hash("device-token-one", settings=settings)

    assert first is not None
    assert first == device_token_hash("device-token-one", settings=settings)
    assert "device-token-one" not in first


def test_different_valid_device_tokens_have_different_hashes() -> None:
    settings = _settings()

    assert device_token_hash("device-token-one", settings=settings) != device_token_hash(
        "device-token-two", settings=settings
    )


@pytest.mark.parametrize("token", [None, "", "   ", " token", "token ", "bad\ntoken"])
def test_missing_or_malformed_token_is_not_hashed(token: str | None) -> None:
    assert device_token_hash(token, settings=_settings()) is None


def test_valid_recognized_device_returns_known_familiarity_without_mutation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    user_id = uuid4()
    recognized_at = datetime(2025, 5, 1, tzinfo=UTC)
    device = _device(recognized_at=recognized_at)
    device.user_id = user_id
    repository = AsyncMock(spec=DeviceRepository)
    repository.get_by_user_and_hash.return_value = device
    token = "private-device-token"

    result = asyncio.run(
        collect_device_familiarity(
            user_id=user_id,
            device_token=token,
            repository=repository,
            settings=_settings(),
        )
    )

    assert result == KNOWN_DEVICE
    assert result.category == "KNOWN"
    assert result.normalized_value == 100
    repository.get_by_user_and_hash.assert_awaited_once_with(
        user_id, device_token_hash(token, settings=_settings())
    )
    repository.add.assert_not_called()
    repository.upsert_for_access.assert_not_awaited()
    assert device.recognized_at == recognized_at
    assert token not in repr(result)
    assert token not in caplog.text


def test_unknown_device_hash_returns_unknown_and_does_not_register() -> None:
    user_id = uuid4()
    repository = AsyncMock(spec=DeviceRepository)
    repository.get_by_user_and_hash.return_value = None

    result = asyncio.run(
        collect_device_familiarity(
            user_id=user_id,
            device_token="unrecognized-device-token",
            repository=repository,
            settings=_settings(),
        )
    )

    assert result == UNKNOWN_DEVICE
    assert result.category == "UNKNOWN"
    assert result.normalized_value == 20
    repository.add.assert_not_called()
    repository.upsert_for_access.assert_not_awaited()


def test_existing_but_unrecognized_device_returns_unknown_without_update() -> None:
    repository = AsyncMock(spec=DeviceRepository)
    device = _device(recognized_at=None)
    repository.get_by_user_and_hash.return_value = device

    result = asyncio.run(
        collect_device_familiarity(
            user_id=device.user_id,
            device_token="unrecognized-device-token",
            repository=repository,
            settings=_settings(),
        )
    )

    assert result == UNKNOWN_DEVICE
    repository.add.assert_not_called()
    repository.upsert_for_access.assert_not_awaited()
    repository.update_last_seen.assert_not_awaited()
    assert device.recognized_at is None


@pytest.mark.parametrize("token", [None, "", "   ", "bad\ntoken"])
def test_missing_or_malformed_token_returns_unknown_without_database_lookup(
    token: str | None,
) -> None:
    repository = AsyncMock(spec=DeviceRepository)

    result = asyncio.run(
        collect_device_familiarity(
            user_id=uuid4(),
            device_token=token,
            repository=repository,
            settings=_settings(),
        )
    )

    assert result == UNKNOWN_DEVICE
    repository.get_by_user_and_hash.assert_not_awaited()
    repository.add.assert_not_called()


def test_device_hash_requires_dedicated_secret_for_valid_token() -> None:
    with pytest.raises(DeviceHashConfigurationError, match="DEVICE_HASH_SECRET"):
        device_token_hash("valid-device-token", settings=_settings(secret=None))


def test_familiarity_uses_existing_repository_lookup_only() -> None:
    repository = AsyncMock(spec=DeviceRepository)
    repository.get_by_user_and_hash.return_value = None
    token = "raw-token-never-used-as-database-key"

    asyncio.run(
        collect_device_familiarity(
            user_id=uuid4(),
            device_token=token,
            repository=repository,
            settings=_settings(),
        )
    )

    lookup_key = repository.get_by_user_and_hash.await_args.args[1]
    assert lookup_key == device_token_hash(token, settings=_settings())
    assert lookup_key != token
    repository.add.assert_not_called()
