"""Tests for the out-of-band admin promotion CLI."""

from __future__ import annotations

import asyncio
import importlib.util
from collections.abc import Callable, Coroutine, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol, cast
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "promote_admin.py"
_SPEC = importlib.util.spec_from_file_location("trustgate_promote_admin", _SCRIPT_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
_SCRIPT_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SCRIPT_MODULE)


class _PromotionScript(Protocol):
    normalize_email: Callable[[str], str]
    promote_profile: Callable[[AsyncSession, str], Coroutine[Any, Any, bool]]
    main: Callable[[Sequence[str] | None], int]
    ProfileNotFoundError: type[Exception]
    _promote_with_database: Callable[[str], Coroutine[Any, Any, bool]]


_script = cast(_PromotionScript, _SCRIPT_MODULE)
_normalize_email = _script.normalize_email
_promote_profile = _script.promote_profile
_main = _script.main


def test_existing_user_is_promoted_and_only_role_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = SimpleNamespace(
        id="user-id",
        email="User@Example.test",
        role="USER",
        is_deleted=False,
        timezone="Asia/Kolkata",
    )
    get_by_email = AsyncMock(return_value=profile)
    monkeypatch.setattr(
        _SCRIPT_MODULE,
        "ProfileRepository",
        lambda _session: SimpleNamespace(get_by_email=get_by_email),
    )
    session = AsyncMock(spec=AsyncSession)

    changed = asyncio.run(_promote_profile(session, "user@example.test"))

    assert changed is True
    assert profile.role == "ADMIN"
    assert profile.id == "user-id"
    assert profile.email == "User@Example.test"
    assert profile.is_deleted is False
    assert profile.timezone == "Asia/Kolkata"
    get_by_email.assert_awaited_once_with("user@example.test")
    session.commit.assert_awaited_once()


def test_existing_admin_is_unchanged_without_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = SimpleNamespace(role="ADMIN")
    get_by_email = AsyncMock(return_value=profile)
    monkeypatch.setattr(
        _SCRIPT_MODULE,
        "ProfileRepository",
        lambda _session: SimpleNamespace(get_by_email=get_by_email),
    )
    session = AsyncMock(spec=AsyncSession)

    changed = asyncio.run(_promote_profile(session, "admin@example.test"))

    assert changed is False
    assert profile.role == "ADMIN"
    session.commit.assert_not_awaited()


def test_unknown_email_does_not_create_a_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    get_by_email = AsyncMock(return_value=None)
    monkeypatch.setattr(
        _SCRIPT_MODULE,
        "ProfileRepository",
        lambda _session: SimpleNamespace(get_by_email=get_by_email),
    )
    session = AsyncMock(spec=AsyncSession)

    with pytest.raises(_script.ProfileNotFoundError):
        asyncio.run(_promote_profile(session, "missing@example.test"))

    session.add.assert_not_called()
    session.commit.assert_not_awaited()


def test_email_normalization_matches_application_convention() -> None:
    assert _normalize_email("  User@Example.test  ") == "user@example.test"


@pytest.mark.parametrize("arguments", [[], ["bad-email"], ["a@example.test", "extra"]])
def test_missing_invalid_or_extra_arguments_fail_with_usage(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _main(arguments)

    assert exit_info.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_database_error_output_does_not_expose_connection_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_connection = "postgresql://operator:private-password@db.example.test"

    async def fail_safely(_: str) -> bool:
        raise RuntimeError(secret_connection)

    monkeypatch.setattr(_SCRIPT_MODULE, "_promote_with_database", fail_safely)

    exit_code = _main(["operator@example.test"])
    output = capsys.readouterr()

    assert exit_code == 1
    assert "database or configuration error" in output.err
    assert secret_connection not in output.out + output.err
