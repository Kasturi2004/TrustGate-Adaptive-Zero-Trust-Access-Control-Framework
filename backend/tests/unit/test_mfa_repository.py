"""Unit tests for MFA credential locking repository queries."""

import asyncio
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from app.db.models.mfa_credential import MfaCredential
from app.db.models.profile import Profile
from app.db.repositories.mfa_credential import MfaCredentialRepository
from sqlalchemy.ext.asyncio import AsyncSession


def _mock_session() -> AsyncMock:
    return AsyncMock(spec=AsyncSession)


def test_locked_lookup_returns_existing_instance_and_locks_profile_and_credential() -> None:
    session = _mock_session()
    user_id = uuid4()
    profile_result = MagicMock()
    profile_result.first.return_value = cast(Profile, object())
    credential_result = MagicMock()
    credential = cast(MfaCredential, object())
    credential_result.first.return_value = credential
    session.scalars.side_effect = [profile_result, credential_result]

    result = asyncio.run(MfaCredentialRepository(session).get_by_user_id_for_update(user_id))

    assert result is credential
    statements = [call.args[0] for call in session.scalars.await_args_list]
    assert len(statements) == 2
    assert "FOR UPDATE" in str(statements[0])
    assert "FOR UPDATE" in str(statements[1])
    assert "public.profiles" in str(statements[0])
    assert "public.mfa_credentials" in str(statements[1])
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()


def test_locked_lookup_returns_none_when_credential_is_missing() -> None:
    session = _mock_session()
    profile_result = MagicMock()
    profile_result.first.return_value = cast(Profile, object())
    credential_result = MagicMock()
    credential_result.first.return_value = None
    session.scalars.side_effect = [profile_result, credential_result]

    result = asyncio.run(MfaCredentialRepository(session).get_by_user_id_for_update(uuid4()))

    assert result is None
    assert session.scalars.await_count == 2
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()


def test_locked_lookup_returns_none_without_a_profile() -> None:
    session = _mock_session()
    profile_result = MagicMock()
    profile_result.first.return_value = None
    session.scalars.return_value = profile_result

    result = asyncio.run(MfaCredentialRepository(session).get_by_user_id_for_update(uuid4()))

    assert result is None
    session.scalars.assert_awaited_once()
    session.commit.assert_not_awaited()
    session.rollback.assert_not_awaited()
