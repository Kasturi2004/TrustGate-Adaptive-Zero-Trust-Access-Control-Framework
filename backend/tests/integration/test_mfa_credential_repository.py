"""MFA credential database integrity and repository persistence checks."""

import base64
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from app.core.config import Settings
from app.core.mfa_secrets import decrypt_totp_secret, encrypt_totp_secret
from app.db.models.mfa_credential import MfaCredential
from app.db.repositories.mfa_credential import MfaCredentialRepository
from pydantic import SecretStr
from sqlalchemy import insert, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.database import ScratchDatabase, repository_migration_head

_TEST_TOTP_SECRET = "POSTGRES-INTEGRATION-TOTP-SECRET"
_TEST_ENCRYPTION_SETTINGS = Settings(
    app_env="test",
    cors_allowed_origin="http://localhost:5173",
    totp_secret_encryption_key=SecretStr(base64.urlsafe_b64encode(b"p" * 32).decode("ascii")),
)


async def _create_auth_user(session: AsyncSession, user_id: UUID) -> None:
    await session.execute(
        text("INSERT INTO auth.users (id, email) VALUES (:id, :email)"),
        {"id": user_id, "email": f"mfa-{user_id}@integration.test"},
    )


def test_mfa_migration_and_credential_integrity(
    migrated_test_database: ScratchDatabase,
) -> None:
    async def exercise(session: AsyncSession) -> None:
        table_exists = await session.scalar(
            text("SELECT to_regclass('public.mfa_credentials') IS NOT NULL")
        )
        revision = await session.scalar(text("SELECT version_num FROM public.alembic_version"))
        assert table_exists is True
        assert revision == repository_migration_head()

        user_id = uuid4()
        await _create_auth_user(session, user_id)

        ciphertext = encrypt_totp_secret(_TEST_TOTP_SECRET, settings=_TEST_ENCRYPTION_SETTINGS)
        assert _TEST_TOTP_SECRET.encode() not in ciphertext
        credential = MfaCredential(user_id=user_id, secret_ciphertext=ciphertext, enabled=False)
        repository = MfaCredentialRepository(session)
        repository.add(credential)
        await session.flush()
        assert credential.verified_at is None
        assert credential.enabled is False
        assert credential.last_accepted_time_step is None
        assert credential.created_at is not None
        assert credential.updated_at is not None

        verified_at = datetime(2026, 10, 4, tzinfo=UTC)
        credential.verified_at = verified_at
        credential.enabled = True
        credential.last_accepted_time_step = 5_000_000
        await session.flush()

        loaded = await repository.get_by_user_id(user_id)
        assert loaded is not None
        assert loaded is credential
        assert loaded.secret_ciphertext == ciphertext
        assert _TEST_TOTP_SECRET.encode() not in loaded.secret_ciphertext
        assert (
            decrypt_totp_secret(loaded.secret_ciphertext, settings=_TEST_ENCRYPTION_SETTINGS)
            == _TEST_TOTP_SECRET
        )
        assert loaded.verified_at == verified_at
        assert loaded.enabled is True
        assert loaded.last_accepted_time_step == 5_000_000
        assert await repository.get_by_user_id(uuid4()) is None

        active_transaction = session.get_transaction()
        assert active_transaction is not None
        locked = await repository.get_by_user_id_for_update(user_id)
        assert locked is loaded
        assert session.get_transaction() is active_transaction

        missing_user_id = uuid4()
        await _create_auth_user(session, missing_user_id)
        assert await repository.get_by_user_id_for_update(missing_user_id) is None
        assert session.get_transaction() is active_transaction

        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                await session.execute(
                    insert(MfaCredential).values(
                        user_id=user_id,
                        secret_ciphertext=b"duplicate-ciphertext",
                        enabled=False,
                    )
                )

        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                repository.add(
                    MfaCredential(
                        user_id=uuid4(),
                        secret_ciphertext=b"orphan-ciphertext",
                        enabled=False,
                    )
                )
                await session.flush()

        invalid_state_user_id = uuid4()
        await _create_auth_user(session, invalid_state_user_id)
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                repository.add(
                    MfaCredential(
                        user_id=invalid_state_user_id,
                        secret_ciphertext=b"invalid-state-ciphertext",
                        enabled=True,
                        verified_at=None,
                    )
                )
                await session.flush()

        await session.execute(
            text("DELETE FROM public.profiles WHERE id = :user_id"), {"user_id": user_id}
        )
        remaining = await session.scalar(
            text("SELECT count(*) FROM public.mfa_credentials WHERE user_id = :user_id"),
            {"user_id": user_id},
        )
        assert remaining == 0

    migrated_test_database.run_in_transaction(exercise)


def test_mfa_credential_transaction_rolls_back(
    migrated_test_database: ScratchDatabase,
) -> None:
    user_id = uuid4()

    async def insert_credential(session: AsyncSession) -> None:
        await _create_auth_user(session, user_id)
        repository = MfaCredentialRepository(session)
        repository.add(
            MfaCredential(
                user_id=user_id,
                secret_ciphertext=encrypt_totp_secret(
                    _TEST_TOTP_SECRET, settings=_TEST_ENCRYPTION_SETTINGS
                ),
                enabled=False,
            )
        )
        await session.flush()
        assert (
            await session.scalar(
                text("SELECT count(*) FROM public.mfa_credentials WHERE user_id = :user_id"),
                {"user_id": user_id},
            )
            == 1
        )
        assert await repository.get_by_user_id_for_update(user_id) is not None

    async def assert_rolled_back(session: AsyncSession) -> None:
        assert (
            await session.scalar(
                text("SELECT count(*) FROM auth.users WHERE id = :user_id"),
                {"user_id": user_id},
            )
            == 0
        )
        assert (
            await session.scalar(
                text("SELECT count(*) FROM public.mfa_credentials WHERE user_id = :user_id"),
                {"user_id": user_id},
            )
            == 0
        )

    migrated_test_database.run_in_transaction(insert_credential)
    migrated_test_database.run_in_transaction(assert_rolled_back)
