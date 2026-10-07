"""Explicitly configured disposable PostgreSQL test database helpers."""

import asyncio
import os
import subprocess
import sys
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import TypeVar
from uuid import UUID

from app.db.session import create_async_engine_for_url
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession

BACKEND_ROOT = Path(__file__).resolve().parents[2]
_ALLOWED_TEST_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres"}
_REQUIRED_TEST_DATABASE = "trustgate_test"
T = TypeVar("T")
SessionOperation = Callable[[AsyncSession], Awaitable[T]]


async def ensure_auth_user_profile(
    test_database_url: str,
    *,
    user_id: UUID,
    email: str,
) -> None:
    """Provision a committed auth identity and matching profile for integration tests."""
    engine = create_async_engine_for_url(test_database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO auth.users (id, email) VALUES (:id, :email) "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {"id": user_id, "email": email},
            )
            await connection.execute(
                text(
                    "INSERT INTO public.profiles (id, email, role) "
                    "VALUES (:id, :email, 'USER') ON CONFLICT (id) DO NOTHING"
                ),
                {"id": user_id, "email": email},
            )
    finally:
        await engine.dispose()


async def remove_auth_user_profile(test_database_url: str, *, user_id: UUID) -> None:
    """Remove a test auth identity and its profile in FK-safe order."""
    engine = create_async_engine_for_url(test_database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM public.profiles WHERE id = :id"), {"id": user_id}
            )
            await connection.execute(
                text("DELETE FROM auth.users WHERE id = :id"), {"id": user_id}
            )
    finally:
        await engine.dispose()


class TestDatabaseConfigurationError(ValueError):
    """The explicit test database URL is missing or unsafe."""


def require_test_database_url(environ: Mapping[str, str] | None = None) -> str:
    """Return TEST_DATABASE_URL only; never consult application settings or DATABASE_URL."""
    values = os.environ if environ is None else environ
    raw_url = values.get("TEST_DATABASE_URL", "").strip()
    if not raw_url:
        raise TestDatabaseConfigurationError("TEST_DATABASE_URL must be set explicitly")

    try:
        parsed = make_url(raw_url)
    except Exception:
        raise TestDatabaseConfigurationError(
            "TEST_DATABASE_URL is not a valid PostgreSQL URL"
        ) from None

    host = (parsed.host or "").lower().rstrip(".")
    if host.endswith((".supabase.co", ".pooler.supabase.com")) or host not in _ALLOWED_TEST_HOSTS:
        raise TestDatabaseConfigurationError(
            "TEST_DATABASE_URL must target a local PostgreSQL test service, never Supabase"
        )
    if parsed.database != _REQUIRED_TEST_DATABASE:
        raise TestDatabaseConfigurationError(
            "TEST_DATABASE_URL must target the dedicated trustgate_test database"
        )
    if parsed.drivername not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise TestDatabaseConfigurationError("TEST_DATABASE_URL must use PostgreSQL")
    return raw_url


async def bootstrap_external_prerequisites(test_database_url: str) -> None:
    """Create only Supabase-owned prerequisites in the disposable test database."""
    engine = create_async_engine_for_url(test_database_url, null_pool=True)
    try:
        async with engine.begin() as connection:
            await connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS auth")
            await connection.exec_driver_sql(
                """
                CREATE TABLE IF NOT EXISTS auth.users (
                    id uuid PRIMARY KEY,
                    email text
                )
                """
            )
            await connection.exec_driver_sql(
                """
                CREATE OR REPLACE FUNCTION auth.uid()
                RETURNS uuid
                LANGUAGE sql
                STABLE
                AS $function$
                    SELECT NULLIF(
                        pg_catalog.current_setting('request.jwt.claim.sub', true), ''
                    )::uuid
                $function$
                """
            )
            for role in ("anon", "authenticated", "trustgate_app"):
                exists = await connection.scalar(
                    text("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :role"),
                    {"role": role},
                )
                if exists is None:
                    await connection.exec_driver_sql(f"CREATE ROLE {role} NOLOGIN")
    finally:
        await engine.dispose()


def run_alembic(test_database_url: str, *command: str) -> str:
    """Run an Alembic command with both DB URLs pinned to the scratch database."""
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "test",
            "CORS_ALLOWED_ORIGIN": "http://localhost:5173",
            "TEST_DATABASE_URL": test_database_url,
            "MIGRATION_DATABASE_URL": test_database_url,
            "DATABASE_URL": "",
        }
    )
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *command],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Alembic {command} failed against TEST_DATABASE_URL (URL redacted)")
    return result.stdout


async def verify_migration_head(test_database_url: str) -> None:
    """Assert that Alembic recorded the expected migration head in the scratch DB."""
    engine = create_async_engine_for_url(test_database_url, null_pool=True)
    try:
        async with engine.connect() as connection:
            revision = await connection.scalar(
                text("SELECT version_num FROM public.alembic_version")
            )
        if revision != "20261005_09":
            raise RuntimeError("Scratch database did not reach the expected Alembic head")
    finally:
        await engine.dispose()


class ScratchDatabase:
    """Migrated disposable database with rollback-isolated session operations."""

    def __init__(self, url: str) -> None:
        self.url = url

    def run_in_transaction(self, operation: SessionOperation[T]) -> T:
        """Run one async test operation, then roll back its outer transaction."""
        return asyncio.run(self._run_in_transaction(operation))

    async def _run_in_transaction(self, operation: SessionOperation[T]) -> T:
        engine = create_async_engine_for_url(self.url, null_pool=True)
        try:
            async with engine.connect() as connection:
                outer_transaction = await connection.begin()
                session = AsyncSession(bind=connection, join_transaction_mode="create_savepoint")
                try:
                    return await operation(session)
                finally:
                    await session.close()
                    if outer_transaction.is_active:
                        await outer_transaction.rollback()
        finally:
            await engine.dispose()
