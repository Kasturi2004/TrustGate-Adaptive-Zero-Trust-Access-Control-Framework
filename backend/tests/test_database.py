import asyncio
import logging
import ssl

import pytest
from app.core.config import Settings, get_settings
from app.db.session import (
    DatabaseConfigurationError,
    create_async_engine_for_url,
    create_db_engine,
    create_session_factory,
    prepare_database_url,
    select_one,
)
from app.main import create_app
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url


def test_missing_database_url_is_rejected_without_a_placeholder() -> None:
    settings = Settings(
        app_env="test", cors_allowed_origin="http://localhost:5173", database_url=None
    )
    with pytest.raises(DatabaseConfigurationError, match="DATABASE_URL is not configured"):
        create_db_engine(settings)


def test_non_postgres_url_is_rejected_without_echoing_the_value() -> None:
    with pytest.raises(DatabaseConfigurationError, match="PostgreSQL scheme"):
        prepare_database_url("mysql://user:secret-password@localhost/trustgate")


def test_postgres_url_becomes_asyncpg_and_disables_the_statement_cache() -> None:
    url, connect_args = prepare_database_url(
        "postgresql://trustgate_app:secret-password@db.example.supabase.co:5432/postgres?sslmode=require"
    )
    parsed = make_url(url)
    assert parsed.drivername == "postgresql+asyncpg"
    assert parsed.host == "db.example.supabase.co"
    assert connect_args["statement_cache_size"] == 0
    ssl_context = connect_args["ssl"]
    assert isinstance(ssl_context, ssl.SSLContext)
    assert ssl_context.verify_mode == ssl.CERT_NONE
    assert "sslmode" not in parsed.query


def test_creating_the_engine_does_not_log_the_password(caplog: pytest.LogCaptureFixture) -> None:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        database_url=(
            "postgresql://trustgate_app:super-secret-password@db.example.supabase.co:5432/postgres"
        ),
    )
    with caplog.at_level(logging.DEBUG):
        engine = create_db_engine(settings)
    assert "super-secret-password" not in caplog.text
    asyncio.run(engine.dispose())


def test_health_works_when_the_database_url_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    get_settings.cache_clear()
    settings = Settings(
        app_env="test", cors_allowed_origin="http://localhost:5173", database_url=None
    )
    response = TestClient(create_app(settings)).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_works_when_the_database_is_unreachable() -> None:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        database_url="postgresql://trustgate_app:secret@127.0.0.1:1/postgres",
    )
    response = TestClient(create_app(settings)).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_live_database_select_one(test_database_url: str) -> None:
    """Check connectivity only to the explicit, validated scratch database."""

    async def _check() -> int:
        engine = create_async_engine_for_url(test_database_url)
        try:
            return await select_one(create_session_factory(engine))
        except Exception:
            raise RuntimeError("Database connectivity check failed") from None
        finally:
            await engine.dispose()

    assert asyncio.run(_check()) == 1
