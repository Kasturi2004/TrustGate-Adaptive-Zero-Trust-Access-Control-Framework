from pathlib import Path

import pytest
from app.core.config import Settings
from app.db.session import DatabaseConfigurationError, require_migration_url

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def test_migration_url_prefers_the_owner_connection() -> None:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        database_url="postgresql://app:app-secret@db.example.supabase.co:5432/postgres",
        migration_database_url="postgresql://owner:owner-secret@db.example.supabase.co:5432/postgres",
    )
    assert require_migration_url(settings).startswith("postgresql://owner:")


def test_migration_url_falls_back_to_database_url() -> None:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        database_url="postgresql://app:app-secret@db.example.supabase.co:5432/postgres",
        migration_database_url=None,
    )
    assert require_migration_url(settings).startswith("postgresql://app:")


def test_migration_url_ignores_supabase_auth_settings() -> None:
    settings = Settings(
        app_env="test",
        cors_allowed_origin="http://localhost:5173",
        supabase_url="https://example.supabase.co",
        supabase_service_role_key="service-role-secret",
        database_url=None,
        migration_database_url=None,
    )
    with pytest.raises(DatabaseConfigurationError, match="not configured"):
        require_migration_url(settings)


def test_alembic_config_has_no_connection_string() -> None:
    contents = (BACKEND_ROOT / "alembic.ini").read_text(encoding="utf-8")
    assert "sqlalchemy.url =" in contents
    assert "://" not in contents
    assert "password" not in contents.lower()


def test_alembic_has_no_application_revision_yet() -> None:
    revisions = list((BACKEND_ROOT / "alembic" / "versions").glob("*.py"))
    assert revisions == []
    env_source = (BACKEND_ROOT / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "target_metadata = None" in env_source
