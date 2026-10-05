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


def test_alembic_has_the_initial_role_rls_audit_and_seed_revisions() -> None:
    revisions = sorted((BACKEND_ROOT / "alembic" / "versions").glob("*.py"))
    assert [revision.name for revision in revisions] == [
        "20260928_01_initial_schema.py",
        "20260928_02_runtime_role_privileges.py",
        "20260928_03_enable_rls.py",
        "20260928_04_profile_auth_triggers.py",
        "20260928_05_security_events_append_only.py",
        "20260928_06_seed_pol_1_0.py",
        "20261004_07_mfa_credentials.py",
        "20261005_08_totp_challenge_hash_nullable.py",
        "20261005_09_mfa_totp_replay_counter.py",
    ]
    env_source = (BACKEND_ROOT / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "from app.db.models import target_metadata" in env_source
