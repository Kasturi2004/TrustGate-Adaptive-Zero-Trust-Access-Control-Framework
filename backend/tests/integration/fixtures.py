"""Session-scoped bootstrap and migration fixture for scratch PostgreSQL."""

import asyncio
import os

import pytest

from tests.integration.database import (
    ScratchDatabase,
    bootstrap_external_prerequisites,
    require_test_database_url,
    run_alembic,
    verify_migration_head,
)


@pytest.fixture(scope="session")
def test_database_url() -> str:
    """Require an explicit local TEST_DATABASE_URL without .env fallback."""
    if not os.environ.get("TEST_DATABASE_URL", "").strip():
        pytest.skip("TEST_DATABASE_URL is absent; scratch PostgreSQL integration tests skipped")
    try:
        return require_test_database_url()
    except ValueError as error:
        pytest.fail(str(error), pytrace=False)


@pytest.fixture(scope="session")
def migrated_test_database(test_database_url: str) -> ScratchDatabase:
    """Bootstrap prerequisites and migrate the disposable database once per run."""
    asyncio.run(bootstrap_external_prerequisites(test_database_url))
    run_alembic(test_database_url, "upgrade", "head")
    run_alembic(test_database_url, "current")
    asyncio.run(verify_migration_head(test_database_url))
    return ScratchDatabase(test_database_url)
