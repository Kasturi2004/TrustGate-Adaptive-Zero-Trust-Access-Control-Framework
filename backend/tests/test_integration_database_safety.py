import pytest

from tests.integration.database import (
    TestDatabaseConfigurationError as DatabaseConfigurationError,
)
from tests.integration.database import (
    require_test_database_url,
)


def test_test_database_url_does_not_fall_back_to_database_url() -> None:
    with pytest.raises(DatabaseConfigurationError, match="must be set explicitly"):
        require_test_database_url({"DATABASE_URL": "postgresql://localhost/trustgate_test"})


def test_test_database_url_rejects_supabase_hosts() -> None:
    with pytest.raises(DatabaseConfigurationError, match="never Supabase"):
        require_test_database_url(
            {"TEST_DATABASE_URL": "postgresql://user:secret@db.example.supabase.co/trustgate_test"}
        )


def test_test_database_url_requires_dedicated_database_name() -> None:
    with pytest.raises(DatabaseConfigurationError, match="dedicated trustgate_test"):
        require_test_database_url({"TEST_DATABASE_URL": "postgresql://localhost/postgres"})
