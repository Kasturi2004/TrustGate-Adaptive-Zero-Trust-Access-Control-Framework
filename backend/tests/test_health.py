from pathlib import Path

from fastapi.testclient import TestClient


def test_health_returns_ok_without_database_fields(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_module_does_not_reference_a_database() -> None:
    source = Path("app/api/routes/health.py").read_text(encoding="utf-8").lower()
    for forbidden in ("sqlalchemy", "asyncpg", "alembic", "session", "database_url"):
        assert forbidden not in source
