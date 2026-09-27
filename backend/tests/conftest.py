import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("CORS_ALLOWED_ORIGIN", "http://localhost:5173")


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> object:
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client() -> TestClient:
    from app.core.config import get_settings
    from app.main import create_app

    return TestClient(create_app(get_settings()))
