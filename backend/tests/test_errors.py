from app.core.config import Settings
from app.main import create_app
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException


def test_unknown_route_uses_error_envelope(client: TestClient) -> None:
    response = client.get("/does-not-exist", headers={"X-Request-ID": "req-phase1"})
    body = response.json()
    assert response.status_code == 404
    assert body["error"]["code"] == "NOT_FOUND"
    assert body["error"]["request_id"] == "req-phase1"
    assert "traceback" not in response.text.lower()


def test_server_error_does_not_leak_exception_text() -> None:
    app = create_app(Settings(app_env="test", cors_allowed_origin="http://localhost:5173"))

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("database password=super-secret")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/boom")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    assert "super-secret" not in response.text
    assert "Traceback" not in response.text


def test_http_exception_uses_safe_message_for_server_errors() -> None:
    app = create_app(Settings(app_env="test", cors_allowed_origin="http://localhost:5173"))

    @app.get("/fail")
    def fail() -> None:
        raise HTTPException(status_code=503, detail=r"C:\secret\app.py SELECT * FROM users")

    client = TestClient(app)
    response = client.get("/fail")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert response.json()["error"]["message"] == "An unexpected error occurred."
    assert "SELECT" not in response.text
    assert "secret" not in response.text.lower()


def test_openapi_disabled_in_production() -> None:
    app = create_app(Settings(app_env="production", cors_allowed_origin="https://app.example"))
    client = TestClient(app)
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/health").status_code == 200


def test_openapi_enabled_outside_production(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "/health" in response.json()["paths"]
