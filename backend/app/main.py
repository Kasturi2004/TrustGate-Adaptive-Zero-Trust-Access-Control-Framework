"""TrustGate API entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.core.config import Settings, get_settings
from app.core.errors import RequestIdMiddleware, register_error_handlers


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application. OpenAPI is disabled in production."""
    resolved = settings if settings is not None else get_settings()
    docs_enabled = resolved.app_env != "production"
    app = FastAPI(
        title="TrustGate",
        version="0.1.0",
        debug=False,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    register_error_handlers(app)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[resolved.cors_allowed_origin],
        allow_credentials=False,
        allow_methods=["GET", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "X-Request-ID"],
    )
    app.include_router(health_router)
    return app


app = create_app()
