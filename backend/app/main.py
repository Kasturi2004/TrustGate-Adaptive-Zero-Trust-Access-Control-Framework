"""TrustGate API entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from app.api.routes.access import router as access_router
from app.api.routes.admin import admin_router
from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.core.config import Settings, get_settings
from app.core.errors import (
    RequestIdMiddleware,
    handle_rate_limit_exceeded,
    register_error_handlers,
)
from app.core.limiter import limiter


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
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, handle_rate_limit_exceeded)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[resolved.cors_allowed_origin],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Accept",
            "Authorization",
            "Content-Type",
            "X-Device-Token",
            "X-Request-ID",
        ],
    )
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(access_router)
    app.include_router(admin_router)
    return app


app = create_app()
