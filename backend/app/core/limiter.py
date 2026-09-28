"""In-process request burst limiter configuration."""

from slowapi import Limiter

from app.core.client_ip import resolve_client_ip

limiter = Limiter(
    key_func=resolve_client_ip,
    default_limits=[],
    storage_uri="memory://",
)
