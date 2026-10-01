"""Backward-compatible access to the centralized context IP resolver."""

from app.services.context.client_ip import ClientIPResolutionError, resolve_client_ip

__all__ = ["ClientIPResolutionError", "resolve_client_ip"]
