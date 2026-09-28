"""Resolve client IP addresses without trusting forwarded headers."""

import ipaddress

from starlette.requests import Request


class ClientIPResolutionError(ValueError):
    """Raised when a request has no usable direct peer IP address."""


def resolve_client_ip(request: Request) -> str:
    """Return the normalized direct peer address, ignoring forwarded headers."""
    client = request.client
    if client is None:
        raise ClientIPResolutionError("Request client address is unavailable")

    try:
        return ipaddress.ip_address(client.host).compressed
    except ValueError:
        raise ClientIPResolutionError("Request client address is invalid") from None
