"""Resolve client IP using the direct peer and explicitly trusted proxies."""

from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from starlette.requests import Request

from app.core.config import Settings, get_settings

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class ClientIPResolutionError(ValueError):
    """Raised when a request has no usable direct peer IP address."""


def _parse_ip(value: str) -> IPAddress | None:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return address


def _configured_proxy_networks(settings: Settings) -> tuple[IPNetwork, ...]:
    configured = settings.trusted_proxies
    if configured is None:
        return ()

    try:
        return tuple(
            ipaddress.ip_network(entry.strip(), strict=False)
            for entry in configured.split(",")
            if entry.strip()
        )
    except ValueError:
        # Invalid proxy configuration must never broaden trust.
        return ()


def _is_trusted_proxy(peer: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    return any(peer.version == network.version and peer in network for network in networks)


def is_trusted_proxy_peer(request: Request, *, settings: Settings | None = None) -> bool:
    """Return whether the direct socket peer is in the configured proxy allowlist."""
    client = request.client
    if client is None:
        return False

    peer = _parse_ip(client.host)
    if peer is None:
        return False

    configuration = settings if settings is not None else get_settings()
    return _is_trusted_proxy(peer, _configured_proxy_networks(configuration))


def _forwarded_client_ip(request: Request, hops: int) -> IPAddress | None:
    if hops <= 0:
        return None

    values = request.headers.getlist("x-forwarded-for")
    # Multiple header fields have ambiguous ordering; use the socket peer.
    if len(values) != 1:
        return None

    entries = values[0].split(",")
    if len(entries) < hops:
        return None

    addresses: list[IPAddress] = []
    for entry in entries:
        address = _parse_ip(entry)
        if address is None:
            return None
        addresses.append(address)

    # The TrustGate implementation plan treats the left-most valid entry as
    # the client address once the immediate peer is trusted.
    return addresses[0]


def resolve_client_ip(request: Request, *, settings: Settings | None = None) -> str:
    """Return a normalized IP; forwarded data is considered only from trusted peers.

    Direct socket addresses are the safe default. Forwarded values are used
    only when TRUSTED_PROXY_HOPS is positive and the immediate peer matches
    an explicitly configured TRUSTED_PROXIES IP/CIDR entry.
    """
    client = request.client
    if client is None:
        raise ClientIPResolutionError("Request client address is unavailable")

    peer = _parse_ip(client.host)
    if peer is None:
        raise ClientIPResolutionError("Request client address is invalid")

    configuration = settings or get_settings()
    hops = configuration.trusted_proxy_hops
    if hops == 0 or not _is_trusted_proxy(peer, _configured_proxy_networks(configuration)):
        return peer.compressed

    forwarded = _forwarded_client_ip(request, hops)
    return peer.compressed if forwarded is None else forwarded.compressed
