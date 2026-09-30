"""Registry of MVP protected resources."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ProtectedResource:
    """A resource the access gateway may evaluate."""

    resource_id: str
    name: str
    description: str


class ProtectedResourceNotFoundError(LookupError):
    """Raised when a resource is absent from the server-owned registry."""


PROTECTED_RESOURCES: Mapping[str, ProtectedResource] = MappingProxyType(
    {
        "ops-dashboard": ProtectedResource(
            resource_id="ops-dashboard",
            name="Operations Dashboard",
            description="The TrustGate operations dashboard protected resource.",
        ),
    }
)


def get_protected_resource(resource_id: str) -> ProtectedResource:
    """Return registered metadata or safely reject an unknown resource ID."""
    try:
        return PROTECTED_RESOURCES[resource_id]
    except KeyError:
        raise ProtectedResourceNotFoundError("Protected resource is not registered.") from None
