"""Registry of MVP protected resources."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProtectedResource:
    """A resource the access gateway may evaluate."""

    resource_id: str
    name: str
    description: str


PROTECTED_RESOURCES: dict[str, ProtectedResource] = {
    "ops-dashboard": ProtectedResource(
        resource_id="ops-dashboard",
        name="Operations Dashboard",
        description="MVP protected resource placeholder.",
    ),
}
