"""Registry of MVP protected resources."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

ResourceAccessRule = Literal["EMPLOYEE", "GROUP_GRANT_REQUIRED"]


@dataclass(frozen=True, slots=True)
class ProtectedResource:
    """A resource the access gateway may evaluate."""

    resource_id: str
    name: str
    description: str
    access_rule: ResourceAccessRule = "EMPLOYEE"
    content: str | None = None

    @property
    def employee_access_allowed(self) -> bool:
        """Whether current server-owned entitlements authorize any employee."""
        return self.access_rule == "EMPLOYEE"

    @property
    def denial_reason(self) -> str | None:
        if self.access_rule == "GROUP_GRANT_REQUIRED":
            return "This resource requires a group grant, which is not configured."
        return None


class ProtectedResourceNotFoundError(LookupError):
    """Raised when a resource is absent from the server-owned registry."""


PROTECTED_RESOURCES: Mapping[str, ProtectedResource] = MappingProxyType(
    {
        "ops-dashboard": ProtectedResource(
            resource_id="ops-dashboard",
            name="Operations Dashboard",
            description="The TrustGate operations dashboard protected resource.",
            content=None,
        ),
        "employee-handbook": ProtectedResource(
            resource_id="employee-handbook",
            name="Employee Handbook",
            description="Fictional Acme employee handbook sample.",
            content=(
                "FICTIONAL SAMPLE — EMPLOYEE HANDBOOK\n\n"
                "Acme supports thoughtful, inclusive work. Employees should work with their "
                "manager and People Operations for current workplace guidance. This sample "
                "is illustrative and is not an actual company policy."
            ),
        ),
        "company-policies": ProtectedResource(
            resource_id="company-policies",
            name="Company Policies",
            description="Fictional Acme company policies sample.",
            content=(
                "FICTIONAL SAMPLE — COMPANY POLICIES\n\n"
                "Acme employees are expected to protect company information, use approved "
                "systems, and ask their manager when guidance is unclear. This sample is "
                "illustrative and is not an actual company policy."
            ),
        ),
        "quarterly-strategy-plan": ProtectedResource(
            resource_id="quarterly-strategy-plan",
            name="Quarterly Strategy Plan",
            description="Restricted fictional Acme strategy sample; group grants are unavailable.",
            access_rule="GROUP_GRANT_REQUIRED",
        ),
        "confidential-financial-report": ProtectedResource(
            resource_id="confidential-financial-report",
            name="Confidential Financial Report",
            description="Restricted fictional Acme financial sample; group grants are unavailable.",
            access_rule="GROUP_GRANT_REQUIRED",
        ),
    }
)


def get_protected_resource(resource_id: str) -> ProtectedResource:
    """Return registered metadata or safely reject an unknown resource ID."""
    try:
        return PROTECTED_RESOURCES[resource_id]
    except KeyError:
        raise ProtectedResourceNotFoundError("Protected resource is not registered.") from None
