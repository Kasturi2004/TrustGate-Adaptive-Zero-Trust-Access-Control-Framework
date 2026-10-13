"""Schemas for protected-resource access requests."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

AccessDecision = Literal["ALLOW", "STEP_UP", "BLOCK"]
DocumentResourceId = Literal[
    "employee-handbook",
    "company-policies",
    "quarterly-strategy-plan",
    "confidential-financial-report",
]


class AccessEvaluateRequest(BaseModel):
    """Client-selectable resource identifier; decisions remain server-owned."""

    model_config = ConfigDict(extra="forbid")

    resource_id: Literal[
        "ops-dashboard",
        "employee-handbook",
        "company-policies",
        "quarterly-strategy-plan",
        "confidential-financial-report",
    ] = "ops-dashboard"


class AccessEvaluateResponse(BaseModel):
    """Curated access-evaluation response; internal evaluation data is excluded."""

    evaluation_id: UUID
    decision: AccessDecision
    explanation: str
    mfa_challenge_id: UUID | None
    access_request_id: UUID | None


class ProtectedResourceRequest(BaseModel):
    """Select an access request to redeem; authorization is checked server-side."""

    model_config = ConfigDict(extra="forbid")

    access_request_id: UUID


class ProtectedDashboardResponse(BaseModel):
    resource_id: Literal["ops-dashboard"]
    title: str
    summary: str
    status: Literal["operational"]


class ProtectedDocumentResponse(BaseModel):
    """Fictional document body returned only by successful protected redemption."""

    resource_id: DocumentResourceId
    title: str
    content: str
