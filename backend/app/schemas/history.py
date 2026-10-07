"""Allow-listed API schemas for a user's access history."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AccessHistoryResponse(BaseModel):
    """Curated history row that excludes internal policy and risk data."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    resource_id: str
    requested_at: datetime
    initial_decision: str
    final_outcome: str | None
    mfa_was_required: bool
    mfa_status: str | None
