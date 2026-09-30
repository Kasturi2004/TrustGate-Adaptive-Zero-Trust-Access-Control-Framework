"""Protected-resource access evaluation endpoint."""

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Header

from app.api.deps import AuthenticatedPrincipal, require_user
from app.schemas.access import AccessEvaluateRequest, AccessEvaluateResponse
from app.services.protected_resource import get_protected_resource

router = APIRouter(prefix="/access", tags=["access"])


@router.post("/evaluate", response_model=AccessEvaluateResponse)
async def evaluate_access(
    payload: AccessEvaluateRequest,
    device_token: Annotated[str, Header(alias="X-Device-Token", min_length=1)],
    _principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
) -> AccessEvaluateResponse:
    """Fail closed until the later-phase security pipeline is implemented.

    This Phase 5 placeholder intentionally performs no partial persistence and
    does not inspect, retain, or return the raw device token. Device token
    derivation belongs to Phase 6; evaluation and audit persistence belong to
    the complete gateway pipeline.
    """
    del device_token
    resource = get_protected_resource(payload.resource_id)
    return AccessEvaluateResponse(
        evaluation_id=uuid4(),
        decision="BLOCK",
        explanation=f"Access evaluation for {resource.name} is not available yet.",
        mfa_challenge_id=None,
    )
