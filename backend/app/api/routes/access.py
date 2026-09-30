"""Protected-resource access evaluation endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_clock, get_db_session, require_user
from app.core.client_ip import resolve_client_ip
from app.core.clock import Clock
from app.schemas.access import AccessEvaluateRequest, AccessEvaluateResponse
from app.services.access_gateway import SecurityPipeline, access_gateway, get_security_pipeline
from app.services.protected_resource import get_protected_resource

router = APIRouter(prefix="/access", tags=["access"])


@router.post("/evaluate", response_model=AccessEvaluateResponse)
async def evaluate_access(
    request: Request,
    payload: AccessEvaluateRequest,
    device_token: Annotated[str, Header(alias="X-Device-Token", min_length=1)],
    _principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
    pipeline: Annotated[SecurityPipeline, Depends(get_security_pipeline)],
) -> AccessEvaluateResponse:
    """Evaluate and atomically persist the authenticated user's access request."""
    resource = get_protected_resource(payload.resource_id)
    try:
        result = await access_gateway(
            session=session,
            principal=_principal,
            resource=resource,
            device_token=device_token,
            client_ip=resolve_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            pipeline=pipeline,
            clock=clock,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from None

    return AccessEvaluateResponse(
        evaluation_id=result.evaluation_id,
        decision=result.decision,
        explanation=result.explanation,
        mfa_challenge_id=result.mfa_challenge_id,
    )
