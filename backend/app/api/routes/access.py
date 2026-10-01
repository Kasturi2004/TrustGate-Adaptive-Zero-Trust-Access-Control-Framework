"""Protected-resource access evaluation endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_clock, get_db_session, require_user
from app.core.client_ip import resolve_client_ip
from app.core.clock import Clock
from app.core.config import Settings, get_settings
from app.db.models.profile import Profile
from app.db.repositories.profile import ProfileRepository
from app.schemas.access import AccessEvaluateRequest, AccessEvaluateResponse
from app.services.access_gateway import SecurityPipeline, access_gateway, get_security_pipeline
from app.services.context.location import GeoResolver, get_geo_resolver
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
    settings: Annotated[Settings, Depends(get_settings)],
    geo_resolver: Annotated[GeoResolver, Depends(get_geo_resolver)],
) -> AccessEvaluateResponse:
    """Evaluate and atomically persist the authenticated user's access request."""
    resource = get_protected_resource(payload.resource_id)
    try:
        profile: Profile | None = await ProfileRepository(session).get_by_id(_principal.id)
        if profile is None or profile.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        result = await access_gateway(
            session=session,
            principal=_principal,
            resource=resource,
            device_token=device_token,
            client_ip=resolve_client_ip(request, settings=settings),
            user_agent=request.headers.get("user-agent"),
            pipeline=pipeline,
            clock=clock,
            request=request,
            profile=profile,
            geo_resolver=geo_resolver,
            settings=settings,
        )
    except HTTPException:
        raise
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
