"""Protected-resource access evaluation endpoint."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_clock, get_db_session, require_user
from app.core.client_ip import resolve_client_ip
from app.core.clock import Clock
from app.core.config import Settings, get_settings
from app.db.models.profile import Profile
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.profile import ProfileRepository
from app.schemas.access import AccessEvaluateRequest, AccessEvaluateResponse
from app.schemas.admin import AdminEventInvestigation
from app.schemas.history import AccessHistoryResponse
from app.services.access_gateway import SecurityPipeline, access_gateway, get_security_pipeline
from app.services.admin_queries import get_admin_event_investigation
from app.services.context.location import GeoResolver, get_geo_resolver
from app.services.protected_resource import get_protected_resource
from app.services.security_events import record_event

router = APIRouter(prefix="/access", tags=["access"])


@router.get("/history", response_model=list[AccessHistoryResponse])
async def read_access_history(
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    page: Annotated[int, Query(ge=1)],
    page_size: Annotated[int, Query(ge=1)],
) -> list[AccessHistoryResponse]:
    """Return one page of the authenticated user's curated access history."""
    records = await AccessRequestRepository(session).list_history_by_user(
        principal.id,
        page=page,
        page_size=page_size,
    )
    return [
        AccessHistoryResponse(
            id=record.id,
            resource_id=record.resource_id,
            requested_at=record.requested_at,
            initial_decision=record.initial_decision,
            final_outcome=record.final_outcome,
            mfa_was_required=record.mfa_was_required,
            mfa_status=record.mfa_status,
        )
        for record in records
    ]


@router.get(
    "/request/{access_request_id}",
    response_model=AccessHistoryResponse | AdminEventInvestigation,
)
async def read_access_request(
    access_request_id: UUID,
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AccessHistoryResponse | AdminEventInvestigation:
    """Return curated USER detail or the full investigation to an ADMIN."""
    if principal.role == "ADMIN":
        investigation = await get_admin_event_investigation(
            session,
            access_request_id=access_request_id,
            clock=clock,
            block_indicator_limit=settings.block_indicator_limit,
        )
        if investigation is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Access request not found",
            )
        route = request.scope.get("route")
        route_path = getattr(route, "path", "")
        record_event(
            session,
            event_type="ADMIN_ACCESS",
            actor_id=principal.id,
            decision="ALLOW",
            risk_category="LOW",
            details={
                "path": route_path if isinstance(route_path, str) else "",
                "method": request.method,
            },
        )
        await session.commit()
        return investigation

    record = await AccessRequestRepository(session).get_history_by_id_for_user(
        access_request_id,
        principal.id,
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found",
        )
    return AccessHistoryResponse(
        id=record.id,
        resource_id=record.resource_id,
        requested_at=record.requested_at,
        initial_decision=record.initial_decision,
        final_outcome=record.final_outcome,
        mfa_was_required=record.mfa_was_required,
        mfa_status=record.mfa_status,
    )


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
