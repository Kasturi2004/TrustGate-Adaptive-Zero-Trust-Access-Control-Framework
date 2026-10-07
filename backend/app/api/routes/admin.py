"""ADMIN-only routes for access verification and dashboard metrics."""

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_db_session, require_role
from app.schemas.admin import (
    AdminDashboardResponse,
    AdminEventInvestigation,
    AdminSecurityEventItem,
    AdminSecurityEventPage,
)
from app.services.admin_queries import (
    get_admin_event_investigation,
    get_admin_security_events,
    get_dashboard_metrics,
)
from app.services.security_events import record_event

_require_admin = require_role("ADMIN")
admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(_require_admin)],
)


def _utc_bound(value: datetime, name: str) -> datetime:
    """Require an offset-aware timestamp and normalize it to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{name} must include a UTC offset",
        )
    return value.astimezone(UTC)


@admin_router.get("/dashboard", response_model=AdminDashboardResponse)
async def read_admin_dashboard(
    request: Request,
    current_user: Annotated[AuthenticatedPrincipal, Depends(_require_admin)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    from_: Annotated[datetime, Query(alias="from")],
    to_: Annotated[datetime, Query(alias="to")],
) -> AdminDashboardResponse:
    """Return real aggregate metrics for the inclusive UTC interval ``from`` to ``to``."""
    from_utc = _utc_bound(from_, "from")
    to_utc = _utc_bound(to_, "to")
    if from_utc > to_utc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="from must not be later than to",
        )

    metrics = await get_dashboard_metrics(session, from_utc=from_utc, to_utc=to_utc)
    route = request.scope.get("route")
    route_path = getattr(route, "path", "")
    record_event(
        session,
        event_type="ADMIN_ACCESS",
        actor_id=current_user.id,
        decision="ALLOW",
        risk_category="LOW",
        details={
            "path": route_path if isinstance(route_path, str) else "",
            "method": request.method,
        },
    )
    await session.commit()

    return AdminDashboardResponse(
        total_requests=metrics.total_requests,
        allow_count=metrics.allow_count,
        step_up_count=metrics.step_up_count,
        block_count=metrics.block_count,
        average_trust_score=metrics.average_trust_score,
        high_risk_count=metrics.high_risk_count,
        mfa_success_rate=metrics.mfa_success_rate,
    )


@admin_router.get("/events", response_model=AdminSecurityEventPage)
async def read_admin_security_events(
    request: Request,
    current_user: Annotated[AuthenticatedPrincipal, Depends(_require_admin)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to_: Annotated[datetime | None, Query(alias="to")] = None,
    user_id: UUID | None = None,
    decision: str | None = None,
    risk_category: str | None = None,
    device_id: UUID | None = None,
    score_min: Annotated[Decimal | None, Query(ge=0, le=100)] = None,
    score_max: Annotated[Decimal | None, Query(ge=0, le=100)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=50)] = 20,
) -> AdminSecurityEventPage:
    """Return a filtered page of security events with an admin-safe projection."""
    from_utc = _utc_bound(from_, "from") if from_ is not None else None
    to_utc = _utc_bound(to_, "to") if to_ is not None else None
    if from_utc is not None and to_utc is not None and from_utc > to_utc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="from must not be later than to",
        )

    result = await get_admin_security_events(
        session,
        from_utc=from_utc,
        to_utc=to_utc,
        user_id=user_id,
        decision=decision,
        risk_category=risk_category,
        device_id=device_id,
        score_min=score_min,
        score_max=score_max,
        page=page,
        page_size=page_size,
    )

    route = request.scope.get("route")
    route_path = getattr(route, "path", "")
    record_event(
        session,
        event_type="ADMIN_ACCESS",
        actor_id=current_user.id,
        decision="ALLOW",
        risk_category="LOW",
        details={
            "path": route_path if isinstance(route_path, str) else "",
            "method": request.method,
        },
    )
    await session.commit()

    return AdminSecurityEventPage(
        items=[
            AdminSecurityEventItem(
                id=item.id,
                event_type=item.event_type,
                created_at=item.created_at,
                user_id=item.user_id,
                decision=item.decision,
                risk_category=item.risk_category,
                trust_score=item.trust_score,
                device=item.device,
            )
            for item in result.items
        ],
        total=result.total,
        page=page,
        page_size=page_size,
    )


@admin_router.get("/events/{event_id}", response_model=AdminEventInvestigation)
async def read_admin_event_investigation(
    event_id: UUID,
    request: Request,
    current_user: Annotated[AuthenticatedPrincipal, Depends(_require_admin)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AdminEventInvestigation:
    """Return one event and its persisted causal chain for an administrator."""
    investigation = await get_admin_event_investigation(session, event_id=event_id)
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found",
        )

    route = request.scope.get("route")
    route_path = getattr(route, "path", "")
    record_event(
        session,
        event_type="ADMIN_ACCESS",
        actor_id=current_user.id,
        decision="ALLOW",
        risk_category="LOW",
        details={
            "path": route_path if isinstance(route_path, str) else "",
            "method": request.method,
        },
    )
    await session.commit()
    return investigation


@admin_router.get("/verification")
async def verify_admin_access(
    request: Request,
    current_user: Annotated[AuthenticatedPrincipal, Depends(_require_admin)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> dict[str, str]:
    """Provide a minimal route for verifying router-level ADMIN protection."""
    route = request.scope.get("route")
    route_path = getattr(route, "path", "")
    record_event(
        session,
        event_type="ADMIN_ACCESS",
        actor_id=current_user.id,
        decision="ALLOW",
        risk_category="LOW",
        details={
            "path": route_path if isinstance(route_path, str) else "",
            "method": request.method,
        },
    )
    await session.commit()
    return {"status": "ok"}
