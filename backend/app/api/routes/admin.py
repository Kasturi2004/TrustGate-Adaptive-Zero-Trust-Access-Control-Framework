"""Admin-only router foundation; feature endpoints belong to later phases."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_db_session, require_role
from app.services.security_events import record_event

_require_admin = require_role("ADMIN")
admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(_require_admin)],
)


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
