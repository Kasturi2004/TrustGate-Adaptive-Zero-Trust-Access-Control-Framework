"""Admin-only router foundation; feature endpoints belong to later phases."""

from fastapi import APIRouter, Depends

from app.api.deps import require_role

admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_role("ADMIN"))],
)


@admin_router.get("/verification")
async def verify_admin_access() -> dict[str, str]:
    """Provide a minimal route for verifying router-level ADMIN protection."""
    return {"status": "ok"}
