"""Authentication routes that proxy credentials to Supabase Auth."""

from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from starlette.responses import Response

from app.api.deps import AuthenticatedPrincipal, get_current_user
from app.core.config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_LOGIN_FAILURE = "Invalid email or password."
_UPSTREAM_FAILURE = "Authentication service is unavailable."


class LoginRequest(BaseModel):
    """Strict login credentials forwarded to Supabase Auth."""

    model_config = ConfigDict(extra="forbid")

    email: Annotated[StrictStr, Field(min_length=1, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    password: Annotated[StrictStr, Field(min_length=1)]


class AuthMeResponse(BaseModel):
    """Identity fields resolved from the authenticated user's profile."""

    id: UUID
    email: str | None
    role: Annotated[str, Field(pattern=r"^(USER|ADMIN)$")]


@router.post("/login")
async def login(payload: LoginRequest) -> Response:
    """Forward login credentials to Supabase without persisting or logging them."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_anon_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_UPSTREAM_FAILURE,
        )

    url = f"{settings.supabase_url.rstrip('/')}/auth/v1/token?grant_type=password"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream = await client.post(
                url,
                headers={
                    "apikey": settings.supabase_anon_key,
                    "Content-Type": "application/json",
                },
                json={"email": payload.email, "password": payload.password},
            )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_UPSTREAM_FAILURE,
        ) from None

    if 200 <= upstream.status_code < 300:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    if upstream.status_code in {400, 401, 422}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_LOGIN_FAILURE,
        ) from None

    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=_UPSTREAM_FAILURE,
    ) from None


@router.get("/me", response_model=AuthMeResponse)
async def read_current_user(
    current_user: Annotated[AuthenticatedPrincipal, Depends(get_current_user)],
) -> AuthMeResponse:
    """Return the verified user's profile identity."""
    return AuthMeResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
    )
