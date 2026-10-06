"""Authentication routes that proxy credentials to Supabase Auth."""

from datetime import timedelta
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from app.api.deps import AuthenticatedPrincipal, get_clock, get_current_user, get_db_session
from app.core.client_ip import resolve_client_ip
from app.core.clock import Clock
from app.core.config import get_settings
from app.core.limiter import limiter
from app.core.rate_limit import account_rate_limit_key, ip_rate_limit_key
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.services.security_events import email_identifier, record_event

router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_LOGIN_FAILURE = "Invalid email or password."
_UPSTREAM_FAILURE = "Authentication service is unavailable."


def _authenticated_user_id(response: httpx.Response) -> UUID | None:
    """Extract Supabase's authenticated user ID without altering its response."""
    try:
        return UUID(response.json()["user"]["id"])
    except (KeyError, TypeError, ValueError):
        return None


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
@limiter.limit("5 per 5 minutes")
async def login(
    request: Request,
    payload: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> Response:
    """Forward login credentials to Supabase without persisting or logging them."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_anon_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_UPSTREAM_FAILURE,
        )

    now = clock.now()
    keys = sorted(
        (
            ip_rate_limit_key(resolve_client_ip(request)),
            account_rate_limit_key(payload.email, settings=settings),
        )
    )
    async with session.begin():
        repository = RateLimitStateRepository(session)
        admitted = [
            await repository.consume_attempt(
                key,
                now,
                attempt_limit=5,
                window_duration=timedelta(minutes=5),
            )
            for key in keys
        ]

    if not all(admitted):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
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
        actor_id = _authenticated_user_id(upstream)
        if actor_id is None:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=_UPSTREAM_FAILURE,
            ) from None

        async with session.begin():
            record_event(
                session,
                event_type="LOGIN_SUCCESS",
                actor_id=actor_id,
                details={"email_identifier": email_identifier(payload.email)},
            )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    if upstream.status_code in {400, 401, 422}:
        async with session.begin():
            record_event(
                session,
                event_type="LOGIN_FAILURE",
                actor_id=None,
                details={"email_identifier": email_identifier(payload.email)},
            )
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
