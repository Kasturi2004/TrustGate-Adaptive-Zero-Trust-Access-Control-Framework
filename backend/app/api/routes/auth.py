"""Authentication routes that proxy credentials to Supabase Auth."""

import re
from datetime import timedelta
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from app.api.deps import AuthenticatedPrincipal, get_clock, get_current_user, get_db_session
from app.core.client_ip import resolve_client_ip
from app.core.clock import Clock
from app.core.config import get_settings
from app.core.limiter import limiter
from app.core.rate_limit import account_rate_limit_key, ip_rate_limit_key
from app.db.models.profile import Profile
from app.db.repositories.mfa_credential import MfaCredentialRepository
from app.db.repositories.profile import ProfileRepository
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


class SignupRequest(BaseModel):
    """Public employee registration fields; role and metadata are never client controlled."""

    model_config = ConfigDict(extra="forbid")

    full_name: Annotated[StrictStr, Field(min_length=2, max_length=100)]
    email: Annotated[StrictStr, Field(min_length=1, max_length=254)]
    password: Annotated[StrictStr, Field(min_length=12, max_length=128)]

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, value: str) -> str:
        if not re.search(r"[a-z]", value) or not re.search(r"[A-Z]", value):
            raise ValueError("Use both uppercase and lowercase letters.")
        if not re.search(r"[0-9]", value):
            raise ValueError("Include at least one number.")
        if not re.search(r"[^A-Za-z0-9]", value):
            raise ValueError("Include at least one symbol.")
        return value

    @field_validator("full_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("Enter your full name.")
        return normalized

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
            raise ValueError("Enter a valid work email address.")
        return normalized


class SignupUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    email: str | None


class SignupResponse(BaseModel):
    """Allowlisted Supabase signup response fields only."""

    model_config = ConfigDict(extra="forbid")

    account_created: bool = True
    session_created: bool
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    user: SignupUser


class AuthMeResponse(BaseModel):
    """Identity fields resolved from the authenticated user's profile."""

    id: UUID
    email: str | None
    role: Annotated[str, Field(pattern=r"^(USER|ADMIN)$")]
    authenticator_required: bool
    mfa_enrolled: bool


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


@router.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5 per 5 minutes")
async def signup(
    request: Request,
    payload: SignupRequest,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> SignupResponse:
    """Create a Supabase Auth identity with a server-assigned employee role."""
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
            detail="Unable to create account. Please try again later.",
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream = await client.post(
                f"{settings.supabase_url.rstrip('/')}/auth/v1/signup",
                headers={
                    "apikey": settings.supabase_anon_key,
                    "Content-Type": "application/json",
                },
                json={
                    "email": payload.email,
                    "password": payload.password,
                    "data": {"full_name": payload.full_name},
                },
            )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_UPSTREAM_FAILURE,
        ) from None

    if not 200 <= upstream.status_code < 300:
        if upstream.status_code in {400, 401, 409, 422}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to create account. Check the details or sign in.",
            ) from None
        if upstream.status_code == 429:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Unable to create account. Please try again later.",
            ) from None
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_UPSTREAM_FAILURE,
        ) from None

    try:
        upstream_body = upstream.json()
        upstream_user = upstream_body["user"]
        user_id = UUID(upstream_user["id"])
        user_email = upstream_user.get("email")
        access_token = upstream_body.get("access_token")
        refresh_token = upstream_body.get("refresh_token")
        token_type = upstream_body.get("token_type")
        expires_in = upstream_body.get("expires_in")
        if user_email is not None and not isinstance(user_email, str):
            raise ValueError("Invalid upstream identity")
        if any(
            value is not None and not isinstance(value, str)
            for value in (access_token, refresh_token, token_type)
        ):
            raise ValueError("Invalid upstream session")
        if expires_in is not None and not isinstance(expires_in, int):
            raise ValueError("Invalid upstream session")
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_UPSTREAM_FAILURE,
        ) from None

    async with session.begin():
        profile_repository = ProfileRepository(session)
        profile = await profile_repository.get_by_id(user_id)
        if profile is None:
            session.add(
                Profile(
                    id=user_id,
                    email=user_email,
                    role="USER",
                    authenticator_required=True,
                )
            )
        else:
            profile.email = user_email
            profile.role = "USER"
            profile.authenticator_required = True

    return SignupResponse(
        session_created=bool(access_token),
        access_token=access_token,
        refresh_token=refresh_token,
        token_type=token_type,
        expires_in=expires_in,
        user=SignupUser(id=user_id, email=user_email),
    )


@router.get("/me", response_model=AuthMeResponse)
async def read_current_user(
    current_user: Annotated[AuthenticatedPrincipal, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AuthMeResponse:
    """Return the verified user's profile identity."""
    credential = await MfaCredentialRepository(session).get_by_user_id(current_user.id)
    return AuthMeResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        authenticator_required=current_user.authenticator_required,
        mfa_enrolled=bool(
            credential is not None and credential.enabled and credential.verified_at is not None
        ),
    )
