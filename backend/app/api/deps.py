"""FastAPI dependencies for authenticated request identities."""

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.clock import Clock, SystemClock
from app.core.config import get_settings
from app.core.jwt import AuthenticatedUser, InvalidJWTError, validate_access_token
from app.db.repositories.profile import ProfileRepository
from app.db.session import create_db_engine, create_session_factory
from app.services.security_events import record_event

_bearer_scheme = HTTPBearer(auto_error=False)
Role = Literal["USER", "ADMIN"]


def get_clock() -> Clock:
    """Provide the production clock through an overrideable FastAPI dependency."""
    return SystemClock()


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Verified identity enriched with the trusted profile record."""

    id: UUID
    email: str | None
    role: str


def _not_authenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_verified_identity(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ],
) -> AuthenticatedUser:
    """Extract a bearer token and validate its cryptographic identity."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _not_authenticated()
    try:
        return await run_in_threadpool(validate_access_token, credentials.credentials)
    except InvalidJWTError:
        raise _not_authenticated() from None


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Yield a request-owned session using the existing database configuration."""
    engine = create_db_engine(get_settings())
    try:
        session_factory = create_session_factory(engine)
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()


async def get_current_user(
    identity: Annotated[AuthenticatedUser, Depends(get_verified_identity)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AuthenticatedPrincipal:
    """Resolve a verified token subject to its non-deleted database profile."""
    profile = await ProfileRepository(session).get_by_id(identity.id)
    if profile is None or profile.is_deleted:
        raise _not_authenticated()
    return AuthenticatedPrincipal(id=identity.id, email=profile.email, role=profile.role)


async def require_user(
    current_user: Annotated[AuthenticatedPrincipal, Depends(get_current_user)],
) -> AuthenticatedPrincipal:
    """Require a valid, non-deleted user profile for an endpoint."""
    return current_user


def require_resource_owner(
    resource_owner_dependency: Callable[..., UUID | Awaitable[UUID]],
    *,
    resource: str,
) -> Callable[..., Awaitable[None]]:
    """Build an ownership dependency around a server-side owner lookup.

    ``resource_owner_dependency`` must resolve the owner from the loaded
    resource. It must not accept an owner ID supplied by the client. On
    mismatch, the audit record is committed before the 403 is raised.
    """

    async def check_resource_owner(
        request: Request,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
        resource_owner_id: Annotated[UUID, Depends(resource_owner_dependency)],
        session: Annotated[AsyncSession, Depends(get_db_session)],
    ) -> None:
        if principal.id == resource_owner_id:
            return

        route = request.scope.get("route")
        route_path = getattr(route, "path", "")
        record_event(
            session,
            event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
            actor_id=principal.id,
            target_user_id=resource_owner_id,
            decision="BLOCK",
            risk_category="HIGH",
            details={
                "resource": resource,
                "path": route_path if isinstance(route_path, str) else "",
                "method": request.method,
            },
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Resource access is forbidden",
        )

    return check_resource_owner


async def _record_admin_unauthorized_attempt(
    request: Request,
    principal: AuthenticatedPrincipal,
    attempted_role: Role,
) -> None:
    """Persist an admin denial in a session independent of the request session."""
    engine = create_db_engine(get_settings())
    try:
        session_factory = create_session_factory(engine)
        async with session_factory() as audit_session:
            async with audit_session.begin():
                route = request.scope.get("route")
                route_path = getattr(route, "path", "")
                record_event(
                    audit_session,
                    event_type="ADMIN_UNAUTHORIZED_ATTEMPT",
                    actor_id=principal.id,
                    decision="BLOCK",
                    risk_category="HIGH",
                    details={
                        "attempted_role": attempted_role,
                        "path": route_path if isinstance(route_path, str) else "",
                        "method": request.method,
                    },
                )
    finally:
        await engine.dispose()


def require_role(
    required_role: Role,
) -> Callable[..., Awaitable[AuthenticatedPrincipal]]:
    """Build a dependency that authorizes against the database-loaded profile role."""

    async def check_role(
        request: Request,
        current_user: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    ) -> AuthenticatedPrincipal:
        if current_user.role != required_role:
            request_path = request.url.path
            is_admin_path = request_path == "/admin" or request_path.startswith("/admin/")
            if required_role == "ADMIN" and is_admin_path:
                try:
                    await _record_admin_unauthorized_attempt(request, current_user, required_role)
                except Exception:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="An unexpected error occurred.",
                    ) from None
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return check_role
