"""FastAPI dependencies for authenticated request identities."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import Clock, SystemClock
from app.core.config import get_settings
from app.core.jwt import AuthenticatedUser, InvalidJWTError, validate_access_token
from app.db.repositories.profile import ProfileRepository
from app.db.session import create_db_engine, create_session_factory

_bearer_scheme = HTTPBearer(auto_error=False)


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
        return validate_access_token(credentials.credentials)
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
