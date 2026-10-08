"""Authenticated current-device familiarity operations."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_clock, get_db_session, require_user
from app.core.clock import Clock
from app.core.config import Settings, get_settings
from app.db.repositories.device import DeviceRepository
from app.schemas.device import DeviceRecognitionRequest, DeviceRecognitionStatus
from app.services.context.device_familiarity import device_token_hash

router = APIRouter(prefix="/devices", tags=["devices"])
_SAFE_FAILURE = "Device recognition is temporarily unavailable. Please try again."


def _current_device_hash(device_token: str, settings: Settings) -> str:
    try:
        value = device_token_hash(device_token, settings=settings)
    except Exception:
        value = None
    if value is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_SAFE_FAILURE)
    return value


@router.get("/current", response_model=DeviceRecognitionStatus)
async def get_current_device_status(
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    device_token: Annotated[str, Header(alias="X-Device-Token", min_length=1)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> DeviceRecognitionStatus:
    """Return only whether this user's current browser identifier is recognized."""
    response.headers["Cache-Control"] = "no-store"
    device_hash = _current_device_hash(device_token, settings)
    try:
        device = await DeviceRepository(session).get_by_user_and_hash(principal.id, device_hash)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_SAFE_FAILURE
        ) from None
    return DeviceRecognitionStatus(
        recognized=device is not None and device.recognized_at is not None
    )


@router.post("/recognition", response_model=DeviceRecognitionStatus)
async def recognize_current_device(
    payload: DeviceRecognitionRequest,
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    device_token: Annotated[str, Header(alias="X-Device-Token", min_length=1)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> DeviceRecognitionStatus:
    """Recognize only this browser's device after its current-session request was redeemed."""
    response.headers["Cache-Control"] = "no-store"
    device_hash = _current_device_hash(device_token, settings)
    try:
        repository = DeviceRepository(session)
        device = await repository.get_recognizable_device(
            access_request_id=payload.access_request_id,
            user_id=principal.id,
            auth_session_id=principal.session_id,
            device_hash=device_hash,
        )
        if device is None:
            await session.rollback()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_SAFE_FAILURE)
        await repository.set_recognized_at_if_unknown(device, clock.now())
        await session.commit()
    except HTTPException:
        raise
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_SAFE_FAILURE
        ) from None
    return DeviceRecognitionStatus(recognized=True)


@router.delete("/current/recognition", response_model=DeviceRecognitionStatus)
async def forget_current_device(
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    device_token: Annotated[str, Header(alias="X-Device-Token", min_length=1)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> DeviceRecognitionStatus:
    """Clear recognition for this user's current browser while preserving its history row."""
    response.headers["Cache-Control"] = "no-store"
    device_hash = _current_device_hash(device_token, settings)
    try:
        device = await DeviceRepository(session).get_by_user_and_hash(principal.id, device_hash)
        if device is not None and device.recognized_at is not None:
            device.recognized_at = None
            await session.commit()
        else:
            await session.rollback()
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_SAFE_FAILURE
        ) from None
    return DeviceRecognitionStatus(recognized=False)
