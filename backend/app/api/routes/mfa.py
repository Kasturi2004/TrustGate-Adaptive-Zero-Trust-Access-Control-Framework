"""Authenticated MFA enrollment routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_clock, get_db_session, require_user
from app.core.clock import Clock
from app.core.mfa_secrets import decrypt_totp_secret, encrypt_totp_secret
from app.db.models.mfa_credential import MfaCredential
from app.db.repositories.mfa_credential import MfaCredentialRepository
from app.schemas.mfa import (
    TotpEnrollmentStartResponse,
    TotpEnrollmentVerificationRequest,
    TotpEnrollmentVerificationResponse,
)
from app.services.security_events import record_event
from app.services.totp import (
    generate_totp_provisioning_uri,
    generate_totp_secret,
    verify_totp_code,
)

router = APIRouter(prefix="/auth/mfa", tags=["mfa"])

_ENROLLMENT_ALREADY_ENABLED = "MFA enrollment cannot be started."
_SAFE_FAILURE = "An unexpected error occurred."
_VERIFICATION_FAILED = "MFA enrollment verification failed."


@router.post(
    "/totp/enrollment",
    response_model=TotpEnrollmentStartResponse,
    status_code=status.HTTP_200_OK,
)
async def start_totp_enrollment(
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> TotpEnrollmentStartResponse:
    """Create or restart pending TOTP enrollment for the authenticated profile."""
    try:
        repository = MfaCredentialRepository(session)
        credential = await repository.get_by_user_id_for_update(principal.id)
        if credential is not None and credential.enabled:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_ENROLLMENT_ALREADY_ENABLED,
            )
        if credential is not None and credential.verified_at is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_ENROLLMENT_ALREADY_ENABLED,
            )

        secret = generate_totp_secret()
        ciphertext = encrypt_totp_secret(secret)
        account_label = principal.email or str(principal.id)
        provisioning_uri = generate_totp_provisioning_uri(secret, account_label)

        if credential is None:
            credential = MfaCredential(
                user_id=principal.id,
                secret_ciphertext=ciphertext,
                verified_at=None,
                enabled=False,
            )
            repository.add(credential)
        else:
            credential.secret_ciphertext = ciphertext
            credential.verified_at = None
            credential.enabled = False

        await session.flush()
        record_event(
            session,
            event_type="MFA_TOTP_ENROLLMENT_STARTED",
            actor_id=principal.id,
            details={},
        )
        await session.commit()
    except HTTPException:
        raise
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_SAFE_FAILURE,
        ) from None

    response.headers["Cache-Control"] = "no-store"
    return TotpEnrollmentStartResponse(
        otpauth_uri=provisioning_uri,
        manual_entry_key=secret,
    )


@router.post(
    "/totp/enrollment/verify",
    response_model=TotpEnrollmentVerificationResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_totp_enrollment(
    request: TotpEnrollmentVerificationRequest,
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> TotpEnrollmentVerificationResponse:
    """Verify a pending authenticator and enable it for the authenticated profile."""
    try:
        repository = MfaCredentialRepository(session)
        credential = await repository.get_by_user_id_for_update(principal.id)
        if credential is None:
            record_event(
                session,
                event_type="MFA_TOTP_ENROLLMENT_VERIFICATION_FAILED",
                actor_id=principal.id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_VERIFICATION_FAILED,
            )
        if credential.enabled or credential.verified_at is not None:
            record_event(
                session,
                event_type="MFA_TOTP_ENROLLMENT_VERIFICATION_FAILED",
                actor_id=principal.id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_VERIFICATION_FAILED,
            )

        verified_at = clock.now()
        try:
            secret = decrypt_totp_secret(credential.secret_ciphertext)
            is_valid = verify_totp_code(secret, request.code, for_time=verified_at)
        except Exception:
            is_valid = False

        if not is_valid:
            record_event(
                session,
                event_type="MFA_TOTP_ENROLLMENT_VERIFICATION_FAILED",
                actor_id=principal.id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_VERIFICATION_FAILED,
            )

        credential.verified_at = verified_at
        credential.enabled = True
        await session.flush()
        record_event(
            session,
            event_type="MFA_TOTP_ENROLLMENT_VERIFICATION_SUCCEEDED",
            actor_id=principal.id,
            details={},
        )
        await session.commit()
    except HTTPException:
        raise
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=_SAFE_FAILURE,
        ) from None

    response.headers["Cache-Control"] = "no-store"
    return TotpEnrollmentVerificationResponse(
        enrollment_status="verified",
        verified_at=verified_at,
    )
