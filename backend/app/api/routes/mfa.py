"""Authenticated MFA enrollment routes."""

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthenticatedPrincipal, get_clock, get_db_session, require_user
from app.core.client_ip import resolve_client_ip
from app.core.clock import Clock
from app.core.mfa_secrets import decrypt_totp_secret, encrypt_totp_secret
from app.core.rate_limit import mfa_ip_rate_limit_key, mfa_user_rate_limit_key
from app.db.models.mfa_credential import MfaCredential
from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.mfa_credential import MfaCredentialRepository
from app.db.repositories.otp_challenge import OtpChallengeRepository
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.schemas.mfa import (
    TotpEnrollmentStartResponse,
    TotpEnrollmentVerificationRequest,
    TotpEnrollmentVerificationResponse,
    TotpStepUpVerificationRequest,
    TotpStepUpVerificationResponse,
)
from app.services.security_events import record_event
from app.services.totp import (
    generate_totp_provisioning_uri,
    generate_totp_secret,
    verify_totp_time_step,
)

router = APIRouter(prefix="/auth/mfa", tags=["mfa"])

_ENROLLMENT_ALREADY_ENABLED = "MFA enrollment cannot be started."
_SAFE_FAILURE = "An unexpected error occurred."
_VERIFICATION_FAILED = "MFA enrollment verification failed."
_RATE_LIMITED = "Too many requests. Please try again later."
_RATE_LIMIT_UNAVAILABLE = "MFA verification is temporarily unavailable."
_STEP_UP_VERIFICATION_FAILED = "MFA verification failed."


async def _consume_verification_rate_limits(
    http_request: Request,
    principal: AuthenticatedPrincipal,
    session: AsyncSession,
    now: datetime,
) -> None:
    """Apply the shared persistent MFA user and IP limits before code checks."""
    try:
        ip_address = resolve_client_ip(http_request)
        rate_limits = [
            (mfa_user_rate_limit_key(principal.id, window="15m"), 5, timedelta(minutes=15)),
            (mfa_user_rate_limit_key(principal.id, window="24h"), 10, timedelta(hours=24)),
            (mfa_ip_rate_limit_key(ip_address), 60, timedelta(minutes=15)),
        ]
        rate_limit_repository = RateLimitStateRepository(session)
        admitted = True
        for key, attempt_limit, window_duration in sorted(rate_limits, key=lambda item: item[0]):
            key_admitted = await rate_limit_repository.consume_attempt(
                key,
                now,
                attempt_limit=attempt_limit,
                window_duration=window_duration,
            )
            admitted = admitted and key_admitted
        await session.commit()
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_RATE_LIMIT_UNAVAILABLE,
            headers={"Cache-Control": "no-store"},
        ) from None

    if not admitted:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_RATE_LIMITED,
            headers={"Cache-Control": "no-store"},
        )


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
            credential.last_accepted_time_step = None

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
    http_request: Request,
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> TotpEnrollmentVerificationResponse:
    """Verify a pending authenticator and enable it for the authenticated profile."""
    now = clock.now()
    await _consume_verification_rate_limits(http_request, principal, session, now)

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
        matched_time_step: int | None = None
        try:
            secret = decrypt_totp_secret(credential.secret_ciphertext)
            matched_time_step = verify_totp_time_step(secret, request.code, for_time=verified_at)
        except Exception:
            matched_time_step = None

        if matched_time_step is None:
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
        credential.last_accepted_time_step = matched_time_step
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


@router.post(
    "/totp/step-up/verify",
    response_model=TotpStepUpVerificationResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_totp_step_up(
    request: TotpStepUpVerificationRequest,
    http_request: Request,
    response: Response,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_user)],
    session: Annotated[AsyncSession, Depends(get_db_session)],
    clock: Annotated[Clock, Depends(get_clock)],
) -> TotpStepUpVerificationResponse:
    """Verify TOTP for one pending STEP_UP challenge owned by the principal."""
    response.headers["Cache-Control"] = "no-store"
    now = clock.now()
    await _consume_verification_rate_limits(http_request, principal, session, now)

    try:
        challenge = await OtpChallengeRepository(session).get_step_up_for_user_for_update(
            request.mfa_challenge_id, principal.id
        )
        if challenge is None:
            record_event(
                session,
                event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                actor_id=principal.id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_STEP_UP_VERIFICATION_FAILED,
                headers={"Cache-Control": "no-store"},
            )

        if challenge.status != "PENDING":
            record_event(
                session,
                event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                actor_id=principal.id,
                access_request_id=challenge.access_request_id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_STEP_UP_VERIFICATION_FAILED,
                headers={"Cache-Control": "no-store"},
            )

        if challenge.expires_at <= now:
            challenge.status = "EXPIRED"
            record_event(
                session,
                event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                actor_id=principal.id,
                access_request_id=challenge.access_request_id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_STEP_UP_VERIFICATION_FAILED,
                headers={"Cache-Control": "no-store"},
            )

        if challenge.attempt_count >= challenge.max_attempts:
            challenge.status = "LOCKED"
            record_event(
                session,
                event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                actor_id=principal.id,
                access_request_id=challenge.access_request_id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_STEP_UP_VERIFICATION_FAILED,
                headers={"Cache-Control": "no-store"},
            )

        credential = await MfaCredentialRepository(session).get_by_user_id_for_update(principal.id)
        matched_time_step: int | None = None
        if credential is not None and credential.enabled and credential.verified_at is not None:
            try:
                secret = decrypt_totp_secret(credential.secret_ciphertext)
                matched_time_step = verify_totp_time_step(secret, request.code, for_time=now)
            except Exception:
                matched_time_step = None

        if matched_time_step is None or (
            credential is not None
            and credential.last_accepted_time_step is not None
            and matched_time_step <= credential.last_accepted_time_step
        ):
            challenge.attempt_count += 1
            if challenge.attempt_count >= challenge.max_attempts:
                challenge.status = "LOCKED"
            record_event(
                session,
                event_type="MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
                actor_id=principal.id,
                access_request_id=challenge.access_request_id,
                details={},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_STEP_UP_VERIFICATION_FAILED,
                headers={"Cache-Control": "no-store"},
            )

        assert credential is not None
        assert matched_time_step is not None
        credential.last_accepted_time_step = matched_time_step
        challenge.status = "SUCCESS"
        challenge.verified_at = now
        await session.flush()
        resolved_request = await AccessRequestRepository(session).resolve_step_up(
            challenge.access_request_id,
            principal.id,
            now,
        )
        if resolved_request is None:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_STEP_UP_VERIFICATION_FAILED,
                headers={"Cache-Control": "no-store"},
            )
        record_event(
            session,
            event_type="MFA_TOTP_STEP_UP_VERIFICATION_SUCCEEDED",
            actor_id=principal.id,
            access_request_id=challenge.access_request_id,
            details={},
        )
        record_event(
            session,
            event_type="ACCESS_MFA_ALLOWED",
            actor_id=principal.id,
            access_request_id=challenge.access_request_id,
            decision="ALLOW",
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
            headers={"Cache-Control": "no-store"},
        ) from None

    response.headers["Cache-Control"] = "no-store"
    return TotpStepUpVerificationResponse(
        verification_status="verified",
        verified_at=now,
    )
