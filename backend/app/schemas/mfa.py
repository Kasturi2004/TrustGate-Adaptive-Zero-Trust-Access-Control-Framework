"""Response schemas for MFA authenticator setup."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StringConstraints


class TotpEnrollmentStartResponse(BaseModel):
    """One-time provisioning material for an authenticated TOTP enrollment."""

    model_config = ConfigDict(extra="forbid")

    otpauth_uri: str
    manual_entry_key: str


class TotpEnrollmentVerificationRequest(BaseModel):
    """The single six-digit authenticator code submitted for enrollment."""

    model_config = ConfigDict(extra="forbid")

    code: Annotated[
        str,
        StringConstraints(strict=True, min_length=6, max_length=6, pattern=r"^[0-9]{6}$"),
    ]


class TotpEnrollmentVerificationResponse(BaseModel):
    """Confirmation that authenticator enrollment was verified."""

    model_config = ConfigDict(extra="forbid")

    enrollment_status: Literal["verified"]
    verified_at: datetime


class TotpStepUpVerificationRequest(BaseModel):
    """Challenge identifier and strict six-digit authenticator code."""

    model_config = ConfigDict(extra="forbid")

    mfa_challenge_id: UUID
    code: Annotated[
        str,
        StringConstraints(strict=True, min_length=6, max_length=6, pattern=r"^[0-9]{6}$"),
    ]


class TotpStepUpVerificationResponse(BaseModel):
    """Confirmation that a pending STEP_UP challenge passed TOTP verification."""

    model_config = ConfigDict(extra="forbid")

    verification_status: Literal["verified"]
    verified_at: datetime
