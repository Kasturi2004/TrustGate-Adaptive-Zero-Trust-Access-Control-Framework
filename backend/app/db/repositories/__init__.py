"""Async SQLAlchemy repositories for TrustGate persistence."""

from app.db.repositories.access_request import AccessRequestRepository
from app.db.repositories.context_signal import ContextSignalRepository
from app.db.repositories.device import DeviceRepository
from app.db.repositories.otp_challenge import OtpChallengeRepository
from app.db.repositories.policy_decision import PolicyDecisionRepository
from app.db.repositories.policy_version import PolicyVersionRepository
from app.db.repositories.profile import ProfileRepository
from app.db.repositories.rate_limit_state import RateLimitStateRepository
from app.db.repositories.security_event import SecurityEventRepository
from app.db.repositories.trust_evaluation import TrustEvaluationRepository
from app.db.repositories.trust_factor import TrustFactorRepository

__all__ = [
    "AccessRequestRepository",
    "ContextSignalRepository",
    "DeviceRepository",
    "OtpChallengeRepository",
    "PolicyDecisionRepository",
    "PolicyVersionRepository",
    "ProfileRepository",
    "RateLimitStateRepository",
    "SecurityEventRepository",
    "TrustEvaluationRepository",
    "TrustFactorRepository",
]
