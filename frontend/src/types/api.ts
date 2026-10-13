export interface RiskIndicator {
  count: number;
  normalized_value: number;
  flagged: boolean;
}

export interface BehavioralRiskIndicators {
  repeated_failed_access_attempts: RiskIndicator;
  recent_blocks: RiskIndicator;
}

export interface DashboardMetrics {
  total_requests: number;
  allow_count: number;
  step_up_count: number;
  block_count: number;
  average_trust_score: number | null;
  high_risk_count: number;
  mfa_success_rate: number | null;
  behavioral_indicators: BehavioralRiskIndicators;
}

export interface SecurityEvent {
  id: string;
  event_type: string;
  created_at: string;
  user_id: string | null;
  decision: string | null;
  risk_category: string | null;
  trust_score: string | number | null;
  device: string | null;
}

export interface SecurityEventPage {
  items: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface Profile {
  id: string;
  email: string | null;
  role: "USER" | "ADMIN";
}

export interface InvestigationEvent {
  id: string;
  event_type: string;
  actor_id: string | null;
  target_user_id: string | null;
  decision: string | null;
  risk_category: string | null;
  created_at: string;
}

export interface Investigation {
  event: InvestigationEvent | null;
  access_request: {
    id: string;
    user_id: string;
    resource_id: string;
    source_ip: string;
    resolved_region: string | null;
    initial_decision: string;
    mfa_required: boolean;
    final_outcome: string | null;
    requested_at: string;
    resolved_at: string | null;
    device: { id: string; device_hash: string } | null;
  } | null;
  context_signals: {
    captured_at: string;
    device_familiarity_raw: string;
    device_health_raw: string;
    device_health_assessment_version?: string | null;
    device_health_assessment?: {
      version: "posture-v1";
      classification: "HEALTHY" | "PARTIAL" | "UNHEALTHY";
      score: string | number | null;
      complete: boolean;
      verified_evidence_count: number;
      total_evidence_count: number;
      reason_codes: string[];
      evidence: Array<{
        check: string;
        state: "PASS" | "FAIL" | "UNKNOWN";
        validation_status:
          | "VALID"
          | "UNVERIFIED"
          | "INVALID"
          | "STALE"
          | "WRONG_DEVICE"
          | "MALFORMED";
        observed_at: string | null;
        reason_code: string | null;
      }>;
    } | null;
    location_raw: string;
    time_raw: string;
  } | null;
  trust_evaluation: {
    id: string;
    trust_score: string | number;
    risk_classification: string;
    status: string;
    evaluated_at: string;
    factors: Array<{
      factor_name: string;
      raw_value: string;
      normalized_score: string | number;
      weight: string | number;
      weighted_contribution: string | number;
      explanation: string;
    }>;
  } | null;
  policy_decision: {
    id: string;
    decision: string;
    decision_reason: string;
    decided_at: string;
    policy_version: {
      id: string;
      version_label: string;
      created_at: string;
    } | null;
  } | null;
  otp_challenges: Array<{
    id: string;
    status: string;
    attempt_count: number;
    created_at: string;
    expires_at: string;
    verified_at: string | null;
  }>;
  related_events: InvestigationEvent[];
  behavioral_indicators: BehavioralRiskIndicators | null;
}
