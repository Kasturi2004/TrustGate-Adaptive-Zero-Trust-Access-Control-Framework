export interface AdminDashboard {
  total_requests: number;
  allow_count: number;
  step_up_count: number;
  block_count: number;
  average_trust_score: number | null;
  high_risk_count: number;
  mfa_success_rate: number | null;
}

export interface AdminSecurityEvent {
  id: string;
  event_type: string;
  created_at: string;
  user_id: string | null;
  decision: string | null;
  risk_category: string | null;
  trust_score: number | null;
  device: string | null;
}

export interface AdminEventPage {
  items: AdminSecurityEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface AdminEventFilters {
  from?: string;
  to?: string;
  user_id?: string;
  decision?: string;
  risk_category?: string;
  device_id?: string;
  score_min?: string;
  score_max?: string;
  page?: number;
  page_size?: number;
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

export interface InvestigationDevice {
  id: string;
  device_hash: string;
}

export interface InvestigationRequest {
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
  device: InvestigationDevice | null;
}

export interface InvestigationContext {
  captured_at: string;
  device_familiarity_raw: string;
  device_health_raw: string;
  location_raw: string;
  time_raw: string;
}

export interface InvestigationFactor {
  factor_name: string;
  raw_value: string;
  normalized_score: number;
  weight: number;
  weighted_contribution: number;
  explanation: string;
}

export interface InvestigationTrustEvaluation {
  id: string;
  trust_score: number;
  risk_classification: string;
  status: string;
  evaluated_at: string;
  factors: InvestigationFactor[];
}

export interface InvestigationPolicyVersion {
  id: string;
  version_label: string;
  created_at: string;
}

export interface InvestigationPolicyDecision {
  id: string;
  decision: string;
  decision_reason: string;
  decided_at: string;
  policy_version: InvestigationPolicyVersion | null;
}

export interface InvestigationOtpChallenge {
  id: string;
  status: string;
  attempt_count: number;
  created_at: string;
  expires_at: string;
  verified_at: string | null;
}

export interface AdminEventInvestigation {
  event: InvestigationEvent | null;
  access_request: InvestigationRequest | null;
  context_signals: InvestigationContext | null;
  trust_evaluation: InvestigationTrustEvaluation | null;
  policy_decision: InvestigationPolicyDecision | null;
  otp_challenges: InvestigationOtpChallenge[];
  related_events: InvestigationEvent[];
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Admin response was not recognized");
  }
  return value as Record<string, unknown>;
}

function string(value: unknown): value is string;
function string(value: unknown, nullable: true): value is string | null;
function string(value: unknown, nullable = false): value is string | null {
  return typeof value === "string" || (nullable && value === null);
}

function finiteNumber(value: unknown): value is number;
function finiteNumber(value: unknown, nullable: true): value is number | null;
function finiteNumber(value: unknown, nullable = false): value is number | null {
  return (typeof value === "number" && Number.isFinite(value)) || (nullable && value === null);
}

function decimalNumber(value: unknown): number | undefined;
function decimalNumber(value: unknown, nullable: true): number | null | undefined;
function decimalNumber(value: unknown, nullable = false): number | null | undefined {
  if (value === null && nullable) return null;
  const parsed = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof parsed === "number" && Number.isFinite(parsed) ? parsed : undefined;
}

function timestamp(value: unknown): value is string;
function timestamp(value: unknown, nullable: true): value is string | null;
function timestamp(value: unknown, nullable = false): value is string | null {
  return typeof value === "string"
    ? Number.isFinite(Date.parse(value))
    : nullable && value === null;
}

export function parseAdminDashboard(value: unknown): AdminDashboard {
  const data = record(value);
  const numericFields = [
    "total_requests",
    "allow_count",
    "step_up_count",
    "block_count",
    "high_risk_count",
  ] as const;
  if (
    numericFields.some((field) => !Number.isInteger(data[field]) || (data[field] as number) < 0) ||
    !finiteNumber(data.average_trust_score, true) ||
    !finiteNumber(data.mfa_success_rate, true)
  ) {
    throw new Error("Admin dashboard response was not recognized");
  }
  return {
    total_requests: data.total_requests as number,
    allow_count: data.allow_count as number,
    step_up_count: data.step_up_count as number,
    block_count: data.block_count as number,
    average_trust_score: data.average_trust_score,
    high_risk_count: data.high_risk_count as number,
    mfa_success_rate: data.mfa_success_rate,
  };
}

function parseEvent(value: unknown): AdminSecurityEvent {
  const data = record(value);
  const trustScore = decimalNumber(data.trust_score, true);
  if (
    !string(data.id) ||
    !string(data.event_type) ||
    !timestamp(data.created_at) ||
    !string(data.user_id, true) ||
    !string(data.decision, true) ||
    !string(data.risk_category, true) ||
    trustScore === undefined ||
    !string(data.device, true)
  ) {
    throw new Error("Admin event response was not recognized");
  }
  return {
    id: data.id,
    event_type: data.event_type,
    created_at: data.created_at,
    user_id: data.user_id,
    decision: data.decision,
    risk_category: data.risk_category,
    trust_score: trustScore,
    device: data.device,
  };
}

export function parseAdminEventPage(value: unknown): AdminEventPage {
  const data = record(value);
  if (
    !Array.isArray(data.items) ||
    !Number.isInteger(data.total) ||
    !Number.isInteger(data.page) ||
    !Number.isInteger(data.page_size)
  ) {
    throw new Error("Admin event page response was not recognized");
  }
  return {
    items: data.items.map(parseEvent),
    total: data.total as number,
    page: data.page as number,
    page_size: data.page_size as number,
  };
}

function parseInvestigationEvent(value: unknown): InvestigationEvent {
  const data = record(value);
  if (
    !string(data.id) ||
    !string(data.event_type) ||
    !string(data.actor_id, true) ||
    !string(data.target_user_id, true) ||
    !string(data.decision, true) ||
    !string(data.risk_category, true) ||
    !timestamp(data.created_at)
  ) {
    throw new Error("Investigation event response was not recognized");
  }
  return {
    id: data.id,
    event_type: data.event_type,
    actor_id: data.actor_id,
    target_user_id: data.target_user_id,
    decision: data.decision,
    risk_category: data.risk_category,
    created_at: data.created_at,
  };
}

function parseInvestigationRequest(value: unknown): InvestigationRequest {
  const data = record(value);
  if (
    !string(data.id) ||
    !string(data.user_id) ||
    !string(data.resource_id) ||
    !string(data.source_ip) ||
    !string(data.resolved_region, true) ||
    !string(data.initial_decision) ||
    typeof data.mfa_required !== "boolean" ||
    !string(data.final_outcome, true) ||
    !timestamp(data.requested_at) ||
    !timestamp(data.resolved_at, true)
  ) {
    throw new Error("Investigation request response was not recognized");
  }
  let device: InvestigationDevice | null = null;
  if (data.device !== null) {
    const deviceData = record(data.device);
    if (!string(deviceData.id) || !string(deviceData.device_hash)) {
      throw new Error("Investigation device response was not recognized");
    }
    device = { id: deviceData.id, device_hash: deviceData.device_hash };
  }
  return {
    id: data.id,
    user_id: data.user_id,
    resource_id: data.resource_id,
    source_ip: data.source_ip,
    resolved_region: data.resolved_region,
    initial_decision: data.initial_decision,
    mfa_required: data.mfa_required,
    final_outcome: data.final_outcome,
    requested_at: data.requested_at,
    resolved_at: data.resolved_at,
    device,
  };
}

export function parseAdminInvestigation(value: unknown): AdminEventInvestigation {
  const data = record(value);
  if (
    !(data.event === null || typeof data.event === "object") ||
    !(data.access_request === null || typeof data.access_request === "object") ||
    !(data.context_signals === null || typeof data.context_signals === "object") ||
    !(data.trust_evaluation === null || typeof data.trust_evaluation === "object") ||
    !(data.policy_decision === null || typeof data.policy_decision === "object") ||
    !Array.isArray(data.otp_challenges) ||
    !Array.isArray(data.related_events)
  ) {
    throw new Error("Admin investigation response was not recognized");
  }

  const context = data.context_signals === null ? null : record(data.context_signals);
  let contextSignals: InvestigationContext | null = null;
  if (context !== null) {
    const fields = [
      "device_familiarity_raw",
      "device_health_raw",
      "location_raw",
      "time_raw",
    ] as const;
    if (!timestamp(context.captured_at) || fields.some((field) => !string(context[field]))) {
      throw new Error("Investigation context response was not recognized");
    }
    contextSignals = {
      captured_at: context.captured_at,
      device_familiarity_raw: context.device_familiarity_raw as string,
      device_health_raw: context.device_health_raw as string,
      location_raw: context.location_raw as string,
      time_raw: context.time_raw as string,
    };
  }

  let trustEvaluation: InvestigationTrustEvaluation | null = null;
  if (data.trust_evaluation !== null) {
    const evaluation = record(data.trust_evaluation);
    const trustScore = decimalNumber(evaluation.trust_score);
    if (
      !string(evaluation.id) ||
      trustScore === undefined ||
      !string(evaluation.risk_classification) ||
      !string(evaluation.status) ||
      !timestamp(evaluation.evaluated_at) ||
      !Array.isArray(evaluation.factors)
    ) {
      throw new Error("Investigation evaluation response was not recognized");
    }
    const factors = evaluation.factors.map((factor) => {
      const item = record(factor);
      const normalizedScore = decimalNumber(item.normalized_score);
      const weight = decimalNumber(item.weight);
      const weightedContribution = decimalNumber(item.weighted_contribution);
      if (
        !string(item.factor_name) ||
        !string(item.raw_value) ||
        normalizedScore === undefined ||
        weight === undefined ||
        weightedContribution === undefined ||
        !string(item.explanation)
      ) {
        throw new Error("Investigation factor response was not recognized");
      }
      return {
        factor_name: item.factor_name,
        raw_value: item.raw_value,
        normalized_score: normalizedScore,
        weight,
        weighted_contribution: weightedContribution,
        explanation: item.explanation,
      };
    });
    trustEvaluation = {
      id: evaluation.id,
      trust_score: trustScore,
      risk_classification: evaluation.risk_classification,
      status: evaluation.status,
      evaluated_at: evaluation.evaluated_at,
      factors,
    };
  }

  let policyDecision: InvestigationPolicyDecision | null = null;
  if (data.policy_decision !== null) {
    const policy = record(data.policy_decision);
    if (
      !string(policy.id) ||
      !string(policy.decision) ||
      !string(policy.decision_reason) ||
      !timestamp(policy.decided_at)
    ) {
      throw new Error("Investigation policy response was not recognized");
    }
    let policyVersion: InvestigationPolicyVersion | null = null;
    if (policy.policy_version !== null) {
      const version = record(policy.policy_version);
      if (!string(version.id) || !string(version.version_label) || !timestamp(version.created_at)) {
        throw new Error("Investigation policy version response was not recognized");
      }
      policyVersion = {
        id: version.id,
        version_label: version.version_label,
        created_at: version.created_at,
      };
    }
    policyDecision = {
      id: policy.id,
      decision: policy.decision,
      decision_reason: policy.decision_reason,
      decided_at: policy.decided_at,
      policy_version: policyVersion,
    };
  }

  const challenges = data.otp_challenges.map((challenge) => {
    const item = record(challenge);
    if (
      !string(item.id) ||
      !string(item.status) ||
      !Number.isInteger(item.attempt_count) ||
      !timestamp(item.created_at) ||
      !timestamp(item.expires_at) ||
      !timestamp(item.verified_at, true)
    ) {
      throw new Error("OTP challenge response was not recognized");
    }
    return {
      id: item.id,
      status: item.status,
      attempt_count: item.attempt_count as number,
      created_at: item.created_at,
      expires_at: item.expires_at,
      verified_at: item.verified_at,
    };
  });

  return {
    event: data.event === null ? null : parseInvestigationEvent(data.event),
    access_request:
      data.access_request === null ? null : parseInvestigationRequest(data.access_request),
    context_signals: contextSignals,
    trust_evaluation: trustEvaluation,
    policy_decision: policyDecision,
    otp_challenges: challenges,
    related_events: data.related_events.map(parseInvestigationEvent),
  };
}
