export interface AccessHistoryEntry {
  id: string;
  resource_id: string;
  requested_at: string;
  initial_decision: string;
  final_outcome: string | null;
  mfa_was_required: boolean;
  mfa_status: string | null;
}

const ALLOWED_FIELDS = [
  "id",
  "resource_id",
  "requested_at",
  "initial_decision",
  "final_outcome",
  "mfa_was_required",
  "mfa_status",
] as const;

export function parseAccessHistoryEntry(value: unknown): AccessHistoryEntry {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Access history response was not recognized");
  }

  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== ALLOWED_FIELDS.length ||
    ALLOWED_FIELDS.some((field) => !(field in record)) ||
    typeof record.id !== "string" ||
    typeof record.resource_id !== "string" ||
    typeof record.requested_at !== "string" ||
    !Number.isFinite(Date.parse(record.requested_at)) ||
    typeof record.initial_decision !== "string" ||
    (typeof record.final_outcome !== "string" && record.final_outcome !== null) ||
    typeof record.mfa_was_required !== "boolean" ||
    (typeof record.mfa_status !== "string" && record.mfa_status !== null)
  ) {
    throw new Error("Access history response was not recognized");
  }

  return {
    id: record.id,
    resource_id: record.resource_id,
    requested_at: record.requested_at,
    initial_decision: record.initial_decision,
    final_outcome: record.final_outcome,
    mfa_was_required: record.mfa_was_required,
    mfa_status: record.mfa_status,
  };
}

export function parseAccessHistoryResponse(value: unknown): AccessHistoryEntry[] {
  if (!Array.isArray(value)) {
    throw new Error("Access history response was not recognized");
  }
  return value.map(parseAccessHistoryEntry);
}
