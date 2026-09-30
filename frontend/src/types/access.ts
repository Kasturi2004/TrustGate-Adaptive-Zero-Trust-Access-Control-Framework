export type AccessDecision = "ALLOW" | "STEP_UP" | "BLOCK";

export interface AccessEvaluationResponse {
  evaluation_id: string;
  decision: AccessDecision;
  explanation: string;
  mfa_challenge_id: string | null;
}

export function isAccessEvaluationResponse(value: unknown): value is AccessEvaluationResponse {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const response = value as Record<string, unknown>;
  return (
    typeof response.evaluation_id === "string" &&
    (response.decision === "ALLOW" ||
      response.decision === "STEP_UP" ||
      response.decision === "BLOCK") &&
    typeof response.explanation === "string" &&
    (typeof response.mfa_challenge_id === "string" || response.mfa_challenge_id === null)
  );
}
