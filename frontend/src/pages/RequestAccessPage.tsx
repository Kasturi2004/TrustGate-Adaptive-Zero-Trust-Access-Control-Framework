import { useState } from "react";
import { apiRequest } from "../api/client.ts";
import { isAccessEvaluationResponse, type AccessEvaluationResponse } from "../types/access.ts";

const RESOURCE_ID = "ops-dashboard";
const SAFE_ERROR = "We couldn't complete the access request. Please try again.";

export function RequestAccessPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evaluation, setEvaluation] = useState<AccessEvaluationResponse | null>(null);

  const requestAccess = async () => {
    setLoading(true);
    setError(null);
    setEvaluation(null);

    try {
      // Phase 5 demo token only; Phase 6 will supply the real device identity.
      const deviceToken = `phase5-demo-${crypto.randomUUID()}`;
      const response = await apiRequest("/access/evaluate", {
        method: "POST",
        body: { resource_id: RESOURCE_ID },
        headers: { "X-Device-Token": deviceToken },
      });

      if (!response.ok) {
        throw new Error("Access request failed");
      }

      const body: unknown = await response.json();
      if (!isAccessEvaluationResponse(body)) {
        throw new Error("Access response was invalid");
      }

      setEvaluation(body);
    } catch {
      setError(SAFE_ERROR);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="panel access-request-panel" aria-labelledby="access-request-title">
      <h1 id="access-request-title">Request Access</h1>
      <p className="lede">
        Request access to <strong>Operations Dashboard</strong>.
      </p>
      <p className="access-resource-id">
        Resource ID: <code>{RESOURCE_ID}</code>
      </p>
      <button
        className="login-submit access-request-button"
        type="button"
        onClick={requestAccess}
        disabled={loading}
      >
        {loading ? "Requesting access…" : "Request Access"}
      </button>

      {error && (
        <p className="login-error" role="alert">
          {error}
        </p>
      )}

      {evaluation && (
        <section className="access-result" aria-live="polite">
          {evaluation.decision === "ALLOW" && (
            <h2 className="access-result-allow">Access allowed</h2>
          )}
          {evaluation.decision === "STEP_UP" && <h2>Additional verification required</h2>}
          {evaluation.decision === "BLOCK" && <h2>Access blocked</h2>}
          <p>{evaluation.explanation}</p>
          {evaluation.decision === "ALLOW" && (
            <p>
              Evaluation ID: <code>{evaluation.evaluation_id}</code>
            </p>
          )}
          {evaluation.decision === "STEP_UP" && evaluation.mfa_challenge_id !== null && (
            <p>An MFA challenge was created. Verification will be available in a later phase.</p>
          )}
        </section>
      )}
    </section>
  );
}
