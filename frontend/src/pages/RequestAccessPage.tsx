import { useRef, useState, type FormEvent } from "react";
import { apiRequest } from "../api/client.ts";
import { DecisionPresentation } from "../components/DecisionPresentation.tsx";
import { isAccessEvaluationResponse, type AccessEvaluationResponse } from "../types/access.ts";

const RESOURCE_ID = "ops-dashboard";
const SAFE_ERROR = "We couldn't complete the access request. Please try again.";
const MFA_SAFE_ERROR = "Verification could not be completed. Please try again.";

function isSuccessfulTotpVerification(value: unknown): boolean {
  if (typeof value !== "object" || value === null || !("verification_status" in value)) {
    return false;
  }

  if (!("verified_at" in value)) return false;
  const verifiedAt = value.verified_at;
  return (
    value.verification_status === "verified" &&
    typeof verifiedAt === "string" &&
    Number.isFinite(Date.parse(verifiedAt))
  );
}

export function RequestAccessPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evaluation, setEvaluation] = useState<AccessEvaluationResponse | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpError, setTotpError] = useState<string | null>(null);
  const [verifyingTotp, setVerifyingTotp] = useState(false);
  const [totpVerified, setTotpVerified] = useState(false);
  const verificationInFlight = useRef(false);

  const submitTotpCode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (verificationInFlight.current) return;

    if (!/^[0-9]{6}$/.test(totpCode)) {
      setTotpError("Enter a six-digit authenticator code.");
      return;
    }

    const challengeId = evaluation?.mfa_challenge_id;
    if (evaluation?.decision !== "STEP_UP" || !challengeId) {
      setTotpError(MFA_SAFE_ERROR);
      setTotpCode("");
      return;
    }

    verificationInFlight.current = true;
    setVerifyingTotp(true);
    setTotpError(null);

    try {
      const response = await apiRequest("/auth/mfa/totp/step-up/verify", {
        method: "POST",
        body: { mfa_challenge_id: challengeId, code: totpCode },
      });
      if (!response.ok) throw new Error("MFA verification failed");

      const body: unknown = await response.json();
      if (!isSuccessfulTotpVerification(body)) throw new Error("MFA response was invalid");

      setTotpVerified(true);
    } catch {
      setTotpError(MFA_SAFE_ERROR);
    } finally {
      setTotpCode("");
      setVerifyingTotp(false);
      verificationInFlight.current = false;
    }
  };

  const requestAccess = async () => {
    setLoading(true);
    setError(null);
    setEvaluation(null);
    setTotpCode("");
    setTotpError(null);
    setVerifyingTotp(false);
    setTotpVerified(false);

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
    <div className="request-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">Access gateway</span>
          <h1 id="access-request-title">Request protected access</h1>
          <p>TrustGate will evaluate your request before access is approved.</p>
        </div>
      </header>
      <div className="request-layout">
        <section className="panel access-request-panel" aria-labelledby="request-resource-title">
          <div className="request-section-heading">
            <span className="request-section-number">01</span>
            <div>
              <h2 id="request-resource-title">Protected resource</h2>
              <p>Choose a resource for this access request.</p>
            </div>
          </div>
          <div className="request-resource-card">
            <span className="request-resource-icon" aria-hidden="true">
              ▧
            </span>
            <span>
              <strong>Operations Dashboard</strong>
              <small>Protected TrustGate resource</small>
            </span>
            <span className="resource-lock" aria-label="Protected">
              ◆
            </span>
          </div>
          <p className="access-resource-id">
            Resource ID <code>{RESOURCE_ID}</code>
          </p>
          <div className="request-safety-note">
            <span aria-hidden="true">◇</span>
            <p>The backend evaluates the request and returns the access decision.</p>
          </div>
          <button
            className="login-submit access-request-button"
            type="button"
            onClick={requestAccess}
            disabled={loading || verifyingTotp}
          >
            {loading ? "Requesting access…" : "Request Access"}
            <span aria-hidden="true">→</span>
          </button>

          {error && (
            <p className="login-error" role="alert">
              {error}
            </p>
          )}

          {evaluation && (
            <DecisionPresentation
              evaluation={evaluation}
              totpCode={totpCode}
              totpError={totpError}
              verifyingTotp={verifyingTotp}
              totpVerified={totpVerified}
              onTotpCodeChange={(code) => {
                setTotpCode(code);
                setTotpError(null);
              }}
              onTotpSubmit={submitTotpCode}
            />
          )}
        </section>
        <aside className="request-explanation">
          <span className="page-eyebrow">How it works</span>
          <h2>Authentication is only the first check.</h2>
          <p>
            Each request is evaluated by TrustGate before the protected resource can be accessed.
          </p>
          <ol>
            <li>
              <span>1</span>
              <div>
                <strong>Submit request</strong>
                <small>Your request is sent to the access gateway.</small>
              </div>
            </li>
            <li>
              <span>2</span>
              <div>
                <strong>Backend evaluation</strong>
                <small>The backend determines the authorization decision.</small>
              </div>
            </li>
            <li>
              <span>3</span>
              <div>
                <strong>View decision</strong>
                <small>The result explains the next safe action.</small>
              </div>
            </li>
          </ol>
        </aside>
      </div>
    </div>
  );
}
