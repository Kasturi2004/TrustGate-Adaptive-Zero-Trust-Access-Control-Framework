import { Link } from "react-router-dom";
import type { FormEvent } from "react";
import type { AccessEvaluationResponse } from "../types/access.ts";

type DecisionPresentationProps = {
  evaluation: AccessEvaluationResponse;
  totpCode: string;
  totpError: string | null;
  verifyingTotp: boolean;
  totpVerified: boolean;
  onTotpCodeChange: (code: string) => void;
  onTotpSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const decisionContent = {
  ALLOW: {
    title: "Access granted",
    description: "Access to Operations Dashboard was granted immediately.",
    label: "ALLOW",
    tone: "allow",
    icon: "✓",
  },
  STEP_UP: {
    title: "Additional verification required",
    description: "Verify with your Authenticator app before access can be granted.",
    label: "STEP-UP",
    tone: "step",
    icon: "···",
  },
  BLOCK: {
    title: "Access denied",
    description:
      "Access to Operations Dashboard was denied based on the current security assessment.",
    label: "BLOCK",
    tone: "block",
    icon: "×",
  },
} as const;

export function DecisionPresentation({
  evaluation,
  totpCode,
  totpError,
  verifyingTotp,
  totpVerified,
  onTotpCodeChange,
  onTotpSubmit,
}: DecisionPresentationProps) {
  const content = decisionContent[evaluation.decision];
  const hasChallenge =
    evaluation.decision === "STEP_UP" &&
    evaluation.mfa_challenge_id !== null &&
    UUID_PATTERN.test(evaluation.mfa_challenge_id);

  if (hasChallenge && totpVerified) {
    return (
      <section
        className="decision-presentation decision-allow"
        aria-labelledby="decision-title"
        aria-live="polite"
      >
        <div className="decision-hero">
          <span className="decision-icon" aria-hidden="true">
            {decisionContent.ALLOW.icon}
          </span>
          <span className="decision-badge">
            <span className="decision-dot" aria-hidden="true" />
            AUTHENTICATOR VERIFIED
          </span>
          <h2 id="decision-title">Access Granted</h2>
          <p>Your authenticator was verified and access has been approved.</p>
        </div>
        <div className="decision-actions">
          <Link className="decision-secondary" to="/dashboard">
            Back to dashboard
          </Link>
        </div>
      </section>
    );
  }

  return (
    <section
      className={`decision-presentation decision-${content.tone}`}
      aria-labelledby="decision-title"
      aria-live="polite"
    >
      <div className="decision-hero">
        <span className="decision-icon" aria-hidden="true">
          {content.icon}
        </span>
        <span className="decision-badge">
          <span className="decision-dot" aria-hidden="true" />
          {content.label}
        </span>
        <h2 id="decision-title">{content.title}</h2>
        <p>{content.description}</p>
      </div>

      <div className="decision-actions">
        {hasChallenge && (
          <form className="totp-verification-form" onSubmit={onTotpSubmit}>
            <h3>Verify with your authenticator</h3>
            <p id="totp-code-help">
              Enter the six-digit code from your authenticator app to continue.
            </p>
            <label htmlFor="totp-code">Authenticator code</label>
            <input
              id="totp-code"
              name="totp-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              minLength={6}
              maxLength={6}
              required
              disabled={verifyingTotp}
              value={totpCode}
              aria-describedby={totpError ? "totp-code-help totp-code-error" : "totp-code-help"}
              onChange={(event) => onTotpCodeChange(event.currentTarget.value)}
            />
            {totpError && (
              <p className="login-error" id="totp-code-error" role="alert">
                {totpError}
              </p>
            )}
            <button className="decision-primary" type="submit" disabled={verifyingTotp}>
              {verifyingTotp ? "Verifying…" : "Verify code"}
            </button>
          </form>
        )}
        <Link className="decision-secondary" to="/dashboard">
          {evaluation.decision === "ALLOW" ? "Back to dashboard" : "Return to dashboard"}
        </Link>
      </div>
    </section>
  );
}
