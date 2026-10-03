import { Link } from "react-router-dom";
import type { AccessEvaluationResponse } from "../types/access.ts";

type DecisionPresentationProps = {
  evaluation: AccessEvaluationResponse;
};

const decisionContent = {
  ALLOW: {
    title: "Access granted",
    description: "Your request was approved.",
    label: "ALLOW",
    tone: "allow",
    icon: "✓",
  },
  STEP_UP: {
    title: "Additional verification required",
    description: "Additional verification is required to continue.",
    label: "STEP-UP",
    tone: "step",
    icon: "···",
  },
  BLOCK: {
    title: "Access denied",
    description: "Access is not approved.",
    label: "BLOCK",
    tone: "block",
    icon: "×",
  },
} as const;

export function DecisionPresentation({ evaluation }: DecisionPresentationProps) {
  const content = decisionContent[evaluation.decision];

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

      <div className="decision-explanation">
        <div>
          <h3>Why this happened</h3>
          <p>{evaluation.explanation}</p>
        </div>
      </div>

      <div className="decision-actions">
        {evaluation.decision === "STEP_UP" && (
          <button className="decision-primary" type="button" disabled>
            Verify with authenticator
          </button>
        )}
        <Link className="decision-secondary" to="/dashboard">
          {evaluation.decision === "ALLOW" ? "Back to dashboard" : "Return to dashboard"}
        </Link>
      </div>
    </section>
  );
}
