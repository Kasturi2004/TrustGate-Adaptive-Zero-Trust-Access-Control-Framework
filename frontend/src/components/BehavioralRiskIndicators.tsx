import type { AdminBehavioralRiskIndicators, AdminRiskIndicator } from "../types/admin.ts";

export function IndicatorCard({
  title,
  description,
  indicator,
}: {
  title: string;
  description: string;
  indicator: AdminRiskIndicator;
}) {
  const progressLabel = `${title} normalized value`;
  const titleId = `${title.toLowerCase().replaceAll(" ", "-")}-indicator-title`;
  return (
    <article className="admin-risk-indicator" aria-labelledby={titleId}>
      <h3 id={titleId}>{title}</h3>
      <p>{description}</p>
      <dl className="admin-risk-indicator-values">
        <div>
          <dt>Current count</dt>
          <dd>{indicator.count}</dd>
        </div>
        <div>
          <dt>Normalized value</dt>
          <dd>{indicator.normalized_value.toFixed(2)} / 1.00</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{indicator.flagged ? "Flagged" : "Not flagged"}</dd>
        </div>
      </dl>
      <progress aria-label={progressLabel} max={1} value={indicator.normalized_value} />
    </article>
  );
}

export function BehavioralRiskIndicatorsView({
  indicators,
}: {
  indicators: AdminBehavioralRiskIndicators;
}) {
  return (
    <section className="panel admin-investigation-section" aria-labelledby="behavioral-risk-title">
      <h2 id="behavioral-risk-title">Behavioral risk indicators</h2>
      <p className="admin-risk-indicator-note">
        Prototype behavioral-risk heuristics over the previous 1 hour. These read-time indicators do
        not modify Trust Score or access decisions.
      </p>
      <div className="admin-risk-indicator-grid">
        <IndicatorCard
          title="Repeated failed access attempts"
          description="Blocked access requests and incorrect OTP attempts."
          indicator={indicators.repeated_failed_access_attempts}
        />
        <IndicatorCard
          title="Recent blocks"
          description="Access requests ending in BLOCK."
          indicator={indicators.recent_blocks}
        />
      </div>
    </section>
  );
}
