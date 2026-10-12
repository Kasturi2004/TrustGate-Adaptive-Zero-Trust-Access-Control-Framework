import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Activity, RefreshCw, ShieldAlert, ShieldCheck, Users } from "../components/Icons";
import { Link } from "react-router-dom";
import { api, dashboardInterval } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { ErrorState, LoadingState } from "../components/States";
import { SectionHeading } from "../components/SectionHeading";
import type { DashboardMetrics, RiskIndicator } from "../types/api";
import { customDashboardInterval, decisionDistribution, utcDateInput } from "./analyticsModel";

type RangeOption = "7" | "30" | "90" | "custom";
const COLORS = { ALLOW: "#3dcc9a", STEP_UP: "#e8b45a", BLOCK: "#f0717d" };

export function AnalyticsPage() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [interval, setInterval] = useState(() => dashboardInterval(new Date(), 30));
  const [rangeOption, setRangeOption] = useState<RangeOption>("30");
  const [customFrom, setCustomFrom] = useState(() => utcDateInput(dashboardInterval(new Date(), 30).from));
  const [customTo, setCustomTo] = useState(() => utcDateInput(new Date()));
  const [rangeError, setRangeError] = useState("");
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      setMetrics(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setMetrics(null);
    void api.dashboard(token, interval.from, interval.to, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setMetrics(data);
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : "Unable to load analytics.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [token, interval, refreshKey]);

  function changeRange(value: RangeOption) {
    setRangeOption(value);
    setRangeError("");
    if (value !== "custom") {
      const days = Number(value);
      const nextInterval = dashboardInterval(new Date(), days);
      setInterval(nextInterval);
      setCustomFrom(utcDateInput(nextInterval.from));
      setCustomTo(utcDateInput(nextInterval.to));
    }
  }

  function applyCustomRange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      setInterval(customDashboardInterval(customFrom, customTo));
      setRangeError("");
    } catch (reason) {
      setRangeError(reason instanceof Error ? reason.message : "Invalid date range.");
    }
  }

  const distribution = metrics ? decisionDistribution(metrics) : [];
  const decisionTotal = distribution.reduce((sum, item) => sum + item.count, 0);
  const allow = distribution.find((item) => item.decision === "ALLOW");
  const stepUp = distribution.find((item) => item.decision === "STEP_UP");
  const block = distribution.find((item) => item.decision === "BLOCK");
  const donut = decisionTotal
    ? `conic-gradient(${COLORS.ALLOW} 0% ${allow?.percentage ?? 0}%, ${COLORS.STEP_UP} ${allow?.percentage ?? 0}% ${(allow?.percentage ?? 0) + (stepUp?.percentage ?? 0)}%, ${COLORS.BLOCK} ${(allow?.percentage ?? 0) + (stepUp?.percentage ?? 0)}% 100%)`
    : "conic-gradient(#1c2736 0% 100%)";

  return (
    <div className="analytics-page">
      <section className="analytics-toolbar">
        <div>
          <b>Security Analytics</b>
          <span>Active UTC range: {interval.from.toLocaleDateString()} – {interval.to.toLocaleDateString()} · inclusive bounds</span>
        </div>
        <div className="analytics-range-controls">
          <label className="sr-only" htmlFor="analytics-range">Reporting date range</label>
          <select id="analytics-range" value={rangeOption} onChange={(event) => changeRange(event.target.value as RangeOption)}>
            <option value="7">Past 7 days</option>
            <option value="30">Past 30 days</option>
            <option value="90">Past 90 days</option>
            <option value="custom">Custom range</option>
          </select>
          <button className="secondary-button" onClick={() => setRefreshKey((value) => value + 1)} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} /> Refresh
          </button>
        </div>
        {rangeOption === "custom" && (
          <form className="analytics-custom-range" onSubmit={applyCustomRange}>
            <label>
              From
              <input type="date" value={customFrom} onChange={(event) => setCustomFrom(event.target.value)} />
            </label>
            <label>
              To
              <input type="date" value={customTo} onChange={(event) => setCustomTo(event.target.value)} />
            </label>
            <button className="primary-button" type="submit">Apply range</button>
          </form>
        )}
      </section>
      {rangeError && <p className="analytics-range-error" role="alert">{rangeError}</p>}
      {error && <ErrorState message={error} onRetry={() => setRefreshKey((value) => value + 1)} />}
      {loading ? <LoadingState label="Loading analytics from the TrustGate backend" /> : metrics && (
        <>
          <section className="metrics-grid analytics-metrics" aria-label="Analytics summary">
            <MetricCard label="Total access attempts" value={metrics.total_requests} detail="Requests in selected UTC range" icon={<Users size={16} />} tone="blue" />
            <MetricCard label="Allowed" value={allow?.count ?? 0} detail={`${(allow?.percentage ?? 0).toFixed(1)}% of classified decisions`} icon={<ShieldCheck size={16} />} tone="green" />
            <MetricCard label="Step-up required" value={stepUp?.count ?? 0} detail={`${(stepUp?.percentage ?? 0).toFixed(1)}% · additional verification required`} icon={<Activity size={16} />} tone="amber" />
            <MetricCard label="Blocked" value={block?.count ?? 0} detail={`${(block?.percentage ?? 0).toFixed(1)}% of classified decisions`} icon={<ShieldAlert size={16} />} tone="red" />
          </section>

          <section className="panel analytics-panel analytics-history-panel">
            <SectionHeading title="Access decisions over time" detail="Historical time series unavailable" />
            <div className="chart-unavailable historical-unavailable analytics-chart-empty">
              <Activity size={22} />
              <div>
                <b>Trend data is not available</b>
                <span>The dashboard API returns period aggregates, not dated decision points. Event results are offset-paginated and capped, so they cannot provide a complete historical chart.</span>
              </div>
            </div>
          </section>

          <section className="panel analytics-panel">
            <SectionHeading
              title="Initial decision distribution"
              detail={`${decisionTotal.toLocaleString()} classified initial policy decisions · STEP-UP is not a final outcome`}
              action={<span className="analytics-total">{metrics.total_requests.toLocaleString()} requests</span>}
            />
            {decisionTotal === 0 ? (
              <div className="chart-unavailable">No access requests were recorded in this reporting period.</div>
            ) : (
              <div className="distribution-layout">
                <div className="analytics-donut" style={{ background: donut }} role="img" aria-label={`Decision split: ${allow?.count ?? 0} allow, ${stepUp?.count ?? 0} step-up, ${block?.count ?? 0} block`}>
                  <div><strong>{decisionTotal.toLocaleString()}</strong><span>decisions</span></div>
                </div>
                <div className="distribution-cards">
                  {distribution.map((item) => (
                    <article className="distribution-card" key={item.decision}>
                      <div className="distribution-card-heading"><span><i style={{ background: COLORS[item.decision] }} />{item.decision === "STEP_UP" ? "STEP-UP required" : item.decision}</span><b style={{ color: COLORS[item.decision] }}>{item.percentage.toFixed(1)}%</b></div>
                      <strong>{item.count.toLocaleString()}</strong>
                      <div className="distribution-track"><span style={{ width: `${item.percentage}%`, background: COLORS[item.decision] }} /></div>
                    </article>
                  ))}
                </div>
              </div>
            )}
            <p className="analytics-footnote">These are initial policy decisions counted from access requests. A STEP-UP count means additional verification was required; it does not indicate that verification succeeded or that access was ultimately granted.</p>
          </section>

          <section className="panel analytics-panel">
            <SectionHeading
              title="Top risk signals"
              detail="Backend behavioral indicators · preceding hour"
              action={<Link className="subtle-link" to="/risk-indicators">View all →</Link>}
            />
            <div className="analytics-behavior-grid">
              <BehaviorCard label="Repeated failed access" indicator={metrics.behavioral_indicators?.repeated_failed_access_attempts} />
              <BehaviorCard label="Recent blocks" indicator={metrics.behavioral_indicators?.recent_blocks} />
            </div>
          </section>

          <section className="panel analytics-panel analytics-trust-panel">
            <SectionHeading title="Trust score summary" detail="Available aggregate measures for the selected period" action={<span className="analytics-total">{metrics.total_requests.toLocaleString()} requests</span>} />
            <div className="trust-summary-grid">
              <article className="trust-summary-card">
                <span>Average trust score</span>
                <strong>{metrics.average_trust_score === null ? "Unavailable" : metrics.average_trust_score.toFixed(1)}</strong>
                <small>Scale 0–100 · grouped by request time</small>
              </article>
              <article className="trust-summary-card">
                <span>High-risk evaluations</span>
                <strong>{metrics.high_risk_count.toLocaleString()}</strong>
                <small>Grouped by evaluation time</small>
              </article>
            </div>
            <p className="analytics-data-note">The API does not return counts by trust-score band, so a score distribution is unavailable.</p>
          </section>
          <p className="analytics-data-note">Metric windows follow backend timestamps: requests and decision counts use request time; average score is grouped by request time; high-risk evaluations use evaluation time; MFA challenges use creation time. Behavioral indicators always cover the preceding hour.</p>
        </>
      )}
    </div>
  );
}

function MetricCard({ label, value, detail, icon, tone }: { label: string; value: string | number; detail: string; icon: React.ReactNode; tone: string }) {
  return (
    <article className={`metric-card analytics-metric-card metric-${tone}`}>
      <div className={`metric-icon icon-${tone}`}>{icon}</div>
      <div className="metric-label">{label}</div>
      <div className="metric-value analytics-metric-value">{typeof value === "number" ? value.toLocaleString() : value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  );
}

function BehaviorCard({ label, indicator }: { label: string; indicator?: RiskIndicator }) {
  if (!indicator) {
    return <div className="behavior-card factor-card"><b>{label}</b><span className="muted-copy">Not returned by the API.</span></div>;
  }
  const progress = Math.max(0, Math.min(100, indicator.normalized_value * 100));
  return (
    <article className="behavior-card factor-card">
      <div className="factor-card-meta">
        <span className={`factor-flag ${indicator.flagged ? "factor-flagged" : "factor-clear"}`}>
          {indicator.flagged ? "Flagged" : "No flag"}
        </span>
        <span className="factor-count">{indicator.count.toLocaleString()} observed</span>
      </div>
      <b>{label}</b>
      <div className="behavior-progress" role="img" aria-label={`Normalized indicator value ${progress.toFixed(0)} out of 100`}>
        <span className={indicator.flagged ? "factor-progress-flagged" : "factor-progress-clear"} style={{ width: `${progress}%` }} />
      </div>
      <small>Normalized value {progress.toFixed(0)} / 100</small>
    </article>
  );
}
