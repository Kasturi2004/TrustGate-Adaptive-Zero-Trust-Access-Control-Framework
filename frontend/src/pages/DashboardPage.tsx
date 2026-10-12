import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  CircleHelp,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Users,
} from "../components/Icons";
import { Link } from "react-router-dom";
import { api, dashboardInterval } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { EventTable } from "../components/EventTable";
import { ErrorState, LoadingState } from "../components/States";
import { SectionHeading } from "../components/SectionHeading";
import { StatusBadge } from "../components/StatusBadge";
import type { DashboardMetrics, SecurityEvent } from "../types/api";

export function DashboardPage() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState<Date | null>(null);
  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const interval = dashboardInterval();
      const [nextMetrics, nextEvents] = await Promise.all([
        api.dashboard(token, interval.from, interval.to),
        api.events(token, 1, 20),
      ]);
      setMetrics(nextMetrics);
      setEvents(nextEvents.items);
      setUpdated(new Date());
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to load dashboard data.",
      );
    } finally {
      setLoading(false);
    }
  }, [token]);
  useEffect(() => {
    void load();
  }, [load]);

  const decisionTotal = metrics
    ? metrics.allow_count + metrics.step_up_count + metrics.block_count
    : 0;
  const averageTrustScore = metrics?.average_trust_score ?? null;
  const averageTrustTone =
    averageTrustScore === null
      ? "unavailable"
      : averageTrustScore < 40
        ? "high"
        : averageTrustScore < 70
          ? "medium"
          : "low";
  const averageTrustProgress =
    averageTrustScore === null
      ? 0
      : Math.max(0, Math.min(100, averageTrustScore));
  const decisionShare = (count: number) =>
    decisionTotal > 0
      ? `${((count / decisionTotal) * 100).toFixed(1)}% of initial decisions`
      : "No classified decisions";
  const cards = metrics
    ? ([
        {
          label: "Total access attempts",
          value: metrics.total_requests.toLocaleString(),
          detail: "Access requests - last 30 days",
          icon: Users,
          tone: "blue",
        },
        {
          label: "ALLOW",
          value: metrics.allow_count.toLocaleString(),
          detail: decisionShare(metrics.allow_count),
          icon: ShieldCheck,
          tone: "green",
        },
        {
          label: "STEP-UP",
          value: metrics.step_up_count.toLocaleString(),
          detail: `${decisionShare(metrics.step_up_count)} - verification required`,
          icon: CircleHelp,
          tone: "amber",
        },
        {
          label: "BLOCK",
          value: metrics.block_count.toLocaleString(),
          detail: decisionShare(metrics.block_count),
          icon: ShieldX,
          tone: "red",
        },
      ] as const)
    : [];
  const suspicious = events
    .filter(
      (event) => event.decision === "BLOCK" || event.risk_category === "HIGH",
    )
    .slice(0, 4);
  const behavioralIndicators = metrics?.behavioral_indicators;
  const signalRows = [
    {
      label: "Failed access / MFA",
      detail: "Blocked access and failed MFA attempts",
      indicator: behavioralIndicators?.repeated_failed_access_attempts,
      icon: ShieldAlert,
      tone: "red",
    },
    {
      label: "Recent blocks",
      detail: "Blocked access requests",
      indicator: behavioralIndicators?.recent_blocks,
      icon: ShieldX,
      tone: "amber",
    },
  ] as const;
  return (
    <>
      <div className="section-toolbar">
        <span className="data-note">
          {updated
            ? `Data refreshed ${updated.toLocaleTimeString()}`
            : "Dashboard data from your TrustGate backend"}
        </span>
        <button
          className="secondary-button"
          onClick={() => void load()}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>
      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && !metrics ? (
        <LoadingState />
      ) : (
        metrics && (
          <div className="overview-dashboard">
            <div className="dashboard-column dashboard-column--left">
              <section className="panel overview-metrics-panel" aria-label="Current access activity">
                <SectionHeading
                  title="Current access activity"
                  detail="Initial policy decisions - last 30 days"
                  action={<span className="range-label">Last 30 days</span>}
                />
                <div className="metrics-grid overview-metrics">
                  {cards.map(({ label, value, detail, icon: Icon, tone }) => (
                    <article className="metric-card" key={label}>
                      <div className={`metric-icon icon-${tone}`}>
                        <Icon size={17} />
                      </div>
                      <div className="metric-label">{label}</div>
                      <div className="metric-value">{value}</div>
                      <div className="metric-detail">{detail}</div>
                    </article>
                  ))}
                </div>
              </section>
              <article className="panel activity-panel">
                <SectionHeading
                  title="Access decision activity"
                  detail="Initial policy decisions - last 30 days"
                />
                <div className="activity-total">
                  <div>
                    <span>Initial decisions recorded</span>
                    <strong>{decisionTotal.toLocaleString()}</strong>
                  </div>
                </div>
                {decisionTotal > 0 ? (
                  <>
                    <div
                      className="decision-bar"
                      aria-label={`Initial decisions: ${metrics.allow_count} ALLOW, ${metrics.step_up_count} STEP-UP required, ${metrics.block_count} BLOCK`}
                    >
                      <span
                        className="bar-allow"
                        style={{
                          width: `${(metrics.allow_count / decisionTotal) * 100}%`,
                        }}
                      />
                      <span
                        className="bar-step"
                        style={{
                          width: `${(metrics.step_up_count / decisionTotal) * 100}%`,
                        }}
                      />
                      <span
                        className="bar-block"
                        style={{
                          width: `${(metrics.block_count / decisionTotal) * 100}%`,
                        }}
                      />
                    </div>
                    <div className="decision-legend">
                      <span>
                        <i className="legend-allow" />
                        ALLOW <b>{metrics.allow_count}</b>
                      </span>
                      <span>
                        <i className="legend-step" />
                        STEP-UP <b>{metrics.step_up_count}</b>
                      </span>
                      <span>
                        <i className="legend-block" />
                        BLOCK <b>{metrics.block_count}</b>
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="chart-unavailable">
                    <Activity size={21} />
                    <span>No initial decisions recorded in this period.</span>
                  </div>
                )}
                <div className="activity-footnote">
                  These are initial policy decisions. STEP-UP means further
                  verification was required; it does not indicate success or
                  granted access.
                </div>
              </article>
            </div>
            <div className="dashboard-column dashboard-column--right">
              <article className="panel risk-panel">
                <SectionHeading
                  title="Risk signals"
                  action={
                    <Link className="subtle-link" to="/risk-indicators">
                      <span className="risk-details-full">View risk details</span>
                      <span className="risk-details-short">Details</span>
                      <ArrowRight size={13} />
                    </Link>
                  }
                />
                <section className="risk-metrics-section" aria-labelledby="trust-overview-heading">
                  <div className="risk-section-heading">
                    <h3 id="trust-overview-heading">Trust overview</h3>
                    <span>Last 30 days</span>
                  </div>
                <div className="risk-score-wrap">
                  <div className="trust-gauge">
                    <div className="trust-gauge-heading">
                      <span className="trust-gauge-label">Average trust score</span>
                      <details className="trust-score-info">
                        <summary aria-label="About the average trust score">
                          <CircleHelp size={14} />
                        </summary>
                        <div className="trust-score-tooltip">
                          <b>Average trust score</b>
                          <p>Mean trust score for requests in this period, on a scale of 0 to 100.</p>
                          <p>Risk bands follow TrustGate classifications: below 40 is High, 40 to below 70 is Medium, and 70 or above is Low.</p>
                        </div>
                      </details>
                    </div>
                    <div
                      className={`score-orbit score-${averageTrustTone}`}
                      role="img"
                      aria-label={
                        averageTrustScore === null
                          ? "Average trust score unavailable"
                          : `Average trust score ${averageTrustScore.toFixed(0)} out of 100; ${averageTrustTone} risk band`
                      }
                      style={{
                        background:
                          averageTrustScore === null
                            ? "conic-gradient(var(--track) 0 100%)"
                            : `conic-gradient(var(--score-color) 0% ${averageTrustProgress}%, var(--track) ${averageTrustProgress}% 100%)`,
                      }}
                    >
                      <div className="score-inner">
                        <strong>
                          {averageTrustScore === null
                            ? "-"
                            : averageTrustScore.toFixed(0)}
                        </strong>
                        <small>out of 100</small>
                      </div>
                    </div>
                    <span className={`trust-score-band score-${averageTrustTone}`}>
                      {averageTrustScore === null
                        ? "Unavailable"
                        : `${averageTrustTone} risk`}
                    </span>
                  </div>
                  <div className="risk-summary">
                    <span className="risk-summary-label">
                      High-risk evaluations
                    </span>
                    <strong>{metrics.high_risk_count.toLocaleString()}</strong>
                    <span className="risk-summary-note">
                      Trust evaluations classified HIGH
                    </span>
                    <span className="risk-summary-period">Last 30 days</span>
                  </div>
                </div>
                </section>
                <section className="risk-signals-section" aria-labelledby="security-signals-heading">
                  <div className="risk-section-heading">
                    <h3 id="security-signals-heading">Security signals</h3>
                    <span>Last hour</span>
                  </div>
                  <div className="risk-signal-list">
                    {signalRows.map(({ label, detail, indicator, icon: Icon, tone }) => {
                      const available =
                        indicator != null &&
                        typeof indicator.count === "number" &&
                        Number.isFinite(indicator.count) &&
                        typeof indicator.flagged === "boolean";
                      return (
                        <div className="risk-indicator-row" key={label}>
                          <span className={`indicator-mark indicator-${tone}`} aria-hidden="true">
                            <Icon size={15} />
                          </span>
                          <div className="risk-indicator-copy">
                            <b>{label}</b>
                            <small>{detail}</small>
                          </div>
                          {available ? (
                            <>
                              <strong className="risk-signal-count">
                                {indicator.count.toLocaleString()}
                              </strong>
                              <StatusBadge
                                value={indicator.flagged ? "HIGH" : "LOW"}
                                label={indicator.flagged ? "Flagged" : "Not flagged"}
                              />
                            </>
                          ) : (
                            <span className="risk-signal-unavailable">Unavailable</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </section>
              </article>
              <section className="panel suspicious-panel">
                <SectionHeading
                  title="Suspicious activity"
                  detail="Recent blocked or high-risk events in the latest results"
                  action={
                    <Link className="subtle-link" to="/events">
                      All events <ArrowRight size={13} />
                    </Link>
                  }
                />
                {suspicious.length ? (
                  <div className="suspicious-list">
                    {suspicious.map((event) => (
                      <Link
                        className="suspicious-item"
                        to={`/investigations/${event.id}`}
                        key={event.id}
                      >
                        <span className="suspicious-symbol">
                          <ShieldAlert size={16} />
                        </span>
                        <span className="suspicious-copy">
                          <b>{event.event_type.replaceAll("_", " ")}</b>
                          <small>
                            {new Date(event.created_at).toLocaleString()} - {" "}
                            {event.user_id
                              ? `Account ${event.user_id.slice(0, 8)}...`
                              : "Account unavailable"}
                          </small>
                        </span>
                        {event.decision && <StatusBadge value={event.decision} />}
                        {event.risk_category && <StatusBadge value={event.risk_category} />}
                        <ArrowRight className="suspicious-arrow" size={15} />
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="compact-empty">
                    <span className="compact-empty-icon" aria-hidden="true">
                      <Activity size={17} />
                    </span>
                    <span>No matching events in the latest results. Open all events to continue your review.</span>
                  </div>
                )}
              </section>
            </div>
            <section className="panel events-panel">
              <SectionHeading
                title="Recent security events"
                detail="Most recent recorded events, with links to investigate"
                action={
                  <Link className="subtle-link" to="/events">
                    View all <ArrowRight size={13} />
                  </Link>
                }
              />
              {loading && !events.length ? (
                <LoadingState />
              ) : (
                <EventTable
                  events={events.slice(0, 8)}
                  emptyTitle="No recent events to show"
                  emptyDetail="Events will appear here as TrustGate records activity."
                />
              )}
            </section>
          </div>
        )
      )}
    </>
  );
}
