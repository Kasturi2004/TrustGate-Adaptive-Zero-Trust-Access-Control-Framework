import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchAdminDashboard, fetchAdminEvents } from "../api/admin.ts";
import { AdminDecision } from "../components/AdminDecision.tsx";
import { AdminLoadingState } from "../components/AdminLoadingState.tsx";
import { BehavioralRiskIndicatorsView } from "../components/BehavioralRiskIndicators.tsx";
import type { AdminDashboard, AdminSecurityEvent } from "../types/admin.ts";

const EVENT_PAGE_SIZE = 50;
const ACTIVITY_LIMIT = 5;
const securityRelevantEventTypes = new Set([
  "LOGIN_FAILURE",
  "MFA_TOTP_ENROLLMENT_VERIFICATION_FAILED",
  "MFA_TOTP_STEP_UP_VERIFICATION_FAILED",
  "MFA_LOCKED",
  "UNAUTHORIZED_ACCESS_ATTEMPT",
  "ADMIN_UNAUTHORIZED_ATTEMPT",
  "PIPELINE_DEGRADED_FAILSAFE",
]);

type LoadState =
  | { key: string; status: "loading" }
  | { key: string; status: "error" }
  | { key: string; status: "success"; data: AdminDashboard };

type ActivityLoadState =
  | { key: string; status: "loading" }
  | { key: string; status: "error" }
  | { key: string; status: "success"; events: AdminSecurityEvent[] };

function defaultRange(): { from: string; to: string } {
  const end = new Date();
  const start = new Date(end);
  start.setUTCDate(start.getUTCDate() - 6);
  return {
    from: start.toISOString().slice(0, 10),
    to: end.toISOString().slice(0, 10),
  };
}

function utcStart(date: string): string {
  return `${date}T00:00:00Z`;
}

function utcEnd(date: string): string {
  return `${date}T23:59:59.999Z`;
}

function eventLink(from: string, to: string, decision?: string, riskCategory?: string): string {
  const query = new URLSearchParams({ from: utcStart(from), to: utcEnd(to) });
  if (decision) query.set("decision", decision);
  if (riskCategory) query.set("risk_category", riskCategory);
  return `/admin/events?${query.toString()}`;
}

function score(value: number | null): string {
  return value === null ? "Not available" : value.toFixed(2);
}

function rate(value: number | null): string {
  return value === null ? "Not available" : `${(value * 100).toFixed(1)}%`;
}

function formatEventDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}

function isSecurityRelevantEvent(event: AdminSecurityEvent): boolean {
  return (
    event.decision === "BLOCK" ||
    event.risk_category === "HIGH" ||
    securityRelevantEventTypes.has(event.event_type)
  );
}

export function AdminDashboardPage() {
  const initialRange = defaultRange();
  const [draftRange, setDraftRange] = useState(initialRange);
  const [activeRange, setActiveRange] = useState(initialRange);
  const [retryCount, setRetryCount] = useState(0);
  const [activityRetryCount, setActivityRetryCount] = useState(0);
  const requestKey = `${activeRange.from}:${activeRange.to}:${retryCount}`;
  const activityRequestKey = `${activeRange.from}:${activeRange.to}:${activityRetryCount}`;
  const [state, setState] = useState<LoadState>({ key: requestKey, status: "loading" });
  const [activityState, setActivityState] = useState<ActivityLoadState>({
    key: activityRequestKey,
    status: "loading",
  });

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void fetchAdminDashboard(utcStart(activeRange.from), utcEnd(activeRange.to), controller.signal)
      .then((data) => {
        if (active) setState({ key: requestKey, status: "success", data });
      })
      .catch(() => {
        if (active && !controller.signal.aborted) setState({ key: requestKey, status: "error" });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [activeRange.from, activeRange.to, requestKey]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void fetchAdminEvents(
      {
        from: utcStart(activeRange.from),
        to: utcEnd(activeRange.to),
        page: 1,
        page_size: EVENT_PAGE_SIZE,
      },
      controller.signal,
    )
      .then((page) => {
        if (active) {
          setActivityState({
            key: activityRequestKey,
            status: "success",
            events: page.items.filter(isSecurityRelevantEvent).slice(0, ACTIVITY_LIMIT),
          });
        }
      })
      .catch(() => {
        if (active && !controller.signal.aborted) {
          setActivityState({ key: activityRequestKey, status: "error" });
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [activeRange.from, activeRange.to, activityRequestKey]);

  const currentState =
    state.key === requestKey ? state : ({ key: requestKey, status: "loading" } as const);
  const currentActivityState =
    activityState.key === activityRequestKey
      ? activityState
      : ({ key: activityRequestKey, status: "loading" } as const);
  const metrics = currentState.status === "success" ? currentState.data : null;
  const cards = metrics
    ? [
        {
          label: "Total requests",
          value: String(metrics.total_requests),
          href: eventLink(activeRange.from, activeRange.to),
        },
        { label: "Initial ALLOW decisions", value: String(metrics.allow_count), decision: "ALLOW" },
        {
          label: "Initial STEP-UP decisions",
          value: String(metrics.step_up_count),
          decision: "STEP_UP",
        },
        { label: "Initial BLOCK decisions", value: String(metrics.block_count), decision: "BLOCK" },
        {
          label: "Average Trust Score",
          value: score(metrics.average_trust_score),
          href: eventLink(activeRange.from, activeRange.to),
        },
        {
          label: "High-risk evaluations",
          value: String(metrics.high_risk_count),
          riskCategory: "HIGH",
        },
        {
          label: "MFA success rate",
          value: rate(metrics.mfa_success_rate),
          href: eventLink(activeRange.from, activeRange.to),
        },
      ]
    : [];

  return (
    <div className="admin-page admin-dashboard-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">Administration</span>
          <h1>Admin dashboard</h1>
          <p>Read-only access and security metrics from the backend.</p>
          <p>
            Decision counts show each request’s initial decision. STEP-UP requests may have a
            different final outcome after Authenticator verification.
          </p>
        </div>
        <Link className="history-back-link" to="/admin/events">
          View security events
        </Link>
      </header>

      <form
        className="panel admin-filter-form admin-date-range"
        aria-label="Dashboard date range"
        onSubmit={(event) => {
          event.preventDefault();
          if (draftRange.from && draftRange.to) setActiveRange(draftRange);
        }}
      >
        <label>
          From
          <input
            type="date"
            value={draftRange.from}
            onChange={(event) => setDraftRange({ ...draftRange, from: event.currentTarget.value })}
          />
        </label>
        <label>
          To
          <input
            type="date"
            value={draftRange.to}
            onChange={(event) => setDraftRange({ ...draftRange, to: event.currentTarget.value })}
          />
        </label>
        <button className="history-secondary-action" type="submit">
          Apply range
        </button>
      </form>

      {currentState.status === "loading" ? (
        <AdminLoadingState label="Loading dashboard metrics…" />
      ) : currentState.status === "error" ? (
        <section className="panel admin-state" aria-labelledby="admin-dashboard-error">
          <h2 id="admin-dashboard-error">Unable to load dashboard</h2>
          <p role="alert">Dashboard data is temporarily unavailable. Please try again.</p>
          <button
            className="history-secondary-action"
            type="button"
            onClick={() => setRetryCount((count) => count + 1)}
          >
            Try again
          </button>
        </section>
      ) : (
        <>
          <BehavioralRiskIndicatorsView indicators={currentState.data.behavioral_indicators} />
          {currentState.status === "success" && currentState.data.total_requests === 0 && (
            <p className="admin-empty-note" role="status">
              No access requests were recorded in this date range.
            </p>
          )}
          <section className="admin-metric-grid" aria-label="Dashboard metrics">
            {cards.map((card) => {
              const href =
                card.href ??
                (card.decision
                  ? eventLink(activeRange.from, activeRange.to, card.decision)
                  : card.riskCategory
                    ? eventLink(activeRange.from, activeRange.to, undefined, card.riskCategory)
                    : eventLink(activeRange.from, activeRange.to));
              return href ? (
                <Link className="panel admin-metric-card" to={href} key={card.label}>
                  <span>{card.label}</span>
                  <strong>{card.value}</strong>
                  <small>View events in this date range</small>
                </Link>
              ) : (
                <article className="panel admin-metric-card" key={card.label}>
                  <span>{card.label}</span>
                  <strong>{card.value}</strong>
                </article>
              );
            })}
          </section>
          <section
            className="panel admin-investigation-section"
            aria-labelledby="admin-suspicious-title"
          >
            <h2 id="admin-suspicious-title">Recent suspicious activity</h2>
            <p className="admin-risk-indicator-note">
              Showing up to five matches from the 50 most recent events in this date range: BLOCK
              decisions, HIGH-risk events, failed login or MFA checks, denied access, and pipeline
              fail-safe events.
            </p>
            {currentActivityState.status === "loading" ? (
              <p className="admin-optional-empty" role="status">
                Loading recent security activity…
              </p>
            ) : currentActivityState.status === "error" ? (
              <div className="admin-state" aria-labelledby="admin-activity-error">
                <h3 id="admin-activity-error">Unable to load recent activity</h3>
                <p role="alert">
                  Recent security activity is temporarily unavailable. Please try again.
                </p>
                <button
                  className="history-secondary-action"
                  type="button"
                  onClick={() => setActivityRetryCount((count) => count + 1)}
                >
                  Try again
                </button>
              </div>
            ) : currentActivityState.events.length === 0 ? (
              <p className="admin-optional-empty" role="status">
                No matching events were found among the 50 most recent security events in this date
                range.
              </p>
            ) : (
              <ul className="admin-related-events" aria-label="Recent security-relevant events">
                {currentActivityState.events.map((event) => (
                  <li key={event.id}>
                    <Link to={`/admin/events/${encodeURIComponent(event.id)}`}>
                      <strong>
                        {event.event_type}
                        <small className="admin-recent-activity-meta">Event ID: {event.id}</small>
                      </strong>
                      <span>{formatEventDate(event.created_at)}</span>
                      <span>
                        {event.decision ? (
                          <AdminDecision decision={event.decision} />
                        ) : event.risk_category ? (
                          `Risk: ${event.risk_category}`
                        ) : (
                          "Investigation"
                        )}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  );
}
