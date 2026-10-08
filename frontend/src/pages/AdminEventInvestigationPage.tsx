import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchAdminEventInvestigation } from "../api/admin.ts";
import { AdminDecision } from "../components/AdminDecision.tsx";
import { AdminLoadingState } from "../components/AdminLoadingState.tsx";
import { BehavioralRiskIndicatorsView } from "../components/BehavioralRiskIndicators.tsx";
import type {
  AdminEventInvestigation,
  InvestigationEvent,
  InvestigationOtpChallenge,
} from "../types/admin.ts";

type LoadState =
  | { key: string; status: "loading" }
  | { key: string; status: "error" }
  | { key: string; status: "success"; data: AdminEventInvestigation };

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}

export function Field({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value || "Not available"}</dd>
    </div>
  );
}

export function EventFields({ event }: { event: InvestigationEvent }) {
  return (
    <dl className="admin-detail-grid">
      <Field label="Event type" value={event.event_type} />
      <Field label="Event ID" value={event.id} />
      <Field label="Created" value={formatDate(event.created_at)} />
      <Field label="Actor ID" value={event.actor_id} />
      <Field label="Target user ID" value={event.target_user_id} />
      <div>
        <dt>Decision</dt>
        <dd>
          <AdminDecision decision={event.decision} />
        </dd>
      </div>
      <Field label="Risk category" value={event.risk_category} />
    </dl>
  );
}

export function ChallengeHistory({ challenges }: { challenges: InvestigationOtpChallenge[] }) {
  if (challenges.length === 0) {
    return <p className="admin-optional-empty">No MFA challenge was recorded for this request.</p>;
  }
  return (
    <ol className="admin-challenge-list">
      {challenges.map((challenge, index) => (
        <li key={challenge.id}>
          <h3>Challenge {index + 1}</h3>
          <dl className="admin-detail-grid">
            <Field label="Status" value={challenge.status} />
            <Field label="Attempts" value={String(challenge.attempt_count)} />
            <Field label="Created" value={formatDate(challenge.created_at)} />
            <Field label="Expires" value={formatDate(challenge.expires_at)} />
            <Field
              label="Verified"
              value={challenge.verified_at ? formatDate(challenge.verified_at) : "Not verified"}
            />
          </dl>
        </li>
      ))}
    </ol>
  );
}

interface AdminEventInvestigationPageProps {
  investigation?: AdminEventInvestigation;
  backTo?: string;
  backLabel?: string;
}

export function AdminEventInvestigationPage({
  investigation: suppliedInvestigation,
  backTo = "/admin/events",
  backLabel = "Back to security events",
}: AdminEventInvestigationPageProps = {}) {
  const { eventId = "" } = useParams();
  const [retryCount, setRetryCount] = useState(0);
  const requestKey = `${eventId}:${retryCount}`;
  const [state, setState] = useState<LoadState>({ key: requestKey, status: "loading" });

  useEffect(() => {
    if (suppliedInvestigation) return;

    const controller = new AbortController();
    let active = true;
    void fetchAdminEventInvestigation(eventId, controller.signal)
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
  }, [eventId, requestKey, suppliedInvestigation]);

  const currentState = suppliedInvestigation
    ? { key: requestKey, status: "success" as const, data: suppliedInvestigation }
    : state.key === requestKey
      ? state
      : ({ key: requestKey, status: "loading" } as const);

  return (
    <div className="admin-page admin-investigation-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">
            {suppliedInvestigation
              ? "Administration · Access History"
              : "Administration · Investigation"}
          </span>
          <h1>{suppliedInvestigation ? "Access request investigation" : "Event investigation"}</h1>
          <p>Persisted event context and related verification history.</p>
        </div>
        <Link className="history-back-link" to={backTo}>
          {backLabel}
        </Link>
      </header>

      {currentState.status === "loading" ? (
        <AdminLoadingState label="Loading event investigation…" />
      ) : currentState.status === "error" ? (
        <section className="panel admin-state" aria-labelledby="admin-investigation-error">
          <h2 id="admin-investigation-error">Unable to load investigation</h2>
          <p role="alert">Investigation data is temporarily unavailable. Please try again.</p>
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
          {currentState.data.behavioral_indicators ? (
            <BehavioralRiskIndicatorsView indicators={currentState.data.behavioral_indicators} />
          ) : (
            <section
              className="panel admin-investigation-section"
              aria-labelledby="behavioral-risk-unavailable-title"
            >
              <h2 id="behavioral-risk-unavailable-title">Behavioral risk indicators</h2>
              <p className="admin-optional-empty">
                Not applicable: this event is not linked to an access request.
              </p>
            </section>
          )}
          {currentState.data.event ? (
            <ol className="admin-investigation-chain" aria-label="Investigation chain">
              <li>
                <section
                  className="panel admin-investigation-section"
                  aria-labelledby="investigation-event-title"
                >
                  <h2 id="investigation-event-title">Security event</h2>
                  <EventFields event={currentState.data.event} />
                </section>
              </li>
              {currentState.data.access_request ? (
                <li>
                  <section
                    className="panel admin-investigation-section"
                    aria-labelledby="investigation-request-title"
                  >
                    <h2 id="investigation-request-title">Access request</h2>
                    <dl className="admin-detail-grid">
                      <Field label="Request ID" value={currentState.data.access_request.id} />
                      <Field label="User ID" value={currentState.data.access_request.user_id} />
                      <Field
                        label="Resource"
                        value={currentState.data.access_request.resource_id}
                      />
                      <Field
                        label="Requested"
                        value={formatDate(currentState.data.access_request.requested_at)}
                      />
                      <Field
                        label="Resolved"
                        value={
                          currentState.data.access_request.resolved_at
                            ? formatDate(currentState.data.access_request.resolved_at)
                            : null
                        }
                      />
                      <Field label="Source IP" value={currentState.data.access_request.source_ip} />
                      <Field
                        label="Region"
                        value={currentState.data.access_request.resolved_region}
                      />
                      <Field
                        label="MFA required"
                        value={currentState.data.access_request.mfa_required ? "Yes" : "No"}
                      />
                      <div>
                        <dt>Initial decision</dt>
                        <dd>
                          <AdminDecision
                            decision={currentState.data.access_request.initial_decision}
                          />
                        </dd>
                      </div>
                      <div>
                        <dt>Final outcome</dt>
                        <dd>
                          <AdminDecision
                            decision={currentState.data.access_request.final_outcome}
                          />
                        </dd>
                      </div>
                      <Field
                        label="Device hash (truncated)"
                        value={currentState.data.access_request.device?.device_hash}
                      />
                    </dl>
                  </section>
                </li>
              ) : (
                <li>
                  <section
                    className="panel admin-investigation-section"
                    aria-labelledby="event-only-title"
                  >
                    <h2 id="event-only-title">Event-only record</h2>
                    <p>This event is not linked to an access request.</p>
                  </section>
                </li>
              )}
              {currentState.data.access_request && (
                <>
                  <li>
                    <section
                      className="panel admin-investigation-section"
                      aria-labelledby="investigation-context-title"
                    >
                      <h2 id="investigation-context-title">Context</h2>
                      {currentState.data.context_signals ? (
                        <dl className="admin-detail-grid">
                          <Field
                            label="Captured"
                            value={formatDate(currentState.data.context_signals.captured_at)}
                          />
                          <Field
                            label="Device familiarity"
                            value={currentState.data.context_signals.device_familiarity_raw}
                          />
                          <Field
                            label="Device health"
                            value={currentState.data.context_signals.device_health_raw}
                          />
                          <Field
                            label="Location signal"
                            value={currentState.data.context_signals.location_raw}
                          />
                          <Field
                            label="Time signal"
                            value={currentState.data.context_signals.time_raw}
                          />
                        </dl>
                      ) : (
                        <p className="admin-optional-empty">No context signals are available.</p>
                      )}
                    </section>
                  </li>
                  <li>
                    <section
                      className="panel admin-investigation-section"
                      aria-labelledby="investigation-evaluation-title"
                    >
                      <h2 id="investigation-evaluation-title">Trust evaluation and factors</h2>
                      {currentState.data.trust_evaluation ? (
                        <>
                          <dl className="admin-detail-grid">
                            <Field
                              label="Trust Score"
                              value={String(currentState.data.trust_evaluation.trust_score)}
                            />
                            <Field
                              label="Risk classification"
                              value={currentState.data.trust_evaluation.risk_classification}
                            />
                            <Field
                              label="Evaluation status"
                              value={currentState.data.trust_evaluation.status}
                            />
                            <Field
                              label="Evaluated"
                              value={formatDate(currentState.data.trust_evaluation.evaluated_at)}
                            />
                          </dl>
                          <div className="admin-factor-list">
                            <h3>Trust factor breakdown</h3>
                            {currentState.data.trust_evaluation.factors.length ? (
                              currentState.data.trust_evaluation.factors.map((factor) => (
                                <article className="admin-factor" key={factor.factor_name}>
                                  <h4>{factor.factor_name}</h4>
                                  <dl className="admin-detail-grid">
                                    <Field label="Raw value" value={factor.raw_value} />
                                    <Field
                                      label="Normalized score"
                                      value={String(factor.normalized_score)}
                                    />
                                    <Field label="Weight" value={String(factor.weight)} />
                                    <Field
                                      label="Weighted contribution"
                                      value={String(factor.weighted_contribution)}
                                    />
                                  </dl>
                                  <p>{factor.explanation}</p>
                                </article>
                              ))
                            ) : (
                              <p className="admin-optional-empty">
                                No trust factors are available.
                              </p>
                            )}
                          </div>
                        </>
                      ) : (
                        <p className="admin-optional-empty">No trust evaluation is available.</p>
                      )}
                    </section>
                  </li>
                  <li>
                    <section
                      className="panel admin-investigation-section"
                      aria-labelledby="investigation-policy-title"
                    >
                      <h2 id="investigation-policy-title">Policy decision</h2>
                      {currentState.data.policy_decision ? (
                        <dl className="admin-detail-grid">
                          <div>
                            <dt>Decision</dt>
                            <dd>
                              <AdminDecision
                                decision={currentState.data.policy_decision.decision}
                              />
                            </dd>
                          </div>
                          <Field
                            label="Reason"
                            value={currentState.data.policy_decision.decision_reason}
                          />
                          <Field
                            label="Decided"
                            value={formatDate(currentState.data.policy_decision.decided_at)}
                          />
                          <Field
                            label="Policy version"
                            value={currentState.data.policy_decision.policy_version?.version_label}
                          />
                        </dl>
                      ) : (
                        <p className="admin-optional-empty">No policy decision is available.</p>
                      )}
                    </section>
                  </li>
                  <li>
                    <section
                      className="panel admin-investigation-section"
                      aria-labelledby="investigation-otp-title"
                    >
                      <h2 id="investigation-otp-title">MFA / OTP challenges</h2>
                      <ChallengeHistory challenges={currentState.data.otp_challenges} />
                    </section>
                  </li>
                  <li>
                    <section
                      className="panel admin-investigation-section"
                      aria-labelledby="investigation-related-title"
                    >
                      <h2 id="investigation-related-title">Related events</h2>
                      {currentState.data.related_events.length ? (
                        <ul className="admin-related-events">
                          {currentState.data.related_events.map((event) => (
                            <li key={event.id}>
                              <Link to={`/admin/events/${encodeURIComponent(event.id)}`}>
                                <strong>{event.event_type}</strong>
                                <span>{formatDate(event.created_at)}</span>
                                <span>
                                  <AdminDecision decision={event.decision} />
                                </span>
                              </Link>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="admin-optional-empty">No related events are available.</p>
                      )}
                    </section>
                  </li>
                </>
              )}
            </ol>
          ) : (
            <section className="panel admin-state" role="alert">
              The investigation response did not include a security event.
            </section>
          )}
        </>
      )}
    </div>
  );
}
