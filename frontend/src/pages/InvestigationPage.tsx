import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  ArrowLeft,
  Clock3,
  Fingerprint,
  GitBranch,
  MapPin,
  Shield,
  ShieldAlert,
} from "../components/Icons";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { ErrorState, LoadingState } from "../components/States";
import { SectionHeading } from "../components/SectionHeading";
import { StatusBadge } from "../components/StatusBadge";
import type { Investigation } from "../types/api";

export function InvestigationPage() {
  const { eventId = "" } = useParams();
  const { session } = useAuth();
  const token = session?.access_token;
  const [loaded, setLoaded] = useState<{
    token: string;
    eventId: string;
    data: Investigation;
  } | null>(null);
  const data = loaded && loaded.token === token && loaded.eventId === eventId
    ? loaded.data
    : null;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  useEffect(() => {
    if (!token) {
      setLoaded(null);
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoaded(null);
    setLoading(true);
    setError("");
    void api.investigation(token, eventId, controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) setLoaded({ token, eventId, data: result });
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to load investigation.",
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [token, eventId, refreshKey]);
  function retry() {
    setRefreshKey((value) => value + 1);
  }
  const request = data?.access_request;

  return (
    <>
      <Link to="/events" className="back-link">
        <ArrowLeft size={15} /> Back to events
      </Link>
      {error && <ErrorState message={error} onRetry={retry} />}
      {loading && !data ? (
        <LoadingState label="Loading persisted investigation" />
      ) : (
        data && (
          <>
            <section className="investigation-banner panel">
              <span className="investigation-emblem">
                <ShieldAlert size={22} />
              </span>
              <div className="investigation-title">
                <span>EVENT INVESTIGATION</span>
                <h2>
                  {data.event?.event_type.replaceAll("_", " ") ??
                    "Event context"}
                </h2>
                <small className="mono">{data.event?.id ?? eventId}</small>
              </div>
              <div className="investigation-status">
                <StatusBadge value={data.event?.decision} />
                <span>
                  {data.event?.created_at
                    ? new Date(data.event.created_at).toLocaleString()
                    : "Event not linked"}
                </span>
              </div>
            </section>
            <div className="investigation-grid">
              <section className="panel detail-panel">
                <SectionHeading
                  title="Access request"
                  detail="Recorded request and final outcome"
                />
                {request ? (
                  <div className="detail-list">
                    <Detail
                      label="Resource"
                      value={request.resource_id}
                      icon={<Shield size={15} />}
                    />
                    <Detail
                      label="Requested"
                      value={new Date(request.requested_at).toLocaleString()}
                      icon={<Clock3 size={15} />}
                    />
                    <Detail
                      label="Initial policy decision"
                      value={<StatusBadge value={request.initial_decision} />}
                      icon={<GitBranch size={15} />}
                    />
                    <Detail
                      label="Final access outcome"
                      value={
                        request.final_outcome ? (
                          <StatusBadge value={request.final_outcome} />
                        ) : (
                          "Not recorded"
                        )
                      }
                      icon={<Shield size={15} />}
                    />
                    <Detail
                      label="MFA step-up"
                      value={request.mfa_required ? "Required" : "Not required"}
                      icon={<Fingerprint size={15} />}
                    />
                    <Detail
                      label="Source region"
                      value={request.resolved_region ?? "Unavailable"}
                      icon={<MapPin size={15} />}
                    />
                  </div>
                ) : (
                  <p className="muted-copy">
                    This security event has no linked access request.
                  </p>
                )}
              </section>
              <section className="panel detail-panel">
                <SectionHeading
                  title="Trust evaluation"
                  detail="Persisted evaluation result"
                />
                {data.trust_evaluation ? (
                  <>
                    <div className="evaluation-score">
                      <span>Trust score</span>
                      <strong>
                        {Number(data.trust_evaluation.trust_score).toFixed(1)}
                      </strong>
                      <span>/ 100</span>
                      <StatusBadge
                        value={data.trust_evaluation.risk_classification}
                      />
                    </div>
                    <div className="factor-list">
                      {data.trust_evaluation.factors.map((factor) => (
                        <div className="factor-item" key={factor.factor_name}>
                          <div>
                            <b>{factor.factor_name.replaceAll("_", " ")}</b>
                            <span>{factor.explanation}</span>
                          </div>
                          <strong>
                            {Number(factor.normalized_score).toFixed(0)}
                          </strong>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <p className="muted-copy">
                    No trust evaluation is linked to this event.
                  </p>
                )}
              </section>
              <section className="panel detail-panel">
                <SectionHeading
                  title="Captured context"
                  detail="Normalized signals stored for this request"
                />
                {data.context_signals ? (
                  <div className="detail-list">
                    <Detail
                      label="Device familiarity"
                      value={data.context_signals.device_familiarity_raw}
                      icon={<Fingerprint size={15} />}
                    />
                    <Detail
                      label="Device health"
                      value={data.context_signals.device_health_raw}
                      icon={<Shield size={15} />}
                    />
                    <Detail
                      label="Location"
                      value={data.context_signals.location_raw}
                      icon={<MapPin size={15} />}
                    />
                    <Detail
                      label="Time pattern"
                      value={data.context_signals.time_raw}
                      icon={<Clock3 size={15} />}
                    />
                  </div>
                ) : (
                  <p className="muted-copy">
                    No context signals are linked to this event.
                  </p>
                )}
              </section>
              <section className="panel detail-panel">
                <SectionHeading
                  title="Related security events"
                  detail={`${data.related_events.length} linked records`}
                />
                {data.related_events.length ? (
                  <div className="related-list">
                    {data.related_events.map((event) => (
                      <Link
                        className="related-item"
                        to={`/investigations/${event.id}`}
                        key={event.id}
                      >
                        <span className="timeline-dot" />
                        <div>
                          <b>{event.event_type.replaceAll("_", " ")}</b>
                          <small>
                            {new Date(event.created_at).toLocaleString()}
                          </small>
                        </div>
                        <StatusBadge value={event.decision} />
                      </Link>
                    ))}
                  </div>
                ) : (
                  <p className="muted-copy">No related events were returned.</p>
                )}
              </section>
            </div>
          </>
        )
      )}
    </>
  );
}

function Detail({
  label,
  value,
  icon,
}: {
  label: string;
  value: ReactNode;
  icon: ReactNode;
}) {
  return (
    <div className="detail-row">
      <span className="detail-icon">{icon}</span>
      <span className="detail-label">{label}</span>
      <span className="detail-value">{value}</span>
    </div>
  );
}
