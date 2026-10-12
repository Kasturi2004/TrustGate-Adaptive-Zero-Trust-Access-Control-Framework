import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  RefreshCw,
  ShieldAlert,
} from "../components/Icons";
import { api, dashboardInterval } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { ErrorState, LoadingState } from "../components/States";
import { SectionHeading } from "../components/SectionHeading";
import type { BehavioralRiskIndicators } from "../types/api";

export function RiskIndicatorsPage() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [indicators, setIndicators] = useState<BehavioralRiskIndicators | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const { from, to } = dashboardInterval();
      const response = await api.dashboard(token, from, to);
      setIndicators(response.behavioral_indicators);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to load behavioral risk indicators.",
      );
    } finally {
      setLoading(false);
    }
  }, [token]);
  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="panel risk-page-panel">
      <div className="page-panel-heading">
        <SectionHeading
          title="Behavioral risk indicators"
          detail="Read-time indicators calculated by the backend from persisted activity"
        />
        <button
          className="secondary-button"
          onClick={() => void load()}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>
      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && !indicators ? (
        <LoadingState />
      ) : (
        indicators && (
          <div className="indicator-cards">
            {[
              {
                key: "repeated_failed_access_attempts",
                title: "Repeated failed access attempts",
                description:
                  "Repeated unsuccessful access activity identified by backend behavior rules.",
                icon: AlertTriangle,
                value: indicators.repeated_failed_access_attempts,
              },
              {
                key: "recent_blocks",
                title: "Recent blocks",
                description:
                  "Recent BLOCK outcomes observed in persisted security activity.",
                icon: ShieldAlert,
                value: indicators.recent_blocks,
              },
            ].map(({ key, title, description, icon: Icon, value }) => (
              <article className="indicator-card" key={key}>
                <span
                  className={`indicator-large-icon ${value.flagged ? "flagged" : "clear"}`}
                >
                  <Icon size={20} />
                </span>
                <div className="indicator-card-top">
                  <div>
                    <h3>{title}</h3>
                    <p>{description}</p>
                  </div>
                  <span
                    className={`flag-state ${value.flagged ? "flag-state-on" : "flag-state-off"}`}
                  >
                    {value.flagged ? "Flagged" : "No flag"}
                  </span>
                </div>
                <div className="indicator-stats">
                  <div>
                    <small>Observed count</small>
                    <strong>{value.count.toLocaleString()}</strong>
                  </div>
                  <div>
                    <small>Normalized value</small>
                    <strong>
                      {(value.normalized_value * 100).toFixed(0)}
                      <em> / 100</em>
                    </strong>
                  </div>
                </div>
                <div className="indicator-meter">
                  <span style={{ width: `${value.normalized_value * 100}%` }} />
                </div>
                <p className="indicator-method">
                  <Activity size={13} /> Flag and normalization supplied by
                  TrustGate backend
                </p>
              </article>
            ))}
          </div>
        )
      )}
    </section>
  );
}
