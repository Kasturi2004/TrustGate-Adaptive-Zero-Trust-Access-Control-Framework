import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { apiRequest } from "../api/client.ts";
import { fetchCurrentDeviceRecognition, recognizeCurrentDevice } from "../api/deviceRecognition.ts";

type DashboardData = {
  title: string;
  summary: string;
  status: "operational";
};

type RecognitionState = "recognized" | "unrecognized" | "unavailable" | "saving" | "failed";

type RedemptionState =
  | { key: string; status: "loading" }
  | { key: string; status: "denied" }
  | {
      key: string;
      status: "success";
      data: DashboardData;
      recognition: RecognitionState;
    };

function isDashboardData(value: unknown): value is DashboardData {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.resource_id === "ops-dashboard" &&
    record.title === "Operations Dashboard" &&
    typeof record.summary === "string" &&
    record.status === "operational"
  );
}

export function OperationsDashboardPage() {
  const location = useLocation();
  const state = location.state as { accessRequestId?: unknown } | null;
  const accessRequestId = typeof state?.accessRequestId === "string" ? state.accessRequestId : null;
  const requestKey = accessRequestId ?? "direct-navigation";
  const [redemption, setRedemption] = useState<RedemptionState>({
    key: requestKey,
    status: "loading",
  });

  useEffect(() => {
    let active = true;

    async function load(): Promise<void> {
      try {
        const response = await apiRequest("/resources/ops-dashboard", {
          method: "POST",
          body: accessRequestId ? { access_request_id: accessRequestId } : {},
        });
        if (!response.ok) throw new Error("Resource unavailable");

        const result: unknown = await response.json();
        if (!isDashboardData(result)) throw new Error("Resource response was not recognized");
        if (!active) return;
        let recognition: RecognitionState;
        try {
          const device = await fetchCurrentDeviceRecognition();
          recognition = device.recognized ? "recognized" : "unrecognized";
        } catch {
          recognition = "unavailable";
        }
        if (active)
          setRedemption({ key: requestKey, status: "success", data: result, recognition });
      } catch {
        if (active) setRedemption({ key: requestKey, status: "denied" });
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [accessRequestId, requestKey]);

  async function trustThisDevice(): Promise<void> {
    if (!accessRequestId || currentRedemption.status !== "success") return;
    setRedemption({ ...currentRedemption, recognition: "saving" });
    try {
      await recognizeCurrentDevice(accessRequestId);
      setRedemption({ ...currentRedemption, recognition: "recognized" });
    } catch {
      setRedemption({ ...currentRedemption, recognition: "failed" });
    }
  }

  const currentRedemption =
    redemption.key === requestKey ? redemption : { key: requestKey, status: "loading" as const };

  if (currentRedemption.status === "loading") {
    return (
      <section className="panel operations-state" role="status" aria-live="polite">
        <span className="page-eyebrow">Protected workspace</span>
        <h1>Opening Operations Dashboard</h1>
        <p>Checking your access to this workspace…</p>
      </section>
    );
  }

  if (currentRedemption.status === "denied") {
    return (
      <section className="panel operations-state" aria-labelledby="operations-denied-title">
        <span className="page-eyebrow">Protected workspace</span>
        <h1 id="operations-denied-title">Access denied</h1>
        <p>We couldn’t open Operations Dashboard. Request access to try again.</p>
        <div className="operations-actions">
          <Link className="dashboard-primary-action" to="/access">
            Request access
          </Link>
          <Link className="history-back-link" to="/dashboard">
            Return to Dashboard
          </Link>
        </div>
      </section>
    );
  }

  return (
    <div className="operations-page">
      <header className="operations-hero panel" aria-labelledby="operations-title">
        <div>
          <span className="page-eyebrow">Protected workspace</span>
          <h1 id="operations-title">{currentRedemption.data.title}</h1>
          <p>You have been granted access to this protected workspace.</p>
        </div>
        <span className="operations-access-badge">
          <span aria-hidden="true">✓</span> Access granted
        </span>
      </header>

      <section className="operations-overview" aria-labelledby="operations-overview-title">
        <div className="section-heading">
          <div>
            <span className="page-eyebrow">Workspace overview</span>
            <h2 id="operations-overview-title">Your operations workspace</h2>
          </div>
          <Link className="history-back-link" to="/dashboard">
            Return to Dashboard
          </Link>
        </div>
        <div className="operations-overview-grid">
          <article className="panel operations-summary-card">
            <span className="operations-card-label">Overview</span>
            <p>{currentRedemption.data.summary}</p>
          </article>
          <article className="panel operations-status-card">
            <span className="operations-card-label">Workspace status</span>
            <strong>
              <span className="operations-status-dot" aria-hidden="true" /> Available
            </strong>
            <p>This workspace is ready to use.</p>
          </article>
        </div>
        {accessRequestId && (
          <section className="panel account-enrollment-panel" aria-labelledby="device-trust-title">
            <span className="page-eyebrow">Device familiarity</span>
            <h2 id="device-trust-title">
              {currentRedemption.recognition === "recognized"
                ? "This device is recognized"
                : "Trust this device for future access"}
            </h2>
            <p>
              Recognition is a familiarity signal for future access decisions. It does not replace
              sign-in or required verification.
            </p>
            {currentRedemption.recognition === "recognized" ? (
              <p role="status">This device is recognized for your account.</p>
            ) : (
              <button
                className="history-secondary-action account-restart-action"
                type="button"
                onClick={() => void trustThisDevice()}
                disabled={currentRedemption.recognition === "saving"}
              >
                {currentRedemption.recognition === "saving"
                  ? "Saving device preference…"
                  : "Trust this device for future access"}
              </button>
            )}
            {currentRedemption.recognition === "unavailable" && (
              <p role="status">
                Device status could not be checked. You can still choose to trust this device.
              </p>
            )}
            {currentRedemption.recognition === "failed" && (
              <p className="login-error" role="alert">
                We couldn’t save this device preference. Please try again.
              </p>
            )}
          </section>
        )}
      </section>
    </div>
  );
}
