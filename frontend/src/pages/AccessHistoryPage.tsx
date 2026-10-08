import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  fetchAccessHistory,
  fetchAccessRequest,
  type AccessRequestDetail,
} from "../api/accessHistory.ts";
import type { AccessHistoryEntry } from "../types/accessHistory.ts";
import { useProfileRole } from "../auth/useProfileRole.ts";
import { AdminEventInvestigationPage } from "./AdminEventInvestigationPage.tsx";

const PAGE_SIZE = 10;
const SAFE_ERROR = "Access history is temporarily unavailable. Please try again.";

type DetailLoadState =
  | { key: string; status: "loading" }
  | { key: string; status: "error" }
  | { key: string; status: "success"; detail: AccessRequestDetail };

type HistoryLoadState =
  | { key: string; status: "loading" }
  | { key: string; status: "error" }
  | { key: string; status: "success"; records: AccessHistoryEntry[]; hasNextPage: boolean };

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatAuthenticatorStatus(record: AccessHistoryEntry): string {
  if (!record.mfa_was_required) return "Not required";
  switch (record.mfa_status) {
    case "SUCCESS":
      return "Verified";
    case "PENDING":
      return "Verification pending";
    case "EXPIRED":
      return "Expired";
    case "LOCKED":
      return "Locked";
    case null:
      return "Not recorded";
    default:
      return "Status unavailable";
  }
}

export function DetailFields({ record }: { record: AccessHistoryEntry }) {
  return (
    <dl className="history-detail-grid">
      <div>
        <dt>Request ID</dt>
        <dd className="history-id">{record.id}</dd>
      </div>
      <div>
        <dt>Resource</dt>
        <dd>{record.resource_id}</dd>
      </div>
      <div>
        <dt>Requested</dt>
        <dd>{formatDate(record.requested_at)}</dd>
      </div>
      <div>
        <dt>Initial decision</dt>
        <dd>{record.initial_decision}</dd>
      </div>
      <div>
        <dt>Final outcome</dt>
        <dd>{record.final_outcome ?? "Pending"}</dd>
      </div>
      <div>
        <dt>Authenticator required</dt>
        <dd>{record.mfa_was_required ? "Yes" : "No"}</dd>
      </div>
      <div>
        <dt>Authenticator</dt>
        <dd>{formatAuthenticatorStatus(record)}</dd>
      </div>
    </dl>
  );
}

function AccessRequestDetail({ accessRequestId }: { accessRequestId: string }) {
  const { role, loading: roleLoading } = useProfileRole();
  const [retryCount, setRetryCount] = useState(0);
  const requestKey = `${accessRequestId}:${retryCount}`;
  const [state, setState] = useState<DetailLoadState>({ key: requestKey, status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    void fetchAccessRequest(accessRequestId, controller.signal)
      .then((result) => {
        if (active) setState({ key: requestKey, status: "success", detail: result });
      })
      .catch(() => {
        if (active && !controller.signal.aborted) {
          setState({ key: requestKey, status: "error" });
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [accessRequestId, requestKey]);

  const currentState =
    state.key === requestKey ? state : { key: requestKey, status: "loading" as const };

  return (
    <div className="history-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">Your activity</span>
          <h1>Access request</h1>
          <p>Curated details for this access request.</p>
        </div>
        <Link className="history-back-link" to="/history">
          Back to history
        </Link>
      </header>

      {currentState.status === "loading" ? (
        <section className="panel history-state" role="status" aria-live="polite">
          Loading access request…
        </section>
      ) : currentState.status === "error" ? (
        <section className="panel history-state" aria-labelledby="history-error-title">
          <h2 id="history-error-title">Unable to load request</h2>
          <p className="history-error" role="alert">
            {SAFE_ERROR}
          </p>
          <button
            className="history-secondary-action"
            type="button"
            onClick={() => setRetryCount((count) => count + 1)}
          >
            Try again
          </button>
        </section>
      ) : currentState.detail.kind === "admin" ? (
        roleLoading ? (
          <section className="panel history-state" role="status" aria-live="polite">
            Checking administrator access…
          </section>
        ) : role === "ADMIN" ? (
          <AdminEventInvestigationPage
            investigation={currentState.detail.investigation}
            backTo="/history"
            backLabel="Back to history"
          />
        ) : (
          <section className="panel history-state" aria-labelledby="history-error-title">
            <h2 id="history-error-title">Unable to load request</h2>
            <p className="history-error" role="alert">
              {SAFE_ERROR}
            </p>
          </section>
        )
      ) : (
        <section className="panel history-detail-panel" aria-label="Access request details">
          <DetailFields record={currentState.detail.record} />
        </section>
      )}
    </div>
  );
}

function AccessHistoryList() {
  const [page, setPage] = useState(1);
  const [retryCount, setRetryCount] = useState(0);
  const requestKey = `${page}:${retryCount}`;
  const [state, setState] = useState<HistoryLoadState>({ key: requestKey, status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    void fetchAccessHistory(page, PAGE_SIZE, controller.signal)
      .then((result) => {
        if (active) {
          setState({
            key: requestKey,
            status: "success",
            records: result,
            hasNextPage: result.length === PAGE_SIZE,
          });
        }
      })
      .catch(() => {
        if (active && !controller.signal.aborted) {
          setState({ key: requestKey, status: "error" });
        }
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [page, requestKey]);

  const currentState =
    state.key === requestKey ? state : { key: requestKey, status: "loading" as const };

  return (
    <div className="history-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">Your activity</span>
          <h1>Access history</h1>
          <p>Review your recent protected-resource requests.</p>
        </div>
      </header>

      {currentState.status === "loading" ? (
        <section className="panel history-state" role="status" aria-live="polite">
          Loading access history…
        </section>
      ) : currentState.status === "error" ? (
        <section className="panel history-state" aria-labelledby="history-error-title">
          <h2 id="history-error-title">Unable to load history</h2>
          <p className="history-error" role="alert">
            {SAFE_ERROR}
          </p>
          <button
            className="history-secondary-action"
            type="button"
            onClick={() => setRetryCount((count) => count + 1)}
          >
            Try again
          </button>
        </section>
      ) : currentState.records.length === 0 ? (
        <section className="panel history-state" aria-labelledby="history-empty-title">
          <h2 id="history-empty-title">
            {page === 1 ? "No access history yet" : "No requests on this page"}
          </h2>
          <p>Your protected-resource requests will appear here.</p>
        </section>
      ) : (
        <>
          <section className="panel history-list-panel" aria-label="Access history results">
            <ul className="history-list">
              {currentState.records.map((record) => (
                <li key={record.id}>
                  <Link className="history-row" to={`/history/${encodeURIComponent(record.id)}`}>
                    <span className="history-row-main">
                      <strong>{record.resource_id}</strong>
                      <span>{formatDate(record.requested_at)}</span>
                    </span>
                    <span className="history-row-outcome">
                      <span>Initial decision: {record.initial_decision}</span>
                      <small>Final outcome: {record.final_outcome ?? "Pending"}</small>
                    </span>
                    <span className="history-row-mfa">
                      <span>
                        Authenticator {record.mfa_was_required ? "required" : "not required"}
                      </span>
                      <small>Authenticator: {formatAuthenticatorStatus(record)}</small>
                    </span>
                    <span className="history-row-id">{record.id}</span>
                    <span className="history-row-arrow" aria-hidden="true">
                      →
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>

          <nav className="history-pagination" aria-label="Access history pages">
            <button
              className="history-secondary-action"
              type="button"
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              disabled={page === 1}
            >
              Previous
            </button>
            <span aria-live="polite">Page {page}</span>
            <button
              className="history-secondary-action"
              type="button"
              onClick={() => setPage((current) => current + 1)}
              disabled={!currentState.hasNextPage}
            >
              Next
            </button>
          </nav>
        </>
      )}
    </div>
  );
}

export function AccessHistoryPage() {
  const { accessRequestId } = useParams();
  return accessRequestId ? (
    <AccessRequestDetail accessRequestId={accessRequestId} />
  ) : (
    <AccessHistoryList />
  );
}
