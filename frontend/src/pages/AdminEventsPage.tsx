import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { fetchAdminEvents } from "../api/admin.ts";
import { AdminDecision } from "../components/AdminDecision.tsx";
import { AdminLoadingState } from "../components/AdminLoadingState.tsx";
import type { AdminEventFilters, AdminEventPage } from "../types/admin.ts";

const PAGE_SIZE = 20;

interface EventFilterDraft {
  from: string;
  to: string;
  user_id: string;
  decision: string;
  risk_category: string;
  device_id: string;
  score_min: string;
  score_max: string;
}

type LoadState =
  | { key: string; status: "loading" }
  | { key: string; status: "error" }
  | { key: string; status: "success"; data: AdminEventPage };

function dateInput(value: string | null): string {
  return value?.slice(0, 10) ?? "";
}

function initialDraft(search: URLSearchParams): EventFilterDraft {
  return {
    from: dateInput(search.get("from")),
    to: dateInput(search.get("to")),
    user_id: search.get("user_id") ?? "",
    decision: search.get("decision") ?? "",
    risk_category: search.get("risk_category") ?? "",
    device_id: search.get("device_id") ?? "",
    score_min: search.get("score_min") ?? "",
    score_max: search.get("score_max") ?? "",
  };
}

function apiFilters(draft: EventFilterDraft, page: number): AdminEventFilters {
  const filters: AdminEventFilters = { page, page_size: PAGE_SIZE };
  if (draft.from) filters.from = `${draft.from}T00:00:00Z`;
  if (draft.to) filters.to = `${draft.to}T23:59:59.999Z`;
  for (const field of [
    "user_id",
    "decision",
    "risk_category",
    "device_id",
    "score_min",
    "score_max",
  ] as const) {
    if (draft[field]) filters[field] = draft[field];
  }
  return filters;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}

export function AdminEventsPage() {
  const [searchParams] = useSearchParams();
  const [draft, setDraft] = useState(() => initialDraft(searchParams));
  const [filters, setFilters] = useState(() => initialDraft(searchParams));
  const [page, setPage] = useState(1);
  const [retryCount, setRetryCount] = useState(0);
  const requestFilters = apiFilters(filters, page);
  const requestKey = `${JSON.stringify(requestFilters)}:${retryCount}`;
  const [state, setState] = useState<LoadState>({ key: requestKey, status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    void fetchAdminEvents(apiFilters(filters, page), controller.signal)
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
  }, [filters, page, retryCount, requestKey]);

  const currentState =
    state.key === requestKey ? state : ({ key: requestKey, status: "loading" } as const);
  const totalPages =
    currentState.status === "success"
      ? Math.max(1, Math.ceil(currentState.data.total / currentState.data.page_size))
      : 1;

  function setField(field: keyof EventFilterDraft, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  function resetFilters() {
    const empty: EventFilterDraft = {
      from: "",
      to: "",
      user_id: "",
      decision: "",
      risk_category: "",
      device_id: "",
      score_min: "",
      score_max: "",
    };
    setDraft(empty);
    setFilters(empty);
    setPage(1);
  }

  return (
    <div className="admin-page admin-events-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">Administration</span>
          <h1>Security events</h1>
          <p>Filter persisted security events and open an investigation.</p>
        </div>
        <Link className="history-back-link" to="/admin/overview">
          Admin dashboard
        </Link>
      </header>

      <form
        className="panel admin-filter-form"
        aria-label="Security event filters"
        onSubmit={(event) => {
          event.preventDefault();
          setFilters(draft);
          setPage(1);
        }}
      >
        <label>
          From
          <input
            type="date"
            value={draft.from}
            onChange={(event) => setField("from", event.currentTarget.value)}
          />
        </label>
        <label>
          To
          <input
            type="date"
            value={draft.to}
            onChange={(event) => setField("to", event.currentTarget.value)}
          />
        </label>
        <label>
          User ID
          <input
            value={draft.user_id}
            onChange={(event) => setField("user_id", event.currentTarget.value)}
          />
        </label>
        <label>
          Decision
          <select
            value={draft.decision}
            onChange={(event) => setField("decision", event.currentTarget.value)}
          >
            <option value="">Any decision</option>
            <option value="ALLOW">ALLOW</option>
            <option value="STEP_UP">STEP-UP</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </label>
        <label>
          Risk category
          <select
            value={draft.risk_category}
            onChange={(event) => setField("risk_category", event.currentTarget.value)}
          >
            <option value="">Any risk category</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
          </select>
        </label>
        <label>
          Device ID
          <input
            value={draft.device_id}
            onChange={(event) => setField("device_id", event.currentTarget.value)}
          />
        </label>
        <label>
          Score minimum
          <input
            type="number"
            min="0"
            max="100"
            step="any"
            value={draft.score_min}
            onChange={(event) => setField("score_min", event.currentTarget.value)}
          />
        </label>
        <label>
          Score maximum
          <input
            type="number"
            min="0"
            max="100"
            step="any"
            value={draft.score_max}
            onChange={(event) => setField("score_max", event.currentTarget.value)}
          />
        </label>
        <button className="history-secondary-action" type="submit">
          Apply filters
        </button>
        <button className="history-secondary-action" type="button" onClick={resetFilters}>
          Reset filters
        </button>
      </form>

      {currentState.status === "loading" ? (
        <AdminLoadingState label="Loading security events…" />
      ) : currentState.status === "error" ? (
        <section className="panel admin-state" aria-labelledby="admin-events-error">
          <h2 id="admin-events-error">Unable to load security events</h2>
          <p role="alert">Security events are temporarily unavailable. Please try again.</p>
          <button
            className="history-secondary-action"
            type="button"
            onClick={() => setRetryCount((count) => count + 1)}
          >
            Try again
          </button>
        </section>
      ) : currentState.data.items.length === 0 ? (
        <section className="panel admin-state" aria-labelledby="admin-events-empty">
          <h2 id="admin-events-empty">No events match these filters</h2>
          <p>Try changing or clearing the filters.</p>
          <button className="history-secondary-action" type="button" onClick={resetFilters}>
            Reset filters
          </button>
        </section>
      ) : (
        <>
          <section className="panel admin-table-panel" aria-label="Security event results">
            <div className="admin-event-table" role="table" aria-label="Security events">
              <div className="admin-event-row admin-event-header" role="row">
                <span role="columnheader">Event</span>
                <span role="columnheader">Time</span>
                <span role="columnheader">User</span>
                <span role="columnheader">Decision</span>
                <span role="columnheader">Risk</span>
                <span role="columnheader">Trust score</span>
                <span role="columnheader">Device</span>
              </div>
              {currentState.data.items.map((item) => (
                <div className="admin-event-row" role="row" key={item.id}>
                  <Link role="cell" to={`/admin/events/${encodeURIComponent(item.id)}`}>
                    {item.event_type}
                  </Link>
                  <span role="cell">{formatDate(item.created_at)}</span>
                  <span role="cell" className="admin-mono">
                    {item.user_id ?? "—"}
                  </span>
                  <span role="cell">
                    <AdminDecision decision={item.decision} />
                  </span>
                  <span role="cell">{item.risk_category ?? "—"}</span>
                  <span role="cell">{item.trust_score === null ? "—" : item.trust_score}</span>
                  <span role="cell" className="admin-mono">
                    {item.device ?? "—"}
                  </span>
                </div>
              ))}
            </div>
          </section>
          <nav className="history-pagination" aria-label="Security event pages">
            <button
              className="history-secondary-action"
              type="button"
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              disabled={page <= 1}
            >
              Previous
            </button>
            <span aria-live="polite">
              Page {currentState.data.page} of {totalPages} · {currentState.data.total} events
            </span>
            <button
              className="history-secondary-action"
              type="button"
              onClick={() => setPage((current) => current + 1)}
              disabled={page >= totalPages}
            >
              Next
            </button>
          </nav>
        </>
      )}
    </div>
  );
}
