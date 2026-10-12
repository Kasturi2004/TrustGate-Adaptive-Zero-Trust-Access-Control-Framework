import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ChevronLeft, ChevronRight, Plus, RefreshCw, X } from "../components/Icons";
import { api } from "../api/client";
import type { SecurityEventFilters } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { EventTable } from "../components/EventTable";
import { DateRangePicker } from "../components/DateRangePicker";
import { ErrorState, LoadingState } from "../components/States";
import type { SecurityEventPage } from "../types/api";
import { formatAuditTimestamp, paginationRange } from "./eventView";

const PAGE_SIZE = 20;
type FilterDraft = {
  from: string;
  to: string;
  user_id: string;
  decision: "" | "ALLOW" | "STEP_UP" | "BLOCK";
  risk_category: "" | "LOW" | "MEDIUM" | "HIGH";
  device_id: string;
  score_min: string;
  score_max: string;
};
type ExtraFilterEditor = "risk_category" | "device_id" | "score_min" | "score_max";
const emptyFilters: FilterDraft = {
  from: "", to: "", user_id: "", decision: "", risk_category: "",
  device_id: "", score_min: "", score_max: "",
};

const filterLabels: Record<keyof SecurityEventFilters, string> = {
  from: "From",
  to: "To",
  user_id: "User ID",
  decision: "Decision",
  risk_category: "Risk",
  device_id: "Device ID",
  score_min: "Trust score min",
  score_max: "Trust score max",
};

function filterValueLabel(key: keyof SecurityEventFilters, value: string) {
  if (key === "from" || key === "to") return formatAuditTimestamp(value);
  if (key === "user_id" || key === "device_id") {
    return value.length > 22 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value;
  }
  if (key === "decision") return value === "STEP_UP" ? "Step-up" : value;
  return value;
}

function dateRangeLabel(from: string, to: string) {
  const date = (value: string) => {
    const [year, month, day] = value.slice(0, 10).split("-").map(Number);
    return new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric" }).format(new Date(year!, month! - 1, day!));
  };
  if (!from || !to) return from ? `From ${date(from)}` : `Through ${date(to)}`;
  return `${date(from)} \u2013 ${date(to)}`;
}

function appliedFilters(draft: FilterDraft): SecurityEventFilters {
  return Object.fromEntries(
    Object.entries(draft).filter(([, value]) => value !== ""),
  ) as SecurityEventFilters;
}

export function EventsPage() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [page, setPage] = useState(1);
  const [draft, setDraft] = useState<FilterDraft>(emptyFilters);
  const [filters, setFilters] = useState<SecurityEventFilters>({});
  const [filterError, setFilterError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);
  const [result, setResult] = useState<SecurityEventPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [dateRangeOpenRequest, setDateRangeOpenRequest] = useState(0);
  const [addFilterOpen, setAddFilterOpen] = useState(false);
  const [visibleFilterEditors, setVisibleFilterEditors] = useState<Set<ExtraFilterEditor>>(() => new Set());
  const addFilterRef = useRef<HTMLDetailsElement>(null);
  const addFilterSummaryRef = useRef<HTMLElement>(null);
  const userIdRef = useRef<HTMLInputElement>(null);
  const decisionTabsRef = useRef<HTMLDivElement>(null);
  const riskRef = useRef<HTMLSelectElement>(null);
  const deviceIdRef = useRef<HTMLInputElement>(null);
  const scoreMinRef = useRef<HTMLInputElement>(null);
  const scoreMaxRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      setResult(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setResult(null);
    void api.events(token, page, PAGE_SIZE, filters, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setResult(data);
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : "Unable to load security events.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [token, page, filters, refreshKey]);

  useEffect(() => {
    if (!addFilterOpen) return;
    const closeOutside = (event: PointerEvent) => {
      if (!addFilterRef.current?.contains(event.target as Node)) {
        if (addFilterRef.current) addFilterRef.current.open = false;
        setAddFilterOpen(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (addFilterRef.current) addFilterRef.current.open = false;
        setAddFilterOpen(false);
        addFilterSummaryRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [addFilterOpen]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilterError("");
    if (draft.from && draft.to && new Date(draft.from) > new Date(draft.to)) {
      setFilterError("From date and time must not be later than To.");
      return;
    }
    if (draft.score_min && draft.score_max && Number(draft.score_min) > Number(draft.score_max)) {
      setFilterError("The minimum trust score must not exceed the maximum.");
      return;
    }
    setPage(1);
    setFilters(appliedFilters(draft));
  }

  function clearFilters() {
    setDraft(emptyFilters);
    setVisibleFilterEditors(new Set());
    setFilterError("");
    setPage(1);
    setFilters({});
  }

  const range = result ? paginationRange(result.page, result.page_size, result.total) : { start: 0, end: 0 };

  function chooseDecision(decision: FilterDraft["decision"]) {
    setDraft((current) => ({ ...current, decision }));
  }

  function removeAppliedFilter(key: keyof SecurityEventFilters) {
    if (key === "from" || key === "to") {
      setFilters((current) => { const next = { ...current }; delete next.from; delete next.to; return next; });
      setDraft((current) => ({ ...current, from: "", to: "" }));
      setFilterError("");
      setPage(1);
      return;
    }
    setFilters((current) => {
      const next = { ...current };
      delete next[key];
      return next;
    });
    setDraft((current) => ({ ...current, [key]: "" }));
    setFilterError("");
    setPage(1);
    if (key === "risk_category" || key === "device_id" || key === "score_min" || key === "score_max") {
      setVisibleFilterEditors((current) => {
        const next = new Set(current);
        next.delete(key);
        return next;
      });
    }
  }

  function showFilterEditor(key: ExtraFilterEditor, target: { current: HTMLElement | null }) {
    setVisibleFilterEditors((current) => new Set(current).add(key));
    requestAnimationFrame(() => target.current?.focus());
  }

  function chooseFilterOption(option: keyof SecurityEventFilters) {
    if (addFilterRef.current) addFilterRef.current.open = false;
    setAddFilterOpen(false);
    switch (option) {
      case "from":
      case "to": setDateRangeOpenRequest((request) => request + 1); break;
      case "user_id": requestAnimationFrame(() => userIdRef.current?.focus()); break;
      case "decision": requestAnimationFrame(() => decisionTabsRef.current?.querySelector("button")?.focus()); break;
      case "risk_category": showFilterEditor("risk_category", riskRef); break;
      case "device_id": showFilterEditor("device_id", deviceIdRef); break;
      case "score_min": showFilterEditor("score_min", scoreMinRef); break;
      case "score_max": showFilterEditor("score_max", scoreMaxRef); break;
    }
  }

  const hasAppliedDateRange = Boolean(filters.from && filters.to);
  const activeFilters = (Object.entries(filters).filter(([key]) => !hasAppliedDateRange || (key !== "from" && key !== "to"))) as [keyof SecurityEventFilters, string][];
  const hasAnyFilters = Object.keys(filters).length > 0 || Object.values(draft).some(Boolean);
  const scoreRangeInvalid = filterError.startsWith("The minimum trust score");

  return (
    <div className="audit-page">
      <form className="audit-toolbar" onSubmit={applyFilters}>
        <label className="audit-search-field">
          <span className="sr-only">Filter by user ID</span>
          <input
            ref={userIdRef}
            type="text"
            inputMode="text"
            autoComplete="off"
            placeholder="Filter by user ID (UUID)..."
            value={draft.user_id}
            onChange={(event) => setDraft({ ...draft, user_id: event.target.value.trim() })}
          />
        </label>
        <div ref={decisionTabsRef} className="audit-decision-tabs" role="group" aria-label="Filter by decision" tabIndex={-1}>
          {([
            ["", "All"],
            ["ALLOW", "Allow"],
            ["STEP_UP", "Step-up"],
            ["BLOCK", "Block"],
          ] as const).map(([value, label]) => (
            <button
              key={label}
              type="button"
              className={draft.decision === value ? "active" : ""}
              aria-pressed={draft.decision === value}
              onClick={() => chooseDecision(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <DateRangePicker
          value={{ from: draft.from, to: draft.to }}
          appliedValue={{ from: filters.from ?? "", to: filters.to ?? "" }}
          onChange={(range) => { setDraft((current) => ({ ...current, from: range.from, to: range.to })); setFilterError(""); }}
          openRequest={dateRangeOpenRequest}
        />
        <details className="audit-add-filter" ref={addFilterRef} onToggle={(event) => setAddFilterOpen(event.currentTarget.open)}>
          <summary ref={addFilterSummaryRef} className="secondary-button" aria-expanded={addFilterOpen} aria-controls="audit-add-filter-menu"><Plus size={15} />Add filter</summary>
          <div id="audit-add-filter-menu" className="audit-add-filter-menu" role="group" aria-label="Add filter">
            <button type="button" onClick={() => chooseFilterOption("user_id")}>User ID</button>
            <button type="button" onClick={() => chooseFilterOption("decision")}>Decision</button>
            <button type="button" onClick={() => chooseFilterOption("risk_category")}>Risk classification</button>
            <button type="button" onClick={() => chooseFilterOption("from")}>Date range</button>
            <button type="button" onClick={() => chooseFilterOption("device_id")}>Device ID</button>
            <button type="button" onClick={() => chooseFilterOption("score_min")}>Minimum trust score</button>
            <button type="button" onClick={() => chooseFilterOption("score_max")}>Maximum trust score</button>
          </div>
        </details>
        {hasAnyFilters && <button className="secondary-button audit-clear-all" type="button" onClick={clearFilters}>Clear all</button>}
        <button className="audit-apply-button" type="submit">Apply filters</button>
        <button
          className="icon-button audit-refresh-button"
          type="button"
          aria-label="Refresh audit logs"
          onClick={() => setRefreshKey((value) => value + 1)}
          disabled={loading}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} />
        </button>

        {visibleFilterEditors.size > 0 && (
          <div className="audit-filter-editors">
            {visibleFilterEditors.has("risk_category") && <label>
              <span>Risk classification</span>
              <select ref={riskRef} value={draft.risk_category} onChange={(event) => setDraft({ ...draft, risk_category: event.target.value as FilterDraft["risk_category"] })}>
                <option value="">All risk levels</option>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
              </select>
            </label>}
            {visibleFilterEditors.has("device_id") && <label>
              <span>Device ID</span>
              <input ref={deviceIdRef} type="text" inputMode="text" autoComplete="off" placeholder="UUID" value={draft.device_id} onChange={(event) => setDraft({ ...draft, device_id: event.target.value.trim() })} />
            </label>}
            {visibleFilterEditors.has("score_min") && <label>
              <span>Trust score min</span>
              <input ref={scoreMinRef} type="number" min="0" max="100" step="any" value={draft.score_min} aria-invalid={scoreRangeInvalid} aria-describedby={scoreRangeInvalid ? "audit-filter-error" : undefined} onChange={(event) => { setDraft({ ...draft, score_min: event.target.value }); setFilterError(""); }} />
            </label>}
            {visibleFilterEditors.has("score_max") && <label>
              <span>Trust score max</span>
              <input ref={scoreMaxRef} type="number" min="0" max="100" step="any" value={draft.score_max} aria-invalid={scoreRangeInvalid} aria-describedby={scoreRangeInvalid ? "audit-filter-error" : undefined} onChange={(event) => { setDraft({ ...draft, score_max: event.target.value }); setFilterError(""); }} />
            </label>}
          </div>
        )}
      </form>
      {(activeFilters.length > 0 || filters.from || filters.to) && (
        <div className="audit-active-filters" role="group" aria-label="Applied filters">
          <span className="audit-active-label">Applied filters</span>
          {(filters.from || filters.to) && (
            <span className="audit-filter-chip">
              <span className="audit-filter-chip-copy"><strong>Date range</strong><span>{dateRangeLabel(filters.from ?? "", filters.to ?? "")}</span></span>
              <button type="button" aria-label="Remove Date range filter" onClick={() => removeAppliedFilter("from")}><X size={13} /></button>
            </span>
          )}
          {activeFilters.map(([key, value]) => (
            <span className="audit-filter-chip" key={key}>
              <span className="audit-filter-chip-copy"><strong>{filterLabels[key]}</strong><span>{filterValueLabel(key, value)}</span></span>
              <button type="button" aria-label={`Remove ${filterLabels[key]} filter`} onClick={() => removeAppliedFilter(key)}><X size={13} /></button>
            </span>
          ))}
        </div>
      )}
      {filterError && (
        <p className="audit-filter-error" role="alert" id="audit-filter-error">
          {filterError}
        </p>
      )}

      {error && <ErrorState message={error} onRetry={() => setRefreshKey((value) => value + 1)} />}
      {loading ? <LoadingState label="Loading persisted security events" /> : result && (
        <>
          <EventTable events={result.items} />
          <div className="pagination">
            <span>{range.start ? `${range.start}–${range.end} of ${result.total} events` : "0 events"}</span>
            <div>
              <button
                className="icon-button"
                aria-label="Previous page"
                disabled={result.page <= 1 || loading}
                onClick={() => setPage((value) => Math.max(1, value - 1))}
              ><ChevronLeft size={17} /></button>
              <span className="page-number">{result.page}</span>
              <button
                className="icon-button"
                aria-label="Next page"
                disabled={result.page * result.page_size >= result.total || loading}
                onClick={() => setPage((value) => value + 1)}
              ><ChevronRight size={17} /></button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
