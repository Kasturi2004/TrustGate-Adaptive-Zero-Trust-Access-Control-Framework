import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "../components/Icons";
import { api } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { EventTable } from "../components/EventTable";
import { ErrorState, LoadingState } from "../components/States";
import { SectionHeading } from "../components/SectionHeading";
import type { SecurityEventPage } from "../types/api";

export function InvestigationsPage() {
  const { session } = useAuth();
  const token = session?.access_token;
  const [result, setResult] = useState<SecurityEventPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      setResult(await api.events(token, 1, 20));
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to load investigation records.",
      );
    } finally {
      setLoading(false);
    }
  }, [token]);
  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="panel page-panel">
      <div className="page-panel-heading">
        <SectionHeading
          title="Investigation queue"
          detail="Open a persisted security event to review its recorded access and risk context"
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
      {loading && !result ? (
        <LoadingState />
      ) : (
        result && <EventTable events={result.items} />
      )}
    </section>
  );
}
