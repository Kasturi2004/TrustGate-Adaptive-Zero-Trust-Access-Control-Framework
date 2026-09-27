import { useEffect, useState } from "react";
import { fetchHealth } from "../api/health.ts";
import { apiBaseUrl } from "../lib/env.ts";
import type { HealthCheckState } from "../types/health.ts";

export function HealthStatus() {
  const [state, setState] = useState<HealthCheckState>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();

    async function run(): Promise<void> {
      setState({ kind: "loading" });
      try {
        await fetchHealth(apiBaseUrl(), controller.signal);
        if (!controller.signal.aborted) {
          setState({ kind: "ok" });
        }
      } catch (error: unknown) {
        if (controller.signal.aborted) {
          return;
        }
        const message = error instanceof Error ? error.message : "Health check failed";
        setState({ kind: "error", message });
      }
    }

    void run();
    return () => controller.abort();
  }, [attempt]);

  const label =
    state.kind === "loading"
      ? "Checking backend"
      : state.kind === "ok"
        ? "Backend reachable"
        : "Backend unreachable";

  return (
    <section className="health" aria-live="polite">
      <span className={`health-dot ${state.kind}`} aria-hidden="true" />
      <div>
        <p className="health-label">{label}</p>
        {state.kind === "error" ? <p className="health-detail">{state.message}</p> : null}
      </div>
      {state.kind === "error" ? (
        <button type="button" className="retry" onClick={() => setAttempt((value) => value + 1)}>
          Retry
        </button>
      ) : null}
    </section>
  );
}
