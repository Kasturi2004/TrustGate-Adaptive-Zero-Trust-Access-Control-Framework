import { describe, expect, it } from "vitest";
import { ApiError, api, dashboardInterval } from "../api/client";
import type { DashboardMetrics } from "../types/api";
import { customDashboardInterval, decisionDistribution, utcDateInput } from "./analyticsModel";

const metrics: DashboardMetrics = {
  total_requests: 8,
  allow_count: 5,
  step_up_count: 2,
  block_count: 1,
  average_trust_score: 73.5,
  high_risk_count: 1,
  mfa_success_rate: 0.75,
  behavioral_indicators: {
    repeated_failed_access_attempts: { count: 2, normalized_value: 0.4, flagged: false },
    recent_blocks: { count: 1, normalized_value: 0.5, flagged: false },
  },
};

describe("analytics calculations and date ranges", () => {
  it("calculates initial decision shares without treating STEP-UP as a final outcome", () => {
    expect(decisionDistribution(metrics)).toEqual([
      { decision: "ALLOW", count: 5, percentage: 62.5 },
      { decision: "STEP_UP", count: 2, percentage: 25 },
      { decision: "BLOCK", count: 1, percentage: 12.5 },
    ]);
  });

  it("returns zero shares for an empty period", () => {
    expect(decisionDistribution({ allow_count: 0, step_up_count: 0, block_count: 0 })).toEqual([
      { decision: "ALLOW", count: 0, percentage: 0 },
      { decision: "STEP_UP", count: 0, percentage: 0 },
      { decision: "BLOCK", count: 0, percentage: 0 },
    ]);
  });

  it("creates preset and custom inclusive UTC intervals", () => {
    const now = new Date("2026-10-12T12:00:00.000Z");
    const sevenDays = dashboardInterval(now, 7);
    expect(sevenDays.from.toISOString()).toBe("2026-10-05T12:00:00.000Z");
    expect(sevenDays.to.toISOString()).toBe(now.toISOString());
    const custom = customDashboardInterval("2026-10-01", "2026-10-03");
    expect(custom.from.toISOString()).toBe("2026-10-01T00:00:00.000Z");
    expect(custom.to.toISOString()).toBe("2026-10-03T23:59:59.999Z");
    expect(utcDateInput(custom.from)).toBe("2026-10-01");
    expect(() => customDashboardInterval("2026-10-04", "2026-10-03")).toThrow("must not be after");
  });

  it("surfaces analytics API errors without inventing a fallback dataset", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Dashboard unavailable" }), { status: 503 });
    try {
      await expect(api.dashboard("token", new Date("2026-10-01T00:00:00Z"), new Date("2026-10-02T00:00:00Z")))
        .rejects.toBeInstanceOf(ApiError);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
