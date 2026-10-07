import { afterEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock } = vi.hoisted(() => ({ apiRequestMock: vi.fn() }));
vi.mock("./client.ts", () => ({ apiRequest: apiRequestMock }));

import { fetchAdminDashboard, fetchAdminEventInvestigation, fetchAdminEvents } from "./admin.ts";
import { parseAdminEventPage } from "../types/admin.ts";

const dashboard = {
  total_requests: 12,
  allow_count: 5,
  step_up_count: 4,
  block_count: 3,
  average_trust_score: 67.5,
  high_risk_count: 2,
  mfa_success_rate: 0.75,
};

afterEach(() => vi.clearAllMocks());

describe("admin API", () => {
  it("loads backend dashboard metrics through the shared authenticated client", async () => {
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(dashboard), { status: 200 }));
    await expect(
      fetchAdminDashboard("2026-10-01T00:00:00Z", "2026-10-07T23:59:59Z"),
    ).resolves.toEqual(dashboard);
    expect(apiRequestMock).toHaveBeenCalledWith(
      "/admin/dashboard?from=2026-10-01T00%3A00%3A00Z&to=2026-10-07T23%3A59%3A59Z",
      { signal: undefined },
    );
  });

  it("sends all active event filters and pagination to the backend", async () => {
    const page = { items: [], total: 0, page: 2, page_size: 20 };
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(page), { status: 200 }));
    await fetchAdminEvents({
      from: "2026-10-01T00:00:00Z",
      to: "2026-10-07T23:59:59Z",
      user_id: "user-1",
      decision: "BLOCK",
      risk_category: "HIGH",
      device_id: "device-1",
      score_min: "75",
      score_max: "100",
      page: 2,
      page_size: 20,
    });
    const [path] = apiRequestMock.mock.calls[0] as [string];
    const query = new URL(path, "https://trustgate.test").searchParams;
    expect(Object.fromEntries(query)).toEqual({
      from: "2026-10-01T00:00:00Z",
      to: "2026-10-07T23:59:59Z",
      user_id: "user-1",
      decision: "BLOCK",
      risk_category: "HIGH",
      device_id: "device-1",
      score_min: "75",
      score_max: "100",
      page: "2",
      page_size: "20",
    });
  });

  it("loads a detail ID through the authenticated client", async () => {
    const detail = {
      event: null,
      access_request: null,
      context_signals: null,
      trust_evaluation: null,
      policy_decision: null,
      otp_challenges: [],
      related_events: [],
    };
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(detail), { status: 200 }));
    await expect(fetchAdminEventInvestigation("event/one")).resolves.toEqual(detail);
    expect(apiRequestMock).toHaveBeenCalledWith("/admin/events/event%2Fone", {
      signal: undefined,
    });
  });

  it("projects event responses to the documented display fields", () => {
    const parsed = parseAdminEventPage({
      items: [
        {
          id: "event-1",
          event_type: "ACCESS_REQUEST_SUBMITTED",
          created_at: "2026-10-01T12:00:00Z",
          user_id: "user-1",
          decision: "ALLOW",
          risk_category: "LOW",
          trust_score: "76.25",
          device: "abcdef012345…",
          otp_hash: "must not render",
        },
      ],
      total: 1,
      page: 1,
      page_size: 20,
      internal_details: "must not render",
    });
    expect(parsed.items[0]).toEqual({
      id: "event-1",
      event_type: "ACCESS_REQUEST_SUBMITTED",
      created_at: "2026-10-01T12:00:00Z",
      user_id: "user-1",
      decision: "ALLOW",
      risk_category: "LOW",
      trust_score: 76.25,
      device: "abcdef012345…",
    });
    expect(JSON.stringify(parsed)).not.toMatch(/otp_hash|internal_details|must not render/i);
  });
});
