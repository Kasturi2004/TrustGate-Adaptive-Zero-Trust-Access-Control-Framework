import { afterEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock } = vi.hoisted(() => ({ apiRequestMock: vi.fn() }));

vi.mock("./client.ts", () => ({ apiRequest: apiRequestMock }));

import { fetchAccessHistory, fetchAccessRequest } from "./accessHistory.ts";
import { parseAccessHistoryEntry, parseAccessHistoryResponse } from "../types/accessHistory.ts";
import type { AdminEventInvestigation } from "../types/admin.ts";

const entry = {
  id: "123e4567-e89b-12d3-a456-426614174000",
  resource_id: "ops-dashboard",
  requested_at: "2026-10-02T12:00:00Z",
  initial_decision: "STEP_UP",
  final_outcome: "ALLOW",
  mfa_was_required: true,
  mfa_status: "SUCCESS",
};

const investigation: AdminEventInvestigation = {
  event: {
    id: "223e4567-e89b-12d3-a456-426614174000",
    event_type: "ACCESS_STEP_UP",
    actor_id: "323e4567-e89b-12d3-a456-426614174000",
    target_user_id: null,
    decision: "STEP_UP",
    risk_category: "MEDIUM",
    created_at: "2026-10-02T12:00:00Z",
  },
  access_request: {
    id: entry.id,
    user_id: "323e4567-e89b-12d3-a456-426614174000",
    resource_id: entry.resource_id,
    source_ip: "192.0.2.10",
    resolved_region: "Example region",
    initial_decision: "STEP_UP",
    mfa_required: true,
    final_outcome: "ALLOW",
    requested_at: entry.requested_at,
    resolved_at: "2026-10-02T12:01:00Z",
    device: { id: "423e4567-e89b-12d3-a456-426614174000", device_hash: "abcd…" },
  },
  context_signals: {
    captured_at: "2026-10-02T12:00:00Z",
    device_familiarity_raw: "unknown_device",
    device_health_raw: "healthy",
    location_raw: "expected_region",
    time_raw: "usual_time",
  },
  trust_evaluation: {
    id: "523e4567-e89b-12d3-a456-426614174000",
    trust_score: 67,
    risk_classification: "MEDIUM",
    status: "COMPLETE",
    evaluated_at: "2026-10-02T12:00:00Z",
    factors: [
      {
        factor_name: "device_familiarity",
        raw_value: "unknown_device",
        normalized_score: 20,
        weight: 0.3,
        weighted_contribution: 6,
        explanation: "Device familiarity explanation",
      },
    ],
  },
  policy_decision: {
    id: "623e4567-e89b-12d3-a456-426614174000",
    decision: "STEP_UP",
    decision_reason: "Additional verification required",
    decided_at: "2026-10-02T12:00:00Z",
    policy_version: {
      id: "723e4567-e89b-12d3-a456-426614174000",
      version_label: "v1",
      created_at: "2026-10-01T12:00:00Z",
    },
  },
  otp_challenges: [
    {
      id: "823e4567-e89b-12d3-a456-426614174000",
      status: "SUCCESS",
      attempt_count: 1,
      created_at: "2026-10-02T12:00:00Z",
      expires_at: "2026-10-02T12:05:00Z",
      verified_at: "2026-10-02T12:01:00Z",
    },
  ],
  related_events: [],
  behavioral_indicators: {
    repeated_failed_access_attempts: { count: 0, normalized_value: 0, flagged: false },
    recent_blocks: { count: 0, normalized_value: 0, flagged: false },
  },
};

afterEach(() => vi.clearAllMocks());

describe("access history API", () => {
  it("requests the requested page through the shared authenticated API client", async () => {
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify([entry]), { status: 200 }));

    await expect(fetchAccessHistory(2, 10)).resolves.toEqual([entry]);
    expect(apiRequestMock).toHaveBeenCalledWith("/access/history?page=2&page_size=10", {
      signal: undefined,
    });
  });

  it("requests USER detail by the history row ID through the shared API client", async () => {
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(entry), { status: 200 }));

    await expect(fetchAccessRequest(entry.id)).resolves.toEqual({ kind: "user", record: entry });
    expect(apiRequestMock).toHaveBeenCalledWith(`/access/request/${entry.id}`, {
      signal: undefined,
    });
  });

  it("parses the existing ADMIN investigation response explicitly", async () => {
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(investigation), { status: 200 }));

    await expect(fetchAccessRequest(entry.id)).resolves.toEqual({
      kind: "admin",
      investigation,
    });
  });

  it("returns only the seven allowed response fields", () => {
    expect(() =>
      parseAccessHistoryEntry({ ...entry, trust_score: 0.91, factors: { location: 1 } }),
    ).toThrow("Access history response was not recognized");
    expect(parseAccessHistoryResponse([entry])).toEqual([entry]);
  });

  it("does not expose backend error response content to the caller", async () => {
    apiRequestMock.mockResolvedValue(
      new Response("private backend error details", { status: 500 }),
    );

    await expect(fetchAccessHistory(1, 10)).rejects.toThrow("Access history request failed");
  });

  it("rejects malformed detail responses instead of treating them as a USER or ADMIN result", async () => {
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify({ id: entry.id, trust_score: 91 }), { status: 200 }),
    );

    await expect(fetchAccessRequest(entry.id)).rejects.toThrow();
  });
});
