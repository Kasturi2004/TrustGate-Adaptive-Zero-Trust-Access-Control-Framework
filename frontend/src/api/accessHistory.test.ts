import { afterEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock } = vi.hoisted(() => ({ apiRequestMock: vi.fn() }));

vi.mock("./client.ts", () => ({ apiRequest: apiRequestMock }));

import { fetchAccessHistory, fetchAccessRequest } from "./accessHistory.ts";
import { parseAccessHistoryEntry, parseAccessHistoryResponse } from "../types/accessHistory.ts";

const entry = {
  id: "123e4567-e89b-12d3-a456-426614174000",
  resource_id: "ops-dashboard",
  requested_at: "2026-10-02T12:00:00Z",
  initial_decision: "STEP_UP",
  final_outcome: "ALLOW",
  mfa_was_required: true,
  mfa_status: "SUCCESS",
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

  it("requests detail by the history row ID through the shared API client", async () => {
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(entry), { status: 200 }));

    await expect(fetchAccessRequest(entry.id)).resolves.toEqual(entry);
    expect(apiRequestMock).toHaveBeenCalledWith(`/access/request/${entry.id}`, {
      signal: undefined,
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
});
