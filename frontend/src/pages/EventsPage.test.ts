import { describe, expect, it } from "vitest";
import { ApiError, api, buildEventsQuery } from "../api/client";
import type { SecurityEventPage } from "../types/api";
import { formatAuditTimestamp, paginationRange } from "./eventView";

const emptyPage: SecurityEventPage = { items: [], total: 0, page: 1, page_size: 20 };

describe("audit event API and pagination", () => {
  it("formats event timestamps consistently in local time", () => {
    expect(formatAuditTimestamp("2026-10-12T12:00:00Z")).toMatch(
      /^12 Oct 2026, \d{1,2}:\d{2} (AM|PM)$/,
    );
    expect(formatAuditTimestamp("invalid")).toBe("Unknown time");
  });

  it("serializes only filters supported by GET /admin/events", () => {
    const query = new URLSearchParams(buildEventsQuery(2, 20, {
      from: "2026-10-01T09:30",
      to: "2026-10-12T17:45",
      user_id: "user-uuid",
      decision: "STEP_UP",
      risk_category: "HIGH",
      device_id: "device-uuid",
      score_min: "25",
      score_max: "80",
    }));
    expect(query.get("page")).toBe("2");
    expect(query.get("page_size")).toBe("20");
    expect(query.get("from")).toBe(new Date("2026-10-01T09:30").toISOString());
    expect(query.get("to")).toBe(new Date("2026-10-12T17:45").toISOString());
    expect(query.get("user_id")).toBe("user-uuid");
    expect(query.get("decision")).toBe("STEP_UP");
    expect(query.get("risk_category")).toBe("HIGH");
    expect(query.get("device_id")).toBe("device-uuid");
    expect(query.get("score_min")).toBe("25");
    expect(query.get("score_max")).toBe("80");
    expect(query.has("search")).toBe(false);
  });

  it("returns API pagination and an empty filtered result without fabricating rows", async () => {
    const originalFetch = globalThis.fetch;
    let requestedUrl = "";
    globalThis.fetch = async (input) => {
      requestedUrl = String(input);
      return new Response(JSON.stringify(emptyPage), { status: 200 });
    };
    try {
      const page = await api.events("token", 3, 20, { decision: "BLOCK" });
      expect(new URL(requestedUrl).searchParams.get("page")).toBe("3");
      expect(new URL(requestedUrl).searchParams.get("decision")).toBe("BLOCK");
      expect(page).toEqual(emptyPage);
      expect(page.items).toHaveLength(0);
      expect(paginationRange(page.page, page.page_size, page.total)).toEqual({ start: 0, end: 0 });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not expose backend error details to the page", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ detail: "sensitive internal detail" }), { status: 422 });
    try {
      await expect(api.events("token", 1, 20)).rejects.toMatchObject({
        name: "ApiError",
        status: 422,
        message: "Request failed (422)",
      } satisfies Partial<ApiError>);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("computes page ranges from the server page size and total", () => {
    expect(paginationRange(2, 20, 45)).toEqual({ start: 21, end: 40 });
    expect(paginationRange(3, 20, 45)).toEqual({ start: 41, end: 45 });
  });
});
