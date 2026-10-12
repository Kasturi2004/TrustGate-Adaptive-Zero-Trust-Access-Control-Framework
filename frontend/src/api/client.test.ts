import { describe, expect, it } from "vitest";
import { ApiError, api, dashboardInterval } from "./client";

describe("dashboardInterval", () => {
  it("returns an inclusive thirty-day UTC window ending at the supplied time", () => {
    const now = new Date("2026-10-12T12:00:00.000Z");
    const { from, to } = dashboardInterval(now);
    expect(to.toISOString()).toBe(now.toISOString());
    expect(from.toISOString()).toBe("2026-09-12T12:00:00.000Z");
  });
});

describe("api.login", () => {
  it("uses the configured backend login endpoint without exposing response details", async () => {
    const originalFetch = globalThis.fetch;
    let requestUrl = "";
    let requestInit: RequestInit | undefined;
    globalThis.fetch = async (input, init) => {
      requestUrl = String(input);
      requestInit = init;
      return new Response(JSON.stringify({ detail: "private upstream failure" }), { status: 503 });
    };
    try {
      await expect(api.login("admin@example.test", "secret")).rejects.toMatchObject({
        name: "ApiError",
        status: 503,
        message: "Sign-in request failed (503)",
      } satisfies Partial<ApiError>);
      expect(requestUrl).toMatch(/\/auth\/login$/);
      expect(requestInit?.method).toBe("POST");
      expect(JSON.parse(String(requestInit?.body))).toEqual({
        email: "admin@example.test",
        password: "secret",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("api.investigation", () => {
  it("forwards an abort signal to the selected event request", async () => {
    const originalFetch = globalThis.fetch;
    const controller = new AbortController();
    let requestUrl = "";
    let requestSignal: AbortSignal | null | undefined;
    globalThis.fetch = async (input, init) => {
      requestUrl = String(input);
      requestSignal = init?.signal;
      return new Response(JSON.stringify({ event: null, related_events: [] }), { status: 200 });
    };
    try {
      await api.investigation("token", "event/id", controller.signal);
      expect(requestUrl).toMatch(/\/admin\/events\/event%2Fid$/);
      expect(requestSignal).toBe(controller.signal);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
