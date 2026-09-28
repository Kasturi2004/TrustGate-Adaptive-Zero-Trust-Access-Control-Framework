import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSessionMock, refreshSessionMock, fetchMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  refreshSessionMock: vi.fn(),
  fetchMock: vi.fn(),
}));

vi.mock("../lib/supabase.ts", () => ({
  supabase: {
    auth: {
      getSession: getSessionMock,
      refreshSession: refreshSessionMock,
    },
  },
}));

import { supabase } from "../lib/supabase.ts";
import { apiRequest } from "./client.ts";

const ACCESS_TOKEN = "test-current-access-token";

beforeEach(() => {
  vi.stubEnv("VITE_API_BASE_URL", "https://api.example.test/");
  vi.stubGlobal("fetch", fetchMock);
  getSessionMock.mockReset();
  getSessionMock.mockResolvedValue({
    data: { session: { access_token: ACCESS_TOKEN } },
    error: null,
  });
  refreshSessionMock.mockReset();
  fetchMock.mockReset();
  fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("apiRequest", () => {
  it("uses the configured API base URL and current session token for GET", async () => {
    const response = new Response(null, { status: 204 });
    fetchMock.mockResolvedValue(response);

    const result = await apiRequest("/profile");

    expect(result).toBe(response);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.example.test/profile");
    expect(init.method).toBe("GET");
    expect(new Headers(init.headers).get("Authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(getSessionMock).toHaveBeenCalledOnce();
  });

  it("sends JSON for POST and preserves additional and compatible headers", async () => {
    await apiRequest("events", {
      method: "POST",
      body: { event: "test" },
      headers: {
        "X-Request-Source": "frontend-test",
        "Content-Type": "application/json; charset=utf-8",
      },
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe("https://api.example.test/events");
    expect(init.method).toBe("POST");
    expect(init.body).toBe('{"event":"test"}');
    expect(headers.get("Content-Type")).toBe("application/json; charset=utf-8");
    expect(headers.get("X-Request-Source")).toBe("frontend-test");
    expect(headers.get("Authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
  });

  it("uses JSON content type when the caller supplied an incompatible content type", async () => {
    await apiRequest("resource", {
      method: "PUT",
      body: { enabled: true },
      headers: { "Content-Type": "text/plain" },
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(init.headers).get("Content-Type")).toBe("application/json");
  });

  it("does not fabricate an authorization header without a session", async () => {
    getSessionMock.mockResolvedValue({ data: { session: null }, error: null });

    await apiRequest("public-status", { method: "GET" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(init.headers).has("Authorization")).toBe(false);
  });

  it("returns a 401 response without retrying or refreshing the session", async () => {
    const unauthorized = new Response(null, { status: 401 });
    fetchMock.mockResolvedValue(unauthorized);

    const result = await apiRequest("protected-resource");

    expect(result).toBe(unauthorized);
    expect(result.status).toBe(401);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(getSessionMock).toHaveBeenCalledOnce();
    expect(refreshSessionMock).not.toHaveBeenCalled();
    expect(supabase.auth.getSession).toBe(getSessionMock);
  });
});
