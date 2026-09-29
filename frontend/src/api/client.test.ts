import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSessionMock, refreshSessionMock, signOutMock, fetchMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  refreshSessionMock: vi.fn(),
  signOutMock: vi.fn(),
  fetchMock: vi.fn(),
}));

vi.mock("../lib/supabase.ts", () => ({
  supabase: {
    auth: {
      getSession: getSessionMock,
      refreshSession: refreshSessionMock,
      signOut: signOutMock,
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
  refreshSessionMock.mockResolvedValue({ data: { session: null }, error: null });
  signOutMock.mockReset();
  signOutMock.mockResolvedValue({ error: null });
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

  it("does not refresh or retry non-401 responses", async () => {
    const forbidden = new Response(null, { status: 403 });
    fetchMock.mockResolvedValue(forbidden);

    const result = await apiRequest("protected-resource");

    expect(result).toBe(forbidden);
    expect(result.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(getSessionMock).toHaveBeenCalledOnce();
    expect(refreshSessionMock).not.toHaveBeenCalled();
    expect(signOutMock).not.toHaveBeenCalled();
    expect(supabase.auth.getSession).toBe(getSessionMock);
  });

  it("refreshes once and retries with the refreshed token", async () => {
    const retryResponse = new Response(null, { status: 200 });
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(retryResponse);
    refreshSessionMock.mockResolvedValue({
      data: { session: { access_token: "refreshed-access-token" } },
      error: null,
    });

    const result = await apiRequest("protected-resource", {
      method: "PATCH",
      body: { active: true },
      headers: { "X-Custom": "preserved" },
    });

    expect(result).toBe(retryResponse);
    expect(refreshSessionMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [retryUrl, retryInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(retryUrl).toBe("https://api.example.test/protected-resource");
    expect(retryInit.method).toBe("PATCH");
    expect(retryInit.body).toBe('{"active":true}');
    expect(new Headers(retryInit.headers).get("Authorization")).toBe(
      "Bearer refreshed-access-token",
    );
    expect(new Headers(retryInit.headers).get("X-Custom")).toBe("preserved");
    expect(signOutMock).not.toHaveBeenCalled();
  });

  it("signs out and returns the original 401 when refresh fails", async () => {
    const unauthorized = new Response("original 401", { status: 401 });
    fetchMock.mockResolvedValue(unauthorized);
    refreshSessionMock.mockResolvedValue({
      data: { session: null },
      error: new Error("private refresh detail"),
    });
    signOutMock.mockRejectedValue(new Error("private sign-out detail"));

    const result = await apiRequest("protected-resource");

    expect(result).toBe(unauthorized);
    expect(refreshSessionMock).toHaveBeenCalledOnce();
    expect(signOutMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(await result.text()).toBe("original 401");
  });

  it.each([
    ["missing session", { data: { session: null }, error: null }],
    ["missing access token", { data: { session: { access_token: "" } }, error: null }],
  ])(
    "signs out without retry when refresh has no usable token (%s)",
    async (_case, refreshResult) => {
      const unauthorized = new Response(null, { status: 401 });
      fetchMock.mockResolvedValue(unauthorized);
      refreshSessionMock.mockResolvedValue(refreshResult);

      const result = await apiRequest("protected-resource");

      expect(result).toBe(unauthorized);
      expect(refreshSessionMock).toHaveBeenCalledOnce();
      expect(signOutMock).toHaveBeenCalledOnce();
      expect(fetchMock).toHaveBeenCalledOnce();
    },
  );

  it("signs out after a retry 401 without attempting a second refresh", async () => {
    const retryUnauthorized = new Response(null, { status: 401 });
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(retryUnauthorized);
    refreshSessionMock.mockResolvedValue({
      data: { session: { access_token: "refreshed-access-token" } },
      error: null,
    });

    const result = await apiRequest("protected-resource");

    expect(result).toBe(retryUnauthorized);
    expect(refreshSessionMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(signOutMock).toHaveBeenCalledOnce();
  });

  it("signs out when refreshSession throws and preserves the original 401", async () => {
    const unauthorized = new Response(null, { status: 401 });
    fetchMock.mockResolvedValue(unauthorized);
    refreshSessionMock.mockRejectedValue(new Error("private refresh exception"));

    const result = await apiRequest("protected-resource");

    expect(result).toBe(unauthorized);
    expect(refreshSessionMock).toHaveBeenCalledOnce();
    expect(signOutMock).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
