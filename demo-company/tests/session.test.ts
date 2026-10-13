import { afterEach, describe, expect, it, vi } from "vitest";
import { authenticatedRequest, readPortalSession, type PortalSession } from "../src/session";

function storageFor(session: PortalSession): Storage {
  let value = JSON.stringify(session);
  return {
    getItem: vi.fn(() => value),
    setItem: vi.fn((_key: string, next: string) => { value = next; }),
    removeItem: vi.fn(() => { value = "null"; }),
    clear: vi.fn(),
    key: vi.fn(() => null),
    get length() { return 1; },
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("employee portal session requests", () => {
  it("returns structured access decisions as successful API responses", async () => {
    const session: PortalSession = { token: "active-access" };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      decision: "BLOCK",
      explanation: "Access is not approved.",
      mfa_challenge_id: null,
      access_request_id: "request-id",
    }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(authenticatedRequest(
      "/api", "/access/evaluate", session, {}, storageFor(session),
    )).resolves.toMatchObject({ decision: "BLOCK", access_request_id: "request-id" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("drops malformed persisted session data instead of treating it as an expired token", () => {
    const storage = storageFor({ token: "" });

    expect(readPortalSession(storage)).toBeNull();
    expect(storage.removeItem).toHaveBeenCalledWith("acme.session");
  });

  it("refreshes an expired access token, retries the API request, and persists rotation", async () => {
    const session: PortalSession = { token: "old-access", refresh_token: "old-refresh" };
    const storage = storageFor(session);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ detail: "expired" }), { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: "new-access",
        refresh_token: "new-refresh",
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "employee" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(authenticatedRequest<{ id: string }>(
      "/api", "/auth/me", session, {}, storage,
    )).resolves.toEqual({ id: "employee" });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1]?.[0]).toBe("/api/auth/refresh");
    expect(JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body))).toEqual({
      refresh_token: "old-refresh",
    });
    expect(session).toEqual({ token: "new-access", refresh_token: "new-refresh" });
    expect(JSON.parse(String(storage.getItem("acme.session")))).toEqual(session);
  });

  it("reports an invalid refresh token as an expired session without retrying the protected API", async () => {
    const session: PortalSession = { token: "old-access", refresh_token: "invalid-refresh" };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("{}", { status: 401 }))
      .mockResolvedValueOnce(new Response("{}", { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(authenticatedRequest("/api", "/auth/me", session, {}, storageFor(session)))
      .rejects.toMatchObject({ status: 401, message: "Your session expired. Sign in again to continue." });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("shares a single rotating refresh across duplicate startup requests", async () => {
    const first: PortalSession = { token: "old-access", refresh_token: "one-time-refresh" };
    const second: PortalSession = { ...first };
    const firstStorage = storageFor(first);
    const secondStorage = storageFor(second);
    let profileRequests = 0;
    let refreshRequests = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/auth/refresh")) {
        refreshRequests += 1;
        return new Response(JSON.stringify({
          access_token: "new-access",
          refresh_token: "rotated-refresh",
        }), { status: 200 });
      }
      profileRequests += 1;
      return profileRequests <= 2
        ? new Response("{}", { status: 401 })
        : new Response(JSON.stringify({ id: "employee" }), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const responses = await Promise.all([
      authenticatedRequest("/api", "/auth/me", first, {}, firstStorage),
      authenticatedRequest("/api", "/auth/me", second, {}, secondStorage),
    ]);

    expect(responses).toEqual([{ id: "employee" }, { id: "employee" }]);
    expect(refreshRequests).toBe(1);
    expect(profileRequests).toBe(4);
  });

  it("preserves backend errors and does not refresh on failed API requests other than 401", async () => {
    const session: PortalSession = { token: "active-access", refresh_token: "active-refresh" };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "Authentication service is unavailable." }), { status: 503 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(authenticatedRequest("/api", "/auth/me", session, {}, storageFor(session)))
      .rejects.toMatchObject({ status: 503, message: "Authentication service is unavailable." });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports network failures as connectivity errors without discarding the session", async () => {
    const session: PortalSession = { token: "active-access", refresh_token: "active-refresh" };
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(authenticatedRequest("/api", "/auth/me", session, {}, storageFor(session)))
      .rejects.toMatchObject({ status: 0, message: expect.stringContaining("Unable to reach TrustGate") });
  });
});
