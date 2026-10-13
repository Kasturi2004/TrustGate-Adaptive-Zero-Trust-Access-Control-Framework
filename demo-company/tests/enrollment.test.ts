import { afterEach, describe, expect, it, vi } from "vitest";
import { requestTotpEnrollment } from "../src/enrollment";

const api = "/api";
const responseBody = {
  otpauth_uri: "otpauth://totp/TrustGate:employee@example.test?secret=fixture-secret",
  manual_entry_key: "fixture-secret",
};
const session = (token: string, refresh_token?: string) => ({ token, refresh_token });

function emptyStorage(): Storage {
  return {
    getItem: vi.fn(() => null),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
    key: vi.fn(() => null),
    get length() { return 0; },
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("TOTP enrollment request", () => {
  it("renders only the enrollment response returned by TrustGate", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(responseBody), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestTotpEnrollment(api, session("valid-test-session"), emptyStorage()))
      .resolves.toEqual(responseBody);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/auth/mfa/totp/enrollment");
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: "Bearer valid-test-session",
      },
    });
  });

  it("shares a delayed enrollment request for the same session", async () => {
    let resolveFetch!: (response: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    }));
    vi.stubGlobal("fetch", fetchMock);

    const currentSession = session("shared-test-session");
    const storage = emptyStorage();
    const first = requestTotpEnrollment(api, currentSession, storage);
    const second = requestTotpEnrollment(api, currentSession, storage);
    expect(second).toBe(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    resolveFetch(new Response(JSON.stringify(responseBody), { status: 200 }));
    await expect(first).resolves.toEqual(responseBody);
  });

  it("refreshes an expired access token and persists the rotated session", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("{}", { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: "rotated-access-token",
        refresh_token: "rotated-refresh-token",
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(responseBody), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const currentSession = session("expired-access-token", "valid-refresh-token");
    const storage = emptyStorage();

    await expect(requestTotpEnrollment(api, currentSession, storage)).resolves.toEqual(responseBody);

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1]?.[0]).toBe("/api/auth/refresh");
    expect(currentSession).toEqual({
      token: "rotated-access-token",
      refresh_token: "rotated-refresh-token",
    });
    expect(storage.setItem).toHaveBeenCalledWith(
      "acme.session",
      JSON.stringify(currentSession),
    );
  });

  it("turns a stalled request into a recoverable timeout and allows retry", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockImplementationOnce(() => new Promise<Response>(() => {}))
      .mockResolvedValueOnce(new Response(JSON.stringify(responseBody), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const currentSession = session("retry-test-session");
    const storage = emptyStorage();
    const stalled = requestTotpEnrollment(api, currentSession, storage);
    const failure = expect(stalled).rejects.toThrow("Secure setup is taking too long");
    await vi.advanceTimersByTimeAsync(15_000);
    await failure;

    await expect(requestTotpEnrollment(api, currentSession, storage)).resolves.toEqual(responseBody);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reports an expired session safely without exposing enrollment data", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ detail: "private error", ...responseBody }), { status: 401 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ detail: "private error", ...responseBody }), { status: 401 }),
      );
    vi.stubGlobal("fetch", fetchMock);

    let caught: unknown;
    try {
      await requestTotpEnrollment(
        api,
        session("expired-test-session", "expired-refresh-token"),
        emptyStorage(),
      );
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe("Your session expired. Sign in again to continue.");
    expect((caught as Error).message).not.toContain("fixture-secret");
    expect((caught as Error).message).not.toContain("private error");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[0]).toBe("/api/auth/refresh");
  });

  it("shows a safe network error and permits another attempt", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError("private network detail"))
      .mockResolvedValueOnce(new Response(JSON.stringify(responseBody), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const currentSession = session("network-test-session");
    const storage = emptyStorage();

    await expect(requestTotpEnrollment(api, currentSession, storage))
      .rejects.toThrow("Unable to reach TrustGate. Check your connection and retry.");
    await expect(requestTotpEnrollment(api, currentSession, storage)).resolves.toEqual(responseBody);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
