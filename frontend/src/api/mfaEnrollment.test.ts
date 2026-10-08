import { afterEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock } = vi.hoisted(() => ({ apiRequestMock: vi.fn() }));

vi.mock("./client.ts", () => ({ apiRequest: apiRequestMock }));

import {
  MfaEnrollmentApiError,
  startTotpEnrollment,
  verifyTotpEnrollment,
} from "./mfaEnrollment.ts";

afterEach(() => vi.clearAllMocks());

describe("TOTP enrollment API", () => {
  it("starts enrollment through the shared API client and validates setup material", async () => {
    const payload = {
      otpauth_uri: "otpauth://totp/TrustGate:user%40example.test?secret=SECRET",
      manual_entry_key: "MANUAL-KEY",
    };
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }));

    await expect(startTotpEnrollment()).resolves.toEqual(payload);
    expect(apiRequestMock).toHaveBeenCalledWith("/auth/mfa/totp/enrollment", { method: "POST" });
  });

  it("posts the code to the existing enrollment verification endpoint", async () => {
    const payload = { enrollment_status: "verified", verified_at: "2026-10-08T10:00:00Z" };
    apiRequestMock.mockResolvedValue(new Response(JSON.stringify(payload), { status: 200 }));

    await expect(verifyTotpEnrollment("012345")).resolves.toEqual(payload);
    expect(apiRequestMock).toHaveBeenCalledWith("/auth/mfa/totp/enrollment/verify", {
      method: "POST",
      body: { code: "012345" },
    });
  });

  it("preserves HTTP status for safe UI error mapping without exposing response details", async () => {
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify({ detail: "private backend message" }), { status: 429 }),
    );

    await expect(startTotpEnrollment()).rejects.toMatchObject({
      name: "MfaEnrollmentApiError",
      status: 429,
    });
    await expect(startTotpEnrollment()).rejects.toBeInstanceOf(MfaEnrollmentApiError);
  });
});
