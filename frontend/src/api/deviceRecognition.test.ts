import { beforeEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock, identifierMock } = vi.hoisted(() => ({
  apiRequestMock: vi.fn(),
  identifierMock: vi.fn(() => "stable-browser-identifier"),
}));

vi.mock("./client.ts", () => ({ apiRequest: apiRequestMock }));
vi.mock("../lib/deviceIdentity.ts", () => ({ getDeviceIdentifier: identifierMock }));

import {
  fetchCurrentDeviceRecognition,
  forgetCurrentDevice,
  recognizeCurrentDevice,
} from "./deviceRecognition.ts";

beforeEach(() => {
  apiRequestMock.mockReset();
  identifierMock.mockClear();
});

describe("device recognition API", () => {
  it("uses the stable identifier only in the existing request header", async () => {
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify({ recognized: false }), { status: 200 }),
    );

    await fetchCurrentDeviceRecognition();

    expect(apiRequestMock).toHaveBeenCalledWith("/devices/current", {
      method: "GET",
      headers: { "X-Device-Token": "stable-browser-identifier" },
    });
    expect(JSON.stringify(apiRequestMock.mock.calls)).not.toContain("?stable-browser-identifier");
  });

  it("sends only the access-request selector when explicitly recognizing", async () => {
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify({ recognized: true }), { status: 200 }),
    );

    await recognizeCurrentDevice("redeemed-access-request");

    expect(apiRequestMock).toHaveBeenCalledWith("/devices/recognition", {
      method: "POST",
      body: { access_request_id: "redeemed-access-request" },
      headers: { "X-Device-Token": "stable-browser-identifier" },
    });
    expect(JSON.stringify(apiRequestMock.mock.calls)).not.toContain("device_hash");
  });

  it("uses DELETE for current-device revocation and reports safe failures", async () => {
    apiRequestMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ recognized: false }), { status: 200 }),
    );
    await forgetCurrentDevice();
    expect(apiRequestMock).toHaveBeenCalledWith("/devices/current/recognition", {
      method: "DELETE",
      headers: { "X-Device-Token": "stable-browser-identifier" },
    });

    apiRequestMock.mockResolvedValueOnce(new Response("private backend detail", { status: 500 }));
    await expect(fetchCurrentDeviceRecognition()).rejects.toMatchObject({
      message: "Device recognition request failed",
      status: 500,
    });
  });
});
