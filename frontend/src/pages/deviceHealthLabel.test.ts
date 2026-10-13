import { describe, expect, it } from "vitest";
import { formatDeviceHealth } from "./deviceHealthLabel";

describe("formatDeviceHealth", () => {
  it("distinguishes unavailable posture from a verified healthy device", () => {
    expect(formatDeviceHealth("unknown", "posture-v1")).toBe(
      "Unknown · posture unverified",
    );
    expect(formatDeviceHealth("healthy", "posture-v1")).toBe(
      "Verified posture healthy",
    );
    expect(formatDeviceHealth("unhealthy", "posture-v1")).toBe(
      "Verified posture failure",
    );
    expect(formatDeviceHealth("partially_healthy", "posture-v1")).toBe(
      "Verified posture below healthy threshold",
    );
  });

  it("labels records without the new marker as legacy browser/transport data", () => {
    expect(formatDeviceHealth("unhealthy", null)).toBe(
      "Legacy browser/transport signal: unhealthy",
    );
  });
});
