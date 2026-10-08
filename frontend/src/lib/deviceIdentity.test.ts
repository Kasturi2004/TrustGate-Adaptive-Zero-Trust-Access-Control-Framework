import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getDeviceIdentifier } from "./deviceIdentity.ts";

const IDENTIFIER = "2d1719d8-b45c-4a23-bab3-daa28aa5eff0";
const STORAGE_KEY = "trustgate.device-identifier.v1";

let values: Map<string, string>;

beforeEach(() => {
  values = new Map();
  vi.stubGlobal("localStorage", {
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => values.set(key, String(value))),
    removeItem: vi.fn((key: string) => values.delete(key)),
    clear: vi.fn(() => values.clear()),
  });
  vi.stubGlobal("crypto", { randomUUID: vi.fn().mockReturnValue(IDENTIFIER) });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("getDeviceIdentifier", () => {
  it("creates a cryptographically random identifier only when storage is empty", () => {
    const randomUUID = vi.mocked(crypto.randomUUID);

    expect(getDeviceIdentifier()).toBe(IDENTIFIER);
    expect(localStorage.getItem(STORAGE_KEY)).toBe(IDENTIFIER);
    expect(localStorage.setItem).toHaveBeenCalledWith(STORAGE_KEY, IDENTIFIER);
    expect(randomUUID).toHaveBeenCalledOnce();
  });

  it("reuses the stored identifier across repeated calls and refreshes", () => {
    getDeviceIdentifier();
    const identifierAfterRefresh = getDeviceIdentifier();

    expect(identifierAfterRefresh).toBe(IDENTIFIER);
    expect(crypto.randomUUID).toHaveBeenCalledOnce();
  });

  it("creates a new identifier after the stored value is removed", () => {
    getDeviceIdentifier();
    values.delete(STORAGE_KEY);
    vi.mocked(crypto.randomUUID).mockReturnValue("31acb2f1-6c5e-4727-bfef-6b4bc8e87f5f");

    expect(getDeviceIdentifier()).toBe("31acb2f1-6c5e-4727-bfef-6b4bc8e87f5f");
    expect(crypto.randomUUID).toHaveBeenCalledTimes(2);
  });
});
