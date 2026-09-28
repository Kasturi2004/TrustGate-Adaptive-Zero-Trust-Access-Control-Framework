import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { supabasePublicConfig } from "./env.ts";

const { createClientMock } = vi.hoisted(() => ({
  createClientMock: vi.fn(() => ({ auth: {} })),
}));

vi.mock("@supabase/supabase-js", () => ({ createClient: createClientMock }));

describe("Supabase public client configuration", () => {
  beforeEach(() => {
    vi.resetModules();
    createClientMock.mockClear();
    vi.stubEnv("VITE_SUPABASE_URL", "");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns the configured public Supabase values", () => {
    vi.stubEnv("VITE_SUPABASE_URL", " https://supabase.example.test ");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", " test-public-anon-key ");

    expect(supabasePublicConfig()).toEqual({
      url: "https://supabase.example.test",
      anonKey: "test-public-anon-key",
    });
  });

  it("requires both public values", () => {
    expect(() => supabasePublicConfig()).toThrow("VITE_SUPABASE_URL is required");

    vi.stubEnv("VITE_SUPABASE_URL", "https://supabase.example.test");
    expect(() => supabasePublicConfig()).toThrow("VITE_SUPABASE_ANON_KEY is required");
  });

  it("creates one client from the public values without network access", async () => {
    vi.stubEnv("VITE_SUPABASE_URL", "https://supabase.example.test");
    vi.stubEnv("VITE_SUPABASE_ANON_KEY", "test-public-anon-key");

    const firstImport = await import("./supabase.ts");
    const secondImport = await import("./supabase.ts");

    expect(createClientMock).toHaveBeenCalledOnce();
    expect(createClientMock).toHaveBeenCalledWith(
      "https://supabase.example.test",
      "test-public-anon-key",
    );
    expect(firstImport.supabase).toBe(secondImport.supabase);
  });
});
