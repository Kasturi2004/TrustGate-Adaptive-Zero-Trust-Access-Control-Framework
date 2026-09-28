import type { Session, User } from "@supabase/supabase-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { harness, supabaseAuth } = vi.hoisted(() => ({
  harness: {
    stateSlots: [] as unknown[],
    stateCursor: 0,
    effects: [] as Array<() => (() => void) | undefined>,
    contextValue: undefined as unknown,
  },
  supabaseAuth: {
    getSession: vi.fn(),
    onAuthStateChange: vi.fn(),
  },
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    createContext: (defaultValue: unknown) => ({
      Provider: function Provider() {
        return null;
      },
      defaultValue,
    }),
    useState: (initialValue: unknown) => {
      const index = harness.stateCursor;
      harness.stateCursor += 1;
      if (!(index in harness.stateSlots)) {
        harness.stateSlots[index] = initialValue;
      }
      return [
        harness.stateSlots[index],
        (nextValue: unknown) => {
          harness.stateSlots[index] =
            typeof nextValue === "function"
              ? (nextValue as (previous: unknown) => unknown)(harness.stateSlots[index])
              : nextValue;
        },
      ];
    },
    useEffect: (effect: () => (() => void) | undefined) => {
      harness.effects.push(effect);
    },
    useContext: () => harness.contextValue,
  } as unknown as typeof actual;
});

vi.mock("../lib/supabase.ts", () => ({ supabase: { auth: supabaseAuth } }));

import { AuthProvider, useAuth } from "./AuthProvider.tsx";

const fakeUser = {
  id: "user-id",
  email: "user@example.test",
} as User;

const fakeSession = {
  access_token: "test-session-access-token",
  refresh_token: "test-session-refresh-token",
  token_type: "bearer",
  expires_in: 3600,
  expires_at: 1_900_000_000,
  user: fakeUser,
} as Session;

function renderProvider() {
  harness.stateCursor = 0;
  harness.effects = [];
  const element = AuthProvider({ children: null });
  const value = (element.props as unknown as { value: ReturnType<typeof useAuth> }).value;
  harness.contextValue = value;
  return { value, effect: harness.effects[0] };
}

async function flushSessionLookup(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
  harness.stateSlots = [];
  harness.stateCursor = 0;
  harness.effects = [];
  harness.contextValue = undefined;
  supabaseAuth.getSession.mockReset();
  supabaseAuth.getSession.mockResolvedValue({ data: { session: null }, error: null });
  supabaseAuth.onAuthStateChange.mockReset();
  supabaseAuth.onAuthStateChange.mockReturnValue({
    data: { subscription: { unsubscribe: vi.fn() } },
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("AuthProvider", () => {
  it("starts in a loading state", () => {
    const { value } = renderProvider();

    expect(value).toEqual({ session: null, user: null, loading: true });
  });

  it("loads an existing session and derives its user", async () => {
    supabaseAuth.getSession.mockResolvedValue({ data: { session: fakeSession }, error: null });
    const initial = renderProvider();

    initial.effect?.();
    await flushSessionLookup();
    const resolved = renderProvider().value;

    expect(resolved).toEqual({ session: fakeSession, user: fakeUser, loading: false });
  });

  it("resolves with no session when the user is signed out", async () => {
    supabaseAuth.getSession.mockResolvedValue({ data: { session: null }, error: null });
    const initial = renderProvider();

    initial.effect?.();
    await flushSessionLookup();
    const resolved = renderProvider().value;

    expect(resolved).toEqual({ session: null, user: null, loading: false });
  });

  it("updates the session and user when Supabase reports an auth change", () => {
    const initial = renderProvider();
    initial.effect?.();
    const onAuthStateChange = supabaseAuth.onAuthStateChange.mock.calls[0]?.[0] as (
      event: string,
      session: Session | null,
    ) => void;

    onAuthStateChange("SIGNED_IN", fakeSession);

    expect(renderProvider().value).toEqual({
      session: fakeSession,
      user: fakeUser,
      loading: false,
    });
  });

  it("clears the session and user when Supabase reports sign-out", () => {
    const initial = renderProvider();
    initial.effect?.();
    const onAuthStateChange = supabaseAuth.onAuthStateChange.mock.calls[0]?.[0] as (
      event: string,
      session: Session | null,
    ) => void;
    onAuthStateChange("SIGNED_IN", fakeSession);
    onAuthStateChange("SIGNED_OUT", null);

    expect(renderProvider().value).toEqual({ session: null, user: null, loading: false });
  });

  it("unsubscribes from Supabase auth changes on cleanup", () => {
    const unsubscribe = vi.fn();
    supabaseAuth.onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe } } });
    const initial = renderProvider();
    const cleanup = initial.effect?.();

    cleanup?.();

    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it("throws a clear error when useAuth is called outside the provider", () => {
    harness.contextValue = undefined;

    expect(() => useAuth()).toThrow("useAuth must be used within an AuthProvider");
  });
});
