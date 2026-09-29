import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { hookHarness, authState, useNavigateMock, signOutMock } = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    stateCursor: 0,
    refs: [] as Array<{ current: unknown }>,
    refCursor: 0,
  },
  authState: { session: null as unknown, user: null as unknown, loading: false },
  useNavigateMock: vi.fn(),
  signOutMock: vi.fn(),
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initialValue: unknown) => {
      const index = hookHarness.stateCursor;
      hookHarness.stateCursor += 1;
      if (!(index in hookHarness.states)) hookHarness.states[index] = initialValue;
      return [
        hookHarness.states[index],
        (nextValue: unknown) => {
          hookHarness.states[index] = nextValue;
        },
      ];
    },
    useRef: (initialValue: unknown) => {
      const index = hookHarness.refCursor;
      hookHarness.refCursor += 1;
      hookHarness.refs[index] ??= { current: initialValue };
      return hookHarness.refs[index];
    },
  } as unknown as typeof actual;
});

vi.mock("../auth/AuthProvider.tsx", () => ({ useAuth: () => authState }));
vi.mock("../lib/supabase.ts", () => ({ supabase: { auth: { signOut: signOutMock } } }));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => useNavigateMock };
});

import { LogoutButton } from "./LogoutButton.tsx";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

function renderLogoutButton(): UiNode | null {
  hookHarness.stateCursor = 0;
  hookHarness.refCursor = 0;
  return LogoutButton() as UiNode | null;
}

function findButton(root: UiNode | null): UiNode | undefined {
  if (!root) return undefined;
  const children = root.props.children;
  if (Array.isArray(children)) {
    return children.find(
      (child): child is UiNode =>
        typeof child === "object" && child !== null && "type" in child && child.type === "button",
    );
  }
  return undefined;
}

function clickHandler(button: UiNode): () => Promise<void> {
  return button.props.onClick as () => Promise<void>;
}

beforeEach(() => {
  hookHarness.states = [];
  hookHarness.stateCursor = 0;
  hookHarness.refs = [];
  hookHarness.refCursor = 0;
  authState.session = { access_token: "test-token" };
  authState.user = { id: "test-user" };
  authState.loading = false;
  useNavigateMock.mockReset();
  signOutMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("LogoutButton", () => {
  it("shows the sign-out action only for an authenticated user", () => {
    expect(findButton(renderLogoutButton())?.props.children).toBe("Sign out");

    authState.session = null;
    authState.user = null;
    expect(renderLogoutButton()).toBeNull();
  });

  it("signs out through Supabase and navigates to login", async () => {
    signOutMock.mockResolvedValue({ error: null });

    await clickHandler(findButton(renderLogoutButton()) as UiNode)();

    expect(signOutMock).toHaveBeenCalledOnce();
    expect(useNavigateMock).toHaveBeenCalledWith("/login", { replace: true });
  });

  it("shows a safe message when Supabase sign-out fails", async () => {
    signOutMock.mockResolvedValue({ error: new Error("private token and session detail") });

    await clickHandler(findButton(renderLogoutButton()) as UiNode)();

    const root = renderLogoutButton();
    const errorNode = root?.props.children as UiNode[];
    expect(errorNode[1]?.props.children).toBe("Unable to sign out right now. Please try again.");
    expect(String(errorNode[1]?.props.children)).not.toContain("private");
    expect(useNavigateMock).not.toHaveBeenCalled();
  });

  it("disables the action while signing out and prevents duplicate calls", async () => {
    let resolveSignOut: (value: { error: null }) => void = () => undefined;
    signOutMock.mockReturnValue(
      new Promise((resolve) => {
        resolveSignOut = resolve;
      }),
    );
    const handler = clickHandler(findButton(renderLogoutButton()) as UiNode);
    const pending = handler();
    await handler();

    expect(signOutMock).toHaveBeenCalledOnce();
    expect(findButton(renderLogoutButton())?.props.disabled).toBe(true);

    resolveSignOut({ error: null });
    await pending;
    expect(findButton(renderLogoutButton())?.props.disabled).toBe(false);
  });

  it("does not manually store or delete tokens", async () => {
    const localStorage = { setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn() };
    const sessionStorage = { setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn() };
    vi.stubGlobal("localStorage", localStorage);
    vi.stubGlobal("sessionStorage", sessionStorage);
    signOutMock.mockResolvedValue({ error: null });

    await clickHandler(findButton(renderLogoutButton()) as UiNode)();

    expect(localStorage.setItem).not.toHaveBeenCalled();
    expect(localStorage.removeItem).not.toHaveBeenCalled();
    expect(localStorage.clear).not.toHaveBeenCalled();
    expect(sessionStorage.setItem).not.toHaveBeenCalled();
    expect(sessionStorage.removeItem).not.toHaveBeenCalled();
    expect(sessionStorage.clear).not.toHaveBeenCalled();
  });
});
