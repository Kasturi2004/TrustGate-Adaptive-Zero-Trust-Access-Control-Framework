import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { authState, useLocationMock } = vi.hoisted(() => ({
  authState: { session: null as unknown, user: null as unknown, loading: false },
  useLocationMock: vi.fn(),
}));

vi.mock("./AuthProvider.tsx", () => ({ useAuth: () => authState }));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    Navigate: function Navigate() {
      return null;
    },
    useLocation: useLocationMock,
  };
});

import { Navigate } from "react-router-dom";
import { AuthEntryRoute } from "./AuthEntryRoute.tsx";
import { ProtectedRoute } from "./ProtectedRoute.tsx";

const location = {
  pathname: "/access",
  search: "",
  hash: "",
  state: null,
  key: "access-key",
};

beforeEach(() => {
  authState.session = null;
  authState.user = null;
  authState.loading = false;
  useLocationMock.mockReturnValue(location);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("authentication entry navigation", () => {
  it("keeps an unauthenticated user on the login/signup entry page", () => {
    const child = "auth form";

    expect(AuthEntryRoute({ children: child })).toBe(child);
  });

  it("redirects an authenticated user away from login/signup to the protected page", () => {
    authState.session = { access_token: "test-token" };
    authState.user = { id: "test-user" };

    const element = AuthEntryRoute({ children: "auth form" }) as ReactElement;

    expect(element.type).toBe(Navigate);
    expect(element.props).toEqual({ to: "/access", replace: true });
  });

  it("shows session restoration instead of redirecting while auth is loading", () => {
    authState.loading = true;

    const element = AuthEntryRoute({ children: "auth form" }) as ReactElement;

    expect(element.props).toMatchObject({ role: "status" });
    expect(element.type).not.toBe(Navigate);
  });

  it("after logout clears auth state, blocks protected content and allows the login page without a loop", () => {
    authState.session = null;
    authState.user = null;

    const protectedRedirect = ProtectedRoute({ children: "protected content" }) as ReactElement;
    const loginPage = AuthEntryRoute({ children: "login form" });

    expect(protectedRedirect.type).toBe(Navigate);
    expect(protectedRedirect.props).toMatchObject({ to: "/login", replace: true });
    expect(loginPage).toBe("login form");
  });
});
