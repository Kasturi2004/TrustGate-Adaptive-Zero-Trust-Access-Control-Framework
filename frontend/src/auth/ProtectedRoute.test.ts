import type { ReactElement } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { afterEach, describe, expect, it, vi } from "vitest";

const { useAuthMock, useLocationMock } = vi.hoisted(() => ({
  useAuthMock: vi.fn(),
  useLocationMock: vi.fn(),
}));

vi.mock("./AuthProvider.tsx", () => ({ useAuth: useAuthMock }));
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
import { ProtectedRoute } from "./ProtectedRoute.tsx";

const location = {
  pathname: "/access",
  search: "?resource=example",
  hash: "#details",
  state: null,
  key: "route-key",
};

const user = { id: "user-id" } as User;
const session = { user } as Session;

afterEach(() => {
  vi.clearAllMocks();
});

describe("ProtectedRoute", () => {
  it("shows a loading state without redirecting while session restores", () => {
    useAuthMock.mockReturnValue({ session: null, user: null, loading: true });
    useLocationMock.mockReturnValue(location);

    const element = ProtectedRoute({ children: "protected content" }) as ReactElement;

    expect(element.props).toMatchObject({ role: "status" });
    expect(element.type).not.toBe(Navigate);
  });

  it("redirects an unauthenticated user to login and preserves the destination", () => {
    useAuthMock.mockReturnValue({ session: null, user: null, loading: false });
    useLocationMock.mockReturnValue(location);

    const element = ProtectedRoute({ children: "protected content" }) as ReactElement;

    expect(element.type).toBe(Navigate);
    expect(element.props).toEqual({ to: "/login", state: { from: location }, replace: true });
  });

  it("renders its children when the session and user are authenticated", () => {
    useAuthMock.mockReturnValue({ session, user, loading: false });
    useLocationMock.mockReturnValue(location);
    const child = "protected content";

    expect(ProtectedRoute({ children: child })).toBe(child);
  });

  it("does not make authentication or API network requests", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    useAuthMock.mockReturnValue({ session, user, loading: false });
    useLocationMock.mockReturnValue(location);

    ProtectedRoute({ children: "protected content" });

    expect(useAuthMock).toHaveBeenCalledOnce();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
